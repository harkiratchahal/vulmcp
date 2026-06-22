import os
import json
import threading
from datetime import datetime, timezone
from loguru import logger
from vulnixmcp.database import SessionLocal
from vulnixmcp.models import ScanJob, AuditLog, Asset, Finding, AttackPath
from vulnixmcp.scanner import scan_target, identify_ai_components
from vulnixmcp.vulns import get_all_vulnerabilities
from vulnixmcp.scoring import score_all_findings


def _analyze_attack_paths(scan_job_id: str, findings: list[dict]) -> list[dict]:
    """
    Send findings to Claude with a structured prompt asking it to identify
    vulnerability chains. Claude must cite Finding IDs as evidence for every
    link in the chain — no speculation without grounding.
    """
    if not findings:
        return []

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        logger.warning("ANTHROPIC_API_KEY not set — skipping attack path analysis")
        return []

    try:
        from anthropic import Anthropic
        client = Anthropic(api_key=api_key)

        prompt = f"""
Here are the vulnerability findings from a recent scan:
{json.dumps(findings, indent=2)}

Identify potential attack chains/paths. Every step MUST reference a specific finding_id from the provided list.
Output JSON ONLY in this exact format, with no other text, markdown blocks, or preamble:
[
  {{
    "title": "Short name",
    "description": "Full explanation of the attack path",
    "finding_ids": ["uuid1", "uuid2"],
    "risk_level": "CRITICAL"
  }}
]
"""

        response = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=1000,
            system="You are a penetration tester. Identify attack chains in these findings. Every step MUST reference a specific finding_id.",
            messages=[
                {"role": "user", "content": prompt}
            ]
        )

        content = response.content[0].text
        # cleanup markdown blocks if model ignored instructions
        if "```json" in content:
            content = content.split("```json")[-1].split("```")[0].strip()
        elif "```" in content:
            content = content.split("```")[1].split("```")[0].strip()

        paths = json.loads(content)

        session = SessionLocal()
        try:
            for p in paths:
                ap = AttackPath(
                    scan_job_id=scan_job_id,
                    title=p.get("title", "Attack Path"),
                    description=p.get("description", ""),
                    finding_ids=p.get("finding_ids", []),
                    risk_level=p.get("risk_level", "MEDIUM")
                )
                session.add(ap)
            session.commit()
        except Exception as db_e:
            session.rollback()
            logger.error(f"Error saving attack paths: {db_e}")
        finally:
            session.close()

        return paths
    except Exception as e:
        logger.error(f"Anthropic API call failed: {e}")
        return []


def _run_scan(scan_job_id: str, target: str):
    """
    Runs the full scan pipeline in the current thread.
    Called from a background thread via run_scan_in_background().
    """
    session = SessionLocal()
    try:
        job = session.query(ScanJob).filter(ScanJob.id == scan_job_id).first()
        if not job:
            return

        job.status = "running"
        job.started_at = datetime.now(timezone.utc)

        audit = AuditLog(
            scan_job_id=scan_job_id,
            event_type="SCAN_STARTED",
            detail=f"Scan started for target {target}"
        )
        session.add(audit)
        session.commit()

        # 1. Run nmap port scan
        services = scan_target(target)

        # 2. Identify AI components from discovered services
        ai_components = identify_ai_components(services)

        # 3. Save discovered assets to DB
        saved_assets = []
        for comp in ai_components:
            asset = Asset(
                scan_job_id=scan_job_id,
                name=comp["component_name"],
                version=comp["version"],
                port=comp["port"],
                service_type=comp["service_type"],
                is_public=comp["is_public"]
            )
            session.add(asset)
            session.flush()  # to get asset.id
            saved_assets.append({
                "db_asset": asset,
                "asset_dict": {
                    "id": asset.id,
                    "component_name": asset.name,
                    "version": asset.version,
                    "port": asset.port,
                    "is_public": asset.is_public
                }
            })

        session.commit()

        # 4. Query vulnerability databases (OSV, NVD, EPSS, KEV)
        assets_for_vulns = [a["asset_dict"] for a in saved_assets]
        all_vulns = get_all_vulnerabilities(assets_for_vulns)

        # 5. Calculate contextual risk scores
        scored_findings = score_all_findings(all_vulns)

        # 6. Save each finding to DB
        for sf in scored_findings:
            finding = Finding(
                scan_job_id=scan_job_id,
                asset_id=sf["asset"]["id"],
                cve_id=sf["cve_id"],
                description=sf["description"],
                cvss_score=sf.get("cvss_score"),
                epss_score=sf.get("epss_score"),
                epss_percentile=sf.get("epss_percentile"),
                is_kev=sf.get("is_kev", False),
                risk_score=sf.get("risk_score"),
                severity=sf.get("severity")
            )
            session.add(finding)
        session.commit()

        # 7. Fetch all findings and generate attack paths via Claude
        db_findings = session.query(Finding).filter(Finding.scan_job_id == scan_job_id).all()
        findings_dicts = []
        for f in db_findings:
            findings_dicts.append({
                "id": f.id,
                "cve_id": f.cve_id,
                "description": f.description,
                "severity": f.severity,
                "asset_id": f.asset_id
            })

        _analyze_attack_paths(scan_job_id, findings_dicts)

        # 8. Mark scan complete
        job.status = "complete"
        job.finished_at = datetime.now(timezone.utc)

        audit_complete = AuditLog(
            scan_job_id=scan_job_id,
            event_type="SCAN_COMPLETE",
            detail=f"Scan complete for target {target}. "
                   f"Assets: {len(saved_assets)}, Findings: {len(scored_findings)}"
        )
        session.add(audit_complete)
        session.commit()

    except Exception as e:
        logger.error(f"Scan failed for job {scan_job_id}: {e}")
        try:
            session.rollback()
            job = session.query(ScanJob).filter(ScanJob.id == scan_job_id).first()
            if job:
                job.status = "failed"
                job.error_message = str(e)[:500]

                audit_fail = AuditLog(
                    scan_job_id=scan_job_id,
                    event_type="SCAN_FAILED",
                    detail=f"Scan failed: {str(e)[:200]}"
                )
                session.add(audit_fail)
                session.commit()
        except Exception as inner_e:
            logger.error(f"Failed to record scan failure: {inner_e}")
    finally:
        session.close()


def run_scan_in_background(scan_job_id: str, target: str):
    """
    Dispatch the scan to a background thread so the MCP tool
    can return immediately with the job ID.
    """
    thread = threading.Thread(
        target=_run_scan,
        args=(scan_job_id, target),
        daemon=True,
        name=f"scan-{scan_job_id[:8]}"
    )
    thread.start()
    logger.info(f"Background scan started for job {scan_job_id} targeting {target}")
