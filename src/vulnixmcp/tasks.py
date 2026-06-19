import os
from datetime import datetime, timezone
from celery import Celery
from vulnixmcp.database import SessionLocal
from vulnixmcp.models import ScanJob, AuditLog, Asset, Finding
from vulnixmcp.scanner import scan_target, identify_ai_components
from vulnixmcp.vulns import get_all_vulnerabilities
from vulnixmcp.scoring import score_all_findings

redis_url = os.getenv("REDIS_URL")
if redis_url and redis_url.startswith("rediss://") and "ssl_cert_reqs" not in redis_url:
    join_char = "&" if "?" in redis_url else "?"
    redis_url += f"{join_char}ssl_cert_reqs=CERT_NONE"

celery_app = Celery(
    "vulnixmcp",
    broker=redis_url,
    backend=redis_url,
)

@celery_app.task
def run_scan_task(scan_job_id: str, target: str):
    from vulnixmcp.server import _analyze_attack_paths
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
        
        # 4. Call scanner.scan_target
        services = scan_target(target)
        
        # 5. Call scanner.identify_ai_components
        ai_components = identify_ai_components(services)
        
        # 6. Save components to DB
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
            session.flush() # to get asset.id
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
        
        # 7. Call vulns.get_all_vulnerabilities
        assets_for_vulns = [a["asset_dict"] for a in saved_assets]
        all_vulns = get_all_vulnerabilities(assets_for_vulns)
        
        # 8. Call scoring.score_all_findings
        scored_findings = score_all_findings(all_vulns)
        
        # 9. Save each Finding
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
        
        # 10. Fetch all findings and send to Claude
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
            
        _analyze_attack_paths(scan_job_id, findings_dicts) # it writes to DB internally
        
        # 12. Update job
        job.status = "complete"
        job.finished_at = datetime.now(timezone.utc)
        
        # 13. Write AuditLog
        audit_complete = AuditLog(
            scan_job_id=scan_job_id,
            event_type="SCAN_COMPLETE",
            detail=f"Scan complete for target {target}"
        )
        session.add(audit_complete)
        session.commit()
        
    except Exception as e:
        session.rollback()
        job = session.query(ScanJob).filter(ScanJob.id == scan_job_id).first()
        if job:
            job.status = "failed"
            job.error_message = str(e)
            
            audit_fail = AuditLog(
                scan_job_id=scan_job_id,
                event_type="SCAN_FAILED",
                detail=f"Scan failed: {str(e)}"
            )
            session.add(audit_fail)
            session.commit()
    finally:
        session.close()
