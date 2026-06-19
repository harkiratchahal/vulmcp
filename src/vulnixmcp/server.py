import json
from fastmcp import FastMCP
from anthropic import Anthropic
from vulnixmcp.database import SessionLocal
from vulnixmcp.models import ScanJob, AuditLog, Finding, AttackPath, Asset
from vulnixmcp.tasks import run_scan_task
from vulnixmcp.reporter import generate_report as run_report
from datetime import datetime

mcp = FastMCP("VulnixMCP")

@mcp.tool()
def full_scan(target: str, authorized_by: str, confirm: bool) -> str:
    """
    Run a complete vulnerability scan against an AI infrastructure target.
    
    Args:
        target: IP address or hostname to scan (e.g. "192.168.1.50")
        authorized_by: Name/role of person authorizing this scan (required)
        confirm: Must be True — explicit authorization confirmation
    """
    if not confirm:
        return "You must confirm authorization with confirm=True."
        
    session = SessionLocal()
    try:
        job = ScanJob(target=target, authorized_by=authorized_by)
        session.add(job)
        session.flush() # populates job.id
        
        audit = AuditLog(
            scan_job_id=job.id,
            event_type="SCAN_AUTHORIZED",
            detail=f"Scan authorized by {authorized_by}"
        )
        session.add(audit)
        session.commit()
        
        job_id = job.id
    except Exception as e:
        session.rollback()
        return f"Database error: {str(e)}"
    finally:
        session.close()
        
    run_scan_task.delay(job_id, target)
    return f"Scan started. Job ID: {job_id}. Poll with get_scan_status('{job_id}')"

@mcp.tool()
def get_scan_status(job_id: str) -> str:
    """
    Check the status of a running scan.
    Returns status, timestamps, asset count, and finding count.
    """
    session = SessionLocal()
    try:
        job = session.query(ScanJob).filter(ScanJob.id == job_id).first()
        if not job:
            return "Scan job not found."
            
        assets_count = session.query(Asset).filter(Asset.scan_job_id == job_id).count()
        findings_count = session.query(Finding).filter(Finding.scan_job_id == job_id).count()
        
        lines = [
            f"Status: {job.status}",
            f"Target: {job.target}",
            f"Authorized by: {job.authorized_by}",
            f"Created at: {job.created_at}",
            f"Started at: {job.started_at or 'N/A'}",
            f"Finished at: {job.finished_at or 'N/A'}",
            f"Assets Discovered: {assets_count}",
            f"Findings Identified: {findings_count}"
        ]
        
        if job.error_message:
            lines.append(f"Error: {job.error_message}")
            
        return "\n".join(lines)
    finally:
        session.close()

@mcp.tool()
def get_findings(job_id: str, severity_filter: str = "ALL") -> str:
    """
    Get scored vulnerability findings for a completed scan.
    severity_filter: "ALL" | "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    Returns findings as formatted text, sorted by risk score.
    """
    session = SessionLocal()
    try:
        query = session.query(Finding).filter(Finding.scan_job_id == job_id)
        if severity_filter != "ALL":
            query = query.filter(Finding.severity == severity_filter.upper())
            
        findings = query.order_by(Finding.risk_score.desc()).all()
        
        if not findings:
            return "No findings match the criteria."
            
        lines = []
        for f in findings:
            lines.append(f"[{f.severity}] {f.cve_id} (Score: {f.risk_score}) - Asset {f.asset_id}\n{f.description}\n")
            
        return "\n".join(lines)
    finally:
        session.close()

@mcp.tool()
def generate_report(job_id: str) -> str:
    """
    Generate the full security report for a completed scan.
    Returns the complete Markdown report including all findings,
    attack paths, and remediation recommendations.
    """
    session = SessionLocal()
    try:
        return run_report(job_id, session)
    finally:
        session.close()

@mcp.tool()
def list_scans(limit: int = 10) -> str:
    """
    List recent scans with their status and summary stats.
    """
    session = SessionLocal()
    try:
        jobs = session.query(ScanJob).order_by(ScanJob.created_at.desc()).limit(limit).all()
        
        if not jobs:
            return "No scans found."
            
        lines = ["Recent Scans:"]
        for j in jobs:
            lines.append(f"- {j.id} | {j.target} | {j.status} | {j.created_at}")
            
        return "\n".join(lines)
    finally:
        session.close()


def _analyze_attack_paths(scan_job_id: str, findings: list[dict]) -> list[dict]:
    """
    Send findings to Claude with a structured prompt asking it to identify
    vulnerability chains. Claude must cite Finding IDs as evidence for every
    link in the chain — no speculation without grounding.
    """
    if not findings:
        return []
        
    client = Anthropic()
    
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
    
    try:
        response = client.messages.create(
            model="claude-3-5-sonnet-20241022",
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
            content = content.split("```")[-1].split("```")[0].strip()
            
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
            print(f"Error saving attack paths: {db_e}")
        finally:
            session.close()
            
        return paths
    except Exception as e:
        print(f"Anthropic API call failed: {e}")
        return []
