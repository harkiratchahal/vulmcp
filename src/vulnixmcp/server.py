import json
from fastmcp import FastMCP
from vulnixmcp.database import SessionLocal
from vulnixmcp.models import ScanJob, AuditLog, Finding, AttackPath, Asset
from vulnixmcp.tasks import run_scan_in_background
from vulnixmcp.reporter import generate_report as run_report

mcp = FastMCP(
    "VulnixMCP",
    instructions=(
        "Security scanner MCP server for AI infrastructure. "
        "Use full_scan to run vulnerability scans against targets. "
        "Use get_scan_status to check scan progress. "
        "Use get_findings to retrieve vulnerability findings. "
        "Use generate_report to create a full security report. "
        "Use list_scans to see recent scan history."
    ),
)

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
        session.flush()  # populates job.id

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

    run_scan_in_background(job_id, target)
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
            
        # In get_scan_status, after fetching the job:
        if job.status == "running" and job.started_at:
            elapsed = datetime.now(timezone.utc) - job.started_at.replace(tzinfo=timezone.utc)
            if elapsed.total_seconds() > int(os.getenv("SCAN_TIMEOUT", 600)):
                job.status = "failed"
                job.error_message = "Scan timed out or server was restarted mid-scan"
                session.commit()

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

@mcp.tool()
def scan_installed_packages() -> str:
    """
    Scan Python packages installed in this environment for CVEs.
    No network scanning needed — queries OSV.dev for every installed package.
    """
    import importlib.metadata
    from vulnixmcp.vulns import query_osv, get_epss_scores, check_kev
    from vulnixmcp.scoring import calculate_risk_score, explain_score

    packages = [
        {"name": dist.metadata["Name"], "version": dist.metadata["Version"]}
        for dist in importlib.metadata.distributions()
        if dist.metadata.get("Name") and dist.metadata.get("Version")
    ]

    findings = []
    for pkg in packages:
        osv_results = query_osv(pkg["name"], pkg["version"])
        for vuln in osv_results:
            cves = [a for a in vuln.get("aliases", []) if a.startswith("CVE-")]
            for cve in cves:
                findings.append({
                    "cve_id": cve,
                    "package": pkg["name"],
                    "version": pkg["version"],
                    "description": vuln.get("summary", ""),
                    "cvss_score": None,
                    "epss_score": None,
                    "is_kev": False,
                    "asset": {"is_public": True}
                })

    if not findings:
        return f"Scanned {len(packages)} packages. No CVEs found."

    # Enrich with EPSS + KEV
    cve_ids = [f["cve_id"] for f in findings]
    epss = get_epss_scores(cve_ids)
    kev = check_kev()

    lines = [f"Scanned {len(packages)} packages. Found {len(findings)} CVEs:\n"]
    for f in findings:
        f["epss_score"] = epss.get(f["cve_id"], {}).get("epss", 0.0)
        f["is_kev"] = f["cve_id"] in kev
        score, severity = calculate_risk_score(
            f["cvss_score"], f["epss_score"], f["is_kev"], True
        )
        f["risk_score"] = score
        f["severity"] = severity
        lines.append(
            f"[{severity}] {f['cve_id']} — {f['package']}=={f['version']}\n"
            f"  {explain_score(f)}\n"
        )

    return "\n".join(lines)