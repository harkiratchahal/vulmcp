from loguru import logger
from jinja2 import Template
from vulnixmcp.models import ScanJob, Asset, Finding, AttackPath, AuditLog

REPORT_TEMPLATE = """
# VulnixMCP Security Report

## Scan Authorization
{% if audit %}
Authorized by: {{ audit.detail }} at {{ audit.created_at.strftime('%Y-%m-%d %H:%M:%S UTC') }}
{% else %}
Authorization record not available.
{% endif %}

## Target
{{ job.target }}

## Discovered AI Components ({{ assets|length }} total)
{% for asset in assets %}
- Port: {{ asset.port }}, Label: {{ asset.name }}, Version: {{ asset.version or 'Unknown' }}, Exposure: {{ 'Public' if asset.is_public else 'Internal' }}
{% endfor %}

## Critical & High Findings ({{ high_findings|length }} total)
{% for finding in high_findings %}
### {{ finding.cve_id }} [{{ finding.severity }}]
- **Affected Component**: Asset {{ finding.asset_id }}
- **Explanation**: {{ explain_map[finding.id] }}
- **CVSS/EPSS**: {{ finding.cvss_score or 'N/A' }} / {{ finding.epss_score or 'N/A' }}
- **CISA KEV**: {{ 'Yes' if finding.is_kev else 'No' }}
{% endfor %}

## All Findings Summary
| CVE ID | Severity | Score | Asset ID | EPSS | KEV |
|--------|----------|-------|----------|------|-----|
{% for finding in findings %}
| {{ finding.cve_id }} | {{ finding.severity }} | {{ finding.risk_score }} | {{ finding.asset_id }} | {{ finding.epss_score or 'N/A' }} | {{ 'Yes' if finding.is_kev else 'No' }} |
{% endfor %}

## Attack Paths Identified
{% for path in attack_paths %}
### {{ path.title }} (Risk: {{ path.risk_level }})
{{ path.description }}
Evidence chain: {{ path.finding_ids | join(', ') }}
{% endfor %}

## Remediation Recommendations
{% for finding in critical_findings %}
- **{{ finding.cve_id }}**: Investigate and apply available patches or configuration changes to Asset {{ finding.asset_id }}.
{% endfor %}
"""

def generate_report(scan_job_id: str, db_session) -> str:
    from vulnixmcp.scoring import explain_score
    job = db_session.query(ScanJob).filter(ScanJob.id == scan_job_id).first()
    if not job:
        return "Scan job not found."
        
    assets = db_session.query(Asset).filter(Asset.scan_job_id == scan_job_id).all()
    findings = db_session.query(Finding).filter(Finding.scan_job_id == scan_job_id).order_by(Finding.risk_score.desc()).all()
    attack_paths = db_session.query(AttackPath).filter(AttackPath.scan_job_id == scan_job_id).all()
    
    audit = db_session.query(AuditLog).filter(
        AuditLog.scan_job_id == scan_job_id,
        AuditLog.event_type == "SCAN_AUTHORIZED"
    ).order_by(AuditLog.created_at.desc()).first()
    
    high_findings = [f for f in findings if f.severity in ["CRITICAL", "HIGH"]]
    critical_findings = [f for f in findings if f.severity == "CRITICAL"]
    
    # We reconstruct a dict like structure to use explain_score since it expects dict
    explain_map = {}
    for f in high_findings:
        f_dict = {}
        for column in f.__table__.columns:
            f_dict[column.name] = getattr(f, column.name)
        # also need to mock asset mapping
        asset_obj = next((a for a in assets if a.id == f.asset_id), None)
        if asset_obj:
            f_dict["asset"] = {"is_public": asset_obj.is_public}
        explain_map[f.id] = explain_score(f_dict)
    
    template = Template(REPORT_TEMPLATE)
    report = template.render(
        job=job,
        assets=assets,
        findings=findings,
        high_findings=high_findings,
        critical_findings=critical_findings,
        attack_paths=attack_paths,
        audit=audit,
        explain_map=explain_map
    )
    
    return report.strip()
