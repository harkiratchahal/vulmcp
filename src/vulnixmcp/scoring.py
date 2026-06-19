from typing import Tuple

def calculate_risk_score(cvss_score: float, epss_score: float, is_kev: bool, is_public: bool) -> Tuple[float, str]:
    if cvss_score is None:
        cvss = 5.0
    else:
        cvss = float(cvss_score)
        
    epss = float(epss_score) if epss_score is not None else 0.0
    
    kev_bonus = 2.0 if is_kev else 0.0
    exposure_score = 3.0 if is_public else 1.0
    
    risk_score = (cvss * 0.3) + (epss * 10 * 0.4) + kev_bonus + (exposure_score * 0.1)
    
    # Cap at 10.0
    risk_score = min(10.0, risk_score)
    
    if risk_score >= 8.0:
        severity = "CRITICAL"
    elif risk_score >= 6.0:
        severity = "HIGH"
    elif risk_score >= 4.0:
        severity = "MEDIUM"
    else:
        severity = "LOW"
        
    return round(risk_score, 1), severity

def score_all_findings(findings: list[dict]) -> list[dict]:
    for f in findings:
        asset = f.get("asset", {})
        is_public = asset.get("is_public", False)
        
        cvss = f.get("cvss_score")
        epss = f.get("epss_score")
        is_kev = f.get("is_kev", False)
        
        score, severity = calculate_risk_score(cvss, epss, is_kev, is_public)
        
        f["risk_score"] = score
        f["severity"] = severity
        
    return sorted(findings, key=lambda x: x.get("risk_score", 0), reverse=True)

def explain_score(finding: dict) -> str:
    score = finding.get("risk_score", 0.0)
    severity = finding.get("severity", "UNKNOWN")
    epss = finding.get("epss_score", 0.0) or 0.0
    is_kev = finding.get("is_kev", False)
    asset = finding.get("asset", {})
    is_public = asset.get("is_public", False)
    cvss = finding.get("cvss_score")
    
    epss_prob = f"{epss * 100:.0f}%"
    
    explanation = f"Scored {score} ({severity}). EPSS of {epss:.2f} means a {epss_prob} probability of exploitation in the next 30 days."
    
    if is_kev:
        explanation += " Confirmed on CISA KEV — actively exploited in the wild."
        
    if is_public:
        explanation += " Service is publicly reachable from the internet."
    else:
        explanation += " Service is not directly exposed to the internet."
        
    if cvss is not None:
        explanation += f" CVSS base: {cvss}."
    else:
        explanation += " CVSS base: Unknown (default 5.0)."
        
    return explanation
