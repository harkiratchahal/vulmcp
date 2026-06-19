from vulnixmcp.scoring import calculate_risk_score, score_all_findings, explain_score

def test_calculate_risk_score():
    score, sev = calculate_risk_score(10.0, 1.0, True, True)
    assert sev == "CRITICAL"
    assert score == 9.3
    
    score, sev = calculate_risk_score(None, None, False, False)
    assert sev == "LOW"
    # CVSS=5.0 -> 1.5, EPSS=0, KEV=0, Exposure=1.0 -> 0.1 ==> 1.6
    assert score == 1.6
