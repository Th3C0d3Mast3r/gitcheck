def generate_report(api_key_findings: dict, malicious_script_findings: list) -> dict:
    """
    Consolidates findings and calculates a risk score.
    Returns a dictionary containing the structured report.
    """
    gitleaks_count = len(api_key_findings.get("gitleaks", []))
    trufflehog_count = len(api_key_findings.get("trufflehog", []))
    malicious_count = len(malicious_script_findings)
    
    total_issues = gitleaks_count + trufflehog_count + malicious_count
    
    # Determine risk level
    # API Keys and Malicious scripts are critical security vulnerabilities.
    if total_issues > 0:
        risk_level = "CRITICAL"
        exit_code = 1
    else:
        risk_level = "CLEAN"
        exit_code = 0
        
    return {
        "risk_level": risk_level,
        "exit_code": exit_code,
        "summary": {
            "total_issues": total_issues,
            "api_keys_found_gitleaks": gitleaks_count,
            "api_keys_found_trufflehog": trufflehog_count,
            "malicious_scripts_found": malicious_count
        },
        "details": {
            "api_keys": api_key_findings,
            "malicious_scripts": malicious_script_findings
        }
    }
