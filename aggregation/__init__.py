from typing import List, Tuple
import re

SEVERITY_WEIGHTS = {
    "CRITICAL": 100,
    "HIGH": 50,
    "MEDIUM": 20,
    "LOW": 5
}

def compute_score(all_findings: List[str]) -> Tuple[int, str]:
    total_score = 0
    
    for finding in all_findings:
        # Extract the severity level from the finding string (e.g., "[CRITICAL] ...")
        match = re.search(r"\[(.*?)\]", finding)
        if match:
            severity = match.group(1).upper()
            total_score += SEVERITY_WEIGHTS.get(severity, 0)
            
    verdict = "PASS"
    if total_score >= 75:
        verdict = "BLOCK"
    elif total_score >= 30:
        verdict = "WARN"
        
    return total_score, verdict
