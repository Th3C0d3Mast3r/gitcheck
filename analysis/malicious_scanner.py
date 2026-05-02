import json
import re
import os

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "config", "malicious_compliance.json")
try:
    with open(CONFIG_PATH, "r") as f:
        COMPLIANCE_RULES = json.load(f)
except FileNotFoundError:
    print(f"[!] Warning: Compliance file not found at {CONFIG_PATH}")
    COMPLIANCE_RULES = {}

def scan_for_malicious(chunk):
    findings = []
    
    for line_number, line_content in enumerate(chunk.added_lines, start=1):
        for rule_name, rule_data in COMPLIANCE_RULES.items():
            pattern = rule_data.get("regex", "")
            
            if not pattern:
                continue
                
            if re.search(pattern, line_content):
                severity = rule_data.get("severity", "UNKNOWN")
                desc = rule_data.get("description", rule_name)
                
                finding_msg = f"[{severity}] {desc} found at {chunk.file_path} (added line {line_number})"
                findings.append(finding_msg)
                
    return findings
