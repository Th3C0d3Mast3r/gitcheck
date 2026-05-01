import json
import re
import os

# Load the compliance file once when the module is imported
# This saves us from reading the file from the disk for every single chunk
CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "config", "secrets_compliance.json")
try:
    with open(CONFIG_PATH, "r") as f:
        COMPLIANCE_RULES = json.load(f)
except FileNotFoundError:
    print(f"[!] Warning: Compliance file not found at {CONFIG_PATH}")
    COMPLIANCE_RULES = {}

def scan_for_secrets(chunk):
    """
    Scans the added lines of a git diff chunk for hardcoded secrets 
    based on regex rules defined in config/secrets_compliance.json.
    """
    findings = []
    
    # We only care about checking the newly added code, not the whole file
    for line_number, line_content in enumerate(chunk.added_lines, start=1):
        
        # Check this line of code against every rule in our compliance JSON
        for secret_name, rule_data in COMPLIANCE_RULES.items():
            pattern = rule_data.get("regex", "")
            
            # Skip if there's no regex defined for the rule
            if not pattern:
                continue
                
            # Use Python's regex search to see if the pattern exists in the line
            if re.search(pattern, line_content):
                severity = rule_data.get("severity", "UNKNOWN")
                desc = rule_data.get("description", secret_name)
                
                # Format a nice output message
                finding_msg = f"[{severity}] {desc} found at {chunk.file_path} (added line {line_number})"
                findings.append(finding_msg)
                
    return findings
