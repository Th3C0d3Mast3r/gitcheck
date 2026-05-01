import json
import os
import re

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "config", "iac_compliance.json")
try:
    with open(CONFIG_PATH, "r") as f:
        IAC_RULES = json.load(f)
except FileNotFoundError:
    print(f"[!] Warning: IaC Compliance file not found at {CONFIG_PATH}")
    IAC_RULES = {"TERRAFORM_RULES": {}, "KUBERNETES_RULES": {}}

def scan_for_iac(chunk):
    """
    Scans Infrastructure as Code files (Terraform/Kubernetes) 
    for real-world cloud misconfigurations using regex rules.
    """
    findings = []
    
    tf_rules = IAC_RULES.get("TERRAFORM_RULES", {})
    k8s_rules = IAC_RULES.get("KUBERNETES_RULES", {})
    
    path = chunk.file_path.lower()
    
    # We only scan the newly added code to avoid yelling at developers 
    # for old tech debt they aren't currently touching.
    for line_num, line in enumerate(chunk.added_lines, start=1):
        
        # 1. Terraform Scanning
        if path.endswith(".tf"):
            for rule_name, rule_data in tf_rules.items():
                if re.search(rule_data["regex"], line):
                    findings.append(f"[{rule_data['severity']}] IaC RISK ({rule_name}): {rule_data['reason']} at {chunk.file_path} (line {line_num})")
                    
        # 2. Kubernetes/Ansible YAML Scanning
        elif path.endswith(".yaml") or path.endswith(".yml"):
            for rule_name, rule_data in k8s_rules.items():
                if re.search(rule_data["regex"], line):
                    findings.append(f"[{rule_data['severity']}] IaC RISK ({rule_name}): {rule_data['reason']} at {chunk.file_path} (line {line_num})")

    return findings
