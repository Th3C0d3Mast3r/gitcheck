import json
import os
import re

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "config", "container_compliance.json")
try:
    with open(CONFIG_PATH, "r") as f:
        CONTAINER_RULES = json.load(f)
except FileNotFoundError:
    print(f"[!] Warning: Container Compliance file not found at {CONFIG_PATH}")
    CONTAINER_RULES = {"BANNED_BASE_IMAGES": {}, "BANNED_TAGS": {}, "DANGEROUS_COMMANDS": {}, "REQUIRE_NON_ROOT": False}

def scan_for_container(chunk):
   
    findings = []
    
    banned_images = CONTAINER_RULES.get("BANNED_BASE_IMAGES", {})
    banned_tags = CONTAINER_RULES.get("BANNED_TAGS", {})
    dangerous_cmds = CONTAINER_RULES.get("DANGEROUS_COMMANDS", {})
    require_non_root = CONTAINER_RULES.get("REQUIRE_NON_ROOT", True)
    
    has_user_directive = False

  
    for line_num, line in enumerate(chunk.added_lines, start=1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        
        if line.startswith("FROM "):
           
            parts = line.split()
            if len(parts) >= 2:
                image_full = parts[1] # e.g., ubuntu:latest
                image_name = image_full.split(":")[0] if ":" in image_full else image_full
                image_tag = image_full.split(":")[1] if ":" in image_full else "latest"
                
               
                if image_full in banned_images:
                    rule = banned_images[image_full]
                    findings.append(f"[{rule['severity']}] CONTAINER RISK: Banned base image '{image_full}' at line {line_num} - {rule['reason']}")
                
              
                if image_tag in banned_tags:
                    rule = banned_tags[image_tag]
                    findings.append(f"[{rule['severity']}] CONTAINER RISK: Banned tag '{image_tag}' at line {line_num} - {rule['reason']}")

       
        elif line.startswith("USER "):
            user = line.split()[1]
            if user == "root":
                findings.append(f"[HIGH] CONTAINER RISK: Explicit 'USER root' at line {line_num}. Containers should run as non-root.")
            has_user_directive = True

        
        elif line.startswith("RUN "):
            for cmd_name, rule_data in dangerous_cmds.items():
                if re.search(rule_data["regex"], line):
                    findings.append(f"[{rule_data['severity']}] CONTAINER RISK: Dangerous command '{cmd_name}' at line {line_num} - {rule_data['reason']}")

    
    if require_non_root:
       
        full_has_user = any(l.strip().startswith("USER ") and not l.strip().startswith("USER root") for l in chunk.content.splitlines())
        if not full_has_user:
             findings.append(f"[MEDIUM] CONTAINER RISK: No non-root USER directive found in Dockerfile. Container defaults to root.")

    return findings
