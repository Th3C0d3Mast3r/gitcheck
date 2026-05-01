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
    """
    Scans Dockerfiles for dangerous base images, the :latest tag, 
    and bad practices like running as root.
    """
    findings = []
    
    banned_images = CONTAINER_RULES.get("BANNED_BASE_IMAGES", {})
    banned_tags = CONTAINER_RULES.get("BANNED_TAGS", {})
    dangerous_cmds = CONTAINER_RULES.get("DANGEROUS_COMMANDS", {})
    require_non_root = CONTAINER_RULES.get("REQUIRE_NON_ROOT", True)
    
    has_user_directive = False

    # Check line by line
    for line_num, line in enumerate(chunk.added_lines, start=1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # 1. Check FROM instruction (Base Image and Tag)
        if line.startswith("FROM "):
            # Example: FROM ubuntu:latest AS build
            parts = line.split()
            if len(parts) >= 2:
                image_full = parts[1] # e.g., ubuntu:latest
                image_name = image_full.split(":")[0] if ":" in image_full else image_full
                image_tag = image_full.split(":")[1] if ":" in image_full else "latest"
                
                # Check banned images
                if image_full in banned_images:
                    rule = banned_images[image_full]
                    findings.append(f"[{rule['severity']}] CONTAINER RISK: Banned base image '{image_full}' at line {line_num} - {rule['reason']}")
                
                # Check banned tags (like 'latest')
                if image_tag in banned_tags:
                    rule = banned_tags[image_tag]
                    findings.append(f"[{rule['severity']}] CONTAINER RISK: Banned tag '{image_tag}' at line {line_num} - {rule['reason']}")

        # 2. Check USER instruction
        elif line.startswith("USER "):
            user = line.split()[1]
            if user == "root":
                findings.append(f"[HIGH] CONTAINER RISK: Explicit 'USER root' at line {line_num}. Containers should run as non-root.")
            has_user_directive = True

        # 3. Check RUN instructions for dangerous patterns
        elif line.startswith("RUN "):
            for cmd_name, rule_data in dangerous_cmds.items():
                if re.search(rule_data["regex"], line):
                    findings.append(f"[{rule_data['severity']}] CONTAINER RISK: Dangerous command '{cmd_name}' at line {line_num} - {rule_data['reason']}")

    # After checking all lines, if non-root is required and we never saw a USER directive, flag it.
    # Note: Since we only scan 'added_lines', a developer might add code to a file that already has a USER directive.
    # A perfect implementation would parse the full chunk.content to check for the USER directive globally.
    if require_non_root:
        # Check full content to see if USER was defined anywhere
        full_has_user = any(l.strip().startswith("USER ") and not l.strip().startswith("USER root") for l in chunk.content.splitlines())
        if not full_has_user:
             findings.append(f"[MEDIUM] CONTAINER RISK: No non-root USER directive found in Dockerfile. Container defaults to root.")

    return findings
