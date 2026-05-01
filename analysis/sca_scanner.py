import json
import os
import re

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "config", "sca_compliance.json")
try:
    with open(CONFIG_PATH, "r") as f:
        SCA_RULES = json.load(f)
except FileNotFoundError:
    print(f"[!] Warning: SCA Compliance file not found at {CONFIG_PATH}")
    SCA_RULES = {"BANNED_PACKAGES": {}, "BANNED_LICENSES": {}, "BANNED_AUTHORS": {}}

def parse_requirements_txt(content):
   
    packages = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Split by ==, >=, <=, ~, or just space
        package_name = re.split(r'[=><~ ]', line)[0].strip().lower()
        if package_name:
            packages.append(package_name)
    return packages

def parse_package_json(content):
   
    packages = []
    try:
        data = json.loads(content)
        deps = data.get("dependencies", {})
        dev_deps = data.get("devDependencies", {})
        packages.extend(deps.keys())
        packages.extend(dev_deps.keys())
    except json.JSONDecodeError:
        pass
    return [p.lower() for p in packages]

def scan_for_sca(chunk):
   
    findings = []
    basename = os.path.basename(chunk.file_path).lower()
    
    # We scan the FULL content of dependency files, not just added_lines, 
    # because the entire manifest defines the security posture.
    content = chunk.content
    packages_found = []

    if basename == "requirements.txt":
        packages_found = parse_requirements_txt(content)
    elif basename == "package.json":
        packages_found = parse_package_json(content)
    # Add parsers for pom.xml, go.mod, etc. as needed

    banned_packages = SCA_RULES.get("BANNED_PACKAGES", {})
    
    for pkg in packages_found:
        if pkg in banned_packages:
            rule = banned_packages[pkg]
            severity = rule.get("severity", "CRITICAL")
            reason = rule.get("reason", "Unknown reason")
            findings.append(f"[{severity}] SUPPLY CHAIN RISK: Banned package '{pkg}' found in {chunk.file_path} - {reason}")

    return findings
