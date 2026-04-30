import re

# Dictionary of malicious patterns with their descriptions
MALICIOUS_PATTERNS = {
    r"(?i)rm\s+-rf\s+/(?!\S)": "Attempt to delete root filesystem",
    r"(?i)curl\s+.*\|\s*(bash|sh)": "Piping curl directly to shell",
    r"(?i)wget\s+.*\|\s*(bash|sh)": "Piping wget directly to shell",
    r"(?i)chmod\s+777": "Overly permissive file permissions (chmod 777)",
    r"(?i)/dev/tcp/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}": "Potential reverse shell connection",
    r"(?i)nc\s+-e\s+/bin/(bash|sh)": "Netcat reverse shell",
    r"(?i)base64\s+-d\s*\|\s*(bash|sh)": "Executing base64 decoded payload",
    r"(?i)>\s*/dev/sda": "Writing directly to block device",
    r"(?i)mkfs\.\w+\s+/dev/": "Attempt to format disk",
}

def scan_for_malicious_scripts(files: list[str]) -> list[dict]:
    """
    Scans the given files for malicious script patterns.
    Returns a list of findings.
    """
    findings = []
    for file_path in files:
        try:
            with open(file_path, 'r', errors='ignore') as f:
                lines = f.readlines()
                
            for line_num, line in enumerate(lines, 1):
                for pattern, description in MALICIOUS_PATTERNS.items():
                    if re.search(pattern, line):
                        findings.append({
                            "file": file_path,
                            "line_number": line_num,
                            "line_content": line.strip()[:100], # Truncate for safety/readability
                            "description": description
                        })
        except Exception as e:
            print(f"Error reading file {file_path} for malicious script scan: {e}")
            
    return findings
