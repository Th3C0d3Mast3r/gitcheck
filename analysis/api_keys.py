import subprocess
import json
import os

def run_gitleaks(repo_path: str) -> list[dict]:
    """Runs gitleaks and returns a list of finding dictionaries."""
    try:
        report_file = os.path.join(repo_path, "gitleaks-report.json")
        # Use gitleaks to scan the directory
        subprocess.run(
            ["gitleaks", "detect", "--source", repo_path, "--report-path", report_file, "--no-git", "--redact", "--exit-code", "0"],
            capture_output=True, text=True
        )
        
        results = []
        if os.path.exists(report_file):
            with open(report_file, 'r') as f:
                content = f.read()
                if content.strip():
                    results = json.loads(content)
            os.remove(report_file)
        return results
    except Exception as e:
        print(f"Error running gitleaks: {e}")
    return []

def run_trufflehog(repo_path: str) -> list[dict]:
    """Runs trufflehog and returns a list of finding dictionaries."""
    findings = []
    try:
        # Trufflehog filesystem scan
        result = subprocess.run(
            ["trufflehog", "filesystem", repo_path, "--json"],
            capture_output=True, text=True
        )
        for line in result.stdout.split('\n'):
            if line.strip():
                try:
                    findings.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except Exception as e:
        print(f"Error running trufflehog: {e}")
    return findings

def scan_for_api_keys(files: list[str]) -> dict:
    """
    Scans for API keys using gitleaks and trufflehog, 
    filtered by the provided list of modified files.
    """
    repo_path = os.environ.get("GITHUB_WORKSPACE", os.getcwd())
    
    gitleaks_results = run_gitleaks(repo_path)
    trufflehog_results = run_trufflehog(repo_path)
    
    # Filter results to only include the changed files
    relevant_gitleaks = []
    for finding in gitleaks_results:
        # gitleaks gives finding['File']
        file_path = finding.get('File', '')
        if any(f in file_path for f in files):
            relevant_gitleaks.append(finding)
            
    relevant_trufflehog = []
    for finding in trufflehog_results:
        try:
            th_file = finding.get('SourceMetadata', {}).get('Data', {}).get('Filesystem', {}).get('file', '')
            if any(f in th_file for f in files):
                relevant_trufflehog.append(finding)
        except Exception:
            continue
            
    return {
        "gitleaks": relevant_gitleaks,
        "trufflehog": relevant_trufflehog
    }
