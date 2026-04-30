import os
import requests
import json

def generate_markdown_summary(report: dict) -> str:
    summary = report["summary"]
    
    md = f"## Git-Check Security Scan Results: {report['risk_level']}\n\n"
    md += "| Metric | Count |\n"
    md += "| --- | --- |\n"
    md += f"| **Total Issues Found** | `{summary['total_issues']}` |\n"
    md += f"| API Keys (Gitleaks) | `{summary['api_keys_found_gitleaks']}` |\n"
    md += f"| API Keys (Trufflehog) | `{summary['api_keys_found_trufflehog']}` |\n"
    md += f"| Malicious Scripts | `{summary['malicious_scripts_found']}` |\n\n"
    
    if summary['total_issues'] > 0:
        md += "### Details\n\n"
        
        # API Keys details
        if summary['api_keys_found_gitleaks'] > 0 or summary['api_keys_found_trufflehog'] > 0:
            md += "#### API Keys Detected\n"
            # Briefly list gitleaks
            for finding in report['details']['api_keys'].get('gitleaks', []):
                file_path = finding.get('File', 'Unknown')
                rule = finding.get('Description', 'Unknown Rule')
                line = finding.get('StartLine', '?')
                md += f"- **File**: `{file_path}:{line}` - **Rule**: `{rule}`\n"
                
            # Briefly list trufflehog
            for finding in report['details']['api_keys'].get('trufflehog', []):
                try:
                    file_path = finding['SourceMetadata']['Data']['Filesystem']['file']
                    detector = finding.get('DetectorName', 'Unknown')
                    md += f"- **File**: `{file_path}` - **Detector**: `{detector}`\n"
                except KeyError:
                    pass
            md += "\n"
            
        # Malicious Scripts details
        if summary['malicious_scripts_found'] > 0:
            md += "#### Malicious Scripts Detected\n"
            for finding in report['details']['malicious_scripts']:
                md += f"- **File**: `{finding['file']}:{finding['line_number']}`\n"
                md += f"  - **Issue**: {finding['description']}\n"
                md += f"  - **Snippet**: `{finding['line_content']}`\n\n"
                
    else:
        md += "✅ No hardcoded API keys or malicious shell scripts were found.\n"
        
    return md

def report_results(report: dict):
    """
    Prints the report to GitHub Actions summary.
    If a PR, it could also post a comment using the GitHub API.
    """
    markdown_content = generate_markdown_summary(report)
    print("\n--- BEGIN REPORT ---")
    print(markdown_content)
    print("--- END REPORT ---\n")
    
    # Write to GitHub Step Summary if available
    step_summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary_file and os.path.exists(step_summary_file):
        with open(step_summary_file, "a") as f:
            f.write(markdown_content)
            
    # Optional: Post PR comment using GitHub API
    github_token = os.environ.get("GITHUB_TOKEN")
    github_repository = os.environ.get("GITHUB_REPOSITORY")
    github_event_path = os.environ.get("GITHUB_EVENT_PATH")
    
    if github_token and github_repository and github_event_path and os.path.exists(github_event_path):
        try:
            with open(github_event_path, "r") as f:
                event_data = json.load(f)
                
            if "pull_request" in event_data:
                pr_number = event_data["pull_request"]["number"]
                post_pr_comment(github_token, github_repository, pr_number, markdown_content)
        except Exception as e:
            print(f"Failed to post PR comment: {e}")

def post_pr_comment(token: str, repo: str, pr_number: int, body: str):
    url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }
    data = {"body": body}
    response = requests.post(url, headers=headers, json=data)
    if response.status_code == 201:
        print(f"Successfully posted comment on PR #{pr_number}")
    else:
        print(f"Failed to post PR comment. Status: {response.status_code}, {response.text}")
