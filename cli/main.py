import sys
import os

# Add the project root to python path so we can import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ingestion.git_extractor import get_changed_files
from filter.noise_filter import filter_files

from analysis.api_keys import scan_for_api_keys
from analysis.malicious_scripts import scan_for_malicious_scripts
from aggregation.scorer import generate_report
from integrations.github_reporter import report_results

def main():
    print("=== Git-Check Security Scanner ===")
    
    # 1. Ingestion: Get modified files
    print("[*] Extracting changed files...")
    changed_files = get_changed_files()
    if not changed_files:
        print("[+] No changed files detected or not a PR context. Exiting gracefully.")
        sys.exit(0)
        
    print(f"[*] Found {len(changed_files)} changed file(s).")
    
    # 2. Filtering: Remove noise
    print("[*] Filtering files...")
    relevant_files = filter_files(changed_files)
    if not relevant_files:
        print("[+] No relevant files to scan after filtering.")
        sys.exit(0)
        
    print(f"[*] Proceeding to scan {len(relevant_files)} file(s).")
    
    # 3. Analysis: Run scanners
    print("[*] Scanning for API keys (Gitleaks & Trufflehog)...")
    api_key_findings = scan_for_api_keys(relevant_files)
    
    print("[*] Scanning for malicious shell scripts...")
    malicious_script_findings = scan_for_malicious_scripts(relevant_files)
    
    # 4. Aggregation: Consolidate findings
    print("[*] Generating report...")
    report = generate_report(api_key_findings, malicious_script_findings)
    
    # 5. Integrations: Output results
    print("[*] Outputting results...")
    report_results(report)
    
    # Finally, exit with the calculated exit code to optionally fail the action
    if report['exit_code'] != 0:
        print("\n[!] Security issues found. Failing the workflow.")
        sys.exit(report['exit_code'])
    else:
        print("\n[+] Scan completed successfully. No issues found.")
        sys.exit(0)

if __name__ == "__main__":
    main()
