import sys
import os    #New change for handling file paths

# Automatically add the project root directory to PYTHONPATH
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import subprocess    #New change for running git commands
from ingestion import GitIngestion, Diff
from filter import filter_chunks
from filter.secret_filter import filter_chunks_for_secrets
from filter.sca_filter import filter_chunks_for_sca
from filter.container_filter import filter_chunks_for_container
from filter.iac_filter import filter_chunks_for_iac
from filter.malicious_filter import filter_chunks_for_malicious
from analysis.ast_engine import scan_python
from analysis.secret_scanner import scan_for_secrets
from analysis.sca_scanner import scan_for_sca
from analysis.container_scanner import scan_for_container
from analysis.iac_scanner import scan_for_iac
from analysis.malicious_scanner import scan_for_malicious
from aggregation import compute_score
from cli.report_generator import generate_html_report

def is_merge_commit():    #New function to check if the current commit is a merge commit
    """Checks if the current HEAD is a merge commit."""
    try:
        # Run the command you tested: returns parent hashes
        result = subprocess.check_output(['git', 'rev-list', '--parents', '-n', '1', 'HEAD']).decode().split()
        # A standard commit has 2 items (ID and 1 parent). A merge has 3+ items.
        return len(result) > 2
    except Exception:
        return False

def check_reporting_rules():    #New function to determine if the pipeline should run based on user preference
    """
    Determines if the pipeline should run based on user preference.
    1 = Always
    2 = Only when not merging
    3 = Never
    """
    # GitHub Actions passes 'args' from action.yml as command line arguments
    mode = sys.argv[1] if len(sys.argv) > 1 else "1"

    if mode == "3":
        print("[-] GitCheck: Mode 3 (Never) active. Exiting without report.")
        sys.exit(0)

    if mode == "2" and is_merge_commit():
        print("[-] GitCheck: Mode 2 (No Merges) active. Merge detected. Exiting.")
        sys.exit(0)
    
    print(f"[+] GitCheck: Mode {mode} active. Proceeding with scan...")


def generate_github_summary(all_findings, score, verdict):  #New function to create a GitHub Actions summary report, which is more visually appealing and user-friendly than just printing to console. This will show up in the "Summary" tab of the GitHub Action run, making it easy for developers to see the results at a glance.
    # GitHub creates a temporary file path for summaries
    summary_env = os.environ.get('GITHUB_STEP_SUMMARY')
    if not summary_env:
        return # Not running in GitHub Actions

    with open(summary_env, 'a') as f:
        f.write(f"## 🛡️ GitCheck Security Scan\n")
        color = "🔴" if verdict == "BLOCK" else "🟢"
        f.write(f"### Verdict: {color} {verdict} (Score: {score}/100)\n\n")
        
        if all_findings:
            f.write("| Issue | Status |\n")
            f.write("| :--- | :--- |\n")
            for issue in all_findings:
                f.write(f"| {issue} | ⚠️ Detected |\n")
        else:
            f.write("✅ No vulnerabilities detected in this push.")

def run_pipeline(target=None):
    # If called via console script, target might be in sys.argv
    if target is None and len(sys.argv) > 2:
        target = sys.argv[2]

    print("Starting ingestion phase...")
    
    scan_range = "HEAD~1 → HEAD"
    if target:
        if os.path.isdir(target):
            # --- FOLDER MODE: scan every file in the directory ---
            scan_range = f"Folder: {target}"
            print(f"[*] Folder mode: scanning all files in '{target}'")
            raw_chunks = []
            for fname in sorted(os.listdir(target)):
                fpath = os.path.join(target, fname)
                if not os.path.isfile(fpath):
                    continue
                try:
                    with open(fpath, 'r', errors='replace') as f:
                        content = f.read()
                    raw_chunks.append(Diff(
                        file_path=fpath,
                        old_path=fpath,
                        change_type="M",
                        content=content,
                        added_lines=content.splitlines(),
                        is_bin=False
                    ))
                    print(f"    -> Ingested: {fpath}")
                except Exception as e:
                    print(f"    [!] Skipping {fpath}: {e}")
            print(f"    -> Total: {len(raw_chunks)} files ingested from folder.")
        else:
            # --- SINGLE FILE MODE ---
            scan_range = f"File: {target}"
            print(f"[*] Targeting specific file: {target}")
            if not os.path.exists(target):
                print(f"[!] Error: Target {target} not found.")
                sys.exit(1)
            with open(target, 'r', errors='replace') as f:
                content = f.read()
            diff_obj = Diff(
                file_path=target,
                old_path=target,
                change_type="M",
                content=content,
                added_lines=content.splitlines(),
                is_bin=False
            )
            raw_chunks = [diff_obj]
            print(f"    -> Ingested target file: {target}")
    else:
        ingester=GitIngestion(repo_path=".")
        try:
            raw_chunks = ingester.get_diff(base_ref="HEAD~1", head="HEAD")
            print(f"    -> Found {len(raw_chunks)} total files changed.")
        except Exception as e:
            print(f"[!] Error during ingestion: {e}. Are there at least two commits in this repo?")
            sys.exit(1)


    print("\n[*] Starting Filtering Phase...")
    # ... (rest of filtering logic stays the same)
    
    clean_chunks_ast = filter_chunks(raw_chunks)
    clean_chunks_secrets = filter_chunks_for_secrets(raw_chunks)
    clean_chunks_sca = filter_chunks_for_sca(raw_chunks)
    clean_chunks_container = filter_chunks_for_container(raw_chunks)
    clean_chunks_iac = filter_chunks_for_iac(raw_chunks)
    clean_chunks_malicious = filter_chunks_for_malicious(raw_chunks)
    
    print(f"    -> AST Filter allowed {len(clean_chunks_ast)} files.")
    print(f"    -> Secret Filter allowed {len(clean_chunks_secrets)} files.")
    print(f"    -> SCA Filter allowed {len(clean_chunks_sca)} files.")
    print(f"    -> Container Filter allowed {len(clean_chunks_container)} files.")
    print(f"    -> IaC Filter allowed {len(clean_chunks_iac)} files.")
    print(f"    -> Malicious Filter allowed {len(clean_chunks_malicious)} files.")

    print("\n[*] Starting Analysis Phase...")
    all_findings = []

    print("\n    [1/6] Running Secret Scanner...")
    for chunk in clean_chunks_secrets:
        secrets = scan_for_secrets(chunk)
        if secrets:
            all_findings.extend(secrets)
            
    print("\n    [2/6] Running AST Scanner...")
    for chunk in clean_chunks_ast:
        if chunk.file_path.endswith(".py"):
            ast_findings = scan_python(chunk.content)
            if ast_findings:
                for ast_f in ast_findings:
                    formatted_msg = f"[{ast_f.severity}] {ast_f.description} found at {chunk.file_path} (line {ast_f.line + 1})"
                    all_findings.append(formatted_msg)
                
    print("\n    [3/6] Running SCA Scanner...")
    for chunk in clean_chunks_sca:
        sca_findings = scan_for_sca(chunk)
        if sca_findings:
            all_findings.extend(sca_findings)

    print("\n    [4/6] Running Container Scanner...")
    for chunk in clean_chunks_container:
        container_findings = scan_for_container(chunk)
        if container_findings:
            all_findings.extend(container_findings)
            
    print("\n    [5/6] Running IaC Scanner...")
    for chunk in clean_chunks_iac:
        iac_findings = scan_for_iac(chunk)
        if iac_findings:
            all_findings.extend(iac_findings)
            
    print("\n    [6/6] Running Malicious Scanner...")
    for chunk in clean_chunks_malicious:
        malicious_findings = scan_for_malicious(chunk)
        if malicious_findings:
            all_findings.extend(malicious_findings)
            
    print("\n" + "="*30)
    print("       SCAN RESULTS")
    print("="*30)
    
    if not all_findings:
        print(" All clear, No secrets or malicious code found.")
        generate_github_summary([], 0, "PASS")
        generate_html_report([], 0, "PASS", scan_range=scan_range)
        return "PASS"
    else:
        print(f" WARNING! Found {len(all_findings)} issues:")
        for issue in all_findings:
            print(f"  - {issue}")

        print("\n[*] Computing Aggregated Score...")
        total_score, verdict = compute_score(all_findings)

        # 1. Print to console
        print(f"    -> Total Risk Score: {total_score}")
        print(f"    -> Final Verdict: {verdict}")

        # 2. Generate GitHub Actions summary (only inside CI)
        generate_github_summary(all_findings, total_score, verdict)

        # 3. Generate local HTML report
        generate_html_report(all_findings, total_score, verdict, scan_range=scan_range)

        # 4. Send the verdict back to the main block
        return verdict

if __name__ == "__main__":
    # Handle arguments: [1] report_mode, [2] target_file
    user_pref = sys.argv[1] if len(sys.argv) > 1 else "1"
    target_file = sys.argv[2] if len(sys.argv) > 2 else None

    # Step 1: Check if we should skip
    check_reporting_rules()

    # Step 2: Run the scan and catch the verdict
    final_verdict = run_pipeline(target=target_file)

    # Step 3: Handle the Exit Code (This actually stops the CI/CD pipeline)
    if final_verdict == "BLOCK":
        print("\n[!] VERDICT IS BLOCK. FAILING PIPELINE.")
        sys.exit(1)
    else:
        print("\n[✓] VERDICT IS PASS/WARN. PIPELINE SUCCEEDED.")
        sys.exit(0)
