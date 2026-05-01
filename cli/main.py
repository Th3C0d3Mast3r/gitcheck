import sys
from ingestion import GitIngestion
from filter import filter_chunks
from filter.secret_filter import filter_chunks_for_secrets
from filter.sca_filter import filter_chunks_for_sca
from filter.container_filter import filter_chunks_for_container
from filter.iac_filter import filter_chunks_for_iac
from analysis.ast_engine import scan_python
from analysis.secret_scanner import scan_for_secrets
from analysis.sca_scanner import scan_for_sca
from analysis.container_scanner import scan_for_container
from analysis.iac_scanner import scan_for_iac

def run_pipeline():
    print("Starting ingestion phase...")

    ingester=GitIngestion(repo_path=".")
    try:
        raw_chunks = ingester.get_diff(base_ref="HEAD~1", head="HEAD")
        print(f"    -> Found {len(raw_chunks)} total files changed.")
    except Exception as e:
        print(f"[!] Error during ingestion: {e}. Are there at least two commits in this repo?")
        sys.exit(1)

    print("\n[*] Starting Filtering Phase...")

    clean_chunks_ast = filter_chunks(raw_chunks)
    clean_chunks_secrets = filter_chunks_for_secrets(raw_chunks)
    clean_chunks_sca = filter_chunks_for_sca(raw_chunks)
    clean_chunks_container = filter_chunks_for_container(raw_chunks)
    clean_chunks_iac = filter_chunks_for_iac(raw_chunks)
    
    print(f"    -> AST Filter allowed {len(clean_chunks_ast)} files.")
    print(f"    -> Secret Filter allowed {len(clean_chunks_secrets)} files.")
    print(f"    -> SCA Filter allowed {len(clean_chunks_sca)} files.")
    print(f"    -> Container Filter allowed {len(clean_chunks_container)} files.")
    print(f"    -> IaC Filter allowed {len(clean_chunks_iac)} files.")

    print("\n[*] Starting Analysis Phase...")
    all_findings = []

    print("\n    [1/5] Running Secret Scanner...")
    for chunk in clean_chunks_secrets:
        secrets = scan_for_secrets(chunk)
        if secrets:
            all_findings.extend(secrets)
            
    print("\n    [2/5] Running AST Scanner...")
    for chunk in clean_chunks_ast:
        if chunk.file_path.endswith(".py"):
            ast_findings = scan_python(chunk.content)
            if ast_findings:
                all_findings.extend(ast_findings)
                
    print("\n    [3/5] Running SCA Scanner...")
    for chunk in clean_chunks_sca:
        sca_findings = scan_for_sca(chunk)
        if sca_findings:
            all_findings.extend(sca_findings)

    print("\n    [4/5] Running Container Scanner...")
    for chunk in clean_chunks_container:
        container_findings = scan_for_container(chunk)
        if container_findings:
            all_findings.extend(container_findings)
            
    print("\n    [5/5] Running IaC Scanner...")
    for chunk in clean_chunks_iac:
        iac_findings = scan_for_iac(chunk)
        if iac_findings:
            all_findings.extend(iac_findings)
    print("\n" + "="*30)
    print("       SCAN RESULTS")
    print("="*30)
    
    if not all_findings:
        print(" All clear, No secrets or malicious code found.")
    else:
        print(f" WARNING! you fucked up: Found {len(all_findings)} issues:")
        for issue in all_findings:
            print(f"  - {issue}")
if __name__ == "__main__":
    run_pipeline()
