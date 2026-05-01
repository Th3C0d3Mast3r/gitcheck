import os
from typing import List
from ingestion import Diff

def should_inspect_for_iac(chunk: Diff) -> bool:
    """
    IaC scanner only cares about Infrastructure as Code files.
    Specifically Terraform (.tf) and Kubernetes/Ansible (.yaml, .yml).
    """
    if chunk.is_bin:
        return False
        
    path = chunk.file_path.lower()
    
    iac_extensions = {".tf", ".yaml", ".yml"}
    _, ext = os.path.splitext(path)
    
    if ext in iac_extensions:
        return True
        
    return False

def filter_chunks_for_iac(chunks: List[Diff]) -> List[Diff]:
    return [c for c in chunks if should_inspect_for_iac(c)]
