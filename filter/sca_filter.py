import os
from typing import List
from ingestion import Diff

def should_inspect_for_sca(chunk: Diff) -> bool:
    """
    SCA (Software Composition Analysis) only cares about dependency manifest files.
    We drop everything else to save computation time.
    """
    if chunk.is_bin:
        return False
        
    path = chunk.file_path.lower()
    basename = os.path.basename(path)
    
    # Standard manifest files used by various package managers
    sca_targets = {
        "requirements.txt", # Python pip
        "package.json",     # Node npm/yarn
        "pom.xml",          # Java Maven
        "go.mod",           # Go modules
        "gemfile"           # Ruby gems
    }
    
    if basename in sca_targets:
        return True
        
    return False

def filter_chunks_for_sca(chunks: List[Diff]) -> List[Diff]:
    return [c for c in chunks if should_inspect_for_sca(c)]
