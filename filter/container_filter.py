import os
from typing import List
from ingestion import Diff

def should_inspect_for_container(chunk: Diff) -> bool:

    if chunk.is_bin:
        return False
        
    path = chunk.file_path.lower()
    basename = os.path.basename(path)
    
   
    if basename == "dockerfile" or path.endswith(".dockerfile"):
        return True
        
    return False

def filter_chunks_for_container(chunks: List[Diff]) -> List[Diff]:
    return [c for c in chunks if should_inspect_for_container(c)]
