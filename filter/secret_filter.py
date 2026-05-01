import os
from typing import List
from ingestion import Diff

MAX_FSIZE = 5_000_000  # 5MB max

def should_inspect_for_secrets(chunk: Diff) -> bool:
    """
    Unlike the AST engine (which only cares about source code like .py or .js),
    secrets can be hidden ANYWHERE. They can be in .env files, .lock files,
    JSON dumps, or config files. 
    So this filter ONLY removes binaries and images.
    """
    if chunk.is_bin:
        return False
        
    path = chunk.file_path.lower()
    _, ext = os.path.splitext(path)
    
    # We only skip pure media/binary formats. Everything else is fair game for secrets.
    skip_exts = {".png", ".jpeg", ".jpg", ".gif", ".ico", ".svg", ".mp4", ".mp3", ".wav"}
    
    if ext in skip_exts or any(path.endswith(skip) for skip in skip_exts):
        return False
        
    # Still want to prevent Denial of Service on massive files
    if len(chunk.content.encode('utf-8', 'ignore')) > MAX_FSIZE:
        return False
        
    return True

def filter_chunks_for_secrets(chunks: List[Diff]) -> List[Diff]:
    return [c for c in chunks if should_inspect_for_secrets(c)]
