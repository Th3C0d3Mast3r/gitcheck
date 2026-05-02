import os
from typing import List
from ingestion import Diff

MALICIOUS_EXTENSIONS = {".sh", ".bash", ".zsh", ".bat", ".ps1", ".ps", ".json", ".yml", ".yaml", ".toml"}
MALICIOUS_FILENAMES = {"makefile", "tox.ini", "package.json"}

def should_inspect_for_malicious(chunk: Diff) -> bool:
    path = chunk.file_path.lower()
    _, ext = os.path.splitext(path)
    basename = os.path.basename(path)

    if chunk.is_bin:
        return False
    if ext in MALICIOUS_EXTENSIONS:
        return True
    if basename in MALICIOUS_FILENAMES:
        return True
    return False

def filter_chunks_for_malicious(chunks: List[Diff]) -> List[Diff]:
    return [c for c in chunks if should_inspect_for_malicious(c)]
