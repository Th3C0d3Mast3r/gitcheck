import os
from typing import List
from ingestion import Diff

SKIP={".png", ".jpeg", ".jpg", ".gif", ".ico",
      ".lock", ".sum", ".min.js", ".min.css",
      ".svg",}

INSPECT_AT_ANY_COST={".sh", ".bash", ".ps1", ".ps", ".js",
                     ".java", ".bat", ".yml", ".toml", ".json",
                     ".dockerfile", "dockerfile", ".py", ".go",
                     ".c", ".php",}

MAX_FSIZE=5_000_000   # 5MB max, not more than that

def should_inspect(chunk:Diff) -> bool:
    path=chunk.file_path.lower()
    _, ext=os.path.splitext(path)
    basename=os.path.basename(path)

    if chunk.is_bin:
        return False
    if ext in SKIP or any(path.endswith(skip) for skip in SKIP):
        return False
    if ext in INSPECT_AT_ANY_COST or basename in INSPECT_AT_ANY_COST:
        return True
    if len(chunk.content.encode())>MAX_FSIZE:
        return False
    return True

# for loop on diff with checking in the above function
def filter_chunks(chunks:List[Diff])->List[Diff]:
    return [c for c in chunks if should_inspect(c)]
