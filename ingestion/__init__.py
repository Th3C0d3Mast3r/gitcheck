# if u read carefully, this is the file that is taking the changes, and putting it in a class (a custom data type)
# based on that, we understand, what all changes are being made and not

import git
from dataclasses import dataclass
from typing import List

@dataclass
class Diff:
    file_path: str
    old_path: str
    change_type: str
    content: str
    added_lines: List[str]
    is_bin: bool

class GitIngestion:
    def __init__(self, repo_path: str="."):
        self.repo=git.Repo(repo_path)
    
    def get_diff(self, base_ref: str, head:str="HEAD")->List[Diff]:
        # here, the base_ref => things before the commit
        # and the head => new incoming things that came
        diffs=self.repo.commit(base_ref).diff(head)
        chunks=[]
        for d in diffs:
            try:
                content=d.diff.decode("utf-8", errors="replace")
            except Exception:
                content=""
            
            addedStuff=[
                line[1:] for line in content.splitlines()
                if line.startswith("+") and not line.startswith("+++")
            ]

            chunks.append(Diff(
                file_path=d.b_path or d.a_path,
                old_path=d.a_path,
                change_type=d.change_type,
                content=content,
                added_lines=addedStuff,
                is_bin=d.diff==b""
            ))
        return chunks