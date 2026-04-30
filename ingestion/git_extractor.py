import os
import subprocess

def get_changed_files() -> list[str]:
    """
    Determines the list of changed files in the current GitHub Action context.
    Returns a list of file paths.
    """
    # In GitHub Actions, GITHUB_BASE_REF is the target branch of a PR
    base_ref = os.environ.get('GITHUB_BASE_REF')
    head_ref = os.environ.get('GITHUB_HEAD_REF')
    
    if base_ref and head_ref:
        # It's a PR. We need to diff between origin/base_ref and origin/head_ref
        try:
            # Ensure we have the base branch to diff against
            subprocess.run(["git", "fetch", "origin", base_ref], check=False, capture_output=True)
            result = subprocess.run(
                ["git", "diff", "--name-only", f"origin/{base_ref}...HEAD"],
                capture_output=True, text=True, check=True
            )
            files = result.stdout.strip().split('\n')
            return [f for f in files if f]
        except subprocess.CalledProcessError as e:
            print(f"Error getting diff: {e.stderr}")
            return []
    else:
        # Fallback to the latest commit if not a PR
        try:
            result = subprocess.run(
                ["git", "diff", "--name-only", "HEAD^", "HEAD"],
                capture_output=True, text=True, check=True
            )
            files = result.stdout.strip().split('\n')
            return [f for f in files if f]
        except subprocess.CalledProcessError:
            return []
