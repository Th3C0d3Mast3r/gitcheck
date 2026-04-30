import os

# Files to ignore
IGNORED_EXTENSIONS = {
    '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
    '.pdf', '.zip', '.tar', '.gz', '.mp4', '.mp3',
    '.woff', '.woff2', '.ttf', '.eot'
}

def is_relevant(file_path: str) -> bool:
    # Check if file still exists (might have been deleted in the diff)
    if not os.path.exists(file_path):
        return False
        
    _, ext = os.path.splitext(file_path)
    if ext.lower() in IGNORED_EXTENSIONS:
        return False
        
    # Ignore minified files or large vendor directories
    if "node_modules/" in file_path or file_path.endswith(".min.js"):
        return False
        
    # Check file size (e.g., > 1MB) to prevent regex DDOS or large memory usage
    try:
        if os.path.getsize(file_path) > 1024 * 1024:
            return False
    except OSError:
        pass
        
    return True

def filter_files(file_paths: list[str]) -> list[str]:
    return [f for f in file_paths if is_relevant(f)]
