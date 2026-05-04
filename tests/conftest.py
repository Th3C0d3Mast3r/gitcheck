import pytest
from ingestion import Diff

@pytest.fixture
def mock_diff_chunk():
    """Provides a basic Diff chunk for testing."""
    def _create_chunk(file_path="test_file.py", added_lines=None, content=""):
        if added_lines is None:
            added_lines = ["print('hello')"]
        return Diff(
            file_path=file_path,
            old_path=file_path,
            change_type="M",
            content=content or "\n".join(added_lines),
            added_lines=added_lines,
            is_bin=False
        )
    return _create_chunk
