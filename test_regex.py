import re
pattern = r"(?i)(?:password|secret|api[_-]?key|token)\s*[:=]\s*[\"']?([a-zA-Z0-9\-_]{8,})[\"']?"
line = "        payload = \"SLACK_TOKEN = 'jhbhjbhjbhj'\""
print("Match:", re.search(pattern, line) is not None)
