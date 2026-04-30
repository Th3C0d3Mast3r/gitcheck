#!/bin/bash
set -e

# $1 is the github token passed from action.yml args

echo "Starting Git-Check Security Scanner..."

# Navigate to the GitHub workspace where the user's code is mounted
if [ -n "$GITHUB_WORKSPACE" ]; then
  git config --global --add safe.directory "$GITHUB_WORKSPACE"
  cd "$GITHUB_WORKSPACE"
else
  echo "Warning: GITHUB_WORKSPACE is not set. Are we running outside of GitHub Actions?"
fi

# Run the python orchestrator
# We pass the token as an environment variable
export GITHUB_TOKEN=$1

python /app/cli/main.py
