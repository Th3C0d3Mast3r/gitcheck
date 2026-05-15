FROM python:3.11-slim

RUN apt-get update && apt-get install -y git gcc python3-dev build-essential
RUN rm -rf /var/lib/apt/lists/*

# Fix for "dubious ownership" error in GitHub Actions
RUN git config --global --add safe.directory /github/workspace

WORKDIR /app

# Copy source code FIRST
COPY . .

# Then install the package
RUN pip install .

# Removing USER gitcheck because GitHub Actions requires the container to run as root 
# to access GITHUB_WORKSPACE and execute successfully.
# RUN useradd -m gitcheck
# USER gitcheck

# Use python to run the script so the __main__ block is executed
# This ensures that exit codes (sys.exit(1) for BLOCK) are properly caught by the CI/CD pipeline
ENTRYPOINT ["python", "/app/cli/main.py"]
