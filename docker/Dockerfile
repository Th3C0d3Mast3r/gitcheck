FROM python:3.11-slim

# Install system dependencies, including git, curl, and bash
RUN apt-get update && apt-get install -y \
    git \
    curl \
    bash \
    jq \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Install Gitleaks
RUN wget https://github.com/gitleaks/gitleaks/releases/download/v8.18.2/gitleaks_8.18.2_linux_x64.tar.gz && \
    tar -xzf gitleaks_8.18.2_linux_x64.tar.gz && \
    mv gitleaks /usr/local/bin/ && \
    rm gitleaks_8.18.2_linux_x64.tar.gz

# Install Trufflehog
RUN curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin

# Set up the working directory for the action
WORKDIR /app

# Copy python requirements and install
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the action code
COPY . /app

# Make the entrypoint executable
RUN chmod +x /app/docker/entrypoint.sh

# Set the entrypoint
ENTRYPOINT ["/app/docker/entrypoint.sh"]
