# 🛡️ GitCheck: Integration & Publishing Guide

Welcome to the GitCheck "How-To" guide. This document provides clear instructions on how to integrate GitCheck into any open-source project and how to make this tool available on the GitHub Actions Marketplace.

---

## 🚀 Integrating GitCheck into Your Workflow

GitCheck acts as a security gate, scanning your code for secrets, malicious logic, and misconfigurations before they reach production.

### 1. Using GitCheck as a GitHub Action (Easiest)

To use GitCheck in your repository, create a new file at `.github/workflows/gitcheck.yml` with the following content:

```yaml
name: "Security Scan (GitCheck)"

on:
  push:
    branches: [ main, master ]
  pull_request:
    branches: [ main, master ]

jobs:
  security-gate:
    runs-on: ubuntu-latest
    steps:
      - name: 📥 Checkout Repository
        uses: actions/checkout@v4
        with:
          fetch-depth: 0 # Required: GitCheck needs history to analyze the diff

      - name: 🛡️ Run GitCheck Security Scan
        uses: Th3C0d3Mast3r/gitcheck@main # Use a specific tag like @v1.0.0 for stability
        with:
          report_mode: '1' # Options: 1 (Always), 2 (Skip Merges), 3 (Never)

> [!TIP]
> **Performance Boost**: By publishing GitCheck to Docker Hub, you can make this scan run 3x faster by pulling a pre-built image instead of building it on every run. See the Docker Hub section below.
```

> [!TIP]
> **Why fetch-depth: 0?**
> GitCheck compares the current commit with its parent to identify changes. A shallow clone (default) might not provide enough history for a proper diff analysis.

### 2. Local Usage via Docker
You can run GitCheck locally to test your changes before pushing them to GitHub.

```bash
# 1. Build the GitCheck image
docker build -t gitcheck -f docker/Dockerfile .

# 2. Run the scan on your local directory
# This mounts your current folder to /app inside the container
docker run --rm -v "$(pwd):/app" gitcheck 1
```

### 3. Local Testing (Developer Mode - Ad-hoc)
If you are developing locally and want to scan specific files or folders without using Docker, use the Python CLI directly.

```bash
# 1. Activate your virtual environment
source venv/bin/activate

# 2. Scan a specific file
python3 cli/main.py 1 malicious.py

# 3. Scan a complete directory (New Feature)
python3 cli/main.py 1 malicious/
```

---

## 🔍 Testing Everything in Detail

To verify that all 6 security scanners are functioning correctly, we have provided a `malicious/` test suite. Follow these steps to perform a full system validation:

### Step 1: Prepare the Test Suite
Ensure the `malicious/` directory contains targets for all scanners:
- `malicious.py`: Targets **Secret** & **AST** scanners.
- `evil.sh`: Targets **Malicious Code** scanner.
- `requirements.txt`: Targets **SCA** scanner.
- `Dockerfile`: Targets **Container** scanner.
- `insecure_infra.tf` & `k8s_pod.yaml`: Target **IaC** scanners.

### Step 2: Execute the Validation Scan
Run the folder-mode scan:
```bash
python3 cli/main.py 1 malicious/
```

### Step 3: Verify the Audit Report
Open `scan_report.html` and check for:
1. **Criticality Filters**: Ensure you can filter by "CRITICAL" and "HIGH".
2. **Scanner Filters**: Ensure you can isolate "IaC Scanner" or "Secret Scanner" results.
3. **Compliance Mapping**: Verify that findings are mapped to standards like **SOC2**, **NIST**, and **OWASP**.

---

---

## 🏗️ How to Publish to GitHub Marketplace

Publishing to the Marketplace allows anyone to find and use `gitcheck` by searching the official GitHub Actions gallery.

### 1. Add Branding to `action.yml`
GitHub requires a `branding` section to display an icon and color in the Marketplace. Update your `action.yml` as follows:

```yaml
name: 'GitCheck Security Scanner'
description: 'Pre-merge CI/CD gate for malicious scripts, secrets, and dangerous logic.'
branding:
  icon: 'shield'   # Choose from: shield, lock, activity, etc.
  color: 'blue'    # Choose from: blue, green, purple, red, etc.
# ... rest of the file
```

### 2. Repository Requirements
- The repository **must be public**.
- It must contain an `action.yml` in the root directory.
- It should have a comprehensive `README.md`.

### 3. Creating a Marketplace Release
1. Navigate to the **Releases** section of your GitHub repository.
2. Click **Draft a new release**.
3. Create a new tag (e.g., `v1.0.0`).
4. **The Magic Step**: Check the box that says **"Publish this Action to the GitHub Marketplace"**.
5. Select a Category (e.g., **Security**).
6. Click **Publish release**.

### 4. Version Management
To make it easier for users, always maintain a "major version" tag:
- When you release `v1.0.1`, also update the `v1` tag to point to the same commit.
- This allows users to use `uses: Th3C0d3Mast3r/gitcheck@v1` and receive non-breaking updates automatically.

---

## 🐳 Publishing to Docker Hub

Pushing GitCheck to Docker Hub makes it globally available and speeds up your GitHub Action, as users can pull a pre-built image instead of building it from scratch every time.

### 1. Login and Build
First, build the image and tag it with your Docker Hub username and a version.

```bash
# Log in to your Docker Hub account
docker login

# Build and Tag (Replace 'your-username' with your actual Docker Hub username)
docker build -t your-username/gitcheck:latest -t your-username/gitcheck:v1.0.0 -f docker/Dockerfile .
```

### 2. Push to Docker Hub
Push the tagged images to your public repository on Docker Hub.

```bash
docker push your-username/gitcheck:latest
docker push your-username/gitcheck:v1.0.0
```

### 3. (Optional) Speed Up Your GitHub Action
Once the image is on Docker Hub, you can change your `action.yml` to pull the image directly. This saves time on every CI/CD run.

**Update `action.yml`**:
```yaml
runs:
  using: 'docker'
  image: 'docker://your-username/gitcheck:latest' # Pulls from Docker Hub instead of building
  args:
    - ${{ inputs.report_mode }}
```

---

## 📊 Understanding the Verdicts

| Verdict | Action Taken | Meaning |
|:---:|:---:|:---|
| **PASS** | ✅ Success | No high-risk issues found. Pipeline continues. |
| **WARN** | ⚠️ Success | Minor issues detected but safe to proceed. |
| **BLOCK** | ❌ Failure | Critical security risk or malicious logic found. Pipeline stopped. |

> [!IMPORTANT]
> If GitCheck returns a **BLOCK** verdict, the GitHub Action will fail, effectively preventing a Pull Request from being merged if you have "Required Status Checks" enabled.

---

## 🛠️ Advanced GitHub Action Configuration

For complex enterprise environments, you can fine-tune how GitCheck behaves in your CI/CD pipeline.

### Integration with Pull Requests
To block a merge only if critical vulnerabilities are found, ensure your workflow is triggered on `pull_request` and your branch protection rules require the `security-gate` job to pass.

### Environment Variables
GitCheck automatically detects if it is running in GitHub Actions and generates a **Job Summary** (Step Summary) in the GitHub UI.

```yaml
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: GitCheck Audit
        uses: your-username/gitcheck@v1
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

