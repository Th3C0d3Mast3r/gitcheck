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

## 📊 Understanding the Verdicts

| Verdict | Action Taken | Meaning |
|:---:|:---:|:---|
| **PASS** | ✅ Success | No high-risk issues found. Pipeline continues. |
| **WARN** | ⚠️ Success | Minor issues detected but safe to proceed. |
| **BLOCK** | ❌ Failure | Critical security risk or malicious logic found. Pipeline stopped. |

> [!IMPORTANT]
> If GitCheck returns a **BLOCK** verdict, the GitHub Action will fail, effectively preventing a Pull Request from being merged if you have "Required Status Checks" enabled.
