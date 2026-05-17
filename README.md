<div align="center">

[![Tests](https://github.com/Th3C0d3Mast3r/gitcheck/actions/workflows/python-tests.yml/badge.svg)](https://github.com/Th3C0d3Mast3r/gitcheck/actions/workflows/python-tests.yml)
[![Build & Push Docker Image](https://github.com/Th3C0d3Mast3r/gitcheck/actions/workflows/docker-publish.yaml/badge.svg)](https://github.com/Th3C0d3Mast3r/gitcheck/actions/workflows/docker-publish.yaml)
[![Docker Pulls](https://img.shields.io/docker/pulls/dcodemaster/gitcheck.svg?logo=docker)](https://hub.docker.com/r/dcodemaster/gitcheck)
[![Docker Version](https://img.shields.io/docker/v/dcodemaster/gitcheck/latest.svg?logo=docker)](https://hub.docker.com/r/dcodemaster/gitcheck)
[![Git Tag](https://img.shields.io/github/v/tag/Th3C0d3Mast3r/gitcheck.svg?logo=git)](https://github.com/Th3C0d3Mast3r/gitcheck/tags)
[![License](https://img.shields.io/badge/license-GPL%202.0-blue.svg?logo=gnu)](https://github.com/Th3C0d3Mast3r/gitcheck)

# 🛡️ Git-Check

### *AI-powered `git diff` security analysis for modern repositories

*Catch suspicious changes before they reach production.*

</div>

---

With AI and agentic coding becoming a major part of modern software development, repository maintainers are increasingly reviewing large AI-generated pull requests and massive `git diff` outputs.

One malicious line of code is often enough to compromise a system, introduce vulnerabilities, or silently erode trust in a project.

**Git-Check** is a GitHub Workflows-first `git diff` analyzer designed to help maintainers detect risky, suspicious, or unexpected code changes quickly and efficiently.

It can run directly inside GitHub Actions or entirely offline for high-security and air-gapped environments.

---

> [!IMPORTANT]
> Git-Check is not some sort of Antivirus which will scan the repository, nor is it an **INTEGRAL PART OF GITHUB**- it is like a plugin which will work **ONLY FOR THOSE REPOS WHERE THE WORKFLOW ACTION IS INTEGRATED** and **IT CHECKS ONLY THE NEW INCOMING DIFFS**- not the previously present code *(assumes, previously it was all going good- and now, you add another layer of security)*

To understand the approach, kindly read and understand the below present HLD of the repository- how we are approaching the problem, what are the stages present, and how we score it. More details are written within every directory's README.

![HLD of the product](/images/projectHLD.png)

---

## UNDERSTANDING THE DIRECTORIES' USE
So, as you can see, the directories in this repo are named- PRETTY OBVIOUSLY, like, every directory does **WHAT IT IS NAMED AS-** 
- [cli/](/cli/) => Acts as the orchestrator that will connects all the things in a pipeline format
- [ingestion/](/ingestion/) => Handles interaction with Git and extracts only the relevant diff for efficient processing.
- [filter/](/filter/) => Reduces unnecessary computation by excluding irrelevant or large files.
- [analysis/](/analysis/) => Core **security layer** performing multi-level detection *(regex, rule-based, AST)*.
- [aggregation/](/aggregation/) => Combines outputs and computes a unified risk score for decision making.
- [dir-mapper/](/dir-mapper/) => Provides structural insights into the repository for better context-aware analysis.
- [integrations/](/integrations/) => Bridges the system with external platforms like GitHub for reporting and enforcement.
- [config/](/config/) => The base configs needed
- [utils/](/utils/) => Common and shared stuff goes here
- [docker/](/docker/) => Dockerization and other docker related things

---

## STEPS TO SETUP & USE
In order to use the following- there are two ways you can integrate and use Git-Check-
### GitHub Workflows Integration [different ways- choose which pleases]
1) Directly using my github action from Marketplace-
```yaml
- name: GitCheck Security Scan
  uses: Th3C0d3Mast3r/gitcheck@v1.0   # Prefer stable version instead of @main - check the same from tags
  with:
    report_mode: '1'
```

2) ✅ Using Git-Check in your github workflows, you should head to your `.github/workflows` directory, and there, make `gitcheck.yml` as:-
```yaml
name: Security Analysis

on:
  push:
    branches: [ "main" ]
  pull_request:
    branches: [ "main" ]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: GitCheck Security Scan
        uses: docker://dcodemaster/gitcheck:latest
        with:
          report_mode: '1'
```

### Local Testing 
You can have a device only check of the git-diff if you are not pushing to GitHub, but jus using local git. For the same, do the following-

1) **Using the Docker Image**:-
Pull the official `latest` tagged DockerHub image of gitcheck on your device. Check about `gitcheck` image [here]()
```bash
# the below commands are made, assuming, there is a docker user present on the Linux. If not, make it. Else, even command should start with- "sudo"
docker pull dcodemaster/gitcheck:latest

# once pulled- check the image presence by running
docker images

# and to test, do this-
docker run --rm \
  -v $(pwd):/repo \
  -w /repo \
  dcodemaster/gitcheck:latest \
  --report_mode 1 <specific file or folder here. Dont have anything for whole>
```
> [!NOTE]
> - What the above command does it- `-v $(pwd):/repo` → mounts your current project.
> - `-w /repo` → runs inside your repo.
> - `--rm` → cleans up container after running.


2) **Without Docker image**:
When you have cloned the repo- then *(not a good thing-cause then you would relative path from `gitcheck` and will have to execute this while being in the gitcheck repo path)*
```yaml
# first make the proper venv (if using global pip, no need for venv)
source venv/bin/activate

# use python3 or python as per the system

# To Scan a specific file
python3 cli/main.py 1 malicious.py

# To Scan a complete directory (New Feature)
python3 cli/main.py 1 malicious/
```

---

## CHANGELOG
The following are the versions of the gitcheck. The github-wokflows marketplace will have the latest of them updated time to time. If not, kindly report the same in the issues.
|Release Date| Latest | Version  | Description              |
|------------|--------|----------|--------------------------------------|
|`TBA`| | v2.0  | Added the optional On-Prem LLM Integration for advanced check |
|`15th May, 2026`|✓| v1.2.8 | Stable Working GitHub Action with Proper Scoring on other repo (tested on [HSL](https://github.com/Th3C0d3Mast3r/HSL) )|
|`6th May, 2026`| | v1.0   | Initial Release with Report Gen and Docker based version |

---

## SECURITY PHILOSOPHY
Git-Check follows a shift-left security approach, focusing on catching issues as early as possible—right at the stage of code changes.

Instead of scanning the entire repository again and again, **Git-Check focuses on what actually matters**: the incoming `git diff`. This keeps the system fast, relevant, and practical for real-world CI/CD pipelines.

The design is based on a layered detection strategy:

- **Regex-based checks** → for quick pattern detection (API keys, secrets, etc.)
- **Rule-based checks** → for enforcing security policies
- **AST-based analysis** → for deeper code understanding

All signals from these layers are combined to form a unified risk perspective, rather than relying on a single detection method.

The core idea is simple:
> Don’t trust the diff blindly. Verify it before it becomes part of your codebase.

---

## LIMITATIONS
Git-Check is designed to be **lightweight and diff-focused**, which comes with **certain trade-offs**:

- It **only scans new incoming diffs**, not the entire repository
- It **assumes** the **existing codebase is already trusted**
- It requires a valid `.git` history to function correctly
- It **may produce false positives, especially in regex-based detections**. For the same LLM Based integration is a work in progress.
- It **does not perform runtime or dynamic analysis** *(no DAST)*
- It is **not a replacement for full SAST/DAST tools**, but an **additional security layer**
- Accuracy depends on the rules and patterns configured

> Git-Check is best used as a first line of defense, not the only one.

---

## CONTRIBUTING
To contribute to the following open-source repository, kindly read the [CONTRIBUTING.md]().
