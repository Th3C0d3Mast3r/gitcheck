[![Python Tests](https://github.com/Th3C0d3Mast3r/gitcheck/actions/workflows/python-tests.yml/badge.svg)](https://github.com/Th3C0d3Mast3r/gitcheck/actions/workflows/python-tests.yml)
# Git-Check
The following product can be used in any GitHub repo for checking if the code that has been written (pushed to be merged in the branch), is that **PROPER, & NON-MALICIOUS STUFF**. The below is the overall HLD of the product- do check this out, and the README for understanding- HOW IT WORKS, WHAT ALL IT USES, and related stuff. Also, every directory in this repo has its own README, which can be used to understand what is going in each directory, and what is the use of that-

![HLD of the product](/images/projectHLD.png)

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

<!-- 
> [!NOTE] 
> USING THIS REPO THE PROPER WAY
!-->

---

### PROGRESS TILL NOW
- [x] Written AST Engine for the Parser
- [x] Base code for `main.py` in /cli written and updated as a Multi-Track Orchestrator
- [x] Base Dockerfile written in /docker
- [x] Code for the ingestion of the git-diff written
- [x] `pyproject.toml` configured, the single point of truth for the project
- [x] requirements.txt written
- [x] **Implemented Modular Filtering Pipeline** (AST, Secrets, SCA, Container, IaC)
- [x] **Implemented Secret Scanner** (Regex matching for API keys, Git leaks, Internal IPs, PII)
- [x] **Implemented SCA Scanner** (Software Composition Analysis for dependencies)
- [x] **Implemented Container Scanner** (Dockerfile static analysis & base image rules)
- [x] **Implemented IaC Scanner** (Terraform and Kubernetes misconfiguration detection)
- [x] Created JSON-based Compliance Rules Engine (`/config`) for all scanners
- [ ] Scoring the malicious things (Aggregation Layer)
- [ ] JSON reporting and overall push score remains (Integrations Layer)
- [ ] Context-aware taint analysis and dynamic testing (Future Scope)
- [ ] SAST and DAST based integration in the Jenkinsfile for local vul checking
