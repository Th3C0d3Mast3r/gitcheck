# Git-Check
The following product can be used in any GitHub repo for checking if the code that has been written (pushed to be merged in the branch), is that **PROPER, & NON-MALICIOUS STUFF**. The below is the overall HLD of the product- do check this out, and the README for understanding- HOW IT WORKS, WHAT ALL IT USES, and related stuff. Also, every directory in this repo has its own README, which can be used to understand what is going in each directory, and what is the use of that-

![HLD of the product](/images/projectHLD.png)

## UNDERSTANDING THE DIRECTORIES' USE
So, as you can see, the directories in this repo are named- PRETTY OBVIOUSLY, like, every directory does **WHAT IT IS NAMED AS-** 
- ![cli/](/cli/) => Acts as the orchestrator that will connects all the things in a pipeline format
- ![ingestion/](/ingestion/) => Handles interaction with Git and extracts only the relevant diff for efficient processing.
- ![filter/](/filter/) => Reduces unnecessary computation by excluding irrelevant or large files.
- ![analysis/](/analysis/) => Core **security layer** performing multi-level detection *(regex, rule-based, AST)*.
- ![aggregation/](/aggregation/) => Combines outputs and computes a unified risk score for decision making.
- ![dir-mapper/](/dir-mapper/) => Provides structural insights into the repository for better context-aware analysis.
- ![integrations/](/integrations/) => Bridges the system with external platforms like GitHub for reporting and enforcement.
- ![config/](/config/) => The base configs needed
- ![utils/](/utils/) => Common and shared stuff goes here
- ![docker/](/docker/) => Dockerization and other docker related things
