pipeline {
    agent {
        // Since Jenkins on-prem is Docker-based, we can leverage the python:3.11-slim image
        // to have an isolated and reproducible environment for every run.
        docker {
            image 'python:3.11-slim'
            args '-u root' // Prevent permission issues during package installation
        }
    }

    options {
        timestamps()
        timeout(time: 15, unit: 'MINUTES')
        skipDefaultCheckout false
    }

    stages {
        stage('Setup & Git Prep') {
            steps {
                // Install git in the slim python container
                sh 'apt-get update && apt-get install -y git'
                
                // For 'on every commit' checking, gitcheck needs to compare HEAD and HEAD~1.
                // Depending on the checkout behavior (e.g. shallow clone), we must ensure 
                // we have at least depth=2 to retrieve the parent commit for ingestion.
                script {
                    try {
                        sh 'git fetch origin ${GIT_COMMIT} --depth=2'
                    } catch (Exception e) {
                        echo "Fetch failed, checking out with deeper depth may be required: ${e}"
                    }
                }
            }
        }

        stage('Install GitCheck') {
            steps {
                // Install dependencies
                sh 'pip install -r requirements.txt'
                
                // Install the gitcheck orchestrator so it is available in the path
                sh 'pip install -e .'
            }
        }

        stage('Security Scan (GitCheck)') {
            steps {
                // Run the gitcheck tool
                // It evaluates the difference between HEAD~1 and HEAD natively.
                // The pipeline will fail if gitcheck exits with a non-zero code (e.g., blocking issues found)
                sh 'gitcheck'
            }
        }
    }

    post {
        success {
            echo "✅ GitCheck Scans Passed! No blocking security vulnerabilities found."
        }
        failure {
            echo "❌ GitCheck Scans Failed! Malicious code or blocking issues detected. Please check the logs."
        }
        always {
            // Clean up workspace after each run to save disk space
            cleanWs()
        }
    }
}
