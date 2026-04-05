pipeline {
    agent any

    environment {
        APP_URL      = "http://localhost:9090"
        DASHBOARD    = "http://localhost:3500/api/report"
        BUILD_BRANCH = "master"
    }

    stages {

        stage('1 - Secrets Scanning (Gitleaks)') {
            steps {
                echo '=== Scan des secrets hardcodes ==='
                script {
                    def output = bat(
                        script: 'gitleaks.exe detect --source . --config .gitleaks.toml -v 2>&1 || exit 0',
                        returnStdout: true
                    ).trim()
                    def status = (output.contains('leaks found') && !output.contains('leaks found: 0')) ? 'warning' : 'success'
                    sendToDashboard("Gitleaks", output, status)
                    echo output
                }
            }
        }

        stage('2 - SAST (Semgrep)') {
            steps {
                echo '=== Analyse statique du code ==='
                script {
                    def output = bat(
                        script: 'docker run --rm -v "%CD%:/src" returntocorp/semgrep semgrep --config=p/nodejs --config=p/security-audit /src/server.js 2>&1 || exit 0',
                        returnStdout: true
                    ).trim()
                    def status = output.contains('blocking') ? 'warning' : 'success'
                    sendToDashboard("Semgrep", output, status)
                    echo output
                }
            }
        }

        stage('3 - SCA (npm audit)') {
            steps {
                echo '=== Analyse des dependances ==='
                script {
                    def output = bat(
                        script: 'npm audit 2>&1 || exit 0',
                        returnStdout: true
                    ).trim()
                    def status = (output.contains('critical') || output.contains('high')) ? 'warning' : 'success'
                    sendToDashboard("npm audit", output, status)
                    echo output
                }
            }
        }

        stage('4 - Container Scan (Trivy)') {
            steps {
                echo '=== Scan de l image Docker ==='
                script {
                    bat 'docker build -t dvna-pfe:pipeline . 2>&1 || exit 0'
                    def output = bat(
                        script: 'docker run --rm -v //var/run/docker.sock://var/run/docker.sock aquasec/trivy:latest image --severity HIGH,CRITICAL dvna-pfe:pipeline 2>&1 || exit 0',
                        returnStdout: true
                    ).trim()
                    def status = (output.contains('CRITICAL') || output.contains('HIGH')) ? 'warning' : 'success'
                    sendToDashboard("Trivy", output, status)
                    echo output
                }
            }
        }

        stage('5 - IaC Security (Checkov)') {
            steps {
                echo '=== Analyse IaC Dockerfile ==='
                script {
                    def output = bat(
                        script: 'docker run --rm -v "%CD%:/workspace" bridgecrew/checkov:2.3.0 -f /workspace/Dockerfile --framework dockerfile 2>&1 || exit 0',
                        returnStdout: true
                    ).trim()
                    def status = (output.contains('Failed checks') && !output.contains('Failed checks: 0')) ? 'warning' : 'success'
                    sendToDashboard("Checkov", output, status)
                    echo output
                }
            }
        }

        stage('6 - DAST (OWASP ZAP)') {
            steps {
                echo '=== Test dynamique de l application ==='
                script {
                    bat 'if not exist zap-report mkdir zap-report'
                    def output = bat(
                        script: 'docker run --rm -v "%CD%\\zap-report:/zap/wrk" ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t http://host.docker.internal:9090 -r zap-pipeline.html -I 2>&1 || exit 0',
                        returnStdout: true
                    ).trim()
                    def status = (output.contains('WARN-NEW') && !output.contains('WARN-NEW: 0')) ? 'warning' : 'success'
                    sendToDashboard("OWASP ZAP", output, status)
                    echo output
                }
            }
        }
    }

    post {
        always {
            echo '=== Pipeline DevSecOps termine ==='
            script {
                def finalStatus = currentBuild.result == 'SUCCESS' ? 'success' : 'warning'
                sendToDashboard("Pipeline Summary", "Pipeline termine - Build ${BUILD_NUMBER} sur ${BUILD_BRANCH}", finalStatus)
            }
        }
    }
}

def sendToDashboard(String tool, String content, String status) {
    try {
        def safe = content
            .replace('\\', '\\\\')
            .replace('"', '\\"')
            .replace('\r\n', '\\n')
            .replace('\n', '\\n')
            .replace('\r', '\\n')
        if (safe.length() > 8000) {
            safe = safe.substring(0, 8000) + '\\n... [tronque]'
        }
        bat """
            curl -s -X POST ${env.DASHBOARD} ^
            -H "Content-Type: application/json" ^
            -d "{\\"tool\\":\\"${tool}\\",\\"build\\":\\"${env.BUILD_NUMBER}\\",\\"branch\\":\\"${env.BUILD_BRANCH}\\",\\"content\\":\\"${safe}\\",\\"status\\":\\"${status}\\"}" ^
            > nul 2>&1
        """
    } catch(e) {
        echo "Envoi dashboard echoue pour ${tool}: ${e.message}"
    }
}