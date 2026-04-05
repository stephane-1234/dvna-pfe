pipeline {
    agent any

    environment {
        APP_URL      = "http://localhost:9090"
        DASHBOARD    = "http://localhost:3500/api/report"
        BUILD_BRANCH = "${env.BRANCH_NAME ?: 'master'}"
    }

    stages {

        stage('1 - Secrets Scanning (Gitleaks)') {
            steps {
                echo '=== Scan des secrets hardcodes ==='
                script {
                    def output = bat(
                        script: 'gitleaks.exe detect --source . --config .gitleaks.toml -v 2>&1',
                        returnStdout: true
                    ).trim()

                    def status = output.contains('leaks found: 0') ? 'success' : 'warning'
                    def escaped = output.replace('\\', '\\\\').replace('"', '\\"').replace('\r\n', '\\n').replace('\n', '\\n')

                    bat """
                        curl -s -X POST %DASHBOARD% ^
                        -H "Content-Type: application/json" ^
                        -d "{\\"tool\\":\\"Gitleaks\\",\\"build\\":\\"%BUILD_NUMBER%\\",\\"branch\\":\\"%BUILD_BRANCH%\\",\\"content\\":\\"${escaped}\\",\\"status\\":\\"${status}\\"}" ^
                        > nul 2>&1 || exit 0
                    """
                    echo output
                }
            }
        }

        stage('2 - SAST (Semgrep)') {
            steps {
                echo '=== Analyse statique du code ==='
                script {
                    def output = bat(
                        script: '''docker run --rm -v "%CD%:/src" ^
                        returntocorp/semgrep semgrep ^
                        --config=p/nodejs ^
                        --config=p/security-audit ^
                        /src/server.js 2>&1''',
                        returnStdout: true
                    ).trim()

                    def status = output.contains('blocking') ? 'warning' : 'success'
                    def escaped = output.replace('\\', '\\\\').replace('"', '\\"').replace('\r\n', '\\n').replace('\n', '\\n')

                    bat """
                        curl -s -X POST %DASHBOARD% ^
                        -H "Content-Type: application/json" ^
                        -d "{\\"tool\\":\\"Semgrep\\",\\"build\\":\\"%BUILD_NUMBER%\\",\\"branch\\":\\"%BUILD_BRANCH%\\",\\"content\\":\\"${escaped}\\",\\"status\\":\\"${status}\\"}" ^
                        > nul 2>&1 || exit 0
                    """
                    echo output
                }
            }
        }

        stage('3 - SCA (npm audit)') {
            steps {
                echo '=== Analyse des dependances ==='
                script {
                    def output = bat(
                        script: 'npm audit 2>&1',
                        returnStdout: true
                    ).trim()

                    def status = output.contains('critical') ? 'warning' : 'success'
                    def escaped = output.replace('\\', '\\\\').replace('"', '\\"').replace('\r\n', '\\n').replace('\n', '\\n')

                    bat """
                        curl -s -X POST %DASHBOARD% ^
                        -H "Content-Type: application/json" ^
                        -d "{\\"tool\\":\\"npm audit\\",\\"build\\":\\"%BUILD_NUMBER%\\",\\"branch\\":\\"%BUILD_BRANCH%\\",\\"content\\":\\"${escaped}\\",\\"status\\":\\"${status}\\"}" ^
                        > nul 2>&1 || exit 0
                    """
                    echo output
                }
            }
        }

        stage('4 - Container Scan (Trivy)') {
            steps {
                echo '=== Scan de l image Docker ==='
                script {
                    bat 'docker build -t dvna-pfe:pipeline . 2>&1'

                    def output = bat(
                        script: '''docker run --rm ^
                        -v //var/run/docker.sock://var/run/docker.sock ^
                        aquasec/trivy:latest image ^
                        --severity HIGH,CRITICAL ^
                        dvna-pfe:pipeline 2>&1''',
                        returnStdout: true
                    ).trim()

                    def status = output.contains('CRITICAL') ? 'warning' : 'success'
                    def escaped = output.replace('\\', '\\\\').replace('"', '\\"').replace('\r\n', '\\n').replace('\n', '\\n')

                    bat """
                        curl -s -X POST %DASHBOARD% ^
                        -H "Content-Type: application/json" ^
                        -d "{\\"tool\\":\\"Trivy\\",\\"build\\":\\"%BUILD_NUMBER%\\",\\"branch\\":\\"%BUILD_BRANCH%\\",\\"content\\":\\"${escaped}\\",\\"status\\":\\"${status}\\"}" ^
                        > nul 2>&1 || exit 0
                    """
                    echo output
                }
            }
        }

        stage('5 - IaC Security (Checkov)') {
            steps {
                echo '=== Analyse IaC Dockerfile ==='
                script {
                    def output = bat(
                        script: '''docker run --rm ^
                        -v "%CD%:/workspace" ^
                        bridgecrew/checkov:2.3.0 ^
                        -f /workspace/Dockerfile ^
                        --framework dockerfile 2>&1''',
                        returnStdout: true
                    ).trim()

                    def status = output.contains('Failed checks: 0') ? 'success' : 'warning'
                    def escaped = output.replace('\\', '\\\\').replace('"', '\\"').replace('\r\n', '\\n').replace('\n', '\\n')

                    bat """
                        curl -s -X POST %DASHBOARD% ^
                        -H "Content-Type: application/json" ^
                        -d "{\\"tool\\":\\"Checkov\\",\\"build\\":\\"%BUILD_NUMBER%\\",\\"branch\\":\\"%BUILD_BRANCH%\\",\\"content\\":\\"${escaped}\\",\\"status\\":\\"${status}\\"}" ^
                        > nul 2>&1 || exit 0
                    """
                    echo output
                }
            }
        }

        stage('6 - DAST (OWASP ZAP)') {
            steps {
                echo '=== Test dynamique de l application ==='
                script {
                    if (!fileExists('zap-report')) {
                        bat 'mkdir zap-report'
                    }

                    def output = bat(
                        script: '''docker run --rm ^
                        -v "%CD%\\zap-report:/zap/wrk" ^
                        ghcr.io/zaproxy/zaproxy:stable ^
                        zap-baseline.py ^
                        -t http://host.docker.internal:9090 ^
                        -r zap-pipeline.html ^
                        -I 2>&1''',
                        returnStdout: true
                    ).trim()

                    def status = output.contains('WARN-NEW: 0') ? 'success' : 'warning'
                    def escaped = output.replace('\\', '\\\\').replace('"', '\\"').replace('\r\n', '\\n').replace('\n', '\\n')

                    bat """
                        curl -s -X POST %DASHBOARD% ^
                        -H "Content-Type: application/json" ^
                        -d "{\\"tool\\":\\"OWASP ZAP\\",\\"build\\":\\"%BUILD_NUMBER%\\",\\"branch\\":\\"%BUILD_BRANCH%\\",\\"content\\":\\"${escaped}\\",\\"status\\":\\"${status}\\"}" ^
                        > nul 2>&1 || exit 0
                    """
                    echo output
                }
            }
        }
    }

    post {
        always {
            echo '=== Pipeline DevSecOps termine ==='
            bat """
                curl -s -X POST %DASHBOARD% ^
                -H "Content-Type: application/json" ^
                -d "{\\"tool\\":\\"Pipeline Summary\\",\\"build\\":\\"%BUILD_NUMBER%\\",\\"branch\\":\\"%BUILD_BRANCH%\\",\\"content\\":\\"Pipeline termine - Build %BUILD_NUMBER% sur %BUILD_BRANCH%\\",\\"status\\":\\"${currentBuild.result == 'SUCCESS' ? 'success' : 'warning'}\\"}" ^
                > nul 2>&1 || exit 0
            """
        }
        success {
            echo '=== Tous les scans executes avec succes ==='
        }
        failure {
            echo '=== Des erreurs ont ete detectees ==='
        }
    }
}