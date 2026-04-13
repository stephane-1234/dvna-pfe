import groovy.json.JsonOutput

pipeline {
    agent any

    environment {
        APP_URL      = "http://localhost:9090"
        DASHBOARD    = "http://localhost:3500/api/report"
        BUILD_BRANCH = "master"
        GITLEAKS     = "C:\\Users\\asngo\\AppData\\Local\\Microsoft\\WinGet\\Packages\\Gitleaks.Gitleaks_Microsoft.Winget.Source_8wekyb3d8bbwe\\gitleaks.exe"

        JAVA_TOOL_OPTIONS = '-Dfile.encoding=UTF-8 -Dstdout.encoding=UTF-8'
        PYTHONIOENCODING  = 'UTF-8'
        PYTHONUTF8        = '1'
    }

    stages {

        stage('1 - Secrets Scanning (Gitleaks)') {
            steps {
                echo '=== Scan des secrets hardcodes ==='
                script {
                    def output = bat(
                        script: '''@chcp 65001 > nul
                                   "%GITLEAKS%" detect --source . --config .gitleaks.toml -v 2>&1 || exit 0''',
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
                        // Utilisation de --json pour éviter tout caractère graphique
                        script: '''@chcp 65001 > nul
                                   docker run --rm -v "%CD%:/src" returntocorp/semgrep semgrep ^
                                   --config=p/nodejs --config=p/security-audit ^
                                   --json --output /src/semgrep_out.json ^
                                   /src/server.js > nul 2>&1 || exit 0
                                   type semgrep_out.json''',
                        returnStdout: true
                    ).trim()
                    def status = output.contains('blocking') ? 'warning' : 'success'
                    sendToDashboard("Semgrep", output, status)
                }
            }
        }

        stage('3 - SCA (npm audit)') {
            steps {
                echo '=== Analyse des dependances ==='
                script {
                    def output = bat(
                        script: '''@chcp 65001 > nul
                                   npm audit --unicode=false 2>&1 || exit 0''',
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
                    bat '@chcp 65001 > nul && docker build -t dvna-pfe:pipeline . 2>&1 || exit 0'
                    def output = bat(
                        script: '''@chcp 65001 > nul
                                   docker run --rm ^
                                   -v //var/run/docker.sock://var/run/docker.sock ^
                                   aquasec/trivy:latest image ^
                                   --severity HIGH,CRITICAL ^
                                   --no-progress ^
                                   dvna-pfe:pipeline 2>&1 || exit 0''',
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
                        script: '''@chcp 65001 > nul
                                   docker run --rm -v "%CD%:/workspace" ^
                                   bridgecrew/checkov:2.3.0 ^
                                   -f /workspace/Dockerfile ^
                                   --framework dockerfile 2>&1 || exit 0''',
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
                    bat '@chcp 65001 > nul && if not exist zap-report mkdir zap-report'
                    def output = bat(
                        script: '''@chcp 65001 > nul
                                   docker run --rm ^
                                   -v "%CD%\\zap-report:/zap/wrk" ^
                                   ghcr.io/zaproxy/zaproxy:stable ^
                                   zap-baseline.py ^
                                   -t http://host.docker.internal:9090 ^
                                   -r zap-pipeline.html -I 2>&1 || exit 0''',
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
        def jsonStr = JsonOutput.toJson([
            tool   : tool,
            build  : env.BUILD_NUMBER,
            branch : env.BUILD_BRANCH ?: 'master',
            content: content,
            status : status
        ])

        def jsonFile = "report_${tool.replaceAll('[^a-zA-Z0-9]', '_')}.json"
        writeFile file: jsonFile, text: jsonStr, encoding: 'UTF-8'  // AJOUT encoding

        bat """
            @chcp 65001 > nul
            curl -s -X POST %DASHBOARD% ^
            -H "Content-Type: application/json; charset=utf-8" ^
            --data-binary @${jsonFile} ^
            > nul 2>&1 || exit 0
        """

        bat "@chcp 65001 > nul && del ${jsonFile} > nul 2>&1 || exit 0"

    } catch(e) {
        echo "Envoi dashboard echoue pour ${tool}: ${e.message}"
    }
}