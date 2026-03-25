pipeline {
    agent any

    environment {
        APP_URL = "http://host.docker.internal:9090"
    }

    stages {

        stage('1 - Secrets Scanning (Gitleaks)') {
            steps {
                echo '=== Scan des secrets hardcodes ==='
                bat '''
                    gitleaks.exe detect --source . --config .gitleaks.toml -v 2>&1 || true
                '''
            }
        }

        stage('2 - SAST (Semgrep)') {
            steps {
                echo '=== Analyse statique du code ==='
                bat '''
                    docker run --rm -v "%CD%:/src" ^
                    returntocorp/semgrep semgrep ^
                    --config=p/nodejs ^
                    --config=p/security-audit ^
                    /src/server.js 2>&1 || true
                '''
            }
        }

        stage('3 - SCA (npm audit)') {
            steps {
                echo '=== Analyse des dependances ==='
                bat 'npm audit --audit-level=critical 2>&1 || true'
            }
        }

        stage('4 - Container Scan (Trivy)') {
            steps {
                echo '=== Scan de l image Docker ==='
                bat '''
                    docker build -t dvna-pfe:pipeline . 2>&1
                    docker run --rm ^
                    -v /var/run/docker.sock:/var/run/docker.sock ^
                    aquasec/trivy:latest image ^
                    --severity HIGH,CRITICAL ^
                    dvna-pfe:pipeline 2>&1 || true
                '''
            }
        }

        stage('5 - IaC Security (Checkov)') {
            steps {
                echo '=== Analyse IaC Dockerfile ==='
                bat '''
                    docker run --rm ^
                    -v "%CD%:/workspace" ^
                    bridgecrew/checkov:2.3.0 ^
                    -f /workspace/Dockerfile ^
                    --framework dockerfile 2>&1 || true
                '''
            }
        }

        stage('6 - DAST (OWASP ZAP)') {
            steps {
                echo '=== Test dynamique de l application ==='
                bat '''
                    docker run --rm ^
                    -v "%CD%/zap-report:/zap/wrk" ^
                    ghcr.io/zaproxy/zaproxy:stable ^
                    zap-baseline.py ^
                    -t http://host.docker.internal:9090 ^
                    -r zap-pipeline.html ^
                    -I 2>&1 || true
                '''
            }
        }
    }

    post {
        always {
            echo '=== Pipeline DevSecOps termine ==='
        }
        success {
            echo '=== Tous les scans ont ete executes avec succes ==='
        }
        failure {
            echo '=== Des erreurs ont ete detectees ==='
        }
    }
}