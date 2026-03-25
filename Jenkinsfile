pipeline {
    agent any

    environment {
        APP_URL = "http://host.docker.internal:9090"
    }

    stages {

        stage('1 - Secrets Scanning (Gitleaks)') {
            steps {
                echo '=== Scan des secrets hardcodes ==='
                sh '''
                    docker run --rm \
                    -v $(pwd):/repo \
                    zricethezav/gitleaks:latest detect \
                    --source /repo \
                    --config /repo/.gitleaks.toml \
                    -v || true
                '''
            }
        }

        stage('2 - SAST (Semgrep)') {
            steps {
                echo '=== Analyse statique du code ==='
                sh '''
                    docker run --rm \
                    -v $(pwd):/src \
                    returntocorp/semgrep semgrep \
                    --config=p/nodejs \
                    --config=p/security-audit \
                    /src/server.js || true
                '''
            }
        }

        stage('3 - SCA (npm audit)') {
            steps {
                echo '=== Analyse des dependances ==='
                sh 'docker run --rm -v $(pwd):/app -w /app node:18 npm audit --audit-level=critical || true'
            }
        }

        stage('4 - Container Scan (Trivy)') {
            steps {
                echo '=== Scan de l image Docker ==='
                sh '''
                    docker build -t dvna-pfe:pipeline .
                    docker run --rm \
                    -v /var/run/docker.sock:/var/run/docker.sock \
                    aquasec/trivy:latest image \
                    --severity HIGH,CRITICAL \
                    dvna-pfe:pipeline || true
                '''
            }
        }

        stage('5 - IaC Security (Checkov)') {
            steps {
                echo '=== Analyse IaC Dockerfile ==='
                sh '''
                    docker run --rm \
                    -v $(pwd):/workspace \
                    bridgecrew/checkov:2.3.0 \
                    -f /workspace/Dockerfile \
                    --framework dockerfile || true
                '''
            }
        }

        stage('6 - DAST (OWASP ZAP)') {
            steps {
                echo '=== Test dynamique de l application ==='
                sh '''
                    mkdir -p zap-report
                    docker run --rm \
                    -v $(pwd)/zap-report:/zap/wrk \
                    ghcr.io/zaproxy/zaproxy:stable \
                    zap-baseline.py \
                    -t http://host.docker.internal:9090 \
                    -r zap-pipeline.html \
                    -I || true
                '''
            }
        }
    }

    post {
        always {
            echo '=== Pipeline DevSecOps termine ==='
        }
        success {
            echo '=== Tous les scans executes avec succes ==='
        }
        failure {
            echo '=== Des erreurs ont ete detectees ==='
        }
    }
}