# DVNA-PFE — Dockerfile SECURISE (branch secure)

# FIX Trivy : image alpine minimale, beaucoup moins de CVEs OS
FROM node:22-alpine3.21

# FIX Checkov CKV_DOCKER_2 : HEALTHCHECK present
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:9090/ || exit 1

WORKDIR /app

COPY package*.json ./

RUN npm ci --only=production && npm cache clean --force

COPY . .

EXPOSE 9090

# FIX Checkov CKV_DOCKER_3 : utilisateur non-root
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser

CMD ["node", "server.js"]
