FROM node:18

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .

# CORRECTION 1 : Utilisateur non-root
RUN useradd -m appuser
USER appuser

EXPOSE 9090

# CORRECTION 2 : Healthcheck
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD node -e "require('http').get('http://localhost:9090', (r) => process.exit(r.statusCode === 200 ? 0 : 1))"

CMD ["node", "server.js"]
