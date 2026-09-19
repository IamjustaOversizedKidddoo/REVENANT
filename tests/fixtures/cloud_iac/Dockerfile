# Insecure Test Dockerfile for Container Security Auditing
FROM node:latest

WORKDIR /usr/src/app

# Hardcoded AWS secret in ENV layer
ENV AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
ENV AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

COPY package*.json ./
RUN npm install --production

COPY . .

EXPOSE 8080

# Explicitly running as root user (container privilege escape risk)
USER root

CMD ["node", "server.js"]
