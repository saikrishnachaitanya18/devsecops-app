# ============================================================
# INTENTIONALLY VULNERABLE DOCKERFILE
# Purpose: Trivy Image Scan Demo for DevSecOps training
# WARNING: DO NOT use this in production!
# ============================================================

# VULNERABILITY 1: Using an old, outdated base image with many known CVEs
FROM node:14.17.0

# VULNERABILITY 2: Running as root (no USER instruction)
# (root is the default - never adding a non-root user is a bad practice)

# VULNERABILITY 3: Hardcoded secrets / credentials in ENV
ENV SECRET_KEY="super_secret_hardcoded_key_123"
ENV DB_PASSWORD="admin123"
ENV JWT_SECRET="jwt_secret_do_not_share"
ENV AWS_ACCESS_KEY_ID="DUMMY_AWS_KEY_ID"
ENV AWS_SECRET_ACCESS_KEY="DUMMY_AWS_SECRET_KEY"
ENV STRIPE_SECRET="DUMMY_STRIPE_SECRET"
ENV NODE_ENV="production"
ENV PORT=3000

# VULNERABILITY 4: Installing packages without pinning versions
# and installing unnecessary/risky tools (curl, wget, netcat)
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    netcat \
    net-tools \
    vim \
    openssh-client \
    && apt-get clean

# VULNERABILITY 5: Copying entire project including .env, secrets, etc.
# (No .dockerignore filtering sensitive files)
WORKDIR /app
COPY . .

# VULNERABILITY 6: Installing ALL npm packages including devDependencies
# in production image (increases attack surface)
RUN npm install

# VULNERABILITY 7: Exposing port and running as root
EXPOSE 3000

# VULNERABILITY 8: Running the app as root with no health check
# and using npm start which can hide process signals
CMD ["npm", "start"]
