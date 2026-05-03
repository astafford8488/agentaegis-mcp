FROM node:20-slim

RUN apt-get update && apt-get install -y \
    nmap \
    python3 \
    python3-pip \
    python3-venv \
    git \
    curl \
    wget \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Install Python-based tools
RUN pip3 install --break-system-packages \
    sslyze \
    semgrep \
    trufflehog

# Install trivy
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Install nuclei
RUN curl -sfL https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | grep tag_name | cut -d '"' -f 4 | sed 's/v//')_linux_amd64.zip -o /tmp/nuclei.zip \
    && unzip /tmp/nuclei.zip -d /usr/local/bin \
    && rm /tmp/nuclei.zip \
    && nuclei -update-templates || true

# Copy application
WORKDIR /app
COPY package.json pnpm-lock.yaml ./
RUN npm install -g pnpm && pnpm install --frozen-lockfile
COPY . .
RUN pnpm build

# Create temp directory for scans
RUN mkdir -p /tmp/aegis-scans && chmod 777 /tmp/aegis-scans

EXPOSE 3000

CMD ["pnpm", "start"]
