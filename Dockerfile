FROM python:3.12-slim

WORKDIR /app

# Install system deps for security scanners
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Trivy (direct GitHub release download — the official install.sh
# redirects through get.trivy.dev, which is unreachable on some networks)
RUN curl -sfL https://github.com/aquasecurity/trivy/releases/download/v0.71.1/trivy_0.71.1_Linux-64bit.tar.gz \
    | tar -xz -C /usr/local/bin trivy

# Install Gitleaks (upstream renamed the linux asset suffix amd64 -> x64
# after this version was pinned; same v8.21.2 binary, corrected filename)
RUN curl -sSfL https://github.com/gitleaks/gitleaks/releases/download/v8.21.2/gitleaks_8.21.2_linux_x64.tar.gz \
    | tar -xz -C /usr/local/bin gitleaks

# Install Semgrep
RUN pip install --no-cache-dir semgrep

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY agent/ ./agent/
COPY config/ ./config/

CMD ["python", "-m", "agent.sandbox.manager"]
