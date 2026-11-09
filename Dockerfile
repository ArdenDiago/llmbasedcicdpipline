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

# Pre-fetch Trivy's vulnerability DB into a fixed, world-readable path.
# This image doubles as the ephemeral sandbox image (agent/sandbox/image.py),
# which runs with network_disabled=True — trivy can't fetch its DB at scan
# time there, so it must already be on disk. See agent/security/scanners/trivy.py
# (OFFLINE_CACHE_DIR) for the matching --cache-dir/--skip-*-update flags.
RUN trivy image --download-db-only --cache-dir /opt/trivy-cache \
    && chmod -R a+rX /opt/trivy-cache

# Install Gitleaks (upstream renamed the linux asset suffix amd64 -> x64
# after this version was pinned; same v8.21.2 binary, corrected filename)
RUN curl -sSfL https://github.com/gitleaks/gitleaks/releases/download/v8.21.2/gitleaks_8.21.2_linux_x64.tar.gz \
    | tar -xz -C /usr/local/bin gitleaks

# Install Semgrep, pinned to match the version cited in the paper
# (Paper/paper/sections/05_results.tex: "Semgrep~v1.86.0") — unlike
# Bandit (pinned in requirements.txt) and Trivy/Gitleaks (pinned above),
# this was previously unpinned, so a rebuild months later could silently
# diverge from the reported results without any record of it.
# Installed into its own venv together with njsscan (which depends on
# semgrep): semgrep 1.86.0 pins pydantic~=2.8.2, which conflicts with
# fastapi 0.137.2 (pydantic>=2.9) in requirements.txt, so a shared
# site-packages made `pip install -r requirements.txt` unresolvable and the
# image could not be built at all. setuptools<81: semgrep's otel
# instrumentation still imports pkg_resources.
RUN python -m venv /opt/semgrep-venv \
    && /opt/semgrep-venv/bin/pip install --no-cache-dir "setuptools<81" semgrep==1.86.0 njsscan==0.4.3
# Appended, not prepended, so `python`/`pip` still resolve to the system
# interpreter; semgrep needs its helper `pysemgrep` on PATH, so a symlink
# to the semgrep binary alone is not enough.
ENV PATH="${PATH}:/opt/semgrep-venv/bin"

# Pre-fetch the same registry rulesets the evaluation harness uses
# (evaluation/run_scanners.py) into a fixed, world-readable path, so the
# network-isolated sandbox can run `--config /opt/semgrep-rules` instead of
# `--config auto` (which needs a live call to semgrep's registry). See
# agent/security/scanners/semgrep.py (OFFLINE_RULES_DIR).
RUN mkdir -p /opt/semgrep-rules \
    && for r in r/python.lang.security r/python.lang.security.audit \
                r/javascript.lang.security r/javascript.express \
                r/javascript.lang.security.audit; do \
         curl -sSL "https://semgrep.dev/c/$r" \
           -o "/opt/semgrep-rules/$(echo "$r" | tr '/' '_').yaml"; \
       done \
    && chmod -R a+rX /opt/semgrep-rules

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY agent/ ./agent/
COPY config/ ./config/

CMD ["python", "-m", "agent.sandbox.manager"]
