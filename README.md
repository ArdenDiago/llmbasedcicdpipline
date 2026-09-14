# LLM-Assisted Vulnerability Detection and Automated Remediation in CI/CD Pipelines

An autonomous CI/CD agent that scans code pushed to a repository for security
vulnerabilities, generates a fix using a cost-tiered LLM cascade, validates
the fix against the project's own test suite, and opens a pull request —
without a human in the loop.

## How it works

```
push event → clone (host) → sandbox scan (Docker, network-isolated)
                                   │
                    Bandit / Semgrep / Gitleaks / Trivy
                                   │
                             findings (JSON)
                                   │
                    LLM escalation cascade (agent/llm/analyzer.py)
                                   │
      DeepSeek Coder (free, local) ──low confidence──► Haiku (classify)
                                                            │
                                              not spurious  ▼
                                                   Sonnet (fix + re-score)
                                                            │
                                              still low     ▼
                                                   Opus (last resort)
                                   │
                     validate fix against project test suite
                                   │
                        commit → push → open PR (GitHub API)
```

Model selection follows a strict escalation order — cheapest/free model
first, more capable (and expensive) models only on demand. See
`config/model_balancing.yml` for the exact task→model table and token
budgets.

## Requirements

- Python 3.11+
- Docker (the sandbox scanner image and, optionally, `docker compose` for
  the full webhook + agent + Ollama stack)
- [Ollama](https://ollama.com) running locally, with `deepseek-coder:6.7b`
  pulled — this is the only tier that runs for free
- Node.js 20+ (only needed for the webhook listener, `agent/webhook/`)
- A GitHub token with **Contents: Read and write** and **Pull requests:
  Read and write** on the target repo, if you want the agent to actually
  push branches and open PRs (a read-only token will scan and generate
  fixes fine, but PR creation will fail)
- An Anthropic API key, if you want the Haiku/Sonnet/Opus escalation tiers
  to run for real — without one, confidence scoring and PR-body generation
  (both hardcoded to Haiku) will fail past tier 1

## Setup

```bash
git clone https://github.com/ArdenDiago/llm-assisted-vulnerability-detection-and-automated-remediation-in-cicd-pipelines.git
cd llm-assisted-vulnerability-detection-and-automated-remediation-in-cicd-pipelines

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# fill in GITHUB_TOKEN, WEBHOOK_SECRET, ANTHROPIC_API_KEY, etc.

ollama pull deepseek-coder:6.7b

# build the sandbox/scanner image (bundles Trivy, Gitleaks, Semgrep, Bandit)
docker build -t llm-cicd-agent:latest .
```

### Run the tests

```bash
pytest tests/
```

### Run a scan by hand

The scanners run inside the sandbox image, not on the host, so they need to
be invoked as a module (not as a script) with the target checkout bind-mounted
read-only:

```bash
docker run --rm --network none \
  -v /path/to/checkout:/workspace:ro \
  llm-cicd-agent:latest \
  python -m agent.security.run_scan --path /workspace
```

This prints a single JSON envelope of normalized, deduplicated findings.

### Run the full stack (webhook → sandbox → LLM → PR)

```bash
docker compose up
```

This starts three services: the Node.js webhook listener, the Python agent
(which spins up a fresh sandbox container per push via the Docker socket),
and a local Ollama instance. See `docker-compose.yml` and each module's own
`CLAUDE.md` for the per-service configuration.

## Project structure

```
agent/
  webhook/    → GitHub webhook listener (Node.js/Express)
  sandbox/    → Docker sandbox lifecycle (clone, container, collector)
  security/   → Scanner orchestration (Trivy, Gitleaks, Bandit, Semgrep)
  llm/        → Prompt templates + the DeepSeek→Haiku→Sonnet→Opus cascade
  testing/    → Test-runner layer used to validate a generated fix
  pr/         → Git operations + GitHub PR creation
config/       → model_balancing.yml, app.yml
evaluation/   → Benchmarking harness (scripts only — datasets are excluded
                from this repo; see the parent research repo)
training/     → QLoRA fine-tuning
tests/        → Unit + integration tests for the agent itself
```

## Status

Research prototype. All 206 unit/integration tests pass; the full
clone→scan→fix→PR pipeline has been verified end-to-end against a live
Docker sandbox and a live Ollama instance. It is not hardened for
production use — see `agent/sandbox/CLAUDE.md`'s "Control-Plane Privilege"
note before deploying the `agent` service (it needs Docker-socket access to
spin up per-push sandboxes).

## License

MIT
