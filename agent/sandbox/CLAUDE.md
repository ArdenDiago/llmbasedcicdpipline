# CLAUDE.md — Sandbox Manager

## Purpose
Manages ephemeral Docker containers — one per push event. Each sandbox
clones the repo, runs tests, runs security scans, then self-destructs.

## Tech
- Language: Python
- Container runtime: Docker (via docker-py SDK)
- Entry: manager.py

## Lifecycle
1. Receive dispatch from webhook listener (repo URL, branch, SHA)
2. Pull/build sandbox image (cached base + project deps)
3. Start container with:
   - Read-only repo clone
   - No network access after clone (security isolation)
   - Resource limits: 2 CPU, 2GB RAM, 10min timeout
4. Run test suite inside container
5. Run security scanners inside container
6. Collect results (JSON) from container stdout
7. Pass results to LLM layer for analysis
8. Destroy container regardless of outcome

## Files
- manager.py         → Orchestrates sandbox lifecycle
- container.py       → Docker container create/start/stop/destroy
- image.py           → Image build and cache management
- collector.py       → Extracts scan/test results from container

## Container Security
- No privileged mode — ever
- Drop all capabilities except minimal set
- No volume mounts to host filesystem (except /tmp for results)
- Network disabled after initial clone
- PID namespace isolation enabled
- Auto-kill after 10 minute timeout

## Testing
- Tests live in /tests/sandbox/
- Run: pytest tests/sandbox/
- Integration tests require Docker daemon running
