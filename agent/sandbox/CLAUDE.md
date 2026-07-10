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
- Two host-filesystem mounts, both narrowly scoped: `/results` (rw, a
  per-run temp dir holding only that run's scan/test JSON output — 0777
  because the container's fixed UID 65534 doesn't otherwise have access;
  see container.py) and `/workspace` (ro, the cloned repo checkout, only
  when a repo_url was supplied). `/tmp` is a separate in-container tmpfs,
  not a host mount.
- Network disabled after initial clone
- PID namespace isolation enabled
- Auto-kill after 10 minute timeout

## Control-Plane Privilege (Known Risk)
The always-on `agent` service (this module's `manager.py`, run via
`docker-compose.yml`) bind-mounts `/var/run/docker.sock` so it can create
per-push sandbox containers via docker-py. Docker socket access is
root-equivalent host access — the isolation above protects against a
*hostile target repo's code* running inside the sandbox, but does nothing
to contain an RCE-class bug in the control-plane process itself (e.g. a
dependency vulnerability, a payload-parsing bug). This is a structural
consequence of a long-lived service spinning up ephemeral containers via
the Docker API, and is not currently mitigated. If this matters for your
deployment, run the control-plane container against a scoped Docker API
proxy (e.g. `docker-socket-proxy`) restricted to the specific
`containers.create/start/wait/logs/remove` and `images.get/pull` calls
this module actually makes, rather than the raw socket.

## Testing
- Tests live in /tests/sandbox/
- Run: pytest tests/sandbox/
- Integration tests require Docker daemon running
