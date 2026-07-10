# CLAUDE.md — Configuration

## Purpose
Central configuration for the agent. All environment-specific values
come from .env files; this directory holds structured config.

## Files
- model_balancing.yml   → Model-to-task mapping, token budgets, escalation
                          rules. The one file here actually loaded at
                          runtime — see agent/llm/config.py.
- app.yml               → General application values (ports, timeouts, log
                          level). **Not currently read by any code** — every
                          value it documents (webhook port, sandbox
                          timeout/CPU/memory, scanner timeouts) is instead a
                          hardcoded constant or env var read directly in the
                          relevant module (agent/webhook/server.js,
                          agent/sandbox/container.py,
                          agent/security/run_scan.py). Editing app.yml has
                          no effect on runtime behavior today; treat it as a
                          record of intended defaults, not live config,
                          until it's actually wired up the way
                          model_balancing.yml is.

`scanners.yml` and `docker.yml`, mentioned in earlier drafts of this file,
do not exist — removed from this list rather than left as a claim about
files that aren't here.

## Rules
- Never hardcode secrets — all secrets come from .env
- Config files are YAML — no JSON config files
- Every config value must have a sensible default
- Document each config key with inline comments
