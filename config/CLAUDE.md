# CLAUDE.md — Configuration

## Purpose
Central configuration for the agent. All environment-specific values
come from .env files; this directory holds structured config.

## Files
- app.yml              → General application config (ports, timeouts, log level)
- model_balancing.yml   → Model-to-task mapping, token budgets, escalation rules
- scanners.yml          → Scanner paths, versions, timeout per scanner
- docker.yml            → Sandbox container resource limits, image config

## Rules
- Never hardcode secrets — all secrets come from .env
- Config files are YAML — no JSON config files
- Every config value must have a sensible default
- Document each config key with inline comments
