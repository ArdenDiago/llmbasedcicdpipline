# CLAUDE.md — Tests

## Purpose
Unit and integration tests for the agent itself (not the target repos).

## Structure
- tests/webhook/       → Webhook listener tests
- tests/sandbox/       → Sandbox manager tests
- tests/testing/       → Test runner layer tests
- tests/security/      → Security scanner layer tests
- tests/llm/           → LLM layer tests
- tests/pr/            → PR creation tests
- tests/integration/   → End-to-end pipeline tests

## Running
- All tests: pytest tests/
- Single module: pytest tests/<module>/
- With coverage: pytest tests/ --cov=agent --cov-report=html

## Rules
- Every module must have corresponding tests before merging
- Mock external APIs (GitHub, Ollama, Claude) in unit tests
- Integration tests may use real Docker — mark with @pytest.mark.integration
- Test fixtures go in tests/fixtures/
- Minimum coverage target: 80% per module
