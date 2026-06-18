import os
from pathlib import Path

from agent.llm import config


def test_load_balancing_from_project_config():
    cfg = config.load(Path("config/model_balancing.yml"))
    assert cfg.escalation.confidence_threshold == 0.5
    assert cfg.escalation.opus_min_attempt == 3
    assert cfg.task("single_file_fix").primary == "deepseek_coder"
    assert cfg.task("multi_file_fix").last_resort == "opus"
    assert cfg.task("error_classification").max_tokens_out == 100


def test_env_expansion(tmp_path, monkeypatch):
    monkeypatch.setenv("TEST_HOST", "http://ollama:9999")
    body = """
models:
  deepseek:
    host: ${TEST_HOST:-http://localhost:11434}
tasks:
  single_file_fix:
    primary: deepseek
    max_tokens_in: 3000
    max_tokens_out: 1000
escalation:
  confidence_threshold: 0.5
  max_attempts: 3
  opus_min_attempt: 3
"""
    p = tmp_path / "c.yml"
    p.write_text(body)
    cfg = config.load(p)
    assert cfg.models["deepseek"]["host"] == "http://ollama:9999"


def test_env_expansion_falls_back_to_default(tmp_path, monkeypatch):
    monkeypatch.delenv("UNSET_HOST", raising=False)
    body = """
models:
  x:
    host: ${UNSET_HOST:-http://default:1}
tasks: {}
escalation:
  confidence_threshold: 0.5
  max_attempts: 3
  opus_min_attempt: 3
"""
    p = tmp_path / "c.yml"
    p.write_text(body)
    cfg = config.load(p)
    assert cfg.models["x"]["host"] == "http://default:1"


def test_unknown_task_raises():
    cfg = config.load(Path("config/model_balancing.yml"))
    import pytest
    with pytest.raises(KeyError):
        cfg.task("nonexistent")
