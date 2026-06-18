from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest

from agent.llm import analyzer, config
from agent.llm.clients.base import LLMResponse


@dataclass
class ScriptedClient:
    name: str
    model: str
    response_text: str
    tokens_in: int = 100
    tokens_out: int = 50
    latency_ms: int = 10

    def complete(self, prompt: str, max_tokens: int, temperature: float = 0.2) -> LLMResponse:
        return LLMResponse(
            text=self.response_text, model=self.model,
            tokens_in=self.tokens_in, tokens_out=self.tokens_out, latency_ms=self.latency_ms,
        )


@pytest.fixture
def cfg():
    return config.load(Path("config/model_balancing.yml"))


FINDING = {
    "scanner": "bandit", "rule_id": "B105", "severity": "low",
    "confidence": "medium", "file": "app/auth.py", "line": 45,
    "message": "hardcoded password", "cwe": "CWE-259",
    "snippet": "password = 'admin123'",
}


def _clients(deepseek_text, haiku_text=None, sonnet_text=None, opus_text=None):
    return analyzer.ClientSet(
        deepseek=ScriptedClient("ollama", "deepseek-coder:6.7b", deepseek_text),
        haiku=ScriptedClient("anthropic", "haiku", haiku_text or ""),
        sonnet=ScriptedClient("anthropic", "sonnet", sonnet_text or ""),
        opus=ScriptedClient("anthropic", "opus", opus_text or ""),
    )


def test_deepseek_high_confidence_stops_at_attempt_1(cfg):
    clients = _clients(deepseek_text="--- a/x\n+++ b/x\n CONFIDENCE: 0.85")
    proposal = analyzer.analyze_finding(
        FINDING, "password = 'admin123'", "octocat/x", "abc", clients, cfg,
    )
    assert proposal.attempts == 1
    assert proposal.confidence == 0.85
    assert proposal.model_used == "deepseek-coder:6.7b"
    assert len(proposal.audit) == 1


def test_low_confidence_escalates_through_sonnet(cfg):
    clients = _clients(
        deepseek_text="CONFIDENCE: 0.2",
        haiku_text='{"category": "simple", "confidence": 0.9, "reasoning": "x"}',
        sonnet_text="CONFIDENCE: 0.9",
    )
    proposal = analyzer.analyze_finding(FINDING, "x", "r", "c", clients, cfg)
    assert proposal.attempts == 2
    assert proposal.model_used == "sonnet"
    assert [e.stage for e in proposal.audit] == ["fix", "classify", "fix"]
    assert proposal.audit[0].model == "deepseek-coder:6.7b"


def test_spurious_classification_short_circuits(cfg):
    clients = _clients(
        deepseek_text="CONFIDENCE: 0.2",
        haiku_text='{"category": "spurious", "confidence": 0.95, "reasoning": "x"}',
    )
    proposal = analyzer.analyze_finding(FINDING, "x", "r", "c", clients, cfg)
    assert proposal.attempts == 2
    assert proposal.diff == ""
    assert "spurious" in (proposal.rationale or "")


def test_opus_only_reached_as_last_resort(cfg):
    clients = _clients(
        deepseek_text="CONFIDENCE: 0.1",
        haiku_text='{"category": "complex", "confidence": 0.9, "reasoning": "x"}',
        sonnet_text="CONFIDENCE: 0.3",
        opus_text="CONFIDENCE: 0.9",
    )
    proposal = analyzer.analyze_finding(FINDING, "x", "r", "c", clients, cfg)
    assert proposal.attempts == 3
    assert proposal.model_used == "opus"
    # CLAUDE.md rule: Opus never called before 3rd attempt.
    opus_entries = [e for e in proposal.audit if e.model == "opus"]
    assert len(opus_entries) == 1
    assert opus_entries[0].attempt == 3


def test_every_call_has_full_audit_metadata(cfg):
    clients = _clients(
        deepseek_text="CONFIDENCE: 0.2",
        haiku_text='{"category": "complex"}',
        sonnet_text="CONFIDENCE: 0.9",
    )
    proposal = analyzer.analyze_finding(FINDING, "x", "r", "c", clients, cfg)
    for entry in proposal.audit:
        assert entry.model
        assert entry.stage in ("fix", "classify")
        assert entry.tokens_in >= 0
        assert entry.tokens_out >= 0
        assert entry.latency_ms >= 0


def test_language_detection_in_prompt():
    assert analyzer._language_for("app/main.py") == "python"
    assert analyzer._language_for("x.ts") == "typescript"
    assert analyzer._language_for("y.go") == "go"
    assert analyzer._language_for("unknown") == ""
