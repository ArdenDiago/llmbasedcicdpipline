from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import pytest

from agent.llm import analyzer, config
from agent.llm.clients.base import LLMResponse


@dataclass
class ScriptedClient:
    """Returns a fixed response_text for every call.

    Real fix-generator clients (DeepSeek/Sonnet/Opus) only ever see one
    prompt template (fix_single_file.j2) in analyze_finding(), so a single
    canned response is realistic for them.
    """
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


@dataclass
class QueuedHaikuClient:
    """Haiku plays two distinct roles per finding (classify_error.j2 and
    confidence_eval.j2), each rendered from a different template and each
    potentially called more than once (once per escalation attempt scored).
    Route by a substring unique to each template's opening line, and pop
    responses in call order per role so successive calls (e.g. scoring
    DeepSeek's fix, then later Sonnet's fix) can return different scores —
    exactly what a real independent evaluator would do.
    """
    model: str = "haiku"
    name: str = "anthropic"
    classify_responses: list[str] = field(default_factory=list)
    eval_responses: list[str] = field(default_factory=list)
    tokens_in: int = 100
    tokens_out: int = 50
    latency_ms: int = 10

    def complete(self, prompt: str, max_tokens: int, temperature: float = 0.2) -> LLMResponse:
        if "code error classifier" in prompt:
            text = self.classify_responses.pop(0) if self.classify_responses else ""
        elif "evaluating the quality" in prompt:
            text = self.eval_responses.pop(0) if self.eval_responses else ""
        else:
            raise AssertionError(f"unrecognized Haiku prompt: {prompt[:80]!r}")
        return LLMResponse(
            text=text, model=self.model,
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


def _clients(
    deepseek_text="--- a/x\n+++ b/x\n-password = 'admin123'\n+password = os.environ['PW']",
    sonnet_text="--- a/x\n+++ b/x\n-password = 'admin123'\n+password = os.environ['PW']",
    opus_text="--- a/x\n+++ b/x\n-password = 'admin123'\n+password = os.environ['PW']",
    classify_responses=None,
    eval_responses=None,
):
    haiku = QueuedHaikuClient(
        classify_responses=list(classify_responses or []),
        eval_responses=list(eval_responses or []),
    )
    return analyzer.ClientSet(
        deepseek=ScriptedClient("ollama", "deepseek-coder:6.7b", deepseek_text),
        haiku=haiku,
        sonnet=ScriptedClient("anthropic", "sonnet", sonnet_text),
        opus=ScriptedClient("anthropic", "opus", opus_text),
    )


def test_deepseek_high_confidence_stops_at_attempt_1(cfg):
    """The fix prompt forbids explanation, so DeepSeek's response never
    contains a confidence marker — the real signal comes from Haiku's
    independent confidence_eval.j2 scoring, not from parsing the fix text."""
    clients = _clients(eval_responses=['{"confidence": 0.85, "reasoning": "correct"}'])
    proposal = analyzer.analyze_finding(
        FINDING, "password = 'admin123'", "octocat/x", "abc", clients, cfg,
    )
    assert proposal.attempts == 1
    assert proposal.confidence == 0.85
    assert proposal.model_used == "deepseek-coder:6.7b"
    assert [e.stage for e in proposal.audit] == ["fix", "evaluate"]
    assert proposal.audit[1].model == "haiku"


def test_low_confidence_escalates_through_sonnet(cfg):
    clients = _clients(
        classify_responses=['{"category": "simple", "reasoning": "x"}'],
        eval_responses=[
            '{"confidence": 0.2, "reasoning": "risky"}',   # scoring DeepSeek's fix
            '{"confidence": 0.9, "reasoning": "solid"}',   # scoring Sonnet's fix
        ],
    )
    proposal = analyzer.analyze_finding(FINDING, "x", "r", "c", clients, cfg)
    assert proposal.attempts == 2
    assert proposal.model_used == "sonnet"
    assert proposal.confidence == 0.9
    assert [e.stage for e in proposal.audit] == ["fix", "evaluate", "classify", "fix", "evaluate"]
    assert proposal.audit[0].model == "deepseek-coder:6.7b"


def test_spurious_classification_short_circuits(cfg):
    clients = _clients(
        classify_responses=['{"category": "spurious", "reasoning": "x"}'],
        eval_responses=['{"confidence": 0.2, "reasoning": "risky"}'],
    )
    proposal = analyzer.analyze_finding(FINDING, "x", "r", "c", clients, cfg)
    assert proposal.attempts == 2
    assert proposal.fixed_content == ""
    assert "spurious" in (proposal.rationale or "")


def test_opus_only_reached_as_last_resort(cfg):
    clients = _clients(
        classify_responses=['{"category": "complex", "reasoning": "x"}'],
        eval_responses=[
            '{"confidence": 0.1, "reasoning": "weak"}',   # DeepSeek's fix
            '{"confidence": 0.3, "reasoning": "weak"}',   # Sonnet's fix
            '{"confidence": 0.9, "reasoning": "solid"}',  # Opus's fix
        ],
    )
    proposal = analyzer.analyze_finding(FINDING, "x", "r", "c", clients, cfg)
    assert proposal.attempts == 3
    assert proposal.model_used == "opus"
    assert proposal.confidence == 0.9
    # CLAUDE.md rule: Opus never called before 3rd attempt.
    opus_entries = [e for e in proposal.audit if e.model == "opus"]
    assert len(opus_entries) == 1
    assert opus_entries[0].attempt == 3


def test_every_call_has_full_audit_metadata(cfg):
    clients = _clients(
        classify_responses=['{"category": "complex"}'],
        eval_responses=[
            '{"confidence": 0.2}',
            '{"confidence": 0.9}',
        ],
    )
    proposal = analyzer.analyze_finding(FINDING, "x", "r", "c", clients, cfg)
    for entry in proposal.audit:
        assert entry.model
        assert entry.stage in ("fix", "classify", "evaluate")
        assert entry.tokens_in >= 0
        assert entry.tokens_out >= 0
        assert entry.latency_ms >= 0


def test_confidence_scoring_always_goes_through_haiku_not_self_report(cfg):
    """Regression test for the bug where should_escalate() was fed
    confidence.extract_score() run on the fix-generating model's own
    response — which fix_single_file.j2's 'no explanation' instruction
    guarantees is always None, so every finding escalated to Opus in
    practice regardless of fix quality. Embedding a fake confidence marker
    directly in the DeepSeek/Sonnet/Opus response text must have zero effect
    now; only Haiku's evaluate-stage response should matter."""
    clients = _clients(
        deepseek_text="CONFIDENCE: 0.99 — but this text is never parsed for scoring",
        eval_responses=['{"confidence": 0.85, "reasoning": "correct"}'],
    )
    proposal = analyzer.analyze_finding(FINDING, "x", "r", "c", clients, cfg)
    assert proposal.attempts == 1
    assert proposal.confidence == 0.85  # from Haiku's eval, not the 0.99 in the fix text


def test_last_resort_none_in_config_prevents_opus_even_at_final_attempt(cfg):
    """Regression test: model_balancing.yml's per-task last_resort field was
    declared but never read — Opus was reachable purely off the global
    escalation.max_attempts/opus_min_attempt counters regardless of whether
    a task's YAML entry authorized it. Stop at Sonnet's result when the task
    config doesn't declare a last_resort model, even though escalation
    counters alone would allow a 3rd attempt."""
    import dataclasses

    cfg_no_opus = dataclasses.replace(
        cfg, tasks={**cfg.tasks, "single_file_fix": dataclasses.replace(
            cfg.tasks["single_file_fix"], last_resort=None,
        )},
    )
    clients = _clients(
        classify_responses=['{"category": "complex"}'],
        eval_responses=[
            '{"confidence": 0.1, "reasoning": "weak"}',  # DeepSeek's fix — escalate
            '{"confidence": 0.2, "reasoning": "weak"}',  # Sonnet's fix — still low
        ],
    )
    proposal = analyzer.analyze_finding(FINDING, "x", "r", "c", clients, cfg_no_opus)
    assert proposal.attempts == 2
    assert proposal.model_used == "sonnet"
    assert proposal.error == "max_attempts below opus_min"
    opus_entries = [e for e in proposal.audit if e.model == "opus"]
    assert opus_entries == []


def test_file_content_truncated_against_max_tokens_in_budget(cfg):
    """Regression test: CLAUDE.md's token-budget table ('Single-file fix: max
    3000 in / 1000 out') was documentation only — nothing truncated
    file_contents before embedding it whole in the prompt, so a large file
    could blow past the intended budget with no guard. single_file_fix's
    max_tokens_in is 3000 in the real config (~12000 chars at the 4
    chars/token heuristic)."""
    captured_prompts = []

    class RecordingClient:
        model = "deepseek-coder:6.7b"
        name = "ollama"

        def complete(self, prompt, max_tokens, temperature=0.2):
            captured_prompts.append(prompt)
            return LLMResponse(text="fixed", model=self.model, tokens_in=1, tokens_out=1, latency_ms=1)

    clients = analyzer.ClientSet(
        deepseek=RecordingClient(),
        haiku=QueuedHaikuClient(eval_responses=['{"confidence": 0.9}']),
        sonnet=ScriptedClient("anthropic", "sonnet", "unused"),
        opus=ScriptedClient("anthropic", "opus", "unused"),
    )

    huge_file = "x = 1\n" * 5000  # ~30,000 chars, well past the 3000-token budget
    analyzer.analyze_finding(FINDING, huge_file, "r", "c", clients, cfg)

    assert len(captured_prompts[0]) < len(huge_file)
    assert "truncated to fit token budget" in captured_prompts[0]


def test_offline_mode_stops_at_tier_1_without_any_haiku_call(cfg, monkeypatch):
    """Paper §III.D: an 'offline' switch forces the cascade to terminate at
    tier 1, sacrificing fix quality for strict data confinement. Confidence
    scoring is a Haiku (paid, Anthropic API) call, so offline mode must skip
    it entirely, not just skip Sonnet/Opus — otherwise 'never leaves tier 1'
    would be false the moment a low-confidence fix needs scoring."""
    monkeypatch.setenv(analyzer.OFFLINE_ENV_VAR, "1")

    class ExplodingHaiku:
        def complete(self, *a, **k):
            raise AssertionError("offline mode must never call a paid tier")

    clients = analyzer.ClientSet(
        deepseek=ScriptedClient("ollama", "deepseek-coder:6.7b", "--- a/x\n+++ b/x\n+fixed"),
        haiku=ExplodingHaiku(),
        sonnet=ExplodingHaiku(),
        opus=ExplodingHaiku(),
    )
    proposal = analyzer.analyze_finding(FINDING, "x", "r", "c", clients, cfg)
    assert proposal.attempts == 1
    assert proposal.model_used == "deepseek-coder:6.7b"
    assert "offline mode" in (proposal.rationale or "")
    assert [e.stage for e in proposal.audit] == ["fix"]


def test_offline_mode_off_by_default(cfg, monkeypatch):
    monkeypatch.delenv(analyzer.OFFLINE_ENV_VAR, raising=False)
    assert analyzer.is_offline_mode() is False


def test_language_detection_in_prompt():
    assert analyzer._language_for("app/main.py") == "python"
    assert analyzer._language_for("x.ts") == "typescript"
    assert analyzer._language_for("y.go") == "go"
    assert analyzer._language_for("unknown") == ""
