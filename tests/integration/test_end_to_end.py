"""End-to-end: scanner fixtures → normalize → pipeline → PR request shape.

Exercises the real prompts.render('pr_body') template, the real branch-name
generator, and the real severity-filter in pipeline — only the LLM clients
and the PyGitHub client + git subprocess calls are stubbed.
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from agent import pipeline
from agent.llm import analyzer
from agent.llm.clients.base import LLMResponse
from agent.llm.config import BalancingConfig, EscalationConfig, TaskConfig
from agent.pr import creator, github_api
from agent.security import normalize
from agent.security.scanners import bandit, semgrep

FIXTURES = Path(__file__).parent.parent / "security" / "fixtures"


def _config() -> BalancingConfig:
    return BalancingConfig(
        models={},
        tasks={
            "single_file_fix": TaskConfig(
                name="single_file_fix", primary="deepseek_coder",
                fallback="sonnet", last_resort=None,
                max_tokens_in=3000, max_tokens_out=1000,
            ),
            "error_classification": TaskConfig(
                name="error_classification", primary="deepseek_coder",
                fallback="haiku", last_resort=None,
                max_tokens_in=500, max_tokens_out=100,
            ),
            "confidence_eval": TaskConfig(
                name="confidence_eval", primary="haiku",
                fallback=None, last_resort=None,
                max_tokens_in=2000, max_tokens_out=150,
            ),
        },
        escalation=EscalationConfig(
            confidence_threshold=0.5, max_attempts=3, opus_min_attempt=3,
        ),
    )


class _FakeLLM:
    def __init__(self, name: str, text: str):
        self.name = name
        self._text = text

    def complete(self, prompt, max_tokens, temperature=0.2):
        return LLMResponse(
            text=self._text, model=self.name,
            tokens_in=len(prompt) // 4, tokens_out=len(self._text) // 4,
            latency_ms=42,
        )


class _FakeHaiku:
    """Haiku is called for two different templates (classify_error.j2 and
    confidence_eval.j2) — route by a substring unique to each so a high
    confidence_eval score can stop escalation at attempt 1, matching what a
    real independent evaluator would do."""

    def __init__(self, classify_text: str, eval_text: str):
        self._classify_text = classify_text
        self._eval_text = eval_text

    def complete(self, prompt, max_tokens, temperature=0.2):
        if "evaluating the quality" in prompt:
            text = self._eval_text
        elif "code error classifier" in prompt:
            text = self._classify_text
        else:
            raise AssertionError(f"unrecognized Haiku prompt: {prompt[:80]!r}")
        return LLMResponse(
            text=text, model="haiku",
            tokens_in=len(prompt) // 4, tokens_out=len(text) // 4,
            latency_ms=42,
        )


def _build_envelope() -> dict:
    bandit_findings, _ = bandit.parse((FIXTURES / "bandit.json").read_text())
    semgrep_findings, _ = semgrep.parse((FIXTURES / "semgrep.json").read_text())
    merged = normalize.dedupe(bandit_findings + semgrep_findings)
    return {
        "dispatch": {
            "repo_full_name": "acme/service",
            "branch": "main",
            "commit_sha": "abc123def456",
            "pusher": "octocat",
        },
        "scanners": {
            "target": "/tmp/clone",
            "findings": [f.to_dict() for f in merged],
            "errors": [],
        },
    }


def test_full_pipeline_creates_one_pr_per_high_severity_finding(tmp_path: Path, monkeypatch):
    envelope = _build_envelope()

    # Stub git + GitHub so we don't hit disk or the network, but keep branch
    # naming, PR body rendering, and severity filtering real.
    monkeypatch.setattr(creator.committer, "reset_to_base", lambda *a, **k: None)
    monkeypatch.setattr(creator.committer, "create_branch", lambda *a, **k: None)
    monkeypatch.setattr(creator.committer, "apply_patch", lambda *a, **k: None)
    monkeypatch.setattr(creator.committer, "commit_all", lambda *a, **k: "sha123")
    monkeypatch.setattr(creator.committer, "push", lambda *a, **k: None)

    created_prs: list[dict] = []

    def fake_create_pr(**kw):
        created_prs.append(kw)
        return github_api.PullRequestRef(
            number=len(created_prs), html_url=f"https://x/pr/{len(created_prs)}",
            head=kw["head"], base=kw["base"],
        )

    monkeypatch.setattr(creator.github_api, "create_pull_request", fake_create_pr)

    fix_text = "diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -1 +1 @@\n-bad\n+good\n"
    clients = analyzer.ClientSet(
        deepseek=_FakeLLM("deepseek-coder:6.7b", fix_text),
        haiku=_FakeHaiku(
            classify_text='{"category": "simple"}',
            eval_text='{"confidence": 0.82, "reasoning": "looks correct"}',
        ),
        sonnet=_FakeLLM("sonnet", fix_text),
        opus=_FakeLLM("opus", fix_text),
    )

    result = pipeline.run(
        envelope=envelope,
        repo_path=tmp_path,
        clients=clients,
        config=_config(),
        validate=lambda _: True,
        github_client=MagicMock(),
        file_reader=lambda p, rel: f"// contents of {rel}\n",
        min_severity="medium",
    )

    # Fixtures contain: B105 (low, skipped), B301 (high), semgrep eval (high/error),
    # semgrep debug (medium/warning). All three medium+ should produce PRs.
    assert result.summary()["created"] == 3
    assert result.summary()["skipped"] >= 1  # B105 low

    titles = [pr["title"] for pr in created_prs]
    assert any(t.startswith("fix(bandit): B301") for t in titles)
    assert any("python.lang.security.audit.eval-detected" in t for t in titles)

    for pr in created_prs:
        assert pr["head"].startswith("fix/")
        assert pr["base"] == "main"
        assert "automated-fix" in pr["labels"]
        assert "security" in pr["labels"]
        assert "## Automated Security Fix" in pr["body"]
        assert "Confidence" in pr["body"]


def test_full_pipeline_respects_failing_validation(tmp_path: Path, monkeypatch):
    envelope = _build_envelope()

    monkeypatch.setattr(creator.committer, "reset_to_base", lambda *a, **k: None)
    monkeypatch.setattr(creator.committer, "create_branch", lambda *a, **k: None)
    monkeypatch.setattr(creator.committer, "apply_patch", lambda *a, **k: None)
    committed = []
    pushed = []
    monkeypatch.setattr(
        creator.committer, "commit_all",
        lambda *a, **k: committed.append(1) or "sha",
    )
    monkeypatch.setattr(
        creator.committer, "push",
        lambda *a, **k: pushed.append(1),
    )
    created = []
    monkeypatch.setattr(
        creator.github_api, "create_pull_request",
        lambda **kw: created.append(kw) or github_api.PullRequestRef(1, "u", "h", "main"),
    )

    clients = analyzer.ClientSet(
        deepseek=_FakeLLM(
            "deepseek", "diff --git a/x b/x\n--- a/x\n+++ b/x\n@@\n-x\n+y\n",
        ),
        haiku=_FakeHaiku(
            classify_text='{"category": "simple"}',
            eval_text='{"confidence": 0.9, "reasoning": "looks correct"}',
        ),
        sonnet=MagicMock(), opus=MagicMock(),
    )

    result = pipeline.run(
        envelope=envelope,
        repo_path=tmp_path,
        clients=clients,
        config=_config(),
        validate=lambda _: False,  # tests never pass
        github_client=MagicMock(),
        file_reader=lambda p, rel: "src",
        min_severity="medium",
    )

    # All eligible findings were attempted, none committed or pushed, zero PRs.
    assert result.processed >= 3
    assert result.summary()["created"] == 0
    assert committed == []
    assert pushed == []
    assert created == []
    for pr_result in result.created:
        assert pr_result.skipped_reason == "validation tests failed"
