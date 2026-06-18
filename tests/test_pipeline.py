from pathlib import Path
from unittest.mock import MagicMock

import pytest

from agent import pipeline
from agent.llm import analyzer
from agent.llm.config import BalancingConfig, EscalationConfig, TaskConfig
from agent.pr import creator, github_api


def _config() -> BalancingConfig:
    return BalancingConfig(
        models={},
        tasks={"single_file_fix": TaskConfig(
            name="single_file_fix", primary="deepseek_coder",
            fallback="sonnet", last_resort=None,
            max_tokens_in=3000, max_tokens_out=1000,
        )},
        escalation=EscalationConfig(
            confidence_threshold=0.5, max_attempts=3, opus_min_attempt=3,
        ),
    )


def _envelope(findings: list[dict]) -> dict:
    return {
        "dispatch": {
            "repo_full_name": "owner/repo",
            "commit_sha": "deadbeef",
            "branch": "main",
        },
        "scanners": {"findings": findings},
    }


def _fix(diff: str = "diff --git a/x b/x\n", error: str | None = None) -> analyzer.FixProposal:
    return analyzer.FixProposal(
        diff=diff,
        confidence=0.8,
        model_used="deepseek-coder:6.7b",
        attempts=1,
        audit=[],
        error=error,
    )


@pytest.fixture
def clients() -> analyzer.ClientSet:
    return analyzer.ClientSet(
        deepseek=MagicMock(), haiku=MagicMock(),
        sonnet=MagicMock(), opus=MagicMock(),
    )


def test_filters_by_min_severity(tmp_path: Path, clients, monkeypatch):
    findings = [
        {"scanner": "bandit", "rule_id": "B1", "severity": "low", "file": "a.py"},
        {"scanner": "bandit", "rule_id": "B2", "severity": "high", "file": "b.py"},
    ]
    monkeypatch.setattr(pipeline, "default_file_reader", lambda p, r: "src")
    monkeypatch.setattr(analyzer, "analyze_finding", lambda **kw: _fix())
    monkeypatch.setattr(creator, "create_pr", lambda req, validate, client=None: creator.PRResult(
        created=True, branch="b", pr=github_api.PullRequestRef(1, "u", "b", "main"),
    ))

    res = pipeline.run(
        envelope=_envelope(findings),
        repo_path=tmp_path,
        clients=clients,
        config=_config(),
        validate=lambda _: True,
        github_client=MagicMock(),
        file_reader=lambda p, r: "src",
        pr_body=lambda f, fix: "body",
        min_severity="medium",
    )

    assert res.processed == 1
    assert len(res.created) == 1
    assert any(s["reason"] == "below min_severity" for s in res.skipped)


def test_skips_when_analyzer_returns_error(tmp_path: Path, clients, monkeypatch):
    findings = [{"scanner": "bandit", "rule_id": "B2", "severity": "high", "file": "b.py"}]
    monkeypatch.setattr(analyzer, "analyze_finding", lambda **kw: _fix(error="escalation disabled"))

    res = pipeline.run(
        envelope=_envelope(findings), repo_path=tmp_path,
        clients=clients, config=_config(),
        validate=lambda _: True, github_client=MagicMock(),
        file_reader=lambda p, r: "src", pr_body=lambda f, fix: "body",
    )

    assert res.processed == 1
    assert not res.created
    assert res.skipped[0]["reason"] == "escalation disabled"


def test_skips_unreadable_file(tmp_path: Path, clients, monkeypatch):
    findings = [{"scanner": "bandit", "rule_id": "B2", "severity": "high", "file": "missing.py"}]

    def bad_read(p, r):
        raise FileNotFoundError(r)

    res = pipeline.run(
        envelope=_envelope(findings), repo_path=tmp_path,
        clients=clients, config=_config(),
        validate=lambda _: True, github_client=MagicMock(),
        file_reader=bad_read, pr_body=lambda f, fix: "body",
    )

    assert res.processed == 0
    assert "read error" in res.skipped[0]["reason"]


def test_happy_path_creates_one_pr_per_finding(tmp_path: Path, clients, monkeypatch):
    findings = [
        {"scanner": "bandit", "rule_id": "B1", "severity": "high", "file": "a.py"},
        {"scanner": "semgrep", "rule_id": "S1", "severity": "critical", "file": "b.py"},
    ]
    calls = []
    monkeypatch.setattr(analyzer, "analyze_finding", lambda **kw: _fix())

    def fake_create_pr(req, validate, client=None):
        calls.append(req.finding["rule_id"])
        return creator.PRResult(
            created=True, branch="b", pr=github_api.PullRequestRef(len(calls), "u", "b", "main"),
        )

    monkeypatch.setattr(creator, "create_pr", fake_create_pr)

    res = pipeline.run(
        envelope=_envelope(findings), repo_path=tmp_path,
        clients=clients, config=_config(),
        validate=lambda _: True, github_client=MagicMock(),
        file_reader=lambda p, r: "src", pr_body=lambda f, fix: "body",
    )

    assert res.processed == 2
    assert calls == ["B1", "S1"]
    assert res.summary() == {"processed": 2, "created": 2, "skipped": 0}


def test_requires_repo_full_name(tmp_path: Path, clients):
    with pytest.raises(ValueError):
        pipeline.run(
            envelope={"dispatch": {}, "scanners": []},
            repo_path=tmp_path,
            clients=clients, config=_config(),
            validate=lambda _: True,
        )


def test_accepts_scanners_as_list(tmp_path: Path, clients, monkeypatch):
    envelope = {
        "dispatch": {"repo_full_name": "o/r", "commit_sha": "s"},
        "scanners": [
            {"scanner": "bandit", "rule_id": "B1", "severity": "high", "file": "a.py"},
        ],
    }
    monkeypatch.setattr(analyzer, "analyze_finding", lambda **kw: _fix())
    monkeypatch.setattr(creator, "create_pr", lambda *a, **k: creator.PRResult(
        created=True, branch="b", pr=github_api.PullRequestRef(1, "u", "b", "main"),
    ))

    res = pipeline.run(
        envelope=envelope, repo_path=tmp_path,
        clients=clients, config=_config(),
        validate=lambda _: True, github_client=MagicMock(),
        file_reader=lambda p, r: "src", pr_body=lambda f, fix: "body",
    )
    assert res.processed == 1
