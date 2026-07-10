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


def _fix(fixed_content: str = "print('fixed')\n", error: str | None = None) -> analyzer.FixProposal:
    return analyzer.FixProposal(
        fixed_content=fixed_content,
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


def test_base_branch_defaults_to_dispatch_branch_not_main(tmp_path: Path, clients, monkeypatch):
    """Regression test: base_branch used to be hardcoded to 'main' regardless
    of which branch was actually pushed and scanned. A fix generated against
    a non-main branch's file content must be committed against that same
    branch's tip, or the fix gets applied to the wrong version of the file."""
    findings = [{"scanner": "bandit", "rule_id": "B1", "severity": "high", "file": "a.py"}]
    monkeypatch.setattr(analyzer, "analyze_finding", lambda **kw: _fix())

    captured_base_branches = []

    def fake_create_pr(req, validate, client=None):
        captured_base_branches.append(req.base_branch)
        return creator.PRResult(created=True, branch="b", pr=None)

    monkeypatch.setattr(creator, "create_pr", fake_create_pr)

    envelope = {
        "dispatch": {
            "repo_full_name": "owner/repo",
            "commit_sha": "deadbeef",
            "branch": "feature/some-branch",
        },
        "scanners": {"findings": findings},
    }

    pipeline.run(
        envelope=envelope, repo_path=tmp_path,
        clients=clients, config=_config(),
        validate=lambda _: True, github_client=MagicMock(),
        file_reader=lambda p, r: "src", pr_body=lambda f, fix: "body",
    )

    assert captured_base_branches == ["feature/some-branch"]


def test_default_pr_body_calls_haiku_instead_of_returning_raw_prompt(
    tmp_path: Path, monkeypatch,
):
    """Regression test: pr_body.j2 is an LLM *prompt* ("Generate a concise
    pull request description...", ending with a format template using
    literal placeholders like {scanner}/{one paragraph} for the model to
    fill in) — not a Jinja2 output template. A prior bug rendered the
    template and used the raw, unfilled-placeholder prompt text directly as
    the PR body, without ever calling an LLM, despite CLAUDE.md documenting
    PR body generation as a Haiku task. This confirms the default path
    actually calls Haiku and uses its response, not the raw prompt."""
    finding = {
        "scanner": "bandit", "rule_id": "B1", "severity": "high",
        "file": "a.py", "cwe": "CWE-798", "message": "hardcoded credential",
    }
    monkeypatch.setattr(analyzer, "analyze_finding", lambda **kw: _fix())

    haiku_calls = []

    class FakeHaiku:
        def complete(self, prompt, max_tokens, temperature=0.2):
            haiku_calls.append(prompt)
            return analyzer.LLMResponse(
                text="## Automated Security Fix\n\nA real Haiku-written body.",
                model="haiku", tokens_in=10, tokens_out=10, latency_ms=1,
            )

    clients_with_real_haiku = analyzer.ClientSet(
        deepseek=MagicMock(), haiku=FakeHaiku(), sonnet=MagicMock(), opus=MagicMock(),
    )

    captured_bodies = []

    def fake_create_pr(req, validate, client=None):
        captured_bodies.append(req.pr_body)
        return creator.PRResult(created=True, branch="b", pr=None)

    monkeypatch.setattr(creator, "create_pr", fake_create_pr)

    pipeline.run(
        envelope=_envelope([finding]), repo_path=tmp_path,
        clients=clients_with_real_haiku, config=_config(),
        validate=lambda _: True, github_client=MagicMock(),
        file_reader=lambda p, r: "src",
        # pr_body intentionally omitted — exercising the default path.
    )

    assert len(haiku_calls) == 1
    assert "pull request description" in haiku_calls[0]  # the actual prompt was sent
    assert captured_bodies == ["## Automated Security Fix\n\nA real Haiku-written body."]
    # The raw prompt's own instruction text / unfilled placeholders must
    # never appear in the final body.
    assert "Generate a concise pull request description" not in captured_bodies[0]
    assert "{one paragraph}" not in captured_bodies[0]


def test_explicit_base_branch_overrides_dispatch_branch(tmp_path: Path, clients, monkeypatch):
    findings = [{"scanner": "bandit", "rule_id": "B1", "severity": "high", "file": "a.py"}]
    monkeypatch.setattr(analyzer, "analyze_finding", lambda **kw: _fix())

    captured_base_branches = []

    def fake_create_pr(req, validate, client=None):
        captured_base_branches.append(req.base_branch)
        return creator.PRResult(created=True, branch="b", pr=None)

    monkeypatch.setattr(creator, "create_pr", fake_create_pr)

    envelope = {
        "dispatch": {
            "repo_full_name": "owner/repo",
            "commit_sha": "deadbeef",
            "branch": "feature/some-branch",
        },
        "scanners": {"findings": findings},
    }

    pipeline.run(
        envelope=envelope, repo_path=tmp_path,
        clients=clients, config=_config(),
        validate=lambda _: True, github_client=MagicMock(),
        file_reader=lambda p, r: "src", pr_body=lambda f, fix: "body",
        base_branch="release",
    )

    assert captured_base_branches == ["release"]


def test_create_pr_failure_does_not_abort_rest_of_batch(tmp_path: Path, clients, monkeypatch):
    """Regression test: create_pr() does real git/GitHub I/O against a
    repo_path shared across every finding in this loop. Before the fix, an
    uncaught CommitError (e.g. a push conflict) from finding #1 would
    propagate out of pipeline.run() entirely, silently dropping every
    remaining finding in the batch instead of just skipping the one that
    failed."""
    findings = [
        {"scanner": "bandit", "rule_id": "B1", "severity": "high", "file": "a.py"},
        {"scanner": "semgrep", "rule_id": "S1", "severity": "critical", "file": "b.py"},
    ]
    monkeypatch.setattr(analyzer, "analyze_finding", lambda **kw: _fix())

    calls = []

    def flaky_create_pr(req, validate, client=None):
        calls.append(req.finding["rule_id"])
        if req.finding["rule_id"] == "B1":
            raise creator.committer.CommitError("git push -u origin fix/x failed (128): non-fast-forward")
        return creator.PRResult(
            created=True, branch="b", pr=github_api.PullRequestRef(len(calls), "u", "b", "main"),
        )

    monkeypatch.setattr(creator, "create_pr", flaky_create_pr)

    res = pipeline.run(
        envelope=_envelope(findings), repo_path=tmp_path,
        clients=clients, config=_config(),
        validate=lambda _: True, github_client=MagicMock(),
        file_reader=lambda p, r: "src", pr_body=lambda f, fix: "body",
    )

    assert calls == ["B1", "S1"]  # both attempted despite B1's failure
    assert res.processed == 2
    assert res.summary()["created"] == 1  # only S1 succeeded
    assert any(s["reason"].startswith("create_pr error") for s in res.skipped)


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
