from pathlib import Path
from unittest.mock import MagicMock

import pytest

from agent.pr import creator, github_api


@pytest.fixture
def finding():
    return {
        "scanner": "bandit",
        "rule_id": "B105",
        "severity": "high",
        "file": "app/auth.py",
        "line": 45,
        "cwe": "CWE-259",
        "message": "Possible hardcoded password",
    }


def _req(tmp_path: Path, finding: dict, diff: str = "diff --git a/x b/x\n") -> creator.PRRequest:
    return creator.PRRequest(
        finding=finding,
        diff=diff,
        confidence=0.82,
        model_used="deepseek-coder:6.7b",
        repo_path=tmp_path,
        repo_full_name="owner/repo",
        base_branch="main",
        commit_sha="deadbeef",
        pr_body="## Automated Security Fix\n\nbody",
    )


def test_empty_diff_skips(tmp_path: Path, finding: dict):
    req = _req(tmp_path, finding, diff="   \n")
    result = creator.create_pr(req, validate=lambda _: True, client=MagicMock())
    assert result.created is False
    assert result.skipped_reason == "empty diff"


def test_failing_validation_aborts(tmp_path: Path, finding: dict, monkeypatch):
    calls = {"apply": 0, "create_branch": 0, "commit": 0, "push": 0, "pr": 0}

    def fake_create_branch(path, branch, base="HEAD"):
        calls["create_branch"] += 1

    def fake_apply(path, diff):
        calls["apply"] += 1

    def fake_commit(path, msg):
        calls["commit"] += 1
        return "sha"

    def fake_push(path, branch, remote="origin"):
        calls["push"] += 1

    monkeypatch.setattr(creator.committer, "create_branch", fake_create_branch)
    monkeypatch.setattr(creator.committer, "apply_patch", fake_apply)
    monkeypatch.setattr(creator.committer, "commit_all", fake_commit)
    monkeypatch.setattr(creator.committer, "push", fake_push)

    client = MagicMock()
    req = _req(tmp_path, finding)
    result = creator.create_pr(req, validate=lambda _: False, client=client)

    assert result.created is False
    assert result.skipped_reason == "validation tests failed"
    assert calls["apply"] == 1
    assert calls["commit"] == 0
    assert calls["push"] == 0
    client.get_repo.assert_not_called()


def test_happy_path_creates_pr(tmp_path: Path, finding: dict, monkeypatch):
    monkeypatch.setattr(creator.committer, "create_branch", lambda *a, **k: None)
    monkeypatch.setattr(creator.committer, "apply_patch", lambda *a, **k: None)
    monkeypatch.setattr(creator.committer, "commit_all", lambda *a, **k: "sha123")
    monkeypatch.setattr(creator.committer, "push", lambda *a, **k: None)

    ref = github_api.PullRequestRef(number=11, html_url="u", head="h", base="main")
    monkeypatch.setattr(
        creator.github_api, "create_pull_request", lambda **kw: ref,
    )

    client = MagicMock()
    req = _req(tmp_path, finding)
    result = creator.create_pr(req, validate=lambda _: True, client=client)

    assert result.created is True
    assert result.pr is ref
    assert result.branch.startswith("fix/bandit-b105-")


def test_title_and_labels(tmp_path: Path, finding: dict, monkeypatch):
    captured = {}

    def fake_create_pr(**kw):
        captured.update(kw)
        return github_api.PullRequestRef(number=1, html_url="u", head=kw["head"], base=kw["base"])

    monkeypatch.setattr(creator.committer, "create_branch", lambda *a, **k: None)
    monkeypatch.setattr(creator.committer, "apply_patch", lambda *a, **k: None)
    monkeypatch.setattr(creator.committer, "commit_all", lambda *a, **k: "sha")
    monkeypatch.setattr(creator.committer, "push", lambda *a, **k: None)
    monkeypatch.setattr(creator.github_api, "create_pull_request", fake_create_pr)

    req = _req(tmp_path, finding)
    creator.create_pr(req, validate=lambda _: True, client=MagicMock())

    assert captured["title"].startswith("fix(bandit):")
    assert captured["labels"] == ["automated-fix", "security", "high"]
    assert captured["base"] == "main"
    assert captured["head"].startswith("fix/bandit-b105-")
