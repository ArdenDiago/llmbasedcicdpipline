import subprocess
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
    calls = {"apply": 0, "create_branch": 0, "commit": 0, "push": 0, "pr": 0, "reset": 0}

    def fake_reset(path, base_branch):
        calls["reset"] += 1

    def fake_create_branch(path, branch, base="HEAD"):
        calls["create_branch"] += 1

    def fake_apply(path, diff):
        calls["apply"] += 1

    def fake_commit(path, msg):
        calls["commit"] += 1
        return "sha"

    def fake_push(path, branch, remote="origin"):
        calls["push"] += 1

    monkeypatch.setattr(creator.committer, "reset_to_base", fake_reset)
    monkeypatch.setattr(creator.committer, "create_branch", fake_create_branch)
    monkeypatch.setattr(creator.committer, "apply_patch", fake_apply)
    monkeypatch.setattr(creator.committer, "commit_all", fake_commit)
    monkeypatch.setattr(creator.committer, "push", fake_push)

    client = MagicMock()
    req = _req(tmp_path, finding)
    result = creator.create_pr(req, validate=lambda _: False, client=client)

    assert result.created is False
    assert result.skipped_reason == "validation tests failed"
    assert calls["reset"] == 1
    assert calls["apply"] == 1
    assert calls["commit"] == 0
    assert calls["push"] == 0
    client.get_repo.assert_not_called()


def test_happy_path_creates_pr(tmp_path: Path, finding: dict, monkeypatch):
    monkeypatch.setattr(creator.committer, "reset_to_base", lambda *a, **k: None)
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

    monkeypatch.setattr(creator.committer, "reset_to_base", lambda *a, **k: None)
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


def _git(cmd: list[str], cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *cmd], cwd=str(cwd), capture_output=True, text=True, check=True)


def _init_real_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(["init", "-q", "-b", "main"], repo)
    _git(["config", "user.email", "test@example.com"], repo)
    _git(["config", "user.name", "Test"], repo)
    (repo / "x.py").write_text("a = 1\n", encoding="utf-8")
    (repo / "y.py").write_text("b = 1\n", encoding="utf-8")
    _git(["add", "-A"], repo)
    _git(["commit", "-q", "-m", "initial"], repo)
    return repo


def test_working_tree_isolated_across_sequential_findings_real_git(tmp_path: Path, monkeypatch):
    """Regression test for the CRITICAL finding that create_pr() shared one
    working tree across findings with no cleanup on validation failure: a
    patch that applied-but-failed-validation for finding #1 must not leak
    into finding #2's branch/PR when processed against the same repo_path,
    the way pipeline.run() does for every finding in a batch. Uses a real
    git repo (no committer mocks) to actually exercise the working-tree
    interaction, which the mocked tests above can't."""
    repo = _init_real_repo(tmp_path)
    # No remote is configured for this local-only repo — push is exercised
    # separately by test_committer.py; stub it here so we can focus on the
    # working-tree isolation this test targets.
    monkeypatch.setattr(creator.committer, "push", lambda *a, **k: None)

    finding1 = {"scanner": "bandit", "rule_id": "B1", "severity": "high", "file": "x.py", "line": 1}
    finding2 = {"scanner": "bandit", "rule_id": "B2", "severity": "high", "file": "y.py", "line": 1}

    diff1 = (
        "diff --git a/x.py b/x.py\n--- a/x.py\n+++ b/x.py\n"
        "@@ -1 +1 @@\n-a = 1\n+a = 2  # finding1 leftover\n"
    )
    diff2 = (
        "diff --git a/y.py b/y.py\n--- a/y.py\n+++ b/y.py\n"
        "@@ -1 +1 @@\n-b = 1\n+b = 2  # finding2 fix\n"
    )

    req1 = creator.PRRequest(
        finding=finding1, diff=diff1, confidence=0.8, model_used="deepseek",
        repo_path=repo, repo_full_name="owner/repo", base_branch="main",
        commit_sha="sha1", pr_body="body1",
    )
    result1 = creator.create_pr(req1, validate=lambda _: False, client=MagicMock())
    assert result1.created is False
    assert result1.skipped_reason == "validation tests failed"
    # finding #1's patch is applied-but-uncommitted on disk at this point —
    # exactly the state that used to leak into the next finding.
    assert "finding1 leftover" in (repo / "x.py").read_text()

    created_prs = []

    def fake_create_pull_request(**kw):
        created_prs.append(kw)
        return github_api.PullRequestRef(number=1, html_url="u", head=kw["head"], base=kw["base"])

    import agent.pr.creator as creator_mod
    orig = creator_mod.github_api.create_pull_request
    creator_mod.github_api.create_pull_request = fake_create_pull_request
    try:
        req2 = creator.PRRequest(
            finding=finding2, diff=diff2, confidence=0.9, model_used="deepseek",
            repo_path=repo, repo_full_name="owner/repo", base_branch="main",
            commit_sha="sha2", pr_body="body2",
        )
        result2 = creator.create_pr(req2, validate=lambda _: True, client=MagicMock())
    finally:
        creator_mod.github_api.create_pull_request = orig

    assert result2.created is True
    # The committed diff on finding #2's branch must contain ONLY finding
    # #2's change — not finding #1's leftover, uncommitted "a = 2" edit.
    committed_diff = _git(["show", result2.branch, "--", "x.py", "y.py"], repo).stdout
    assert "finding2 fix" in committed_diff
    assert "finding1 leftover" not in committed_diff
    # And x.py on the new branch must match the original commit exactly.
    x_on_branch = _git(["show", f"{result2.branch}:x.py"], repo).stdout
    assert x_on_branch == "a = 1\n"
