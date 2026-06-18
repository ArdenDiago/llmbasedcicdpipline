from pathlib import Path

import pytest

from agent.pr import committer


def _git(repo: Path, *args: str) -> None:
    import subprocess
    subprocess.run(
        ["git", *args], cwd=str(repo), check=True, capture_output=True, text=True,
    )


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    _git(tmp_path, "init", "-q", "-b", "main")
    _git(tmp_path, "config", "user.email", "t@t")
    _git(tmp_path, "config", "user.name", "t")
    (tmp_path / "a.txt").write_text("hello\n")
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-q", "-m", "init")
    return tmp_path


def test_create_branch_rejects_main(repo: Path):
    with pytest.raises(committer.CommitError):
        committer.create_branch(repo, "main")


def test_push_rejects_master(repo: Path):
    with pytest.raises(committer.CommitError):
        committer.push(repo, "master")


def test_apply_patch_rejects_empty(repo: Path):
    with pytest.raises(committer.CommitError):
        committer.apply_patch(repo, "   \n")


def test_create_branch_and_commit_flow(repo: Path):
    committer.create_branch(repo, "fix/test-1")
    (repo / "a.txt").write_text("hello world\n")
    sha = committer.commit_all(repo, "fix: update a.txt")
    assert len(sha) == 40


def test_commit_message_format():
    msg = committer.commit_message(
        {"scanner": "bandit", "rule_id": "B105", "severity": "high", "file": "a.py"},
        confidence=0.82,
        model_used="deepseek-coder:6.7b",
    )
    assert msg.startswith("fix(bandit): B105 in a.py")
    assert "Severity: high" in msg
    assert "Confidence: 0.82" in msg
    assert "Model: deepseek-coder:6.7b" in msg


def test_apply_patch_applies_unified_diff(repo: Path):
    committer.create_branch(repo, "fix/test-2")
    diff = (
        "diff --git a/a.txt b/a.txt\n"
        "--- a/a.txt\n"
        "+++ b/a.txt\n"
        "@@ -1 +1 @@\n"
        "-hello\n"
        "+hello world\n"
    )
    committer.apply_patch(repo, diff)
    assert (repo / "a.txt").read_text() == "hello world\n"


def test_apply_patch_surfaces_git_error(repo: Path):
    bogus = (
        "diff --git a/missing.txt b/missing.txt\n"
        "--- a/missing.txt\n"
        "+++ b/missing.txt\n"
        "@@ -1 +1 @@\n"
        "-x\n"
        "+y\n"
    )
    with pytest.raises(committer.CommitError):
        committer.apply_patch(repo, bogus)
