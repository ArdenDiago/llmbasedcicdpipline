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


def test_push_raises_branch_already_exists_on_non_fast_forward(tmp_path: Path):
    """Regression test: branch names are deterministic (brancher.branch_name
    hashes file+line+commit_sha), so re-processing the same commit (webhook
    retry, manager restart) reproduces the identical branch name. Pushing a
    diverged version of that branch a second time must raise a distinct,
    catchable error rather than an indistinguishable-from-anything-else
    CommitError, so callers can treat it as "a PR for this finding likely
    already exists" instead of a hard failure."""
    import subprocess

    remote_dir = tmp_path / "remote.git"
    subprocess.run(["git", "init", "-q", "--bare", str(remote_dir)], check=True)

    repo = tmp_path / "repo"
    repo.mkdir()
    for args in (
        ["init", "-q", "-b", "main"],
        ["config", "user.email", "t@t"],
        ["config", "user.name", "t"],
    ):
        subprocess.run(["git", *args], cwd=repo, check=True)
    (repo / "a.txt").write_text("hello\n")
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "init"], cwd=repo, check=True)
    subprocess.run(["git", "remote", "add", "origin", str(remote_dir)], cwd=repo, check=True)

    committer.create_branch(repo, "fix/dup")
    (repo / "a.txt").write_text("first push\n")
    committer.commit_all(repo, "first")
    committer.push(repo, "fix/dup")  # succeeds — branch now exists on the remote

    # Simulate a second, independent run reprocessing the same commit_sha
    # from a fresh checkout: same deterministic branch name, diverged content.
    subprocess.run(["git", "checkout", "main"], cwd=repo, check=True)
    subprocess.run(["git", "branch", "-D", "fix/dup"], cwd=repo, check=True)
    subprocess.run(["git", "checkout", "-b", "fix/dup"], cwd=repo, check=True)
    (repo / "a.txt").write_text("second push, diverged\n")
    committer.commit_all(repo, "second")

    with pytest.raises(committer.BranchAlreadyExistsError):
        committer.push(repo, "fix/dup")


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
