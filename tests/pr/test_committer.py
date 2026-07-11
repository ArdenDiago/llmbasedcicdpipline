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


def test_write_full_file_rejects_empty_content(repo: Path):
    with pytest.raises(committer.CommitError):
        committer.write_full_file(repo, "a.txt", "   \n")


def test_write_full_file_rejects_content_that_is_blank_only_after_fence_stripping(repo: Path):
    """Regression test: a degenerate fenced response like '```python\\n\\n```'
    is non-blank as raw text (the backticks alone are non-whitespace), so a
    blank check against the RAW response before fence-stripping misses this
    case entirely. _strip_fences() reduces it to "", and ast.parse("") is
    valid Python (an empty module), so the .py syntax gate doesn't catch it
    either — without this check, the target file gets silently overwritten
    to empty with no exception raised at all."""
    with pytest.raises(committer.CommitError, match="empty fix content"):
        committer.write_full_file(repo, "a.txt", "```python\n\n```")
    with pytest.raises(committer.CommitError, match="empty fix content"):
        committer.write_full_file(repo, "a.txt", "```python\n   \n```")
    # the original content must survive — never silently emptied
    assert (repo / "a.txt").read_text() == "hello\n"


def test_write_full_file_rejects_empty_target_path(repo: Path):
    with pytest.raises(committer.CommitError):
        committer.write_full_file(repo, "", "hello world\n")


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


def test_write_full_file_overwrites_target(repo: Path):
    """fix_single_file.j2 instructs the model to return the entire
    corrected file, not a unified diff — this is the corrected 'apply'
    operation a CRITICAL bug used to implement as `git apply` instead."""
    committer.create_branch(repo, "fix/test-2")
    committer.write_full_file(repo, "a.txt", "hello world\n")
    # _strip_fences() strips surrounding whitespace (matching
    # evaluation/patcher.py's identical convention for LLM output quirks),
    # so a lone trailing newline is not preserved.
    assert (repo / "a.txt").read_text() == "hello world"


def test_write_full_file_strips_code_fence(repo: Path):
    """Models sometimes wrap the 'ONLY the corrected file content'
    response in a ```lang fence anyway despite being told not to explain."""
    committer.create_branch(repo, "fix/test-fence")
    fenced = "```python\nhello world\n```"
    committer.write_full_file(repo, "a.txt", fenced)
    assert (repo / "a.txt").read_text() == "hello world"


def test_write_full_file_rejects_invalid_python_syntax(repo: Path):
    """Regression test: the live agent's PR gate re-runs only the target
    repo's own test suite, which returns pass unconditionally when no test
    suite is discoverable (agent/sandbox/manager.py's
    _is_no_test_suite_error branch) — so without this check, a repo with no
    tests would get zero validation of any kind before a syntactically
    broken .py fix reached a PR. Mirrors evaluation/patcher.py::_validate's
    ast.parse check, applied at the point the fix is actually written."""
    (repo / "broken.py").write_text("def f(:\n")
    committer.create_branch(repo, "fix/bad-syntax")
    with pytest.raises(committer.CommitError, match="does not parse"):
        committer.write_full_file(repo, "broken.py", "def f(:\n    pass\n")


def test_write_full_file_accepts_valid_python_syntax(repo: Path):
    (repo / "ok.py").write_text("def f():\n    return 1\n")
    committer.create_branch(repo, "fix/good-syntax")
    committer.write_full_file(repo, "ok.py", "def f():\n    return 2\n")
    assert "return 2" in (repo / "ok.py").read_text()


def test_write_full_file_does_not_syntax_check_non_python_targets(repo: Path):
    """Only .py targets get the ast.parse gate — matching the paper's and
    evaluation/patcher.py's scope (Python-only static syntax check)."""
    committer.create_branch(repo, "fix/txt-target")
    committer.write_full_file(repo, "a.txt", "this is not python at all (((\n")
    assert "not python" in (repo / "a.txt").read_text()


def test_write_full_file_rejects_missing_target(repo: Path):
    with pytest.raises(committer.CommitError):
        committer.write_full_file(repo, "missing.txt", "y\n")


def test_write_full_file_rejects_path_escaping_repo(repo: Path):
    with pytest.raises(committer.CommitError):
        committer.write_full_file(repo, "../../etc/passwd", "malicious\n")
