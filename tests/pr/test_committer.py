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


def test_run_raises_commit_error_on_timeout(repo: Path, monkeypatch):
    """Regression test: unlike clone.py's clone_repo() (already bounded),
    committer._run() previously had no timeout at all — a stalled network
    push, or any other hung git subprocess, could block the host
    control-plane process indefinitely instead of failing the one
    finding it's processing."""
    def fake_run(cmd, **kwargs):
        raise committer.subprocess.TimeoutExpired(cmd=cmd, timeout=kwargs.get("timeout"))

    monkeypatch.setattr(committer.subprocess, "run", fake_run)

    with pytest.raises(committer.CommitError, match="timed out"):
        committer._run(["git", "status"], repo, timeout=5)


def test_push_authenticates_via_env_not_argv(repo: Path, monkeypatch):
    """Regression test, three layers deep:
    1. clone.py checks out the repo anonymously (no credential passed to
       `git clone`), and GITHUB_TOKEN was previously read only inside
       github_api.py for the PyGithub REST call that opens the PR — never
       used to authenticate this push, so `git push origin <branch>`
       always failed a credential prompt against any repo requiring write
       access (i.e. every real one), silently swallowed per-finding by
       pipeline.run() into a skip reason rather than a crash.
    2. Embedding the token in the push URL (an earlier fix) put it in
       subprocess argv, readable by any local process via `ps` or the
       world-readable (0444, any UID) /proc/<pid>/cmdline.
    3. So the token must be passed via the environment instead (only
       readable by the same UID via /proc/<pid>/environ) — using git's
       env-based config injection (GIT_CONFIG_COUNT/KEY/VALUE) to set an
       Authorization header, never a URL-embedded credential."""
    committer.create_branch(repo, "fix/auth-test")
    calls = []
    envs = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        envs.append(kwargs.get("env"))
        class _Proc:
            returncode = 0
            stdout = ""
            stderr = ""
        return _Proc()

    monkeypatch.setattr(committer.subprocess, "run", fake_run)
    committer.push(
        repo, "fix/auth-test",
        github_token="ghp_secrettoken123", repo_full_name="acme/service",
    )

    push_cmd = calls[-1]
    assert push_cmd == ["git", "push", "https://github.com/acme/service.git", "fix/auth-test"]
    assert not any("ghp_secrettoken123" in arg for arg in push_cmd)

    push_env = envs[-1]
    assert push_env["GIT_CONFIG_COUNT"] == "1"
    assert push_env["GIT_CONFIG_KEY_0"] == "http.extraheader"
    assert "Authorization: basic" in push_env["GIT_CONFIG_VALUE_0"]
    # the header value is base64(x-access-token:<token>), not the raw
    # token, but decoding it back out is exactly what a real HTTP
    # transport would do — assert the round-trip is correct.
    import base64
    encoded = push_env["GIT_CONFIG_VALUE_0"].split("basic ", 1)[1]
    assert base64.b64decode(encoded).decode() == "x-access-token:ghp_secrettoken123"


def test_push_falls_back_to_plain_remote_without_token(repo: Path, monkeypatch):
    committer.create_branch(repo, "fix/no-token")
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        class _Proc:
            returncode = 0
            stdout = ""
            stderr = ""
        return _Proc()

    monkeypatch.setattr(committer.subprocess, "run", fake_run)
    committer.push(repo, "fix/no-token")

    assert "origin" in calls[-1]
    assert not any("@github.com" in c for c in calls[-1])


def test_push_redacts_token_from_failure_message(repo: Path, monkeypatch):
    """The raised CommitError's message embeds the full command argv
    verbatim (destination URL included), and separately git's own stderr
    can echo it back too on some transports/versions — either way, the
    exception must not leak the token, since it propagates into
    pipeline.run()'s skip reason and from there into the /dispatch HTTP
    response and logs."""
    committer.create_branch(repo, "fix/leak-test")
    token = "ghp_secrettoken123"

    def fake_run(cmd, **kwargs):
        class _Proc:
            returncode = 128
            stdout = ""
            stderr = (
                f"fatal: unable to access "
                f"'https://x-access-token:{token}@github.com/acme/service.git/': "
                f"The requested URL returned error: 403"
            )
        return _Proc()

    monkeypatch.setattr(committer.subprocess, "run", fake_run)

    with pytest.raises(committer.CommitError) as exc_info:
        committer.push(
            repo, "fix/leak-test",
            github_token=token, repo_full_name="acme/service",
        )

    message = str(exc_info.value)
    assert token not in message
    assert "REDACTED" in message


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


def test_push_does_not_leak_token_into_git_config_on_success(tmp_path: Path):
    """Regression test: a real (non-mocked) git push. Before this fix,
    `push()` passed `-u`/`--set-upstream` to `git push`, which on a
    SUCCESSFUL push writes the literal destination URL — credentials
    included — into .git/config as branch.<name>.remote. That write
    happens regardless of exit code, so the failure-path token
    redaction (_run's `redact=`) never touches it. The clone directory
    this .git/config lives in is deliberately made world-readable
    (clone.py chmod 0o755, needed for the sandbox's unprivileged UID to
    traverse it) for the lifetime of the /dispatch call — so a real
    GITHUB_TOKEN would sit there, readable by any local unprivileged
    process, for as long as that directory exists. Verified here against
    a real local git remote, not a mock, since this class of bug only
    shows up in git's actual on-disk config-writing behavior."""
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

    committer.create_branch(repo, "fix/leak-check")
    (repo / "a.txt").write_text("changed\n")
    committer.commit_all(repo, "change")

    # A real, local successful push (no `github_token`/`repo_full_name`,
    # exercising the same _run(["git", "push", destination, branch], ...)
    # call every push takes — the property under test, that `-u` is never
    # passed, holds regardless of whether `destination` came from `remote`
    # or a built token URL, since the earlier tests in this file already
    # cover that URL-construction logic separately via mocks).
    committer.push(repo, "fix/leak-check", remote=str(remote_dir))

    config_text = (repo / ".git" / "config").read_text()
    assert "[branch" not in config_text, (
        "git push -u writes branch.<name>.remote = <destination-url> into "
        ".git/config on success — a real token-bearing destination would "
        "leak here, into a directory clone.py deliberately makes "
        "world-readable"
    )


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
