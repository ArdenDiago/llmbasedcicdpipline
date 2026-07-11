from __future__ import annotations

import stat
import subprocess as real_subprocess
from pathlib import Path

import pytest

from agent.sandbox import clone


def test_clone_repo_success(tmp_path, monkeypatch):
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        class _Proc:
            returncode = 0
            stderr = ""
        return _Proc()

    monkeypatch.setattr(clone.subprocess, "run", fake_run)

    dest = clone.clone_repo("https://example.com/acme/service.git", "abc123def4567")

    assert dest.exists()
    assert calls[0][:2] == ["git", "clone"]
    assert calls[0][-2] == "https://example.com/acme/service.git"
    assert calls[1] == ["git", "-C", str(dest), "checkout", "--quiet", "abc123def4567", "--"]

    clone.shutil.rmtree(dest, ignore_errors=True)


def test_clone_repo_rejects_option_injection_via_leading_dash(monkeypatch):
    """repo_url is webhook-derived and untrusted. Without a `--` separator
    before positional args, a value starting with `-` (e.g.
    `--upload-pack=...`) is parsed by git as an option instead of data, which
    for local/ssh transports can execute an arbitrary command on the host."""
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        class _Proc:
            returncode = 0
            stderr = ""
        return _Proc()

    monkeypatch.setattr(clone.subprocess, "run", fake_run)

    hostile_url = "--upload-pack=touch /tmp/pwned"
    dest = clone.clone_repo(hostile_url, "abc123def4567")

    clone_cmd = calls[0]
    assert "--" in clone_cmd
    assert clone_cmd.index("--") < clone_cmd.index(hostile_url)

    clone.shutil.rmtree(dest, ignore_errors=True)


def test_clone_repo_rejects_option_injection_via_hostile_commit_sha(monkeypatch):
    """commit_sha is also webhook-derived and untrusted. `git checkout` gives
    `--` a PATHSPEC meaning (not "end of options" like `clone`), so it can't
    be used to neutralize a hostile commit_sha the way it protects repo_url
    — a value like `--upload-pack=...` must instead be rejected outright by
    the SHA-format validation before any git subprocess runs."""
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        class _Proc:
            returncode = 0
            stderr = ""
        return _Proc()

    monkeypatch.setattr(clone.subprocess, "run", fake_run)

    hostile_sha = "--upload-pack=touch /tmp/pwned2"

    with pytest.raises(clone.CloneError, match="not a well-formed SHA"):
        clone.clone_repo("https://example.com/acme/service.git", hostile_sha)

    assert calls == []


def test_clone_repo_checkout_puts_sha_before_trailing_separator(monkeypatch):
    """Regression test: a prior 'fix' added `--` BEFORE commit_sha in the
    checkout call to guard against injection, but for `git checkout` that
    separator marks everything after it as a pathspec, not a revision —
    `git checkout --quiet -- <sha>` fails for every legitimate SHA too
    (`error: pathspec '<sha>' did not match any file(s) known to git`),
    verified empirically against real git. `git checkout --quiet <sha> --`
    (separator AFTER the revision) is the idiomatic safe form and was also
    verified empirically to still exit 0 for a real commit."""
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        class _Proc:
            returncode = 0
            stderr = ""
        return _Proc()

    monkeypatch.setattr(clone.subprocess, "run", fake_run)

    dest = clone.clone_repo("https://example.com/acme/service.git", "abc123def4567")

    _, checkout_cmd = calls
    assert checkout_cmd[-2:] == ["abc123def4567", "--"]

    clone.shutil.rmtree(dest, ignore_errors=True)


def test_clone_repo_leaves_dir_traversable_by_other_users(monkeypatch):
    """mkdtemp defaults to 0700, which the sandbox's unprivileged UID 65534
    can't traverse once bind-mounted — regression test for a bug where every
    scanner silently "saw" an empty tree instead of erroring."""
    def fake_run(cmd, **kwargs):
        class _Proc:
            returncode = 0
            stderr = ""
        return _Proc()

    monkeypatch.setattr(clone.subprocess, "run", fake_run)

    dest = clone.clone_repo("https://example.com/acme/service.git", "abc123def4567")

    mode = stat.S_IMODE(dest.stat().st_mode)
    assert mode & stat.S_IROTH and mode & stat.S_IXOTH

    clone.shutil.rmtree(dest, ignore_errors=True)


def _git(repo: Path, *args: str) -> None:
    import subprocess
    subprocess.run(
        ["git", *args], cwd=str(repo), check=True, capture_output=True, text=True,
    )


def test_clone_repo_checks_out_real_commit_end_to_end(tmp_path: Path):
    """No subprocess mocking: exercises the real git binary against a real
    local repo, so this class of bug (clone.py's checkout call being
    syntactically well-formed but semantically broken for real git) can't
    hide behind a fake `subprocess.run` that always reports success — which
    is exactly what let the `-- <sha>` regression ship undetected through
    186 previously-passing mocked tests."""
    source = tmp_path / "source"
    source.mkdir()
    _git(source, "init", "-q", "-b", "main")
    _git(source, "config", "user.email", "t@t")
    _git(source, "config", "user.name", "t")
    (source / "a.txt").write_text("v1\n")
    _git(source, "add", "-A")
    _git(source, "commit", "-q", "-m", "v1")
    first_sha = real_subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=str(source),
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    (source / "a.txt").write_text("v2\n")
    _git(source, "commit", "-qam", "v2")

    dest = clone.clone_repo(f"file://{source}", first_sha)
    try:
        assert (dest / "a.txt").read_text() == "v1\n"  # checked out the OLDER commit, not HEAD
    finally:
        clone.shutil.rmtree(dest, ignore_errors=True)


def test_clone_repo_raises_and_cleans_up_on_failure(monkeypatch):
    def fake_run(cmd, **kwargs):
        class _Proc:
            returncode = 128
            stderr = "fatal: repository not found"
        return _Proc()

    monkeypatch.setattr(clone.subprocess, "run", fake_run)

    created_dirs = []
    real_mkdtemp = clone.tempfile.mkdtemp

    def tracking_mkdtemp(*a, **k):
        d = real_mkdtemp(*a, **k)
        created_dirs.append(d)
        return d

    monkeypatch.setattr(clone.tempfile, "mkdtemp", tracking_mkdtemp)

    with pytest.raises(clone.CloneError, match="repository not found"):
        clone.clone_repo("https://example.com/nope.git", "deadbeef")

    assert created_dirs
    assert not Path(created_dirs[0]).exists()


def test_clone_repo_never_uses_shell(monkeypatch):
    """Guards against a future shell=True regression (command injection risk)."""
    seen_kwargs = {}

    def fake_run(cmd, **kwargs):
        seen_kwargs.update(kwargs)
        class _Proc:
            returncode = 0
            stderr = ""
        return _Proc()

    monkeypatch.setattr(clone.subprocess, "run", fake_run)
    dest = clone.clone_repo("https://example.com/acme/service.git; rm -rf /", "abc123def4567")
    assert seen_kwargs.get("shell", False) is False
    clone.shutil.rmtree(dest, ignore_errors=True)
