from __future__ import annotations

import stat
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

    dest = clone.clone_repo("https://example.com/acme/service.git", "abc123")

    assert dest.exists()
    assert calls[0][:2] == ["git", "clone"]
    assert calls[0][-2] == "https://example.com/acme/service.git"
    assert calls[1] == ["git", "-C", str(dest), "checkout", "--quiet", "--", "abc123"]

    clone.shutil.rmtree(dest, ignore_errors=True)


def test_clone_repo_rejects_option_injection_via_leading_dash(monkeypatch):
    """repo_url/commit_sha are webhook-derived and untrusted. Without a `--`
    separator before positional args, a value starting with `-` (e.g.
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
    hostile_sha = "--upload-pack=touch /tmp/pwned2"
    dest = clone.clone_repo(hostile_url, hostile_sha)

    clone_cmd, checkout_cmd = calls
    assert "--" in clone_cmd
    assert clone_cmd.index("--") < clone_cmd.index(hostile_url)
    assert "--" in checkout_cmd
    assert checkout_cmd.index("--") < checkout_cmd.index(hostile_sha)

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

    dest = clone.clone_repo("https://example.com/acme/service.git", "abc123")

    mode = stat.S_IMODE(dest.stat().st_mode)
    assert mode & stat.S_IROTH and mode & stat.S_IXOTH

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
    dest = clone.clone_repo("https://example.com/acme/service.git; rm -rf /", "abc123")
    assert seen_kwargs.get("shell", False) is False
    clone.shutil.rmtree(dest, ignore_errors=True)
