from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from agent.sandbox import clone


def _fake_run(returncode: int = 0, stderr: str = ""):
    def _inner(cmd, capture_output, text, timeout, check):
        class _Proc:
            pass

        p = _Proc()
        p.returncode = returncode
        p.stderr = stderr
        return p

    return _inner


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
    assert calls[1] == ["git", "-C", str(dest), "checkout", "--quiet", "abc123"]

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
