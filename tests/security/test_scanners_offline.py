"""Covers the offline/online branching in trivy.py and semgrep.py.

The sandbox image bakes a pre-fetched trivy DB / semgrep ruleset into fixed
paths (see Project/Dockerfile); these scanners auto-detect that path's
presence and switch command construction accordingly. A normal dev/eval
host won't have those paths, so it should keep using today's online
behavior unchanged.
"""
from __future__ import annotations

import subprocess
from unittest.mock import patch

from agent.security.scanners import semgrep, trivy


def _fake_proc(stdout: str = "{}"):
    return subprocess.CompletedProcess(args=[], returncode=0, stdout=stdout, stderr="")


def test_trivy_uses_online_defaults_when_no_offline_cache(tmp_path, monkeypatch):
    monkeypatch.setattr(trivy.os.path, "isdir", lambda p: False)
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return _fake_proc()

    with patch("agent.security.scanners.trivy.subprocess.run", side_effect=fake_run):
        trivy.run(str(tmp_path))

    assert "--cache-dir" not in captured["cmd"]
    assert "--offline-scan" not in captured["cmd"]
    assert captured["cmd"][-1] == str(tmp_path)


def test_trivy_uses_offline_flags_when_cache_present(tmp_path, monkeypatch):
    monkeypatch.setattr(
        trivy.os.path, "isdir", lambda p: p == trivy.OFFLINE_CACHE_DIR
    )
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return _fake_proc()

    with patch("agent.security.scanners.trivy.subprocess.run", side_effect=fake_run):
        trivy.run(str(tmp_path))

    cmd = captured["cmd"]
    assert "--cache-dir" in cmd
    assert cmd[cmd.index("--cache-dir") + 1] == trivy.OFFLINE_CACHE_DIR
    for flag in ("--skip-db-update", "--skip-java-db-update", "--skip-check-update", "--offline-scan"):
        assert flag in cmd


def test_semgrep_uses_config_auto_when_no_offline_rules(tmp_path, monkeypatch):
    monkeypatch.setattr(semgrep.os.path, "isdir", lambda p: False)
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["env"] = kwargs.get("env")
        return _fake_proc()

    with patch("agent.security.scanners.semgrep.subprocess.run", side_effect=fake_run):
        semgrep.run(str(tmp_path))

    assert captured["cmd"][captured["cmd"].index("--config") + 1] == "auto"
    assert captured["env"] is None


def test_semgrep_uses_local_config_and_home_when_rules_present(tmp_path, monkeypatch):
    monkeypatch.setattr(
        semgrep.os.path, "isdir", lambda p: p == semgrep.OFFLINE_RULES_DIR
    )
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["env"] = kwargs.get("env")
        return _fake_proc()

    with patch("agent.security.scanners.semgrep.subprocess.run", side_effect=fake_run):
        semgrep.run(str(tmp_path))

    assert captured["cmd"][captured["cmd"].index("--config") + 1] == semgrep.OFFLINE_RULES_DIR
    assert captured["env"]["HOME"] == "/tmp"
