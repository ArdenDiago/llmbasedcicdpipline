"""Live post-repair re-scan, end to end against a real Docker sandbox.

Real: the llm-cicd-agent sandbox image, Bandit/Semgrep/Gitleaks/Trivy inside
it, the repo's own pytest suite, git branch/commit on a real checkout, and
the manager's validate+rescan wiring. Stubbed: the LLM clients (fixed patch
text, so the test is deterministic), `git push`, and the GitHub API.

Needs Docker and the image (`docker build -t llm-cicd-agent:latest Project/`).
Run: pytest -m integration tests/integration/test_live_rescan.py
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from agent import pipeline
from agent.llm import analyzer
from agent.pr import creator, github_api
from agent.sandbox import collector, container
from agent.sandbox.manager import _default_validate_factory
from tests.integration.test_end_to_end import _config, _FakeHaiku, _FakeLLM

pytestmark = pytest.mark.integration

IMAGE = "llm-cicd-agent:latest"

VULN = '''import subprocess


def ping(host):
    return subprocess.call("ping -c 1 " + host, shell=True)
'''
# Same injection moved to another high-severity sink: must still be rejected.
BAD_FIX = '''import os


def ping(host):
    return os.system("ping -c 1 " + host)
'''
# Real fix: argument list, no shell. Bandit still reports B404/B603 (low,
# CWE-78) for the subprocess import/call, which must not block the PR.
GOOD_FIX = '''import subprocess


def ping(host):
    return subprocess.call(["ping", "-c", "1", host])
'''
TESTS = '''from app import ping


def test_ping_is_callable():
    assert callable(ping)
'''


def _docker():
    try:
        import docker
        client = docker.from_env()
        client.images.get(IMAGE)
        return client
    except Exception as exc:  # no daemon or image
        pytest.skip(f"docker/image unavailable: {exc}")


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True).stdout


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "app.py").write_text(VULN)
    (repo / "test_app.py").write_text(TESTS)
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "-c", "user.email=t@t", "-c", "user.name=t", "add", ".")
    _git(repo, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "init")
    _git(repo, "config", "user.email", "agent@test")
    _git(repo, "config", "user.name", "agent")
    repo.chmod(0o755)
    return repo


def _run(repo: Path, fix_text: str, monkeypatch, docker_client):
    payload = {"repo_full_name": "acme/target", "branch": "main", "commit_sha": "c0ffee"}
    scan = container.run_sandbox(docker_client, payload, IMAGE, repo_path=repo)
    envelope = collector.collect(payload, scan)
    findings = envelope["scanners"]["findings"]
    assert envelope["scanners"]["scanners"] == {"bandit": "ok", "gitleaks": "ok", "semgrep": "ok", "trivy": "ok"}
    shell = [f for f in findings if f["file"] == "app.py" and f["severity"] == "high" and f["cwe"] == "CWE-78"]
    assert len(shell) == 1, findings
    envelope["scanners"]["findings"] = shell  # one finding -> one fix attempt

    monkeypatch.setattr(creator.committer, "push", lambda *a, **k: None)
    opened = []
    monkeypatch.setattr(creator.github_api, "create_pull_request", lambda **kw: opened.append(kw) or
                        github_api.PullRequestRef(number=1, html_url="https://x/pr/1", head=kw["head"], base=kw["base"]))

    clients = analyzer.ClientSet(
        deepseek=_FakeLLM("deepseek-coder:6.7b", fix_text),
        haiku=_FakeHaiku(classify_text='{"category": "simple"}',
                         eval_text='{"confidence": 0.9, "reasoning": "ok"}'),
        sonnet=_FakeLLM("sonnet", fix_text), opus=_FakeLLM("opus", fix_text),
    )
    validate = _default_validate_factory(docker_client, IMAGE, payload)
    result = pipeline.run(
        envelope=envelope, repo_path=repo, clients=clients, config=_config(),
        validate=validate, github_client=object(), min_severity="medium",
        rescan=validate.rescan,
    )
    return result, opened


def test_live_gate_rejects_fix_that_moves_injection(tmp_path, monkeypatch):
    docker_client = _docker()
    result, opened = _run(_repo(tmp_path), BAD_FIX, monkeypatch, docker_client)
    assert opened == []
    assert [r.skipped_reason for r in result.created] == ["finding still flagged on re-scan"]


def test_live_gate_opens_pr_for_real_fix(tmp_path, monkeypatch):
    docker_client = _docker()
    repo = _repo(tmp_path)
    result, opened = _run(repo, GOOD_FIX, monkeypatch, docker_client)
    assert [r.created for r in result.created] == [True], [r.skipped_reason for r in result.created]
    assert len(opened) == 1
    # the committed branch carries the fix
    assert "shell=True" not in _git(repo, "show", f"{result.created[0].branch}:app.py")
