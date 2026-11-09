"""End-to-end smoke run of the live fix pipeline with the real free-tier model.

Real: the llm-cicd-agent sandbox image (all four scanners + test runner),
DeepSeek Coder 6.7B through Ollama (GPU if Ollama has one), the analyzer,
the post-repair re-scan gate, git branch/commit on a real checkout.
Not real: `git push` and the GitHub API (recorded instead). AGENT_OFFLINE=1
stops the cascade at tier 1 and the PR body comes from the local offline
template, as a data-confined deployment would; any paid-tier call raises.
Nothing leaves the machine.

Usage (from Project/):  .venv/bin/python scripts/live_smoke.py [--out result.json]
Prints and optionally writes the per-finding outcome. No result is invented:
if the model's patch is rejected, that is what gets reported.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

os.environ["AGENT_OFFLINE"] = "1"

from agent import pipeline  # noqa: E402
from agent.llm import analyzer, config as llm_config  # noqa: E402
from agent.llm.clients.ollama import OllamaClient  # noqa: E402
from agent.pr import creator, github_api  # noqa: E402
from agent.sandbox import collector, container  # noqa: E402
from agent.sandbox.manager import _default_validate_factory  # noqa: E402

IMAGE = "llm-cicd-agent:latest"

FILES = {
    "app.py": '''import sqlite3
import subprocess


def ping(host):
    return subprocess.call("ping -c 1 " + host, shell=True)


def find_user(conn: sqlite3.Connection, name: str):
    return conn.execute("SELECT * FROM users WHERE name = '%s'" % name).fetchall()
''',
    "test_app.py": '''import sqlite3

from app import find_user


def test_find_user_returns_match():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE users (name TEXT)")
    conn.execute("INSERT INTO users VALUES ('ann')")
    assert find_user(conn, "ann") == [("ann",)]
''',
}


class _NoPaidTier:
    """AGENT_OFFLINE=1 must never reach a paid tier; fail loudly if it does."""

    def complete(self, *a, **k):
        raise RuntimeError("paid tier called in offline mode")


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True).stdout


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path)
    args = ap.parse_args()

    import docker
    dk = docker.from_env()
    dk.images.get(IMAGE)

    repo = Path(tempfile.mkdtemp(prefix="live-smoke-")) / "target"
    repo.mkdir()
    for name, body in FILES.items():
        (repo / name).write_text(body)
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "-c", "user.email=s@s", "-c", "user.name=s", "add", ".")
    _git(repo, "-c", "user.email=s@s", "-c", "user.name=s", "commit", "-qm", "init")
    _git(repo, "config", "user.email", "agent@smoke")
    _git(repo, "config", "user.name", "agent")
    repo.parent.chmod(0o755)
    repo.chmod(0o755)

    payload = {"repo_full_name": "smoke/target", "branch": "main", "commit_sha": "smoke"}
    scan = container.run_sandbox(dk, payload, IMAGE, repo_path=repo)
    envelope = collector.collect(payload, scan)
    findings = envelope["scanners"]["findings"]

    pushed, opened, bodies = [], [], []
    creator.committer.push = lambda path, branch, **k: pushed.append(branch)
    creator.github_api.create_pull_request = lambda **kw: opened.append(kw["head"]) or bodies.append(kw["body"]) or \
        github_api.PullRequestRef(number=len(opened), html_url="(not opened: smoke run)",
                                  head=kw["head"], base=kw["base"])

    cfg = llm_config.load()
    ds = cfg.models.get("deepseek_coder", {})
    clients = analyzer.ClientSet(
        deepseek=OllamaClient(model=ds.get("model_id", "deepseek-coder:6.7b"), host=ds.get("host")),
        haiku=_NoPaidTier(), sonnet=_NoPaidTier(), opus=_NoPaidTier(),
    )
    validate = _default_validate_factory(dk, IMAGE, payload)
    result = pipeline.run(
        envelope=envelope, repo_path=repo, clients=clients, config=cfg,
        validate=validate, github_client=object(), rescan=validate.rescan,
    )

    report = {
        "scanner_status": envelope["scanners"]["scanners"],
        "initial_tests": {k: envelope["tests"].get(k) for k in ("framework", "passed", "failed", "error")},
        "findings": [{k: f[k] for k in ("scanner", "rule_id", "severity", "cwe", "file", "line")} for f in findings],
        "summary": result.summary(),
        "pull_requests_would_open": opened,
        "pr_bodies": bodies,
        "branches_would_push": pushed,
        "skipped": [{"rule_id": s["finding"].get("rule_id"), "line": s["finding"].get("line"),
                     "reason": s["reason"]} for s in result.skipped],
        "created": [{"branch": c.branch, "created": c.created, "reason": c.skipped_reason} for c in result.created],
    }
    text = json.dumps(report, indent=2)
    print(text)
    if args.out:
        args.out.write_text(text + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
