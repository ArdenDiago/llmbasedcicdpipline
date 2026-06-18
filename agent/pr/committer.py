"""Git operations: apply diff, stage, commit, push.

Runs `git` via subprocess against a local clone path. Does not push to
main/master — caller must pass the feature branch name.
"""
from __future__ import annotations

import logging
import subprocess
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

PROTECTED_BRANCHES = frozenset({"main", "master"})


class CommitError(RuntimeError):
    pass


@dataclass
class CommitResult:
    branch: str
    sha: str
    pushed: bool


def _run(cmd: list[str], cwd: Path) -> str:
    logger.debug("git %s", " ".join(cmd[1:]))
    proc = subprocess.run(
        cmd,
        cwd=str(cwd),
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise CommitError(
            f"git {' '.join(cmd[1:])} failed ({proc.returncode}): {proc.stderr.strip()}"
        )
    return proc.stdout.strip()


def create_branch(repo_path: Path, branch: str, base: str = "HEAD") -> None:
    if branch in PROTECTED_BRANCHES:
        raise CommitError(f"refusing to create protected branch: {branch}")
    _run(["git", "checkout", "-b", branch, base], repo_path)


def apply_patch(repo_path: Path, diff_text: str) -> None:
    if not diff_text.strip():
        raise CommitError("empty diff")
    proc = subprocess.run(
        ["git", "apply", "--whitespace=nowarn", "-"],
        cwd=str(repo_path),
        input=diff_text,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise CommitError(f"git apply failed: {proc.stderr.strip()}")


def commit_all(repo_path: Path, message: str) -> str:
    _run(["git", "add", "-A"], repo_path)
    _run(["git", "commit", "-m", message], repo_path)
    return _run(["git", "rev-parse", "HEAD"], repo_path)


def push(repo_path: Path, branch: str, remote: str = "origin") -> None:
    if branch in PROTECTED_BRANCHES:
        raise CommitError(f"refusing to push to protected branch: {branch}")
    _run(["git", "push", "-u", remote, branch], repo_path)


def commit_message(finding: dict, confidence: float, model_used: str) -> str:
    scanner = finding.get("scanner", "unknown")
    rule = finding.get("rule_id", "unknown")
    severity = finding.get("severity", "info")
    file = finding.get("file", "")
    return (
        f"fix({scanner}): {rule} in {file}\n\n"
        f"Severity: {severity}\n"
        f"Confidence: {confidence:.2f}\n"
        f"Model: {model_used}\n"
    )
