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


class BranchAlreadyExistsError(CommitError):
    """Raised by push() when the remote already has this branch.

    Branch names are deterministic (brancher.branch_name() hashes
    file+line+commit_sha), so re-processing the same commit (webhook retry,
    manager restart) reproduces the identical branch name and a plain
    `git push` fails non-fast-forward. Callers can catch this specifically
    to treat it as "a PR for this finding likely already exists, skip" —
    the base CommitError is still raised so anything only catching that
    keeps working unchanged."""


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


def reset_to_base(repo_path: Path, base_branch: str) -> None:
    """Discard any uncommitted changes/stray branch checkout left behind by
    a prior finding's create_pr() call (e.g. one whose patch applied but
    failed validation) so every finding starts from a clean, known state.
    Without this, a dirty tree from finding N can either abort finding N+1's
    `git checkout -b` outright or silently carry finding N's changes onto
    finding N+1's branch/PR."""
    _run(["git", "checkout", "--force", base_branch], repo_path)
    _run(["git", "reset", "--hard"], repo_path)
    _run(["git", "clean", "-fd"], repo_path)


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


_NON_FAST_FORWARD_MARKERS = ("non-fast-forward", "fetch first", "already exists")


def push(repo_path: Path, branch: str, remote: str = "origin") -> None:
    if branch in PROTECTED_BRANCHES:
        raise CommitError(f"refusing to push to protected branch: {branch}")
    try:
        _run(["git", "push", "-u", remote, branch], repo_path)
    except CommitError as exc:
        if any(marker in str(exc).lower() for marker in _NON_FAST_FORWARD_MARKERS):
            raise BranchAlreadyExistsError(str(exc)) from exc
        raise


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
