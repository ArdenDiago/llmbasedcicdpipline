"""Git operations: write the fix, stage, commit, push.

Runs `git` via subprocess against a local clone path. Does not push to
main/master — caller must pass the feature branch name.
"""
from __future__ import annotations

import logging
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

_FENCE_RE = re.compile(r"^\s*```[a-zA-Z0-9_+-]*\s*\n(.*?)\n```\s*$", re.DOTALL)


def _strip_fences(text: str) -> str:
    """Strip a single outer ```lang ... ``` fence if the whole response is
    one; otherwise prefer the largest fenced block embedded in prose. Models
    sometimes wrap the "ONLY the corrected file content" response in a fence
    anyway despite being told not to explain. Mirrors
    evaluation/patcher.py::strip_fences (duplicated rather than imported —
    agent/ is the production path and shouldn't depend on evaluation/)."""
    text = text.strip()
    m = _FENCE_RE.match(text)
    if m:
        return m.group(1)
    blocks = re.findall(r"```[a-zA-Z0-9_+-]*\s*\n(.*?)\n```", text, re.DOTALL)
    if blocks:
        return max(blocks, key=len)
    return text

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


def write_full_file(repo_path: Path, target_relpath: str, new_content: str) -> None:
    """Overwrite target_relpath inside repo_path with new_content.

    fix_single_file.j2 instructs the fix-generating model to return the
    ENTIRE corrected file, not a unified diff, so the correct "apply"
    operation is a direct overwrite — matching
    evaluation/patcher.py::apply_full_file_replacement, the evaluation
    harness's independently-correct implementation of the same contract.
    A previous version of this function ran `git apply` on this same
    full-file text, which no real model's response (as the prompt actually
    instructs it to respond) could ever satisfy, since `git apply` requires
    unified-diff syntax the model was never asked to produce.
    """
    if not target_relpath:
        raise CommitError("empty target file path")
    if not new_content.strip():
        raise CommitError("empty fix content")

    repo_root = repo_path.resolve()
    target = (repo_path / target_relpath).resolve()
    if repo_root not in target.parents:
        raise CommitError(f"target path escapes repo: {target_relpath}")
    if not target.exists():
        raise CommitError(f"target file not found in repo: {target_relpath}")

    target.write_text(_strip_fences(new_content), encoding="utf-8")


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
