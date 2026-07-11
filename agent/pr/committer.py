"""Git operations: write the fix, stage, commit, push.

Runs `git` via subprocess against a local clone path. Does not push to
main/master — caller must pass the feature branch name.
"""
from __future__ import annotations

import ast
import base64
import logging
import os
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

# Local git operations (checkout/reset/clean/add/commit/rev-parse) touch
# only the on-disk clone, no network — 30s is generous headroom. push() is
# the one network-bound operation here and gets its own, longer default;
# both exist because, unlike clone.py's clone_repo() (which already timed
# out via subprocess.run's timeout=), _run() previously had no timeout at
# all, so a stalled push (or any other git subprocess) could block the
# host control-plane process indefinitely.
DEFAULT_TIMEOUT_SECONDS = 30
DEFAULT_PUSH_TIMEOUT_SECONDS = 60


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


def _run(
    cmd: list[str],
    cwd: Path,
    redact: str | None = None,
    extra_env: dict[str, str] | None = None,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
) -> str:
    """redact: a secret substring (e.g. an access token embedded in a push
    URL) to scrub from any log line or exception message this call might
    produce. The failure-path CommitError message embeds the full argv
    (including any token-bearing destination) verbatim, so that alone
    needs scrubbing; stderr is scrubbed too as defense in depth (verified
    empirically that git 2.55.0 does *not* echo the credential portion of
    a failed URL back into stderr for a DNS or auth failure, but this is
    transport/version-dependent and not a property we want this code to
    depend on staying true).

    extra_env: additional environment variables merged over the current
    process's environment for this call only — used by push() to inject
    credentials via git's env-based config mechanism instead of argv.
    Unlike argv (visible to any local process via `ps`/`/proc/<pid>/cmdline`,
    which is world-readable, 0444, regardless of owning UID), a child
    process's environment block is only readable by the same UID (or
    root/CAP_SYS_PTRACE) via /proc/<pid>/environ.

    timeout: unlike clone.py's clone_repo() (which already bounded its
    subprocess calls), this function previously had no timeout at all —
    a stalled network push, or any other hung git subprocess, could block
    the host control-plane process indefinitely."""
    def _scrub(s: str) -> str:
        return s.replace(redact, "***REDACTED***") if redact else s

    logger.debug("git %s", " ".join(_scrub(c) for c in cmd[1:]))
    env = {**os.environ, **extra_env} if extra_env else None
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            check=False,
            env=env,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        cmd_display = " ".join(_scrub(c) for c in cmd[1:])
        raise CommitError(f"git {cmd_display} timed out after {timeout}s") from exc
    if proc.returncode != 0:
        cmd_display = " ".join(_scrub(c) for c in cmd[1:])
        raise CommitError(
            f"git {cmd_display} failed ({proc.returncode}): {_scrub(proc.stderr.strip())}"
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

    For .py targets, rejects a patch that doesn't even parse before it's
    ever written to disk (mirrors evaluation/patcher.py::_validate's
    ast.parse check) — this is the live agent's only syntax-validity gate:
    the sandboxed test-suite re-run (agent/sandbox/manager.py) returns True
    unconditionally when the target repo has no discoverable test suite, so
    without this check a repo with no tests would get zero validation of
    any kind before a syntactically broken patch reaches a PR.
    """
    if not target_relpath:
        raise CommitError("empty target file path")

    # Check blankness on the FENCE-STRIPPED content, not the raw response: a
    # degenerate fenced reply like "```python\n\n```" is non-blank raw text
    # (the backticks alone are non-whitespace) but strips down to "" — a
    # blank-content check against new_content misses this case entirely,
    # silently overwriting the target with an empty file (ast.parse("") is
    # valid Python, so the .py syntax gate below doesn't catch it either).
    stripped = _strip_fences(new_content)
    if not stripped.strip():
        raise CommitError("empty fix content")

    repo_root = repo_path.resolve()
    target = (repo_path / target_relpath).resolve()
    if repo_root not in target.parents:
        raise CommitError(f"target path escapes repo: {target_relpath}")
    if not target.exists():
        raise CommitError(f"target file not found in repo: {target_relpath}")

    if target.suffix.lower() == ".py":
        try:
            ast.parse(stripped)
        except SyntaxError as exc:
            raise CommitError(
                f"fix does not parse as valid Python: {exc.msg} (line {exc.lineno})"
            ) from exc

    target.write_text(stripped, encoding="utf-8")


def commit_all(repo_path: Path, message: str) -> str:
    _run(["git", "add", "-A"], repo_path)
    _run(["git", "commit", "-m", message], repo_path)
    return _run(["git", "rev-parse", "HEAD"], repo_path)


_NON_FAST_FORWARD_MARKERS = ("non-fast-forward", "fetch first", "already exists")


def push(
    repo_path: Path,
    branch: str,
    remote: str = "origin",
    github_token: str | None = None,
    repo_full_name: str | None = None,
) -> None:
    """Push branch to remote.

    clone.py checks out the repo anonymously via its public HTTPS
    clone_url — no credential is ever passed to `git clone`. GITHUB_TOKEN
    was previously read only inside github_api.py, for the PyGithub REST
    call that opens the PR, and never used to authenticate this push —
    so `git push origin <branch>` always failed with a credential prompt
    against any repo requiring write access (i.e. every real one), and
    because pipeline.run() catches this per-finding, it surfaced only as
    a swallowed skip reason, never a crash, making the pipeline look like
    it "worked" (200 OK, findings processed) while never actually opening
    a single PR against a real repo.

    When both github_token and repo_full_name are given, authenticates via
    an `Authorization` header injected through git's env-based config
    mechanism (`GIT_CONFIG_COUNT`/`GIT_CONFIG_KEY_n`/`GIT_CONFIG_VALUE_n`,
    git >= 2.31), not a token embedded in the destination URL. Two prior
    fixes here both still leaked the token through different channels:
    embedding it in the URL argv leaks it to any local process via `ps`
    or the world-readable (0444, any UID) `/proc/<pid>/cmdline`; adding
    `-u`/`--set-upstream` on top of that also wrote the credential-bearing
    URL into `.git/config` (a file inside a directory clone.py deliberately
    makes world-readable, 0o755, for the sandbox's unprivileged UID) on a
    SUCCESSFUL push, a write the failure-path `redact` never reaches. A
    child process's environment block, by contrast, is only readable by
    the same UID (or root/CAP_SYS_PTRACE) via `/proc/<pid>/environ` — so
    passing the token there instead closes both leak paths. Also
    deliberately does NOT pass `-u`/`--set-upstream`: no branch-tracking
    metadata is needed here, since repo_path is deleted right after this
    pipeline run and nothing downstream reads local git tracking state —
    only the GitHub REST API (github_api.py) and the finding's branch
    name (a value already known to the caller).
    """
    if branch in PROTECTED_BRANCHES:
        raise CommitError(f"refusing to push to protected branch: {branch}")
    destination = remote
    extra_env = None
    if github_token and repo_full_name:
        destination = f"https://github.com/{repo_full_name}.git"
        basic = base64.b64encode(f"x-access-token:{github_token}".encode()).decode()
        extra_env = {
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "http.extraheader",
            "GIT_CONFIG_VALUE_0": f"Authorization: basic {basic}",
        }
    try:
        _run(
            ["git", "push", destination, branch], repo_path,
            redact=github_token, extra_env=extra_env, timeout=DEFAULT_PUSH_TIMEOUT_SECONDS,
        )
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
