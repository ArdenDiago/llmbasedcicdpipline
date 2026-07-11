"""Host-side repo clone.

The sandbox container runs with network_disabled=True (see container.py), so
any repo fetch must happen on the control-plane host beforehand; the cloned
directory is then bind-mounted read-only into the sandbox. This module is the
"Read-only repo clone" step from the module CLAUDE.md lifecycle, run before
the network-isolated container starts.
"""
from __future__ import annotations

import logging
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

logger = logging.getLogger(__name__)

DEFAULT_CLONE_TIMEOUT = 120

# A real git commit SHA is 7-40 lowercase/uppercase hex characters. Validating
# this BEFORE ever invoking git closes the option-injection path for the
# checkout step without relying on `--`, which (see below) does not mean
# what it means for `git clone`.
_SHA_RE = re.compile(r"^[0-9a-fA-F]{7,40}$")


class CloneError(RuntimeError):
    """Raised when the host-side git clone/checkout fails."""


def clone_repo(repo_url: str, commit_sha: str, timeout: int = DEFAULT_CLONE_TIMEOUT) -> Path:
    """Clone repo_url into a fresh temp dir and check out commit_sha.

    Uses argument-list subprocess calls throughout (never shell=True) so a
    hostile repo_url/commit_sha cannot inject shell commands. `git clone`
    additionally gets a `--` separator before its positional arguments so a
    repo_url starting with `-` (e.g. `--upload-pack=...`) can't be parsed as
    an option. `git checkout` does NOT get the same treatment: unlike
    `clone`, `checkout`'s `--` marks everything after it as a PATHSPEC, not
    a revision — `git checkout --quiet -- <sha>` fails for every real SHA
    (`error: pathspec '<sha>' did not match any file(s) known to git`), not
    just hostile ones, which is a regression a previous "fix" introduced
    here. commit_sha is instead validated as a well-formed hex SHA before
    git ever sees it, which closes the same injection path (a leading `-`
    is not a hex digit) without breaking the common case. The checkout call
    additionally puts commit_sha *before* a trailing `--` (`checkout
    --quiet <sha> --`, verified empirically to still exit 0) — the
    idiomatic "treat this unambiguously as a revision, not a pathspec"
    form, guarding the theoretical edge case of a repo containing a file
    whose name happens to collide with the SHA. Raises CloneError on any
    git failure or malformed commit_sha; the caller owns cleanup of the
    returned directory (see manager.py, which removes it after the sandbox
    run).
    """
    if not _SHA_RE.match(commit_sha):
        raise CloneError(f"commit_sha is not a well-formed SHA: {commit_sha!r}")

    dest = Path(tempfile.mkdtemp(prefix="sandbox-src-"))
    # mkdtemp defaults to 0700, owned by the host user. The checkout is
    # later bind-mounted read-only into the sandbox container, which always
    # runs as the fixed unprivileged UID 65534 (nobody) — matching neither
    # owner nor group here, so without this it can't even traverse into the
    # directory (every scanner then silently "sees" an empty, unreadable
    # tree rather than erroring, which is worse: it looks like a clean scan).
    dest.chmod(0o755)
    try:
        _run(["git", "clone", "--quiet", "--", repo_url, str(dest)], timeout)
        _run(["git", "-C", str(dest), "checkout", "--quiet", commit_sha, "--"], timeout)
    except CloneError:
        shutil.rmtree(dest, ignore_errors=True)
        raise
    return dest


def _run(cmd: list[str], timeout: int) -> None:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        raise CloneError(f"git command timed out after {timeout}s: {' '.join(cmd)}") from exc
    if proc.returncode != 0:
        raise CloneError(f"git command failed ({proc.returncode}): {' '.join(cmd)}\n{proc.stderr}")
