"""Apply LLM-emitted full-file replacement to a copy of a source tree.

The fix_single_file.j2 prompt asks for "ONLY the corrected file content, no
explanation". Models often wrap that in a ```language fence anyway — strip it.
After writing, optionally validate that the file still parses (Python: ast,
JS/TS: node --check). The parse check is the fix_safety signal.
"""
from __future__ import annotations

import ast
import logging
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

_FENCE_RE = re.compile(
    r"^\s*```[a-zA-Z0-9_+-]*\s*\n(.*?)\n```\s*$",
    re.DOTALL,
)


@dataclass
class PatchResult:
    workdir: Path           # the copied source tree the patch was applied into
    target_file: Path       # the file inside workdir that was rewritten
    parse_ok: bool          # did the rewritten file parse cleanly?
    parse_error: str | None
    original_bytes: int
    new_bytes: int


def strip_fences(text: str) -> str:
    """Strip a single outer ```lang ... ``` fence, if present.

    Models sometimes return only a fenced block; sometimes prose + fence.
    If a fence is present anywhere, prefer the *largest* fenced block.
    """
    text = text.strip()
    m = _FENCE_RE.match(text)
    if m:
        return m.group(1)
    # find the longest fenced block embedded in prose
    blocks = re.findall(r"```[a-zA-Z0-9_+-]*\s*\n(.*?)\n```", text, re.DOTALL)
    if blocks:
        return max(blocks, key=len)
    return text


def apply_full_file_replacement(
    source_root: Path,
    target_relpath: str,
    new_content: str,
    workdir_root: Path,
) -> PatchResult:
    """Copy source_root → workdir_root, then overwrite target_relpath.

    workdir_root is created (must not pre-exist or must be empty/cleanable —
    we use shutil.copytree so we wipe it first if present).
    """
    workdir_root = Path(workdir_root)
    if workdir_root.exists():
        shutil.rmtree(workdir_root)
    shutil.copytree(source_root, workdir_root)

    target = workdir_root / target_relpath
    if not target.exists():
        raise FileNotFoundError(f"target {target_relpath} not in {source_root}")
    original_bytes = target.stat().st_size

    cleaned = strip_fences(new_content)
    target.write_text(cleaned, encoding="utf-8")

    # A degenerate fenced response like "```python\n\n```" is non-blank as
    # raw text (the backticks alone are non-whitespace), so a caller's
    # blank-response check against the RAW model output (fix_eval.py checks
    # resp.text.strip() before this function is ever called) misses this
    # case. Checked here instead, against the post-fence-stripping content:
    # ast.parse("") is valid Python (an empty module), so without this the
    # .py branch of _validate() below would silently record an empty file
    # as "parses cleanly," inflating fix_safety (and potentially
    # fix_accuracy, if a re-scan then finds nothing to flag in an empty
    # file) for what is actually a non-answer from the model.
    if not cleaned.strip():
        return PatchResult(
            workdir=workdir_root, target_file=target, parse_ok=False,
            parse_error="empty content after fence-stripping",
            original_bytes=original_bytes, new_bytes=target.stat().st_size,
        )

    parse_ok, err = _validate(target)
    return PatchResult(
        workdir=workdir_root,
        target_file=target,
        parse_ok=parse_ok,
        parse_error=err,
        original_bytes=original_bytes,
        new_bytes=target.stat().st_size,
    )


def _validate(path: Path) -> tuple[bool, str | None]:
    suffix = path.suffix.lower()
    try:
        text = path.read_text(encoding="utf-8")
    except Exception as exc:
        return False, f"unreadable: {exc}"

    if suffix == ".py":
        try:
            ast.parse(text)
            return True, None
        except SyntaxError as exc:
            return False, f"py syntax: {exc.msg} (line {exc.lineno})"

    if suffix in (".js", ".mjs", ".cjs", ".ts"):
        try:
            r = subprocess.run(
                ["node", "--check", str(path)],
                capture_output=True, text=True, timeout=15,
            )
            if r.returncode == 0:
                return True, None
            return False, f"node --check: {r.stderr.strip().splitlines()[-1] if r.stderr else 'failed'}"
        except FileNotFoundError:
            return True, None  # node not installed — don't penalize
        except subprocess.TimeoutExpired:
            return False, "node --check timed out"

    # Unknown extension — accept as long as it's not empty.
    return bool(text.strip()), None if text.strip() else "empty file"
