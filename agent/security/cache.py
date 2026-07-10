"""Content-addressed scanner-output cache.

Wraps run_scan.run_all(). Key = sha256(source_dir contents, scanner_version)
so repeated benchmark/evaluation runs over an unchanged source tree skip
re-running bandit/semgrep/trivy/gitleaks entirely. Mirrors agent/llm/cache.py's
CachedClient pattern, but run_scan.run_all() is a plain function rather than
an object behind the LLMClient protocol, so this is a function wrapper
instead of a drop-in class.

Usage:
    from agent.security import cache, run_scan
    result = cache.run_all_cached(
        run_scan.run_all, "/path/to/source",
        cache_dir=Path(".cache/scanner_outputs"),
    )
"""
from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from typing import Any, Callable

logger = logging.getLogger(__name__)

DEFAULT_SCANNER_VERSION_TAG = "unversioned"


def hash_source_dir(path: str | Path) -> str:
    """sha256 over every regular file's relative path + content under
    `path`, sorted for determinism. A full tree walk, not a VCS-aware diff
    — the cache keys on "did the source tree change at all", not on any
    particular commit."""
    h = hashlib.sha256()
    root = Path(path)
    for file_path in sorted(p for p in root.rglob("*") if p.is_file()):
        rel = file_path.relative_to(root).as_posix()
        h.update(rel.encode("utf-8"))
        h.update(b"\x00")
        h.update(file_path.read_bytes())
        h.update(b"\x00")
    return h.hexdigest()


def run_all_cached(
    run_all_fn: Callable[..., dict[str, Any]],
    target_path: str,
    cache_dir: Path,
    scanner_version: str = DEFAULT_SCANNER_VERSION_TAG,
    **run_all_kwargs: Any,
) -> dict[str, Any]:
    """Cache-aware wrapper around run_scan.run_all (pass it as run_all_fn).

    `scanner_version` should capture whatever would invalidate a cached
    result — e.g. a string built from each enabled scanner's `--version`
    output — so a scanner upgrade doesn't silently serve stale findings.
    Defaults to a fixed tag when the caller doesn't have one on hand; that
    still keys correctly on source content, just not on scanner version.
    """
    cache_dir = Path(cache_dir)
    cache_dir.mkdir(parents=True, exist_ok=True)
    key = hashlib.sha256(
        (hash_source_dir(target_path) + "\x00" + scanner_version).encode("utf-8")
    ).hexdigest()
    path = cache_dir / f"{key}.json"
    if path.exists():
        try:
            logger.debug("scanner_cache HIT %s", key[:12])
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.warning("scanner_cache corrupt %s: %s — rerunning", path.name, exc)

    result = run_all_fn(target_path, **run_all_kwargs)
    try:
        path.write_text(json.dumps(result), encoding="utf-8")
    except Exception as exc:
        logger.warning("scanner_cache write failed %s: %s", path.name, exc)
    return result
