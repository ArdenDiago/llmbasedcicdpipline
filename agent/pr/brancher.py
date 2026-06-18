"""Deterministic branch naming for automated fixes.

Format: fix/<scanner>-<rule_id>-<short_hash>
"""
from __future__ import annotations

import hashlib
import re

_SLUG_RE = re.compile(r"[^a-z0-9]+")
_MAX_SLUG = 40


def _slugify(value: str) -> str:
    slug = _SLUG_RE.sub("-", value.lower()).strip("-")
    return slug[:_MAX_SLUG] or "unknown"


def short_hash(*parts: str, length: int = 8) -> str:
    digest = hashlib.sha1("::".join(parts).encode("utf-8")).hexdigest()
    return digest[:length]


def branch_name(
    scanner: str,
    rule_id: str,
    file: str,
    line: int | None,
    commit_sha: str,
) -> str:
    """Generate a branch name unique to this finding+commit."""
    h = short_hash(file, str(line or 0), commit_sha)
    return f"fix/{_slugify(scanner)}-{_slugify(rule_id)}-{h}"
