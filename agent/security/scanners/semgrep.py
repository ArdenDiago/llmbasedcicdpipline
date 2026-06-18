"""Semgrep runner + parser."""
from __future__ import annotations

import json
import logging
import re
import subprocess
from typing import Any

from ..normalize import Finding, normalize_confidence, normalize_severity

logger = logging.getLogger(__name__)

NAME = "semgrep"
_CWE_RE = re.compile(r"CWE-\d+")


def run(target_path: str, timeout: int = 180) -> list[Finding]:
    cmd = [
        "semgrep",
        "scan",
        "--config",
        "auto",
        "--json",
        "--quiet",
        "--error",
        target_path,
    ]
    logger.debug("semgrep: %s", " ".join(cmd))
    proc = subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout, check=False
    )
    return parse(proc.stdout or "{}")


def parse(stdout: str) -> list[Finding]:
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        logger.warning("semgrep output was not valid JSON")
        return []
    results = data.get("results") or []
    return [_to_finding(r) for r in results if isinstance(r, dict)]


def _to_finding(r: dict[str, Any]) -> Finding:
    extra = r.get("extra") or {}
    metadata = extra.get("metadata") or {}
    cwe = _extract_cwe(metadata.get("cwe"))
    start = r.get("start") or {}
    confidence_meta = metadata.get("confidence") or extra.get("severity")
    return Finding(
        scanner=NAME,
        rule_id=str(r.get("check_id", "")),
        severity=normalize_severity(extra.get("severity")),
        confidence=normalize_confidence(confidence_meta),
        file=str(r.get("path", "")),
        line=start.get("line"),
        message=str(extra.get("message") or r.get("check_id") or ""),
        cwe=cwe,
        snippet=extra.get("lines"),
    )


def _extract_cwe(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, list):
        for item in value:
            m = _CWE_RE.search(str(item))
            if m:
                return m.group(0)
        return None
    m = _CWE_RE.search(str(value))
    return m.group(0) if m else None
