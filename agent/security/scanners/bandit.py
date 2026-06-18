"""Bandit runner + parser.

Bandit exits with code 1 when findings exist — that is NOT an error.
"""
from __future__ import annotations

import json
import logging
import subprocess
from typing import Any

from ..normalize import Finding, normalize_confidence, normalize_severity

logger = logging.getLogger(__name__)

NAME = "bandit"


def run(target_path: str, timeout: int = 180) -> list[Finding]:
    cmd = ["bandit", "-r", target_path, "-f", "json", "--quiet"]
    logger.debug("bandit: %s", " ".join(cmd))
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    return parse(proc.stdout or "{}")


def parse(stdout: str) -> list[Finding]:
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        logger.warning("bandit output was not valid JSON")
        return []
    results = data.get("results") or []
    return [_to_finding(r) for r in results if isinstance(r, dict)]


def _to_finding(r: dict[str, Any]) -> Finding:
    cwe_id = None
    cwe = r.get("issue_cwe")
    if isinstance(cwe, dict) and cwe.get("id") is not None:
        cwe_id = f"CWE-{cwe['id']}"
    return Finding(
        scanner=NAME,
        rule_id=str(r.get("test_id", "")),
        severity=normalize_severity(r.get("issue_severity")),
        confidence=normalize_confidence(r.get("issue_confidence")),
        file=str(r.get("filename", "")),
        line=r.get("line_number"),
        message=str(r.get("issue_text", "")),
        cwe=cwe_id,
        snippet=r.get("code"),
    )
