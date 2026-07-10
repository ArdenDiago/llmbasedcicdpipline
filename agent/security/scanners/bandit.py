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


def run(target_path: str, timeout: int = 180) -> tuple[list[Finding], list[str]]:
    cmd = ["bandit", "-r", target_path, "-f", "json", "--quiet"]
    logger.debug("bandit: %s", " ".join(cmd))
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    return parse(proc.stdout or "{}", proc.returncode)


def parse(stdout: str, returncode: int = 0) -> tuple[list[Finding], list[str]]:
    """Returns (findings, errors). `errors` surfaces bandit's own per-file
    error array (e.g. a syntax error bandit couldn't parse) plus any
    unexpected exit code, so a partial/failed scan is never indistinguishable
    from "0 findings, clean scan"."""
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        logger.warning("bandit output was not valid JSON")
        return [], [f"bandit produced non-JSON output (exit code {returncode})"]
    results = data.get("results") or []
    findings = [_to_finding(r) for r in results if isinstance(r, dict)]
    errors = [_format_error(e) for e in (data.get("errors") or [])]
    # bandit exit codes: 0 = no issues, 1 = issues found. Anything else is a
    # real failure that "results: []" alone would otherwise hide.
    if returncode not in (0, 1):
        errors.append(f"bandit exited with unexpected code {returncode}")
    return findings, errors


def _format_error(e: Any) -> str:
    if isinstance(e, dict):
        return f"{e.get('filename', '?')}: {e.get('reason', 'unknown bandit error')}"
    return str(e)


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
