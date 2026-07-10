"""Gitleaks runner + parser.

Gitleaks `detect --no-git --source <path> -f json -r <file>` writes a JSON
array to the report file. When leaks are found the exit code is non-zero.
"""
from __future__ import annotations

import json
import logging
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from ..normalize import Finding, normalize_confidence, normalize_severity

logger = logging.getLogger(__name__)

NAME = "gitleaks"


def run(target_path: str, timeout: int = 180) -> tuple[list[Finding], list[str]]:
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        report_path = tmp.name
    cmd = [
        "gitleaks",
        "detect",
        "--no-git",
        "--source",
        target_path,
        "--report-format",
        "json",
        "--report-path",
        report_path,
        "--exit-code",
        "0",
    ]
    logger.debug("gitleaks: %s", " ".join(cmd))
    errors: list[str] = []
    try:
        # The subprocess call itself must be inside this try/finally, not
        # just the report read below it — otherwise a missing binary or a
        # timeout leaves the NamedTemporaryFile (already created above)
        # stranded on disk on every such error path.
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        try:
            raw = Path(report_path).read_text(encoding="utf-8")
        except FileNotFoundError:
            raw = ""
    finally:
        Path(report_path).unlink(missing_ok=True)
    # --exit-code 0 forces success even when leaks are found, so any
    # non-zero code here is a real invocation failure, not "leaks found".
    if proc.returncode != 0:
        errors.append(f"gitleaks exited with unexpected code {proc.returncode}: {proc.stderr.strip()}")
    return parse(raw), errors


def parse(stdout: str) -> list[Finding]:
    if not stdout.strip():
        return []
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        logger.warning("gitleaks output was not valid JSON")
        return []
    if not isinstance(data, list):
        return []
    return [_to_finding(r) for r in data if isinstance(r, dict)]


def _to_finding(r: dict[str, Any]) -> Finding:
    return Finding(
        scanner=NAME,
        rule_id=str(r.get("RuleID", "")),
        severity=normalize_severity("high"),  # any leaked secret is high
        confidence=normalize_confidence("high"),
        file=str(r.get("File", "")),
        line=r.get("StartLine"),
        message=str(r.get("Description") or r.get("RuleID") or "leak detected"),
        cwe="CWE-798",  # Use of Hard-coded Credentials
        snippet=r.get("Match"),
    )
