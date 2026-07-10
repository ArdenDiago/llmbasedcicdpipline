"""Semgrep runner + parser."""
from __future__ import annotations

import json
import logging
import os
import re
import subprocess
from typing import Any

from ..normalize import Finding, normalize_confidence, normalize_severity

logger = logging.getLogger(__name__)

NAME = "semgrep"
_CWE_RE = re.compile(r"CWE-\d+")

# Baked into the sandbox image at build time (Project/Dockerfile) as a
# local copy of the same registry rulesets the evaluation harness uses
# (r/python.lang.security etc. — see evaluation/run_scanners.py), so the
# ephemeral sandbox can scan without --config auto's registry API call,
# which needs network the sandbox doesn't have (network_disabled=True).
# Absent on a normal dev/eval host, so this is a no-op there and semgrep
# keeps using --config auto exactly as before.
OFFLINE_RULES_DIR = "/opt/semgrep-rules"


def run(target_path: str, timeout: int = 180) -> tuple[list[Finding], list[str]]:
    offline = os.path.isdir(OFFLINE_RULES_DIR)
    config = OFFLINE_RULES_DIR if offline else "auto"
    cmd = [
        "semgrep",
        "scan",
        "--config",
        config,
        "--json",
        "--quiet",
        "--error",
        target_path,
    ]
    # semgrep writes a log file under $HOME even for local --config runs;
    # the sandbox's unprivileged, unmapped UID (65534) has no real home
    # directory, so $HOME must point somewhere writable (the tmpfs /tmp
    # mount) or semgrep crashes with a PermissionError before scanning.
    env = {**os.environ, "HOME": "/tmp"} if offline else None
    logger.debug("semgrep: %s", " ".join(cmd))
    proc = subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout, check=False, env=env
    )
    return parse(proc.stdout or "{}", proc.returncode)


def parse(stdout: str, returncode: int = 0) -> tuple[list[Finding], list[str]]:
    """Returns (findings, errors). `errors` surfaces semgrep's own top-level
    error array (e.g. a rule that crashed on a specific file) plus any
    unexpected exit code, so a partial/failed scan is never indistinguishable
    from "0 findings, clean scan"."""
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        logger.warning("semgrep output was not valid JSON")
        return [], [f"semgrep produced non-JSON output (exit code {returncode})"]
    results = data.get("results") or []
    findings = [_to_finding(r) for r in results if isinstance(r, dict)]
    errors = [_format_error(e) for e in (data.get("errors") or [])]
    # Invoked with --error: exit 0 = no findings, 1 = findings present.
    # Anything else is a real failure (bad rule, crash) that "results: []"
    # alone would otherwise hide.
    if returncode not in (0, 1):
        errors.append(f"semgrep exited with unexpected code {returncode}")
    return findings, errors


def _format_error(e: Any) -> str:
    if isinstance(e, dict):
        msg = e.get("message") or e.get("long_msg") or e.get("type") or "unknown semgrep error"
        path = e.get("path")
        return f"{path}: {msg}" if path else str(msg)
    return str(e)


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
