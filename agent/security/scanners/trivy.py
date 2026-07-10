"""Trivy filesystem runner + parser.

Covers vulnerabilities, secrets, and misconfigurations from `trivy fs`.
"""
from __future__ import annotations

import json
import logging
import os
import subprocess
from typing import Any

from ..normalize import Finding, normalize_confidence, normalize_severity

logger = logging.getLogger(__name__)

NAME = "trivy"

# Baked into the sandbox image at build time (Project/Dockerfile) via
# `trivy image --download-db-only --cache-dir OFFLINE_CACHE_DIR`, so the
# ephemeral sandbox — which runs with network_disabled=True — can still
# scan without a live vulnerability-DB fetch. Absent on a normal dev/eval
# host, so this is a no-op there and trivy falls back to its default
# online behavior. `--cache-dir` is passed explicitly rather than relying
# on trivy's $HOME-derived default: the sandbox runs as an unprivileged,
# unmapped UID (65534) whose $HOME doesn't resolve the way trivy expects,
# which silently breaks --skip-db-update even when the DB is present.
OFFLINE_CACHE_DIR = "/opt/trivy-cache"


def run(target_path: str, timeout: int = 180) -> list[Finding]:
    cmd = [
        "trivy",
        "fs",
        "--format",
        "json",
        "--quiet",
        "--scanners",
        "vuln,secret,misconfig",
    ]
    if os.path.isdir(OFFLINE_CACHE_DIR):
        cmd += [
            "--cache-dir", OFFLINE_CACHE_DIR,
            "--skip-db-update",
            "--skip-java-db-update",
            "--skip-check-update",
            "--offline-scan",
        ]
    cmd.append(target_path)
    logger.debug("trivy: %s", " ".join(cmd))
    proc = subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout, check=False
    )
    return parse(proc.stdout or "{}", proc.returncode)


def parse(stdout: str, returncode: int = 0) -> tuple[list[Finding], list[str]]:
    """Returns (findings, errors). No `--exit-code` flag is passed above, so
    trivy exits 0 whenever the scan itself completed (regardless of findings)
    and non-zero only on a real execution failure — surface that instead of
    silently reporting "ok" with 0 findings."""
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        logger.warning("trivy output was not valid JSON")
        return [], [f"trivy produced non-JSON output (exit code {returncode})"]
    findings: list[Finding] = []
    for result in data.get("Results") or []:
        if not isinstance(result, dict):
            continue
        target = result.get("Target", "")
        findings.extend(_vulns(result, target))
        findings.extend(_secrets(result, target))
        findings.extend(_misconfigs(result, target))
    errors: list[str] = []
    if returncode != 0:
        errors.append(f"trivy exited with unexpected code {returncode}")
    return findings, errors


def _vulns(result: dict[str, Any], target: str) -> list[Finding]:
    out = []
    for v in result.get("Vulnerabilities") or []:
        if not isinstance(v, dict):
            continue
        cwe = None
        cwes = v.get("CweIDs") or []
        if cwes:
            cwe = str(cwes[0])
        out.append(
            Finding(
                scanner=NAME,
                rule_id=str(v.get("VulnerabilityID", "")),
                severity=normalize_severity(v.get("Severity")),
                confidence=normalize_confidence("high"),
                file=target,
                line=None,
                message=str(v.get("Title") or v.get("Description") or v.get("VulnerabilityID") or ""),
                cwe=cwe,
                snippet=v.get("PkgName"),
                extra={"installed_version": v.get("InstalledVersion"), "fixed_version": v.get("FixedVersion")},
            )
        )
    return out


def _secrets(result: dict[str, Any], target: str) -> list[Finding]:
    out = []
    for s in result.get("Secrets") or []:
        if not isinstance(s, dict):
            continue
        out.append(
            Finding(
                scanner=NAME,
                rule_id=str(s.get("RuleID", "")),
                severity=normalize_severity(s.get("Severity")),
                confidence=normalize_confidence("high"),
                file=target,
                line=s.get("StartLine"),
                message=str(s.get("Title") or s.get("RuleID") or "secret detected"),
                cwe="CWE-798",
                snippet=s.get("Match"),
            )
        )
    return out


def _misconfigs(result: dict[str, Any], target: str) -> list[Finding]:
    out = []
    for m in result.get("Misconfigurations") or []:
        if not isinstance(m, dict):
            continue
        cause = m.get("CauseMetadata") or {}
        out.append(
            Finding(
                scanner=NAME,
                rule_id=str(m.get("ID", "")),
                severity=normalize_severity(m.get("Severity")),
                confidence=normalize_confidence("medium"),
                file=target,
                line=cause.get("StartLine"),
                message=str(m.get("Title") or m.get("Description") or m.get("ID") or ""),
                cwe=None,
                snippet=cause.get("Code", {}).get("Lines") if isinstance(cause.get("Code"), dict) else None,
            )
        )
    return out
