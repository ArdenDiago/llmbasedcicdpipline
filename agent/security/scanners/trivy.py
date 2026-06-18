"""Trivy filesystem runner + parser.

Covers vulnerabilities, secrets, and misconfigurations from `trivy fs`.
"""
from __future__ import annotations

import json
import logging
import subprocess
from typing import Any

from ..normalize import Finding, normalize_confidence, normalize_severity

logger = logging.getLogger(__name__)

NAME = "trivy"


def run(target_path: str, timeout: int = 180) -> list[Finding]:
    cmd = [
        "trivy",
        "fs",
        "--format",
        "json",
        "--quiet",
        "--scanners",
        "vuln,secret,misconfig",
        target_path,
    ]
    logger.debug("trivy: %s", " ".join(cmd))
    proc = subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout, check=False
    )
    return parse(proc.stdout or "{}")


def parse(stdout: str) -> list[Finding]:
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        logger.warning("trivy output was not valid JSON")
        return []
    findings: list[Finding] = []
    for result in data.get("Results") or []:
        if not isinstance(result, dict):
            continue
        target = result.get("Target", "")
        findings.extend(_vulns(result, target))
        findings.extend(_secrets(result, target))
        findings.extend(_misconfigs(result, target))
    return findings


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
