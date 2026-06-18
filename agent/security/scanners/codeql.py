"""CodeQL scanner wrapper (item #3).

CodeQL requires a GitHub-licensed CLI (codeql) and database creation before
analysis. This module provides a best-effort wrapper that:
  1. Checks whether `codeql` is on PATH.
  2. Creates a CodeQL database from the target directory.
  3. Runs the standard security query suites.
  4. Parses SARIF output into the unified Finding format.

If CodeQL is not installed, run() returns an empty list and sets the
CODEQL_UNAVAILABLE flag. The paper records this as "not evaluated" rather
than 0 TP — see Paper/paper/sections/05_results.tex.

Install: https://github.com/github/codeql-action/releases (codeql-bundle)
Minimum version: 2.15.0
"""
from __future__ import annotations

import json
import logging
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

NAME = "codeql"
CODEQL_UNAVAILABLE = not bool(shutil.which("codeql"))

_LANG_SUITE = {
    ".py":   ("python",     "python-security-extended"),
    ".js":   ("javascript", "javascript-security-extended"),
    ".ts":   ("javascript", "javascript-security-extended"),
    ".go":   ("go",         "go-security-extended"),
    ".java": ("java",       "java-security-extended"),
    ".rb":   ("ruby",       "ruby-security-extended"),
}

_CWE_PREFIX = "https://cwe.mitre.org/data/definitions/"


class Finding:
    __slots__ = ("scanner", "rule_id", "severity", "confidence", "file", "line", "message", "cwe", "snippet")

    def __init__(self, **kw: Any) -> None:
        for k in self.__slots__:
            setattr(self, k, kw.get(k, ""))

    def to_dict(self) -> dict:
        return {k: getattr(self, k) for k in self.__slots__}


def _detect_language(path: str) -> tuple[str, str] | None:
    for ext, pair in _LANG_SUITE.items():
        if path.endswith(ext):
            return pair
    return None


def _extract_cwe(tags: list[str]) -> str:
    for tag in tags:
        if tag.startswith(_CWE_PREFIX):
            cwe_id = tag[len(_CWE_PREFIX):].rstrip("/")
            return f"CWE-{cwe_id}"
    return ""


def _parse_sarif(sarif: dict, source_root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for run in sarif.get("runs", []):
        rules: dict[str, dict] = {}
        for rule in run.get("tool", {}).get("driver", {}).get("rules", []):
            rules[rule.get("id", "")] = rule

        for result in run.get("results", []):
            rule_id = result.get("ruleId", "")
            rule_meta = rules.get(rule_id, {})
            tags = (
                rule_meta.get("properties", {}).get("tags", [])
                or rule_meta.get("properties", {}).get("security-severity", [])
            )
            cwe = _extract_cwe(tags if isinstance(tags, list) else [])
            severity = _sarif_severity(result.get("level", "warning"))
            message = result.get("message", {}).get("text", "")

            for loc in result.get("locations", []):
                phys = loc.get("physicalLocation", {})
                art = phys.get("artifactLocation", {})
                rel = art.get("uri", "")
                try:
                    rel = str(Path(rel).relative_to(source_root))
                except (ValueError, TypeError):
                    pass
                line = phys.get("region", {}).get("startLine", 0)
                findings.append(Finding(
                    scanner=NAME,
                    rule_id=rule_id,
                    severity=severity,
                    confidence="medium",
                    file=rel,
                    line=int(line),
                    message=message,
                    cwe=cwe,
                    snippet="",
                ))
    return findings


def _sarif_severity(level: str) -> str:
    return {"error": "high", "warning": "medium", "note": "low"}.get(level, "medium")


def run(source_path: str, timeout: int = 300) -> list[Finding]:
    """Run CodeQL on source_path. Returns [] if CodeQL unavailable."""
    if CODEQL_UNAVAILABLE:
        logger.warning(
            "codeql not found on PATH — install from https://github.com/github/codeql-action/releases. "
            "Returning empty result set; paper records this as 'not evaluated'."
        )
        return []

    src = Path(source_path).resolve()
    lang_pair = _detect_language(str(src)) or ("python", "python-security-extended")
    lang, suite = lang_pair

    with tempfile.TemporaryDirectory(prefix="codeql_db_") as tmp:
        db_path = Path(tmp) / "db"
        sarif_path = Path(tmp) / "results.sarif"

        try:
            subprocess.run(
                ["codeql", "database", "create", str(db_path),
                 f"--language={lang}", f"--source-root={src}"],
                capture_output=True, text=True, timeout=timeout, check=True,
            )
            subprocess.run(
                ["codeql", "database", "analyze", str(db_path),
                 f"codeql/{suite}", "--format=sarif-latest",
                 f"--output={sarif_path}"],
                capture_output=True, text=True, timeout=timeout, check=True,
            )
        except subprocess.CalledProcessError as exc:
            logger.error("codeql failed: %s", exc.stderr[-500:] if exc.stderr else exc)
            return []
        except subprocess.TimeoutExpired:
            logger.error("codeql timed out after %ds", timeout)
            return []

        sarif = json.loads(sarif_path.read_text())
        return _parse_sarif(sarif, src)
