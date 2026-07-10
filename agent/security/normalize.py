"""Unified finding format + dedupe + severity ranking."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field, replace
from typing import Any

SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}

_SEVERITY_ALIASES = {
    "unknown": "info",
    "none": "info",
    "informational": "info",
    "warning": "medium",
    "error": "high",
    "moderate": "medium",
}


def normalize_severity(value: str | None) -> str:
    if not value:
        return "info"
    v = value.strip().lower()
    v = _SEVERITY_ALIASES.get(v, v)
    return v if v in SEVERITY_RANK else "info"


def normalize_confidence(value: str | None) -> str:
    if not value:
        return "medium"
    v = value.strip().lower()
    return v if v in {"high", "medium", "low"} else "medium"


def severity_rank(value: str | None) -> int:
    return SEVERITY_RANK.get(normalize_severity(value), 0)


@dataclass
class Finding:
    scanner: str
    rule_id: str
    severity: str
    confidence: str
    file: str
    line: int | None
    message: str
    cwe: str | None = None
    snippet: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def dedupe(findings: list[Finding]) -> list[Finding]:
    """Collapse duplicate findings.

    When CWE is present, key is (file, line, CWE) — this collapses cases
    where multiple scanners flag the same vuln under different rule IDs.
    Otherwise falls back to (file, line, rule_id). On conflict, keep the
    highest severity; ties are broken by first occurrence.

    The dropped duplicate's scanner/rule_id/message aren't discarded outright
    — they're recorded under the kept Finding's extra["corroborated_by"], so
    a second tool flagging the same issue is still visible to downstream
    consumers (e.g. the LLM fix-generation prompt) even though only one
    Finding object survives.
    """
    by_key: dict[tuple, Finding] = {}
    for f in findings:
        if f.cwe:
            key = ("cwe", f.file, f.line, f.cwe)
        else:
            key = ("rule", f.file, f.line, f.rule_id)
        existing = by_key.get(key)
        if existing is None:
            by_key[key] = f
        elif severity_rank(f.severity) > severity_rank(existing.severity):
            by_key[key] = _corroborate(f, existing)
        else:
            by_key[key] = _corroborate(existing, f)
    return list(by_key.values())


def _corroborate(kept: Finding, other: Finding) -> Finding:
    if kept.scanner == other.scanner:
        return kept
    corroborated = list(kept.extra.get("corroborated_by") or [])
    corroborated.append({"scanner": other.scanner, "rule_id": other.rule_id, "message": other.message})
    corroborated.extend(other.extra.get("corroborated_by") or [])
    return replace(kept, extra={**kept.extra, "corroborated_by": corroborated})
