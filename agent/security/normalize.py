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


# Narrow set of well-known CWE parent links — lets ground truth / the original
# finding use the broader category while still matching a scanner that emits
# the specific child. Keys are children, values are parents. Matching is
# bidirectional. Shared by the live post-repair re-scan (finding_still_present)
# and evaluation/metrics.py, so "fixed" means the same thing in both.
CWE_PARENT = {
    "CWE-259": "CWE-798",   # Hardcoded password ⊂ Hardcoded credentials
    "CWE-321": "CWE-798",   # Hardcoded crypto key ⊂ Hardcoded credentials
    "CWE-916": "CWE-327",   # Weak password hash ⊂ Broken/risky crypto
    "CWE-326": "CWE-327",   # Inadequate encryption strength ⊂ Broken crypto
    "CWE-328": "CWE-327",   # Reversible one-way hash ⊂ Broken crypto
}


def cwes_match(a: str | None, b: str | None) -> bool:
    if not a or not b:
        return False
    if a == b:
        return True
    return CWE_PARENT.get(a) == b or CWE_PARENT.get(b) == a


def finding_still_present(scan: dict[str, Any] | None, finding: dict[str, Any]) -> bool | None:
    """Post-repair re-scan check: is `finding` still reported in `scan`?

    `scan` is a run_scan.run_all() envelope from re-scanning the *patched*
    tree. Returns True (still flagged), False (cleared), or None when the
    re-scan cannot be trusted to answer — no envelope, a top-level error, or
    any scanner that did not finish cleanly. Callers must
    treat None as "not verified" (fail closed), never as "cleared".

    The finding counts as still present when, in the same file (lines are
    ignored, since a patch shifts them):
      - the same scanner reports the same rule_id again (or a scanner that
        corroborated it at dedupe time reports its rule again), or
      - any scanner reports the same CWE (parent links included) at the
        finding's severity or higher.
    The severity floor is what keeps a correct fix from being rejected by
    import-level advisories: replacing `subprocess.call(cmd, shell=True)`
    (Bandit B602, high, CWE-78) with an argument list leaves Bandit's B404
    "import subprocess" (low, CWE-78) in the file forever. Moving the same
    injection to another high-severity sink (B605 os.system) still fails.
    Findings without a CWE match on scanner + rule_id only.
    """
    if not isinstance(scan, dict) or scan.get("error") or not isinstance(scan.get("findings"), list):
        return None
    # Any scanner that did not finish cleanly makes the re-scan incomplete:
    # the same CWE could be reported by a different tool than the one that
    # raised the finding, so only an all-"ok" re-scan can clear it.
    if any(s != "ok" for s in (scan.get("scanners") or {}).values()):
        return None
    target = finding.get("file") or ""
    cwe = finding.get("cwe")
    floor = severity_rank(finding.get("severity"))
    same_rule = {(finding.get("scanner"), finding.get("rule_id"))}
    for c in (finding.get("extra") or {}).get("corroborated_by") or []:
        same_rule.add((c.get("scanner"), c.get("rule_id")))
    for f in scan["findings"]:
        if (f.get("file") or "") != target:
            continue
        if (f.get("scanner"), f.get("rule_id")) in same_rule:
            return True
        if cwe and cwes_match(f.get("cwe"), cwe) and severity_rank(f.get("severity")) >= floor:
            return True
    return False


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
