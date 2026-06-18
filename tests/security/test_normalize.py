from __future__ import annotations

from agent.security.normalize import (
    Finding,
    dedupe,
    normalize_confidence,
    normalize_severity,
    severity_rank,
)


def _finding(**over):
    base = dict(
        scanner="bandit",
        rule_id="B105",
        severity="low",
        confidence="medium",
        file="app/auth.py",
        line=45,
        message="Possible hardcoded password",
    )
    base.update(over)
    return Finding(**base)


def test_normalize_severity_handles_aliases_and_case():
    assert normalize_severity("HIGH") == "high"
    assert normalize_severity("error") == "high"
    assert normalize_severity("warning") == "medium"
    assert normalize_severity("unknown") == "info"
    assert normalize_severity(None) == "info"
    assert normalize_severity("garbage") == "info"


def test_normalize_confidence_defaults_to_medium():
    assert normalize_confidence("HIGH") == "high"
    assert normalize_confidence(None) == "medium"
    assert normalize_confidence("nonsense") == "medium"


def test_severity_rank_ordering():
    assert severity_rank("critical") > severity_rank("high")
    assert severity_rank("high") > severity_rank("medium")
    assert severity_rank("medium") > severity_rank("low")
    assert severity_rank("low") > severity_rank("info")


def test_dedupe_keeps_highest_severity_on_conflict():
    low = _finding(severity="low", scanner="bandit")
    high = _finding(severity="high", scanner="semgrep")
    deduped = dedupe([low, high])
    assert len(deduped) == 1
    assert deduped[0].severity == "high"
    assert deduped[0].scanner == "semgrep"


def test_dedupe_preserves_distinct_findings():
    a = _finding(file="a.py", line=1, rule_id="R1")
    b = _finding(file="b.py", line=1, rule_id="R1")
    c = _finding(file="a.py", line=2, rule_id="R1")
    d = _finding(file="a.py", line=1, rule_id="R2")
    deduped = dedupe([a, b, c, d])
    assert len(deduped) == 4


def test_dedupe_stable_when_severities_equal():
    first = _finding(severity="high", scanner="first")
    second = _finding(severity="high", scanner="second")
    deduped = dedupe([first, second])
    assert len(deduped) == 1
    assert deduped[0].scanner == "first"


def test_dedupe_collapses_same_cwe_across_scanners():
    bandit_finding = _finding(scanner="bandit", rule_id="B608", cwe="CWE-89", severity="medium")
    semgrep_finding = _finding(scanner="semgrep", rule_id="python.lang.sqli", cwe="CWE-89", severity="high")
    deduped = dedupe([bandit_finding, semgrep_finding])
    assert len(deduped) == 1
    assert deduped[0].scanner == "semgrep"  # higher severity wins


def test_dedupe_keeps_distinct_cwes_at_same_line():
    a = _finding(rule_id="R1", cwe="CWE-89")
    b = _finding(rule_id="R2", cwe="CWE-78")
    deduped = dedupe([a, b])
    assert len(deduped) == 2
