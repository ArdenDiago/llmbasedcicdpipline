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


def test_dedupe_preserves_dropped_scanners_message_as_corroboration():
    """Regression test: dedupe used to discard the lower-severity
    duplicate's scanner name and message entirely on conflict. A second
    tool independently flagging the same (file, line, CWE) is useful
    evidence for the LLM fix-generation prompt even though only one Finding
    object can be kept."""
    bandit_finding = _finding(
        scanner="bandit", rule_id="B608", cwe="CWE-89", severity="medium",
        message="possible SQL injection via string formatting",
    )
    semgrep_finding = _finding(
        scanner="semgrep", rule_id="python.lang.sqli", cwe="CWE-89", severity="high",
        message="SQL query built from f-string, injection risk",
    )
    deduped = dedupe([bandit_finding, semgrep_finding])
    assert len(deduped) == 1
    kept = deduped[0]
    assert kept.scanner == "semgrep"
    assert kept.extra["corroborated_by"] == [
        {"scanner": "bandit", "rule_id": "B608", "message": "possible SQL injection via string formatting"},
    ]


def test_dedupe_accumulates_corroboration_across_three_scanners():
    a = _finding(scanner="bandit", rule_id="B608", cwe="CWE-89", severity="low", message="m1")
    b = _finding(scanner="semgrep", rule_id="S1", cwe="CWE-89", severity="medium", message="m2")
    c = _finding(scanner="trivy", rule_id="T1", cwe="CWE-89", severity="high", message="m3")
    deduped = dedupe([a, b, c])
    assert len(deduped) == 1
    kept = deduped[0]
    assert kept.scanner == "trivy"
    corroborators = {entry["scanner"] for entry in kept.extra["corroborated_by"]}
    assert corroborators == {"bandit", "semgrep"}


# --- post-repair re-scan check (finding_still_present) ---------------------
from agent.security.normalize import cwes_match, finding_still_present  # noqa: E402

_ORIG = {"scanner": "bandit", "rule_id": "B602", "severity": "high", "file": "app/run.py", "line": 7, "cwe": "CWE-78"}


def _scan(findings, status=None):
    return {"scanners": status or {"bandit": "ok", "semgrep": "ok"}, "findings": findings, "errors": []}


def test_cwes_match_uses_parent_links_both_ways():
    assert cwes_match("CWE-259", "CWE-798") and cwes_match("CWE-798", "CWE-259")
    assert not cwes_match("CWE-78", "CWE-89")
    assert not cwes_match(None, "CWE-78")


def test_still_present_when_same_file_and_cwe_even_if_line_moved():
    scan = _scan([{"scanner": "semgrep", "rule_id": "x", "severity": "high",
                   "file": "app/run.py", "line": 40, "cwe": "CWE-78"}])
    assert finding_still_present(scan, _ORIG) is True


def test_same_rule_still_present_at_any_severity():
    scan = _scan([{"scanner": "bandit", "rule_id": "B602", "severity": "low",
                   "file": "app/run.py", "line": 9, "cwe": "CWE-78"}])
    assert finding_still_present(scan, _ORIG) is True


def test_lower_severity_import_advisory_does_not_block_a_real_fix():
    # B602 shell=True fixed; B404 "import subprocess" (low, CWE-78) remains
    scan = _scan([{"scanner": "bandit", "rule_id": "B404", "severity": "low",
                   "file": "app/run.py", "line": 1, "cwe": "CWE-78"}])
    assert finding_still_present(scan, _ORIG) is False


def test_moving_injection_to_another_high_sink_still_fails():
    scan = _scan([{"scanner": "bandit", "rule_id": "B605", "severity": "high",
                   "file": "app/run.py", "line": 7, "cwe": "CWE-78"}])
    assert finding_still_present(scan, _ORIG) is True


def test_corroborating_scanner_rule_counts_as_same_finding():
    orig = {**_ORIG, "extra": {"corroborated_by": [{"scanner": "semgrep", "rule_id": "sg.shell", "message": "m"}]}}
    scan = _scan([{"scanner": "semgrep", "rule_id": "sg.shell", "severity": "medium",
                   "file": "app/run.py", "line": 7, "cwe": None}])
    assert finding_still_present(scan, orig) is True


def test_cleared_when_cwe_only_in_other_file_or_other_cwe():
    scan = _scan([
        {"scanner": "bandit", "rule_id": "B602", "severity": "high", "file": "app/other.py", "line": 7, "cwe": "CWE-78"},
        {"scanner": "bandit", "rule_id": "B608", "severity": "high", "file": "app/run.py", "line": 9, "cwe": "CWE-89"},
    ])
    assert finding_still_present(scan, _ORIG) is False


def test_no_cwe_falls_back_to_scanner_and_rule():
    orig = {"scanner": "gitleaks", "rule_id": "aws-key", "file": "cfg.py", "cwe": None}
    assert finding_still_present(_scan([{**orig, "line": 3}], {"gitleaks": "ok"}), orig) is True
    other_rule = {**orig, "rule_id": "slack-token"}
    assert finding_still_present(_scan([other_rule], {"gitleaks": "ok"}), orig) is False


def test_unusable_rescan_is_none_not_cleared():
    assert finding_still_present(None, _ORIG) is None
    assert finding_still_present({"error": "boom"}, _ORIG) is None
    assert finding_still_present(_scan([], {"bandit": "timeout"}), _ORIG) is None
    assert finding_still_present(_scan([], {"bandit": "error"}), _ORIG) is None


def test_any_scanner_failure_makes_rescan_unusable():
    scan = _scan([], {"bandit": "ok", "semgrep": "timeout"})
    assert finding_still_present(scan, _ORIG) is None
