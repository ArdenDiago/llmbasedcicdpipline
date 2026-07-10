from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from agent.security.scanners import bandit, gitleaks, semgrep, trivy

FIXTURES = Path(__file__).parent / "fixtures"


def _load(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def test_bandit_parser_extracts_findings_with_cwe():
    findings, errors = bandit.parse(_load("bandit.json"))
    assert len(findings) == 2
    assert errors == []

    b105 = next(f for f in findings if f.rule_id == "B105")
    assert b105.scanner == "bandit"
    assert b105.severity == "low"
    assert b105.confidence == "medium"
    assert b105.file == "app/auth.py"
    assert b105.line == 45
    assert b105.cwe == "CWE-259"
    assert "hardcoded" in b105.message.lower()

    b301 = next(f for f in findings if f.rule_id == "B301")
    assert b301.severity == "high"
    assert b301.cwe == "CWE-502"


def test_bandit_parser_handles_invalid_json():
    assert bandit.parse("not json") == ([], ["bandit produced non-JSON output (exit code 0)"])
    assert bandit.parse("{}") == ([], [])


def test_bandit_parser_surfaces_per_file_errors():
    stdout = json.dumps({
        "errors": [{"filename": "broken.py", "reason": "syntax error while parsing AST"}],
        "results": [],
    })
    findings, errors = bandit.parse(stdout)
    assert findings == []
    assert errors == ["broken.py: syntax error while parsing AST"]


def test_bandit_parser_flags_unexpected_exit_code():
    findings, errors = bandit.parse('{"results": [], "errors": []}', returncode=2)
    assert findings == []
    assert errors == ["bandit exited with unexpected code 2"]


def test_gitleaks_parser_marks_all_as_high_severity():
    findings = gitleaks.parse(_load("gitleaks.json"))
    assert isinstance(findings, list)  # gitleaks.parse() itself is unchanged; run() wraps errors
    assert len(findings) == 1
    f = findings[0]
    assert f.scanner == "gitleaks"
    assert f.severity == "high"
    assert f.rule_id == "generic-api-key"
    assert f.file == "config/settings.py"
    assert f.line == 12
    assert f.cwe == "CWE-798"


def test_gitleaks_parser_handles_empty():
    assert gitleaks.parse("") == []
    assert gitleaks.parse("null") == []


def test_semgrep_parser_maps_severity_and_extracts_cwe():
    findings, errors = semgrep.parse(_load("semgrep.json"))
    assert len(findings) == 2
    assert errors == []

    eval_finding = next(f for f in findings if "eval" in f.rule_id)
    assert eval_finding.scanner == "semgrep"
    assert eval_finding.severity == "high"  # ERROR → high via alias
    assert eval_finding.cwe == "CWE-95"
    assert eval_finding.line == 10

    debug = next(f for f in findings if "debug" in f.rule_id)
    assert debug.severity == "medium"  # WARNING → medium
    assert debug.cwe == "CWE-489"


def test_semgrep_parser_handles_invalid_json():
    assert semgrep.parse("not json") == ([], ["semgrep produced non-JSON output (exit code 0)"])


def test_semgrep_parser_surfaces_top_level_errors():
    stdout = json.dumps({"errors": [{"path": "broken.py", "message": "rule crashed"}], "results": []})
    findings, errors = semgrep.parse(stdout)
    assert findings == []
    assert errors == ["broken.py: rule crashed"]


def test_semgrep_parser_flags_unexpected_exit_code():
    findings, errors = semgrep.parse('{"results": [], "errors": []}', returncode=2)
    assert findings == []
    assert errors == ["semgrep exited with unexpected code 2"]


def test_trivy_parser_covers_vulns_secrets_misconfigs():
    findings, errors = trivy.parse(_load("trivy.json"))
    assert errors == []
    by_rule = {f.rule_id: f for f in findings}

    assert "CVE-2023-32681" in by_rule
    vuln = by_rule["CVE-2023-32681"]
    assert vuln.severity == "medium"
    assert vuln.cwe == "CWE-200"
    assert vuln.file == "requirements.txt"

    assert "aws-access-token" in by_rule
    secret = by_rule["aws-access-token"]
    assert secret.severity == "critical"
    assert secret.cwe == "CWE-798"
    assert secret.line == 3

    assert "DS002" in by_rule
    misconf = by_rule["DS002"]
    assert misconf.severity == "high"
    assert misconf.file == "Dockerfile"
    assert misconf.line == 5


def test_trivy_parser_handles_invalid_json():
    assert trivy.parse("garbage") == ([], ["trivy produced non-JSON output (exit code 0)"])
    assert trivy.parse('{"Results": []}') == ([], [])


def test_trivy_parser_flags_unexpected_exit_code():
    findings, errors = trivy.parse('{"Results": []}', returncode=1)
    assert findings == []
    assert errors == ["trivy exited with unexpected code 1"]


def test_gitleaks_run_surfaces_unexpected_exit_code(tmp_path, monkeypatch):
    import subprocess as sp

    def fake_run(cmd, **kwargs):
        report_path = cmd[cmd.index("--report-path") + 1]
        Path(report_path).write_text("[]", encoding="utf-8")
        return sp.CompletedProcess(args=cmd, returncode=2, stdout="", stderr="bad flag")

    monkeypatch.setattr(gitleaks.subprocess, "run", fake_run)
    findings, errors = gitleaks.run(str(tmp_path))
    assert findings == []
    assert errors == ["gitleaks exited with unexpected code 2: bad flag"]


def test_gitleaks_run_cleans_up_temp_file_on_subprocess_error(tmp_path, monkeypatch):
    """Regression test: the subprocess call must be inside the same
    try/finally that unlinks report_path, not just the read after it —
    otherwise a missing binary/timeout leaves the already-created
    NamedTemporaryFile stranded on disk."""
    created = {}
    real_named_temp = tempfile.NamedTemporaryFile

    def tracking_named_temp(*a, **k):
        real = real_named_temp(*a, **k)
        created["path"] = real.name
        return real

    def fake_run(cmd, **kwargs):
        raise FileNotFoundError("gitleaks")

    monkeypatch.setattr(gitleaks.tempfile, "NamedTemporaryFile", tracking_named_temp)
    monkeypatch.setattr(gitleaks.subprocess, "run", fake_run)

    with pytest.raises(FileNotFoundError):
        gitleaks.run(str(tmp_path))

    assert not Path(created["path"]).exists()
