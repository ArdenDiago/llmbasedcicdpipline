from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from agent.security import run_scan
from agent.security.normalize import Finding

FIXTURES = Path(__file__).parent / "fixtures"


def _fake_proc(stdout: str, returncode: int = 0):
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr="")


def test_run_all_merges_and_dedupes_findings(tmp_path):
    bandit_json = (FIXTURES / "bandit.json").read_text()
    semgrep_json = (FIXTURES / "semgrep.json").read_text()

    def fake_run(cmd, **kwargs):
        first = cmd[0]
        if first == "bandit":
            return _fake_proc(bandit_json, returncode=1)
        if first == "semgrep":
            return _fake_proc(semgrep_json)
        return _fake_proc("{}")

    with patch("subprocess.run", side_effect=fake_run):
        result = run_scan.run_all(
            str(tmp_path), enabled=["bandit", "semgrep"], per_scanner_timeout=5, total_timeout=10
        )

    assert result["scanners"] == {"bandit": "ok", "semgrep": "ok"}
    assert result["errors"] == []
    assert result["stats"]["total_findings"] == 4  # 2 bandit + 2 semgrep
    assert result["stats"]["deduped_findings"] == 4
    rule_ids = {f["rule_id"] for f in result["findings"]}
    assert "B105" in rule_ids
    assert any("eval" in rid for rid in rule_ids)


def test_run_all_relativizes_absolute_paths_scanners_report(tmp_path):
    """Regression test: scanners that receive an absolute target_path on
    their command line (e.g. the sandbox container's /workspace bind mount
    — confirmed empirically for bandit, which reports filenames exactly as
    resolved from the `-r` argument it was given) return absolute "file"
    paths, not paths relative to target_path. Every downstream consumer
    (pipeline.default_file_reader, committer.write_full_file) silently
    breaks on an absolute path because `repo_path / absolute_rel` discards
    repo_path (pathlib join semantics) — so run_all() must relativize
    before returning, matching security/CLAUDE.md's documented "file":
    "app/auth.py" (relative) contract."""
    absolute_finding_path = str(tmp_path / "app" / "auth.py")
    bandit_stdout = json.dumps({
        "results": [{
            "filename": absolute_finding_path,
            "line_number": 12,
            "test_id": "B105",
            "issue_severity": "HIGH",
            "issue_confidence": "HIGH",
            "issue_text": "hardcoded password",
            "issue_cwe": {"id": 259},
            "code": "password = 'x'",
        }],
        "errors": [],
    })

    def fake_run(cmd, **kwargs):
        if cmd[0] == "bandit":
            return _fake_proc(bandit_stdout, returncode=1)
        return _fake_proc("{}")

    with patch("subprocess.run", side_effect=fake_run):
        result = run_scan.run_all(
            str(tmp_path), enabled=["bandit"], per_scanner_timeout=5, total_timeout=10
        )

    assert result["findings"][0]["file"] == str(Path("app") / "auth.py")


def test_run_all_records_error_when_binary_missing(tmp_path):
    def fake_run(cmd, **kwargs):
        raise FileNotFoundError(cmd[0])

    with patch("subprocess.run", side_effect=fake_run):
        result = run_scan.run_all(
            str(tmp_path), enabled=["bandit"], per_scanner_timeout=1, total_timeout=5
        )

    assert result["scanners"] == {"bandit": "error"}
    assert len(result["errors"]) == 1
    assert "binary not found" in result["errors"][0]["error"]
    assert result["findings"] == []


def test_run_all_records_timeout_error(tmp_path):
    def fake_run(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd=cmd, timeout=1)

    with patch("subprocess.run", side_effect=fake_run):
        result = run_scan.run_all(
            str(tmp_path), enabled=["bandit"], per_scanner_timeout=1, total_timeout=5
        )

    assert result["scanners"]["bandit"] == "error"
    assert "timed out" in result["errors"][0]["error"]


def test_run_all_rejects_unknown_scanner(tmp_path):
    with pytest.raises(ValueError, match="unknown scanner"):
        run_scan.run_all(str(tmp_path), enabled=["nope"])


def test_run_all_dedupes_across_scanners(tmp_path):
    bandit_finding = Finding(
        scanner="bandit", rule_id="SHARED", severity="low",
        confidence="medium", file="x.py", line=1, message="lo",
    )
    semgrep_finding = Finding(
        scanner="semgrep", rule_id="SHARED", severity="high",
        confidence="high", file="x.py", line=1, message="hi",
    )

    with patch.object(run_scan.bandit, "run", return_value=([bandit_finding], [])), \
         patch.object(run_scan.semgrep, "run", return_value=([semgrep_finding], [])):
        result = run_scan.run_all(
            str(tmp_path), enabled=["bandit", "semgrep"], per_scanner_timeout=5, total_timeout=10
        )

    assert result["stats"]["total_findings"] == 2
    assert result["stats"]["deduped_findings"] == 1
    kept = result["findings"][0]
    assert kept["severity"] == "high"
    assert kept["scanner"] == "semgrep"


def test_run_all_marks_scanner_error_but_keeps_partial_findings(tmp_path):
    """Regression test: a scanner that failed to parse one file (bandit's own
    top-level `errors` array) must not look identical to a clean scan — but
    findings it *did* produce for other files must not be silently dropped
    either."""
    bandit_json = json.dumps({
        "errors": [{"filename": "broken.py", "reason": "syntax error while parsing AST"}],
        "results": [
            {
                "filename": "app/auth.py",
                "issue_severity": "LOW",
                "issue_confidence": "MEDIUM",
                "issue_text": "hardcoded password",
                "test_id": "B105",
                "line_number": 45,
            }
        ],
    })

    def fake_run(cmd, **kwargs):
        return _fake_proc(bandit_json, returncode=1)

    with patch("subprocess.run", side_effect=fake_run):
        result = run_scan.run_all(
            str(tmp_path), enabled=["bandit"], per_scanner_timeout=5, total_timeout=10
        )

    assert result["scanners"]["bandit"] == "error"
    assert any("broken.py" in e["error"] for e in result["errors"])
    assert result["stats"]["total_findings"] == 1
    assert result["findings"][0]["rule_id"] == "B105"


def test_run_all_total_timeout_bounds_wall_clock_and_keeps_completed_results(tmp_path):
    """Regression test: a `with ThreadPoolExecutor() as pool:` block's
    __exit__ always calls shutdown(wait=True), which blocks until every
    submitted thread finishes regardless of any total_timeout handled inside
    the block — the old code took as long as the slowest scanner no matter
    what total_timeout said, and (separately) discarded results from
    scanners that finished after the timeout fired but before the executor
    actually returned. This asserts both are fixed: run_all() itself returns
    close to total_timeout, and the scanner that finished in time keeps its
    finding."""
    import time

    def fake_run(cmd, **kwargs):
        if cmd[0] == "trivy":
            time.sleep(2)  # far longer than total_timeout below
            return _fake_proc("{}")
        return _fake_proc(
            json.dumps({"errors": [], "results": [
                {"filename": "app/auth.py", "issue_severity": "LOW",
                 "issue_confidence": "MEDIUM", "issue_text": "hardcoded password",
                 "test_id": "B105", "line_number": 45},
            ]}),
            returncode=1,
        )

    with patch("subprocess.run", side_effect=fake_run):
        started = time.monotonic()
        result = run_scan.run_all(
            str(tmp_path), enabled=["bandit", "trivy"],
            per_scanner_timeout=5, total_timeout=0.3,
        )
        elapsed = time.monotonic() - started

    assert elapsed < 1.5, f"run_all() blocked for {elapsed:.2f}s despite total_timeout=0.3s"
    assert result["scanners"]["trivy"] == "timeout"
    assert result["scanners"]["bandit"] == "ok"
    assert result["findings"][0]["rule_id"] == "B105"


def test_cli_emits_json(tmp_path, capsys):
    with patch.object(run_scan, "run_all", return_value={"target": str(tmp_path), "findings": []}):
        exit_code = run_scan.main(["--path", str(tmp_path), "--scanners", "bandit"])
    assert exit_code == 0
    out = capsys.readouterr().out
    parsed = json.loads(out)
    assert parsed["target"] == str(tmp_path)
