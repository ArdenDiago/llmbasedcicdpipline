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

    with patch.object(run_scan.bandit, "run", return_value=[bandit_finding]), \
         patch.object(run_scan.semgrep, "run", return_value=[semgrep_finding]):
        result = run_scan.run_all(
            str(tmp_path), enabled=["bandit", "semgrep"], per_scanner_timeout=5, total_timeout=10
        )

    assert result["stats"]["total_findings"] == 2
    assert result["stats"]["deduped_findings"] == 1
    kept = result["findings"][0]
    assert kept["severity"] == "high"
    assert kept["scanner"] == "semgrep"


def test_cli_emits_json(tmp_path, capsys):
    with patch.object(run_scan, "run_all", return_value={"target": str(tmp_path), "findings": []}):
        exit_code = run_scan.main(["--path", str(tmp_path), "--scanners", "bandit"])
    assert exit_code == 0
    out = capsys.readouterr().out
    parsed = json.loads(out)
    assert parsed["target"] == str(tmp_path)
