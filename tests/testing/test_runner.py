from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import patch

from agent.testing import runner

FIXTURES = Path(__file__).parent / "fixtures"


def _completed(stdout: str = "", returncode: int = 0, stderr: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


def test_run_returns_error_when_no_framework_detected(tmp_path: Path):
    result = runner.run(str(tmp_path))
    assert result.framework == "unknown"
    assert "no supported test framework" in (result.error or "")


def test_run_pytest_reads_report_file(tmp_path: Path):
    (tmp_path / "pytest.ini").write_text("[pytest]\n")
    report_body = (FIXTURES / "pytest_report.json").read_text()

    def fake_run(cmd, capture_output, text, timeout, check):
        report_arg = next(a for a in cmd if a.startswith("--json-report-file="))
        report_path = report_arg.split("=", 1)[1]
        Path(report_path).write_text(report_body)
        return _completed(stdout="summary\n", returncode=1)

    with patch("subprocess.run", side_effect=fake_run):
        result = runner.run(str(tmp_path))

    assert result.framework == "pytest"
    assert result.total == 4
    assert result.failed == 1
    assert result.errors == 1


def test_run_pytest_reports_missing_plugin(tmp_path: Path):
    (tmp_path / "pytest.ini").write_text("[pytest]\n")

    def fake_run(cmd, **kwargs):
        return _completed(stdout="", stderr="unknown option --json-report", returncode=2)

    with patch("subprocess.run", side_effect=fake_run):
        result = runner.run(str(tmp_path))

    assert result.framework == "pytest"
    assert result.error is not None
    assert "plugin missing" in result.error


def test_run_jest_parses_stdout(tmp_path: Path):
    (tmp_path / "package.json").write_text('{"devDependencies":{"jest":"^29"}}')
    report_body = (FIXTURES / "jest_report.json").read_text()

    def fake_run(cmd, **kwargs):
        return _completed(stdout=report_body, returncode=1)

    with patch("subprocess.run", side_effect=fake_run):
        result = runner.run(str(tmp_path))

    assert result.framework == "jest"
    assert result.total == 5
    assert result.failed == 2


def test_run_gotest_parses_jsonl(tmp_path: Path):
    (tmp_path / "go.mod").write_text("module x\n")
    body = (FIXTURES / "gotest_output.jsonl").read_text()

    def fake_run(cmd, **kwargs):
        return _completed(stdout=body, returncode=1)

    with patch("subprocess.run", side_effect=fake_run):
        result = runner.run(str(tmp_path))

    assert result.framework == "gotest"
    assert result.total == 3
    assert result.failed == 1


def test_run_handles_timeout(tmp_path: Path):
    (tmp_path / "pytest.ini").write_text("[pytest]\n")

    def fake_run(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd=cmd, timeout=kwargs.get("timeout", 1))

    with patch("subprocess.run", side_effect=fake_run):
        result = runner.run(str(tmp_path), timeout=1)

    assert result.framework == "pytest"
    assert result.error is not None
    assert "timed out" in result.error


def test_run_handles_missing_binary(tmp_path: Path):
    (tmp_path / "package.json").write_text('{"devDependencies":{"jest":"^29"}}')

    def fake_run(cmd, **kwargs):
        raise FileNotFoundError("npx")

    with patch("subprocess.run", side_effect=fake_run):
        result = runner.run(str(tmp_path))

    assert result.framework == "jest"
    assert "binary not found" in (result.error or "")


def test_run_respects_framework_override(tmp_path: Path):
    (tmp_path / "random.txt").write_text("nothing")

    def fake_run(cmd, **kwargs):
        return _completed(stdout="{}", returncode=0)

    with patch("subprocess.run", side_effect=fake_run):
        result = runner.run(str(tmp_path), framework="jest")

    assert result.framework == "jest"
