from __future__ import annotations

from pathlib import Path

from agent.testing.parsers import gotest, jest, pytest

FIXTURES = Path(__file__).parent / "fixtures"


def _load(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def test_pytest_parser_extracts_counts_and_failures():
    result = pytest.parse(_load("pytest_report.json"))

    assert result.framework == "pytest"
    assert result.total == 4
    assert result.passed == 2
    assert result.failed == 1
    assert result.errors == 1
    assert result.duration_seconds == 1.234

    titles = [f.test for f in result.failures]
    assert "tests/test_auth.py::test_login" in titles
    assert "tests/test_db.py::test_connect" in titles

    login = next(f for f in result.failures if "test_login" in f.test)
    assert login.file == "tests/test_auth.py"
    assert login.line == 23
    assert "expected 200" in login.message
    assert login.traceback and "AssertionError" in login.traceback


def test_pytest_parser_handles_invalid_json():
    result = pytest.parse("not json")
    assert result.framework == "pytest"
    assert result.error is not None
    assert result.total == 0


def test_jest_parser_extracts_counts_and_failures():
    result = jest.parse(_load("jest_report.json"))

    assert result.framework == "jest"
    assert result.total == 5
    assert result.passed == 3
    assert result.failed == 2
    assert result.duration_seconds == 2.5

    titles = [f.test for f in result.failures]
    assert "auth logs in valid user" in titles
    assert "auth rejects invalid token" in titles

    logs_in = next(f for f in result.failures if "logs in" in f.test)
    assert logs_in.file == "/repo/tests/auth.test.js"
    assert logs_in.line == 10
    assert "Expected: 200" in (logs_in.traceback or "")


def test_jest_parser_handles_missing_location():
    result = jest.parse(_load("jest_report.json"))
    rejects = next(f for f in result.failures if "rejects" in f.test)
    assert rejects.line is None
    assert rejects.file == "/repo/tests/auth.test.js"


def test_gotest_parser_aggregates_jsonl_stream():
    result = gotest.parse(_load("gotest_output.jsonl"))

    assert result.framework == "gotest"
    assert result.total == 3
    assert result.passed == 1
    assert result.failed == 1
    assert result.skipped == 1

    assert len(result.failures) == 1
    fail = result.failures[0]
    assert fail.test == "example.com/app.TestDivide"
    assert fail.file == "math_test.go"
    assert fail.line == 42
    assert "expected 5, got 3" in fail.message


def test_gotest_parser_ignores_invalid_lines():
    mixed = 'not json\n{"Action":"pass","Package":"p","Test":"T"}\ngarbage\n'
    result = gotest.parse(mixed)
    assert result.passed == 1
    assert result.failed == 0
