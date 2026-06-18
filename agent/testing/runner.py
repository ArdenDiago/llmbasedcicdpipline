"""Test runner orchestrator.

Detects the project framework, runs the test suite with a JSON reporter,
and returns a unified TestResult envelope. Handles pytest, Jest, and
`go test` per the module CLAUDE.md.

Designed to be called from inside the sandbox container; subprocess commands
assume the relevant toolchain is present on PATH.
"""
from __future__ import annotations

import argparse
import json
import logging
import subprocess
import sys
import tempfile
from dataclasses import asdict
from pathlib import Path
from typing import Any

from . import detect
from .normalize import TestResult
from .parsers import gotest as gotest_parser
from .parsers import jest as jest_parser
from .parsers import pytest as pytest_parser

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 300

PARSERS = {
    pytest_parser.NAME: pytest_parser,
    jest_parser.NAME: jest_parser,
    gotest_parser.NAME: gotest_parser,
}


def run(
    target_path: str,
    framework: str | None = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> TestResult:
    fw = framework or detect.detect_framework(target_path)
    if fw is None:
        return TestResult(
            framework="unknown",
            error="no supported test framework detected",
        )
    if fw not in PARSERS:
        return TestResult(framework=fw, error=f"unsupported framework: {fw}")

    try:
        if fw == "pytest":
            return _run_pytest(target_path, timeout)
        if fw == "jest":
            return _run_jest(target_path, timeout)
        if fw == "gotest":
            return _run_gotest(target_path, timeout)
    except FileNotFoundError as exc:
        return TestResult(framework=fw, error=f"runner binary not found: {exc}")
    except subprocess.TimeoutExpired:
        return TestResult(framework=fw, error=f"test suite timed out after {timeout}s")
    except Exception as exc:
        logger.exception("test runner %s failed", fw)
        return TestResult(framework=fw, error=f"{type(exc).__name__}: {exc}")

    return TestResult(framework=fw, error="unreachable")


def _run_pytest(target_path: str, timeout: int) -> TestResult:
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        report_path = tmp.name
    try:
        cmd = [
            sys.executable,
            "-m",
            "pytest",
            target_path,
            "--json-report",
            f"--json-report-file={report_path}",
            "-q",
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        try:
            raw = Path(report_path).read_text(encoding="utf-8")
        except FileNotFoundError:
            raw = ""
        if not raw.strip():
            return TestResult(
                framework=pytest_parser.NAME,
                error="pytest did not produce a report (plugin missing?)",
                stderr=proc.stderr,
            )
        result = pytest_parser.parse(raw)
        if proc.returncode not in (0, 1) and result.error is None:
            result.stderr = proc.stderr
        return result
    finally:
        Path(report_path).unlink(missing_ok=True)


def _run_jest(target_path: str, timeout: int) -> TestResult:
    cmd = ["npx", "--yes", "jest", "--json", "--ci"]
    proc = subprocess.run(
        cmd, cwd=target_path, capture_output=True, text=True, timeout=timeout, check=False
    )
    result = jest_parser.parse(proc.stdout or "{}")
    if proc.returncode not in (0, 1) and result.error is None:
        result.error = f"jest exit={proc.returncode}"
        result.stderr = proc.stderr
    return result


def _run_gotest(target_path: str, timeout: int) -> TestResult:
    cmd = ["go", "test", "-json", "./..."]
    proc = subprocess.run(
        cmd, cwd=target_path, capture_output=True, text=True, timeout=timeout, check=False
    )
    result = gotest_parser.parse(proc.stdout or "")
    if proc.returncode not in (0, 1) and result.error is None:
        result.error = f"go test exit={proc.returncode}"
        result.stderr = proc.stderr
    return result


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Run the target repo's test suite and emit unified JSON")
    p.add_argument("--path", required=True, help="Target directory containing the test suite")
    p.add_argument("--framework", choices=sorted(PARSERS.keys()), help="Override auto-detection")
    p.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    result = run(args.path, framework=args.framework, timeout=args.timeout)
    json.dump(asdict(result), sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0 if result.error is None else 2


if __name__ == "__main__":
    sys.exit(main())
