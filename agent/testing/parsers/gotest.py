"""Parse `go test -json` output.

Emits one JSON object per line (JSONL). Actions of interest: run / pass /
fail / skip. `output` actions carry failure text; we aggregate them per test.
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any

from ..normalize import TestFailure, TestResult

logger = logging.getLogger(__name__)

NAME = "gotest"
_LOCATION_RE = re.compile(r"^\s*([^\s:]+\.go):(\d+):", re.MULTILINE)


def parse(raw: str) -> TestResult:
    passed = failed = skipped = 0
    outputs: dict[tuple[str, str], list[str]] = {}
    final_status: dict[tuple[str, str], str] = {}

    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        test = event.get("Test")
        pkg = event.get("Package") or ""
        if not test:
            continue
        key = (pkg, test)
        action = event.get("Action")
        if action == "output":
            outputs.setdefault(key, []).append(event.get("Output", ""))
        elif action in ("pass", "fail", "skip"):
            final_status[key] = action

    failures: list[TestFailure] = []
    for key, status in final_status.items():
        if status == "pass":
            passed += 1
        elif status == "skip":
            skipped += 1
        elif status == "fail":
            failed += 1
            failures.append(_to_failure(key, "".join(outputs.get(key, []))))

    total = len(final_status)
    return TestResult(
        framework=NAME,
        total=total,
        passed=passed,
        failed=failed,
        errors=0,
        skipped=skipped,
        failures=failures,
    )


def _to_failure(key: tuple[str, str], output: str) -> TestFailure:
    pkg, test = key
    file = None
    line = None
    m = _LOCATION_RE.search(output)
    if m:
        file = m.group(1)
        try:
            line = int(m.group(2))
        except ValueError:
            line = None
    message = _first_meaningful_line(output) or "test failed"
    return TestFailure(
        test=f"{pkg}.{test}" if pkg else test,
        file=file,
        line=line,
        message=message,
        traceback=output or None,
    )


def _first_meaningful_line(output: str) -> str:
    for raw in output.splitlines():
        s = raw.strip()
        if not s:
            continue
        if s.startswith("===") or s.startswith("---"):
            continue
        return s
    return ""
