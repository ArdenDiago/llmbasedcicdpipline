"""Parse pytest-json-report output.

The plugin writes a single JSON document with a `summary` block and a `tests`
array. Schema: https://pypi.org/project/pytest-json-report/
"""
from __future__ import annotations

import json
import logging
from typing import Any

from ..normalize import TestFailure, TestResult

logger = logging.getLogger(__name__)

NAME = "pytest"


def parse(raw: str) -> TestResult:
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        logger.warning("pytest report was not valid JSON")
        return TestResult(framework=NAME, error="pytest report was not valid JSON")

    summary = data.get("summary") or {}
    tests = data.get("tests") or []

    failures: list[TestFailure] = []
    for t in tests:
        outcome = t.get("outcome")
        if outcome not in ("failed", "error"):
            continue
        failures.append(_to_failure(t))

    return TestResult(
        framework=NAME,
        total=int(summary.get("total", len(tests))),
        passed=int(summary.get("passed", 0)),
        failed=int(summary.get("failed", 0)),
        errors=int(summary.get("error", 0)),
        skipped=int(summary.get("skipped", 0)),
        failures=failures,
        duration_seconds=_duration(data),
    )


def _to_failure(t: dict[str, Any]) -> TestFailure:
    nodeid = str(t.get("nodeid", ""))
    call = t.get("call") or {}
    setup = t.get("setup") or {}
    crash = call.get("crash") or setup.get("crash") or {}
    longrepr = call.get("longrepr") or setup.get("longrepr")

    file = crash.get("path") or (nodeid.split("::", 1)[0] if "::" in nodeid else None)
    line = crash.get("lineno")
    message = (
        crash.get("message")
        or (longrepr.splitlines()[-1] if isinstance(longrepr, str) and longrepr else "")
        or t.get("outcome", "failed")
    )
    return TestFailure(
        test=nodeid,
        file=file,
        line=line,
        message=str(message),
        traceback=longrepr if isinstance(longrepr, str) else None,
    )


def _duration(data: dict[str, Any]) -> float | None:
    d = data.get("duration")
    return float(d) if isinstance(d, (int, float)) else None
