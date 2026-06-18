"""Parse Jest `--json` output."""
from __future__ import annotations

import json
import logging
from typing import Any

from ..normalize import TestFailure, TestResult

logger = logging.getLogger(__name__)

NAME = "jest"


def parse(raw: str) -> TestResult:
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        logger.warning("jest report was not valid JSON")
        return TestResult(framework=NAME, error="jest report was not valid JSON")

    failures: list[TestFailure] = []
    for suite in data.get("testResults") or []:
        if not isinstance(suite, dict):
            continue
        file = suite.get("testFilePath") or suite.get("name")
        for t in suite.get("testResults") or []:
            if not isinstance(t, dict):
                continue
            if t.get("status") != "failed":
                continue
            failures.append(_to_failure(t, file))

    return TestResult(
        framework=NAME,
        total=int(data.get("numTotalTests", 0)),
        passed=int(data.get("numPassedTests", 0)),
        failed=int(data.get("numFailedTests", 0)),
        errors=int(data.get("numRuntimeErrorTestSuites", 0)),
        skipped=int(data.get("numPendingTests", 0)) + int(data.get("numTodoTests", 0)),
        failures=failures,
        duration_seconds=_duration(data),
    )


def _to_failure(t: dict[str, Any], file: str | None) -> TestFailure:
    messages = t.get("failureMessages") or []
    traceback = "\n".join(str(m) for m in messages) if messages else None
    first_line = (traceback.splitlines()[0] if traceback else "") or t.get("title", "failed")
    location = t.get("location") or {}
    return TestFailure(
        test=str(t.get("fullName") or t.get("title") or ""),
        file=file,
        line=location.get("line"),
        message=first_line.strip(),
        traceback=traceback,
    )


def _duration(data: dict[str, Any]) -> float | None:
    start = data.get("startTime")
    end = data.get("endTime")
    if isinstance(start, (int, float)) and isinstance(end, (int, float)) and end >= start:
        return round((end - start) / 1000.0, 3)
    return None
