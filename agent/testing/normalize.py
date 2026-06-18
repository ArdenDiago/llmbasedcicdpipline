"""Unified test-result format shared by all framework parsers."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class TestFailure:
    test: str
    file: str | None
    line: int | None
    message: str
    traceback: str | None = None


@dataclass
class TestResult:
    framework: str
    total: int = 0
    passed: int = 0
    failed: int = 0
    errors: int = 0
    skipped: int = 0
    failures: list[TestFailure] = field(default_factory=list)
    duration_seconds: float | None = None
    error: str | None = None
    stderr: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
