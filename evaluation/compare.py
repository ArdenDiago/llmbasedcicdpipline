"""Compare agent findings vs baselines (Checkov, Semgrep) on the same dataset.

Inputs are JSON lists already normalized into the unified finding format
from agent.security.normalize.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from . import metrics


@dataclass
class ToolResult:
    name: str
    detection: metrics.DetectionMetrics


@dataclass
class ComparisonRow:
    dataset: str
    tool: str
    tp: int
    fp: int
    fn: int
    detection_rate: float
    precision: float
    recall: float
    f1: float


def compare(
    dataset: str,
    ground_truth: list[dict[str, Any]],
    tool_findings: dict[str, list[dict[str, Any]]],
    line_tolerance: int = metrics.DEFAULT_LINE_TOLERANCE,
) -> list[ComparisonRow]:
    rows: list[ComparisonRow] = []
    for tool, findings in tool_findings.items():
        d = metrics.detection(findings, ground_truth, line_tolerance)
        rows.append(
            ComparisonRow(
                dataset=dataset,
                tool=tool,
                tp=d.true_positives,
                fp=d.false_positives,
                fn=d.false_negatives,
                detection_rate=d.detection_rate,
                precision=d.precision,
                recall=d.recall,
                f1=d.f1,
            )
        )
    return rows
