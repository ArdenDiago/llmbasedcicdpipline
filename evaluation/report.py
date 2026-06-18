"""Benchmark report writers: CSV + Markdown."""
from __future__ import annotations

import csv
from dataclasses import asdict
from pathlib import Path
from typing import Iterable

from .compare import ComparisonRow


CSV_HEADERS = [
    "dataset", "tool", "tp", "fp", "fn",
    "detection_rate", "precision", "recall", "f1",
]


def write_csv(rows: Iterable[ComparisonRow], path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=CSV_HEADERS)
        w.writeheader()
        for row in rows:
            w.writerow({k: _fmt(v) for k, v in asdict(row).items()})
    return path


def write_markdown(rows: list[ComparisonRow], path: Path, title: str = "Benchmark Report") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [f"# {title}", "", "| " + " | ".join(CSV_HEADERS) + " |",
             "|" + "|".join(["---"] * len(CSV_HEADERS)) + "|"]
    for row in rows:
        d = asdict(row)
        lines.append("| " + " | ".join(_fmt(d[h]) for h in CSV_HEADERS) + " |")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _fmt(v) -> str:
    if isinstance(v, float):
        return f"{v:.3f}"
    return str(v)
