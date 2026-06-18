"""Aggregate multi-seed benchmark CSVs into mean ± stdev per (dataset, tool).

Reads every benchmark-*.csv under a directory (one per seed), groups by
(dataset, tool), reports mean ± stdev for detection_rate / precision /
recall / f1, plus mean tp/fp/fn.

Used by Phase 1 of RUN_PLAN.md to bound run-to-run variance from scanner
non-determinism (e.g. semgrep auto-rule fetches).
"""
from __future__ import annotations

import argparse
import csv
import math
import statistics
from collections import defaultdict
from pathlib import Path

METRIC_COLS = ("detection_rate", "precision", "recall", "f1")
COUNT_COLS = ("tp", "fp", "fn")


def _load_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8") as f:
        return list(csv.DictReader(f))


def _stats(vals: list[float]) -> tuple[float, float]:
    if not vals:
        return (math.nan, math.nan)
    if len(vals) == 1:
        return (vals[0], 0.0)
    return (statistics.fmean(vals), statistics.stdev(vals))


def aggregate(results_dir: Path) -> str:
    csv_files = sorted(results_dir.glob("benchmark-*.csv"))
    if not csv_files:
        return f"# Multi-seed aggregate\n\nNo CSVs found under `{results_dir}`.\n"

    # group rows by (dataset, tool)
    by_key: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    for p in csv_files:
        for row in _load_csv(p):
            by_key[(row["dataset"], row["tool"])].append(row)

    lines = [
        f"# Multi-seed detection benchmark — {len(csv_files)} seeds",
        "",
        f"Source: `{results_dir}`",
        "",
        "| dataset | tool | n | tp (mean) | fp (mean) | fn (mean) "
        "| detection_rate | precision | recall | f1 |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for (ds, tool), rows in sorted(by_key.items()):
        n = len(rows)
        counts = {c: _stats([float(r[c]) for r in rows]) for c in COUNT_COLS}
        metrics = {m: _stats([float(r[m]) for r in rows]) for m in METRIC_COLS}
        lines.append(
            "| {ds} | {tool} | {n} | {tp} | {fp} | {fn} | {dr} | {pr} | {rc} | {f1} |".format(
                ds=ds,
                tool=tool,
                n=n,
                tp=f"{counts['tp'][0]:.1f}",
                fp=f"{counts['fp'][0]:.1f}",
                fn=f"{counts['fn'][0]:.1f}",
                dr=_fmt(metrics["detection_rate"]),
                pr=_fmt(metrics["precision"]),
                rc=_fmt(metrics["recall"]),
                f1=_fmt(metrics["f1"]),
            )
        )
    lines.append("")
    return "\n".join(lines)


def _fmt(stats: tuple[float, float]) -> str:
    mean, sd = stats
    if math.isnan(mean):
        return "—"
    return f"{mean:.3f} ± {sd:.3f}"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("results_dir", type=Path, help="dir containing benchmark-*.csv")
    p.add_argument("--out", type=Path, help="write to file (else stdout)")
    args = p.parse_args(argv)

    md = aggregate(args.results_dir)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(md, encoding="utf-8")
        print(f"wrote {args.out}")
    else:
        print(md)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
