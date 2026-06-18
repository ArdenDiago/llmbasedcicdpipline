"""Benchmark runner CLI.

Loads datasets from evaluation/datasets/<name>/ which must contain:
  - ground_truth.json   : list of findings (unified format)
  - source/             : (optional) source tree to scan live with the agent
                          and per-tool baselines. When present, the runner
                          invokes scanners and writes <tool>.json into the
                          dataset dir before comparison.
  - <tool>.json         : list of findings (unified format) per tool —
                          either pre-baked or written by --scan.

Emits timestamped CSV + Markdown in evaluation/results/ and reports/.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import logging
from pathlib import Path

from . import compare as _compare
from . import report as _report
from . import scan as _scan

logger = logging.getLogger(__name__)

DATASETS_DIR = Path(__file__).parent / "datasets"
RESULTS_DIR = Path(__file__).parent / "results"
REPORTS_DIR = Path(__file__).parent / "reports"


def load_dataset(path: Path) -> tuple[list[dict], dict[str, list[dict]]]:
    gt_path = path / "ground_truth.json"
    if not gt_path.exists():
        raise FileNotFoundError(f"missing {gt_path}")
    ground_truth = json.loads(gt_path.read_text())

    tool_findings: dict[str, list[dict]] = {}
    for p in sorted(path.glob("*.json")):
        if p.name == "ground_truth.json":
            continue
        tool_findings[p.stem] = json.loads(p.read_text())
    return ground_truth, tool_findings


def run_benchmark(
    datasets_dir: Path = DATASETS_DIR,
    results_dir: Path = RESULTS_DIR,
    reports_dir: Path = REPORTS_DIR,
    line_tolerance: int = 3,
    scan: bool = False,
    now: _dt.datetime | None = None,
) -> dict[str, Path]:
    now = now or _dt.datetime.now(tz=_dt.timezone.utc)
    stamp = now.strftime("%Y%m%dT%H%M%SZ")

    all_rows: list[_compare.ComparisonRow] = []
    for dataset_path in sorted(p for p in datasets_dir.iterdir() if p.is_dir()):
        if scan and (dataset_path / "source").is_dir():
            logger.info("scanning %s", dataset_path.name)
            _scan.scan_dataset(dataset_path)

        truth, tools = load_dataset(dataset_path)
        rows = _compare.compare(
            dataset=dataset_path.name,
            ground_truth=truth,
            tool_findings=tools,
            line_tolerance=line_tolerance,
        )
        all_rows.extend(rows)

    if not all_rows:
        logger.warning("no datasets found under %s", datasets_dir)

    csv_path = _report.write_csv(all_rows, results_dir / f"benchmark-{stamp}.csv")
    md_path = _report.write_markdown(
        all_rows, reports_dir / f"benchmark-{stamp}.md",
        title=f"Benchmark {stamp}",
    )
    return {"csv": csv_path, "markdown": md_path}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run agent benchmark suite")
    parser.add_argument("--datasets-dir", type=Path, default=DATASETS_DIR)
    parser.add_argument("--results-dir", type=Path, default=RESULTS_DIR)
    parser.add_argument("--reports-dir", type=Path, default=REPORTS_DIR)
    parser.add_argument("--line-tolerance", type=int, default=3)
    parser.add_argument(
        "--scan",
        action="store_true",
        help="Run scanners on each dataset's source/ before comparing",
    )
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    paths = run_benchmark(
        datasets_dir=args.datasets_dir,
        results_dir=args.results_dir,
        reports_dir=args.reports_dir,
        line_tolerance=args.line_tolerance,
        scan=args.scan,
    )
    for kind, path in paths.items():
        print(f"{kind}: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
