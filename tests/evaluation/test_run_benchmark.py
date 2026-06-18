import datetime as _dt
import json
from pathlib import Path

import pytest

from evaluation import run_benchmark


def _write_dataset(base: Path, name: str, truth: list[dict], tools: dict[str, list[dict]]):
    d = base / name
    d.mkdir(parents=True)
    (d / "ground_truth.json").write_text(json.dumps(truth))
    for tool, findings in tools.items():
        (d / f"{tool}.json").write_text(json.dumps(findings))


def _f(file, rule, line=None):
    return {"file": file, "rule_id": rule, "line": line, "severity": "high"}


def test_load_dataset_missing_ground_truth(tmp_path: Path):
    (tmp_path / "bad").mkdir()
    with pytest.raises(FileNotFoundError):
        run_benchmark.load_dataset(tmp_path / "bad")


def test_run_benchmark_writes_csv_and_markdown(tmp_path: Path):
    datasets = tmp_path / "datasets"
    _write_dataset(
        datasets, "owasp-py",
        truth=[_f("a.py", "B105", 10)],
        tools={
            "agent": [_f("a.py", "B105", 10)],
            "semgrep": [],
        },
    )
    paths = run_benchmark.run_benchmark(
        datasets_dir=datasets,
        results_dir=tmp_path / "results",
        reports_dir=tmp_path / "reports",
        now=_dt.datetime(2026, 4, 18, 12, 0, tzinfo=_dt.timezone.utc),
    )
    csv = paths["csv"].read_text()
    md = paths["markdown"].read_text()
    assert "agent" in csv and "semgrep" in csv
    assert "owasp-py" in csv
    assert paths["csv"].name == "benchmark-20260418T120000Z.csv"
    assert "# Benchmark 20260418T120000Z" in md


def test_run_benchmark_handles_no_datasets(tmp_path: Path):
    datasets = tmp_path / "empty"
    datasets.mkdir()
    paths = run_benchmark.run_benchmark(
        datasets_dir=datasets,
        results_dir=tmp_path / "results",
        reports_dir=tmp_path / "reports",
        now=_dt.datetime(2026, 4, 18, 12, 0, tzinfo=_dt.timezone.utc),
    )
    # CSV is still emitted with headers-only
    assert paths["csv"].exists()
    assert paths["csv"].read_text().strip().splitlines()[0].startswith("dataset,")
