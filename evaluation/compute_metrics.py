"""
Compute real detection metrics for all datasets and tools.
Usage: python evaluation/compute_metrics.py
"""
from __future__ import annotations
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
from evaluation.metrics import detection

DATASETS = REPO / "evaluation" / "datasets"

CONFIGS = [
    ("python_vulns",          ["bandit_baseline", "semgrep_baseline"]),
    ("python_vulns_extended", ["bandit_baseline", "semgrep_baseline"]),
    ("js_vulns",              ["bandit_baseline", "semgrep_baseline"]),
    ("js_vulns_extended",     ["bandit_baseline", "semgrep_baseline"]),
]


def load_json(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return json.loads(path.read_text())


def fmt(v: float) -> str:
    return f"{v:.3f}"


print(f"{'dataset':<28} {'tool':<22} {'N':>4} {'TP':>4} {'FP':>4} {'FN':>4} {'P':>6} {'R':>6} {'F1':>6}")
print("-" * 92)

for ds_name, tools in CONFIGS:
    ds_dir = DATASETS / ds_name
    gt = load_json(ds_dir / "ground_truth.json")
    N = len(gt)
    for tool in tools:
        findings = load_json(ds_dir / f"{tool}.json")
        m = detection(findings, gt)
        print(
            f"{ds_name:<28} {tool:<22} {N:>4} {m.true_positives:>4} "
            f"{m.false_positives:>4} {m.false_negatives:>4} "
            f"{fmt(m.precision):>6} {fmt(m.recall):>6} {fmt(m.f1):>6}"
        )
    print()
