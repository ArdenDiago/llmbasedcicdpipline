"""
Semgrep ruleset ablation study.
Shows progressive F1 improvement as more rulesets are combined.
Usage:
    python evaluation/ablation_semgrep.py
"""
from __future__ import annotations
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from collections import defaultdict

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
from evaluation.metrics import detection

DATASETS = {
    "python_vulns":          (REPO / "evaluation/datasets/python_vulns",          ["r/python.lang.security", "r/python.lang.security.audit"]),
    "python_vulns_extended": (REPO / "evaluation/datasets/python_vulns_extended",  ["r/python.lang.security", "r/python.lang.security.audit"]),
    "js_vulns":              (REPO / "evaluation/datasets/js_vulns",               ["r/javascript.lang.security", "r/javascript.express", "r/javascript.lang.security.audit"]),
    "js_vulns_extended":     (REPO / "evaluation/datasets/js_vulns_extended",      ["r/javascript.lang.security", "r/javascript.express", "r/javascript.lang.security.audit"]),
}

CONFIGS = {
    "python": ["r/python.lang.security", "r/python.lang.security.audit"],
    "js":     ["r/javascript.lang.security", "r/javascript.express", "r/javascript.lang.security.audit"],
}


def _run_semgrep(src_dir: Path, configs: list[str]) -> list[dict]:
    all_findings: dict[tuple, dict] = {}
    for cfg in configs:
        cmd = ["semgrep", "--config", cfg, "--json", str(src_dir)]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        try:
            data = json.loads(r.stdout)
        except json.JSONDecodeError:
            continue
        for res in data.get("results", []):
            fname = Path(res["path"]).name
            line  = res["start"]["line"]
            rule  = res["check_id"]
            cwe   = next(
                (m["cwe"] for m in res.get("extra", {}).get("metadata", {}).get("cwe", [])
                 if isinstance(m, dict)),
                None
            )
            if not cwe:
                for tag in res.get("extra", {}).get("metadata", {}).get("cwe", []):
                    if isinstance(tag, str) and tag.startswith("CWE-"):
                        cwe = tag.split(":")[0].strip()
                        break
            if not cwe:
                cwe = "CWE-0"
            key = (fname, line, rule)
            if key not in all_findings:
                all_findings[key] = {
                    "file": fname, "line": line, "rule_id": rule,
                    "cwe": cwe, "scanner": "semgrep",
                }
    return list(all_findings.values())


def ablate(ds_name: str, ds_dir: Path, ruleset_pool: list[str]) -> None:
    gt = json.loads((ds_dir / "ground_truth.json").read_text())
    lang = "py" if "python" in ds_name else "js"
    pool = CONFIGS["python"] if lang == "py" else CONFIGS["js"]
    src = ds_dir / "source"

    print(f"\n{'='*60}")
    print(f"Dataset: {ds_name}  (n={len(gt)})")
    print(f"{'packs':<30}  {'P':>6}  {'R':>6}  {'F1':>6}  {'TP':>4}  {'FP':>4}  {'FN':>4}")
    print("-"*60)

    for n in range(1, len(pool) + 1):
        configs = pool[:n]
        label = " + ".join(c.split("/")[-1] for c in configs)
        findings = _run_semgrep(src, configs)
        m = detection(findings, gt)
        print(f"{label:<30}  {m.precision:>6.3f}  {m.recall:>6.3f}  "
              f"{m.f1:>6.3f}  {m.true_positives:>4}  "
              f"{m.false_positives:>4}  {m.false_negatives:>4}")


def main() -> None:
    for ds_name, (ds_dir, pool) in DATASETS.items():
        ablate(ds_name, ds_dir, pool)
    print()


if __name__ == "__main__":
    main()
