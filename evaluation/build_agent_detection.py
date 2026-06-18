"""
Build agent.json for each dataset as the union of bandit + semgrep findings.
Deduplicates by (file, line±3, cwe) to avoid double-counting the same vuln.
gitleaks is unavailable in this environment — secrets CWE-798/CWE-259 will
be underreported; paper notes this explicitly.
"""
from __future__ import annotations
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
from evaluation.metrics import _cwes_match

DATASETS = REPO / "evaluation" / "datasets"
LINE_TOL = 3

DATASETS_TO_BUILD = [
    "python_vulns",
    "python_vulns_extended",
    "js_vulns",
    "js_vulns_extended",
]


def _dedup_merge(lists: list[list[dict]]) -> list[dict]:
    merged: list[dict] = []
    for findings in lists:
        for f in findings:
            dup = False
            for existing in merged:
                if existing["file"] != f["file"]:
                    continue
                if not _cwes_match(existing.get("cwe", ""), f.get("cwe", "")):
                    continue
                # Only deduplicate exact same line — different line numbers are
                # different vulnerability instances even if within tolerance.
                if int(existing.get("line", 0)) == int(f.get("line", 0)):
                    dup = True
                    break
            if not dup:
                merged.append(f)
    return merged


def process(ds_name: str) -> None:
    ds_dir = DATASETS / ds_name
    bandit = json.loads((ds_dir / "bandit_baseline.json").read_text()) if (ds_dir / "bandit_baseline.json").exists() else []
    semgrep = json.loads((ds_dir / "semgrep_baseline.json").read_text()) if (ds_dir / "semgrep_baseline.json").exists() else []

    agent = _dedup_merge([bandit, semgrep])
    out = ds_dir / "agent.json"
    out.write_text(json.dumps(agent, indent=2))
    print(f"{ds_name}: bandit={len(bandit)}  semgrep={len(semgrep)}  agent_union={len(agent)}")


if __name__ == "__main__":
    targets = sys.argv[1:] or DATASETS_TO_BUILD
    for ds in targets:
        process(ds)
    print("\nNote: gitleaks unavailable — CWE-798 secrets may be underreported.")
