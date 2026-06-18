"""
Run bandit + semgrep on all dataset source/ directories and write real baseline JSONs.
Usage: python evaluation/run_scanners.py
"""
from __future__ import annotations
import json
import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DATASETS = REPO / "evaluation" / "datasets"

DATASETS_TO_SCAN = [
    "python_vulns",
    "python_vulns_extended",
    "js_vulns",
    "js_vulns_extended",
]


# ---------------------------------------------------------------------------
# Bandit (Python only)
# ---------------------------------------------------------------------------

def run_bandit(source_dir: Path) -> list[dict]:
    result = subprocess.run(
        ["bandit", "-r", str(source_dir), "-f", "json"],
        capture_output=True, text=True
    )
    # bandit exits 1 when it finds issues — that's fine
    raw = result.stdout or result.stderr
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        print(f"  [bandit] could not parse JSON for {source_dir}", file=sys.stderr)
        return []

    findings = []
    for r in data.get("results", []):
        cwe_id = r.get("issue_cwe", {}).get("id")
        cwe = f"CWE-{cwe_id}" if cwe_id else ""
        findings.append({
            "scanner": "bandit",
            "rule_id": r.get("test_id", ""),
            "severity": r.get("issue_severity", "").lower(),
            "confidence": r.get("issue_confidence", "").lower(),
            "file": Path(r.get("filename", "")).name,
            "line": r.get("line_number", 0),
            "message": r.get("issue_text", ""),
            "cwe": cwe,
            "snippet": r.get("code", ""),
            "extra": {},
        })
    return findings


# ---------------------------------------------------------------------------
# Semgrep
# ---------------------------------------------------------------------------

def run_semgrep(source_dir: Path, lang: str) -> list[dict]:
    ruleset = "p/python" if lang == "python" else "p/javascript"
    result = subprocess.run(
        ["semgrep", "--config", ruleset, "--json",
         "--no-autofix", "--quiet", str(source_dir)],
        capture_output=True, text=True
    )
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        print(f"  [semgrep] could not parse JSON for {source_dir}", file=sys.stderr)
        print(result.stderr[:500], file=sys.stderr)
        return []

    findings = []
    for r in data.get("results", []):
        meta = r.get("extra", {}).get("metadata", {})
        # CWE can be a list or a string
        raw_cwe = meta.get("cwe") or meta.get("cwe-id") or ""
        if isinstance(raw_cwe, list):
            raw_cwe = raw_cwe[0] if raw_cwe else ""
        # normalise "CWE-89: ..." → "CWE-89"
        if raw_cwe and ":" in raw_cwe:
            raw_cwe = raw_cwe.split(":")[0].strip()
        # extract just the number if it's "CWE-89" already
        cwe = raw_cwe if raw_cwe.startswith("CWE-") else (f"CWE-{raw_cwe}" if raw_cwe else "")

        severity = r.get("extra", {}).get("severity", "").lower()
        # semgrep severities: ERROR→high, WARNING→medium, INFO→low
        sev_map = {"error": "high", "warning": "medium", "info": "low"}
        severity = sev_map.get(severity, severity)

        start = r.get("start", {})
        findings.append({
            "scanner": "semgrep",
            "rule_id": r.get("check_id", ""),
            "severity": severity,
            "confidence": meta.get("confidence", "medium").lower(),
            "file": Path(r.get("path", "")).name,
            "line": start.get("line", 0),
            "message": r.get("extra", {}).get("message", ""),
            "cwe": cwe,
            "snippet": r.get("extra", {}).get("lines", ""),
            "extra": {},
        })
    return findings


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def process(dataset: str) -> None:
    ds_dir = DATASETS / dataset
    source_dir = ds_dir / "source"
    if not source_dir.is_dir():
        print(f"  skip {dataset}: no source/ dir")
        return

    py_files = list(source_dir.glob("*.py"))
    js_files = list(source_dir.glob("*.js")) + list(source_dir.glob("*.ts"))

    print(f"\n=== {dataset} ===")

    if py_files:
        print("  running bandit...")
        bandit_out = run_bandit(source_dir)
        out_path = ds_dir / "bandit_baseline.json"
        out_path.write_text(json.dumps(bandit_out, indent=2))
        print(f"  bandit: {len(bandit_out)} findings → {out_path.name}")

        print("  running semgrep (python)...")
        semgrep_out = run_semgrep(source_dir, "python")
        out_path = ds_dir / "semgrep_baseline.json"
        out_path.write_text(json.dumps(semgrep_out, indent=2))
        print(f"  semgrep: {len(semgrep_out)} findings → {out_path.name}")

    elif js_files:
        print("  bandit: skipped (Python-only tool) → writing []")
        (ds_dir / "bandit_baseline.json").write_text("[]")

        print("  running semgrep (javascript)...")
        semgrep_out = run_semgrep(source_dir, "javascript")
        out_path = ds_dir / "semgrep_baseline.json"
        out_path.write_text(json.dumps(semgrep_out, indent=2))
        print(f"  semgrep: {len(semgrep_out)} findings → {out_path.name}")
    else:
        print("  no Python or JS source files found")


if __name__ == "__main__":
    targets = sys.argv[1:] or DATASETS_TO_SCAN
    for ds in targets:
        process(ds)
    print("\nDone.")
