"""
Extended scanner run: bandit + multiple semgrep rulesets + njsscan.
Writes individual baseline JSONs and a merged 'agent.json' per dataset.
Usage: python evaluation/run_extended_scan.py
"""
from __future__ import annotations
import json
import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
from evaluation.metrics import _cwes_match

DATASETS = REPO / "evaluation" / "datasets"
DATASETS_TO_SCAN = [
    "python_vulns",
    "python_vulns_extended",
    "js_vulns",
    "js_vulns_extended",
]

SEMGREP_PY_CONFIGS  = ["r/python.lang.security", "r/python.lang.security.audit"]
SEMGREP_JS_CONFIGS  = ["r/javascript.lang.security", "r/javascript.express", "r/javascript.lang.security.audit"]


# ---------------------------------------------------------------------------
# Bandit
# ---------------------------------------------------------------------------
def run_bandit(source_dir: Path) -> list[dict]:
    result = subprocess.run(
        ["bandit", "-r", str(source_dir), "-f", "json"],
        capture_output=True, text=True,
    )
    try:
        data = json.loads(result.stdout or result.stderr)
    except json.JSONDecodeError:
        return []
    findings = []
    for r in data.get("results", []):
        cwe_id = r.get("issue_cwe", {}).get("id")
        findings.append({
            "scanner": "bandit",
            "rule_id": r.get("test_id", ""),
            "severity": r.get("issue_severity", "").lower(),
            "confidence": r.get("issue_confidence", "").lower(),
            "file": Path(r.get("filename", "")).name,
            "line": r.get("line_number", 0),
            "message": r.get("issue_text", ""),
            "cwe": f"CWE-{cwe_id}" if cwe_id else "",
            "snippet": r.get("code", ""),
            "extra": {},
        })
    return findings


# ---------------------------------------------------------------------------
# Semgrep (multi-config merged)
# ---------------------------------------------------------------------------
def run_semgrep(source_dir: Path, configs: list[str]) -> list[dict]:
    all_findings: list[dict] = []
    for cfg in configs:
        result = subprocess.run(
            ["semgrep", "--config", cfg, "--json", "--no-autofix", "--quiet",
             str(source_dir)],
            capture_output=True, text=True,
        )
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            print(f"    [semgrep:{cfg}] parse error", file=sys.stderr)
            continue
        for r in data.get("results", []):
            meta = r.get("extra", {}).get("metadata", {})
            raw_cwe = meta.get("cwe") or meta.get("cwe-id") or ""
            if isinstance(raw_cwe, list):
                raw_cwe = raw_cwe[0] if raw_cwe else ""
            if raw_cwe and ":" in raw_cwe:
                raw_cwe = raw_cwe.split(":")[0].strip()
            cwe = raw_cwe if raw_cwe.startswith("CWE-") else (f"CWE-{raw_cwe}" if raw_cwe else "")
            sev = {"error": "high", "warning": "medium", "info": "low"}.get(
                r.get("extra", {}).get("severity", "").lower(), "medium")
            start = r.get("start", {})
            all_findings.append({
                "scanner": f"semgrep:{cfg}",
                "rule_id": r.get("check_id", ""),
                "severity": sev,
                "confidence": meta.get("confidence", "medium").lower(),
                "file": Path(r.get("path", "")).name,
                "line": start.get("line", 0),
                "message": r.get("extra", {}).get("message", ""),
                "cwe": cwe,
                "snippet": r.get("extra", {}).get("lines", ""),
                "extra": {},
            })
    # Deduplicate across rulesets by (file, line, rule_id)
    seen: set[tuple] = set()
    deduped = []
    for f in all_findings:
        key = (f["file"], f["line"], f["rule_id"])
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    return deduped


# ---------------------------------------------------------------------------
# njsscan
# ---------------------------------------------------------------------------
def run_njsscan(source_dir: Path) -> list[dict]:
    result = subprocess.run(
        ["njsscan", "--json", str(source_dir)],
        capture_output=True, text=True,
    )
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        print(f"    [njsscan] parse error: {result.stderr[:200]}", file=sys.stderr)
        return []
    findings = []
    for rule_id, info in data.get("nodejs", {}).items():
        metadata = info.get("metadata", {})
        cwe_raw = metadata.get("cwe", "")
        if isinstance(cwe_raw, list):
            cwe_raw = cwe_raw[0] if cwe_raw else ""
        cwe = cwe_raw if cwe_raw.startswith("CWE-") else ""
        for match in info.get("files", []):
            fname = Path(match.get("file_path", "")).name
            for ln in match.get("match_lines", [[]]):
                line_no = ln[0] if isinstance(ln, (list, tuple)) and ln else ln
                findings.append({
                    "scanner": "njsscan",
                    "rule_id": rule_id,
                    "severity": metadata.get("severity", "").lower(),
                    "confidence": "medium",
                    "file": fname,
                    "line": int(line_no) if line_no else 0,
                    "message": metadata.get("description", ""),
                    "cwe": cwe,
                    "snippet": "",
                    "extra": {},
                })
    return findings


# ---------------------------------------------------------------------------
# Merge / dedup
# ---------------------------------------------------------------------------
def dedup_merge(lists: list[list[dict]]) -> list[dict]:
    merged: list[dict] = []
    for findings in lists:
        for f in findings:
            dup = any(
                e["file"] == f["file"]
                and int(e.get("line", 0)) == int(f.get("line", 0))
                and _cwes_match(e.get("cwe", ""), f.get("cwe", ""))
                for e in merged
            )
            if not dup:
                merged.append(f)
    return merged


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def process(ds_name: str) -> None:
    ds_dir = DATASETS / ds_name
    source_dir = ds_dir / "source"
    if not source_dir.is_dir():
        return

    py_files = list(source_dir.glob("*.py"))
    js_files = list(source_dir.glob("*.js")) + list(source_dir.glob("*.ts"))

    print(f"\n=== {ds_name} ===")
    all_for_agent: list[list[dict]] = []

    if py_files:
        print("  bandit...")
        bandit = run_bandit(source_dir)
        (ds_dir / "bandit_baseline.json").write_text(json.dumps(bandit, indent=2))
        print(f"    {len(bandit)} findings")
        all_for_agent.append(bandit)

        print("  semgrep (multi-ruleset)...")
        semgrep = run_semgrep(source_dir, SEMGREP_PY_CONFIGS)
        (ds_dir / "semgrep_baseline.json").write_text(json.dumps(semgrep, indent=2))
        print(f"    {len(semgrep)} findings (deduped across {len(SEMGREP_PY_CONFIGS)} rulesets)")
        all_for_agent.append(semgrep)

    if js_files:
        (ds_dir / "bandit_baseline.json").write_text("[]")

        print("  semgrep (multi-ruleset)...")
        semgrep = run_semgrep(source_dir, SEMGREP_JS_CONFIGS)
        (ds_dir / "semgrep_baseline.json").write_text(json.dumps(semgrep, indent=2))
        print(f"    {len(semgrep)} findings")
        all_for_agent.append(semgrep)

        try:
            import njsscan  # noqa: F401 — just check it's importable
            print("  njsscan...")
            njs = run_njsscan(source_dir)
            (ds_dir / "njsscan_baseline.json").write_text(json.dumps(njs, indent=2))
            print(f"    {len(njs)} findings")
            # NOTE: njsscan detects missing security controls (Helmet headers etc.),
            # not injection vulnerabilities — excluded from agent union to avoid FPs.
        except ImportError:
            print("  njsscan: not installed, skipping")

    agent = dedup_merge(all_for_agent)
    (ds_dir / "agent.json").write_text(json.dumps(agent, indent=2))
    print(f"  agent (union): {len(agent)} findings")


if __name__ == "__main__":
    targets = sys.argv[1:] or DATASETS_TO_SCAN
    for ds in targets:
        process(ds)
    print("\nDone.")
