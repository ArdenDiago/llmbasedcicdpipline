# CLAUDE.md — Evaluation & Benchmarking

## Purpose
Benchmarks the agent's vulnerability detection and fix quality against
established tools (Checkov, Semgrep) and human baselines.

## Tech
- Language: Python
- Entry: run_benchmark.py
- CLI: python evaluation/run_benchmark.py

## Metrics
- **Detection rate**: % of known vulns found (vs ground truth)
- **False positive rate**: % of findings that are not real vulns
- **Fix accuracy**: % of generated fixes that resolve the vuln
- **Fix safety**: % of fixes that don't break existing tests
- **Model cost**: total API tokens consumed per fix

## Benchmark Datasets
- OWASP Benchmark (Java)
- Juliet Test Suite (C/C++)
- Custom curated dataset (Python, JS) — see evaluation/datasets/

## Files
- run_benchmark.py    → Main benchmark runner (use `--scan` to invoke scanners on source/)
- scan.py             → Drives agent + per-tool baselines against a dataset's source/
- datasets/           → Each subdir = one dataset
- metrics.py          → Metric calculation and reporting
- compare.py          → Compare agent vs Checkov/Semgrep results
- report.py           → Generate benchmark report (Markdown + CSV)

## Dataset layout
Each dataset directory contains:
- `source/`           → vulnerable source tree (optional; needed for `--scan`)
- `ground_truth.json` → list of known vulns (file relative to source/, line, cwe, severity)
- `<tool>.json`       → per-tool findings in unified format. Emitted by `--scan`
                        as `agent.json`, `bandit_baseline.json`, `semgrep_baseline.json`,
                        or pre-baked offline.

## Ground truth & matching
Ground truth uses CWE as the cross-tool identifier (rule IDs differ per scanner).
A finding matches a truth entry when (file, line ± tolerance) align AND either
rule_id matches or CWE matches. Well-known parent/child CWE relations are
treated as equivalent — see `_CWE_PARENT` in metrics.py.

## Output
- evaluation/results/ — timestamped benchmark results
- evaluation/reports/ — generated comparison reports

## Rules
- Never modify datasets without updating ground truth labels
- Always run full benchmark before claiming detection improvements
- GPT-4o and Claude are used here for evaluation — this is the only
  place where paid API usage is acceptable outside escalation
- Record model, tokens, and cost for every evaluation run
