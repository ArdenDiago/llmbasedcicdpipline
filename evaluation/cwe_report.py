"""Per-CWE breakdown — Phase 2.

Standalone so it doesn't perturb run_benchmark.py's existing interface.
Reads the same dataset layout (ground_truth.json + <tool>.json per dataset)
and emits a Markdown table grouped by (dataset, tool, cwe).

Useful for the paper claim "agent excels at CWE-X, weak on CWE-Y".
"""
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path

from evaluation import metrics

DEFAULT_DATASETS_DIR = Path(__file__).parent / "datasets"


def _load_findings(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return json.loads(path.read_text())


def per_cwe_breakdown(
    ground_truth: list[dict],
    tool_findings: dict[str, list[dict]],
    line_tolerance: int = 3,
) -> dict[tuple[str, str], metrics.DetectionMetrics]:
    """Compute (tool, cwe) → DetectionMetrics, treating each CWE bucket separately."""
    cwes = sorted({(t.get("cwe") or "") for t in ground_truth} - {""})
    out: dict[tuple[str, str], metrics.DetectionMetrics] = {}

    for tool, findings in tool_findings.items():
        for cwe in cwes:
            truth_subset = [t for t in ground_truth if metrics._cwes_match(t.get("cwe", ""), cwe)]
            findings_subset = [f for f in findings if metrics._cwes_match(f.get("cwe", ""), cwe)]
            d = metrics.detection(findings_subset, truth_subset, line_tolerance)
            out[(tool, cwe)] = d
    return out


def render_markdown(datasets_dir: Path, line_tolerance: int = 3) -> str:
    lines = ["# Per-CWE detection breakdown", ""]
    for ds_dir in sorted(p for p in datasets_dir.iterdir() if p.is_dir()):
        gt = _load_findings(ds_dir / "ground_truth.json")
        if not gt:
            continue
        tools = {
            p.stem: _load_findings(p)
            for p in sorted(ds_dir.glob("*.json"))
            if p.name != "ground_truth.json"
        }
        if not tools:
            continue
        breakdown = per_cwe_breakdown(gt, tools, line_tolerance)

        lines += [f"## {ds_dir.name}", "",
                  "| tool | cwe | tp | fp | fn | recall | precision | f1 |",
                  "|---|---|---|---|---|---|---|---|"]
        # group rows for readable output
        by_tool: dict[str, list[tuple[str, metrics.DetectionMetrics]]] = defaultdict(list)
        for (tool, cwe), m in breakdown.items():
            by_tool[tool].append((cwe, m))
        for tool in sorted(by_tool):
            for cwe, m in sorted(by_tool[tool]):
                if m.true_positives + m.false_positives + m.false_negatives == 0:
                    continue
                lines.append(
                    f"| {tool} | {cwe} | {m.true_positives} | {m.false_positives} "
                    f"| {m.false_negatives} | {m.recall:.3f} | {m.precision:.3f} | {m.f1:.3f} |"
                )
        lines.append("")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--datasets-dir", type=Path, default=DEFAULT_DATASETS_DIR)
    p.add_argument("--line-tolerance", type=int, default=3)
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args(argv)

    md = render_markdown(args.datasets_dir, args.line_tolerance)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(md, encoding="utf-8")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
