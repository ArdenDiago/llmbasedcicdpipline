"""Phase 7 — combine all phase outputs into a single REPORT.md.

Reads from runs/<stamp>/{phase1,phase2,phase4,phase6}/. Skips phases whose
sentinel (.done file) is missing — keeps the report honest about what
actually completed.
"""
from __future__ import annotations

import argparse
from pathlib import Path


def _section(run_dir: Path, sentinel: str, title: str, paths: list[Path]) -> list[str]:
    out = [f"## {title}", ""]
    if not (run_dir / sentinel).exists():
        out.append(f"_Phase did not complete (no `{sentinel}`)._")
        out.append("")
        return out
    found_any = False
    for p in paths:
        if p.exists():
            out.append(f"### {p.relative_to(run_dir)}")
            out.append("")
            out.append(p.read_text(encoding="utf-8"))
            out.append("")
            found_any = True
    if not found_any:
        out.append("_Phase complete but no report files found._")
        out.append("")
    return out


def build(run_dir: Path) -> str:
    lines = [f"# Run report — {run_dir.name}", ""]

    # Phase 0 — setup
    setup_log = run_dir / "0_setup.log"
    lines.append("## Phase 0 — environment")
    lines.append("")
    if (run_dir / "0_setup.done").exists():
        lines.append("Setup completed. Tail of log:")
        lines.append("")
        lines.append("```")
        if setup_log.exists():
            lines.extend(setup_log.read_text(errors="replace").splitlines()[-30:])
        lines.append("```")
    else:
        lines.append("_Setup did not complete._")
    lines.append("")

    lines.extend(_section(
        run_dir, "1_multiseed.done", "Phase 1 — multi-seed detection benchmark",
        [run_dir / "phase1" / "summary.md"],
    ))
    lines.extend(_section(
        run_dir, "2_cwe.done", "Phase 2 — per-CWE breakdown",
        sorted((run_dir / "phase2" / "reports").glob("*-cwe.md")) if (run_dir / "phase2" / "reports").exists() else [],
    ))
    lines.extend(_section(
        run_dir, "4_fix.done", "Phase 4 — fix-quality benchmark",
        [run_dir / "phase4" / "summary.md"],
    ))
    lines.extend(_section(
        run_dir, "5_lora.done", "Phase 5 — QLoRA fine-tune",
        [run_dir / "phase5" / "summary.md"],
    ))
    lines.extend(_section(
        run_dir, "6_reeval.done", "Phase 6 — fine-tuned re-eval",
        [run_dir / "phase6" / "summary.md"],
    ))
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--run-dir", required=True, type=Path)
    p.add_argument("--out", required=True, type=Path)
    args = p.parse_args(argv)

    md = build(args.run_dir)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(md, encoding="utf-8")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
