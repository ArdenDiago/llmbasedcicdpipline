"""Generate a cascade-tier Markdown table from fix_eval attempts.json output."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _load(path: Path) -> list[dict]:
    return json.loads(path.read_text())


def build_table(attempts: list[dict]) -> str:
    # Tier is inferred from model_spec: paid models mean escalation occurred.
    # We proxy tier via the sequence of attempts per (dataset, vuln_index):
    # here we report per-model counts aggregated from the flat attempts list.
    by_model: dict[str, dict] = {}
    for a in attempts:
        m = a["model_spec"]
        s = by_model.setdefault(m, {"total": 0, "fixed": 0, "cost_usd": 0.0})
        s["total"] += 1
        s["fixed"] += int(bool(a.get("fixed")))
        s["cost_usd"] += a.get("cost_usd", 0.0)

    lines = [
        "## Cascade tier summary",
        "",
        "| model | tier | findings | fixed | fix_rate | cost_usd |",
        "|---|---|---|---|---|---|",
    ]
    tier_map = {
        "ollama": 1, "hf": 1,
        "anthropic": 2, "openai": 2,
    }
    for m, s in sorted(by_model.items()):
        provider = m.split(":")[0] if ":" in m else "unknown"
        tier = tier_map.get(provider, "?")
        # Opus is tier 3 if detected
        if "opus" in m.lower():
            tier = 3
        elif "sonnet" in m.lower() or "haiku" in m.lower() or "gpt" in m.lower():
            tier = 2
        rate = s["fixed"] / s["total"] if s["total"] else 0.0
        lines.append(
            f"| `{m}` | {tier} | {s['total']} | {s['fixed']} "
            f"| {rate:.1%} | ${s['cost_usd']:.4f} |"
        )

    # Global escalation stats across all paid-model rows
    tier1_total = sum(s["total"] for m, s in by_model.items()
                      if m.split(":")[0] in ("ollama", "hf") and "opus" not in m)
    tier2_total = sum(s["total"] for m, s in by_model.items()
                      if m.split(":")[0] in ("anthropic", "openai") and "opus" not in m)
    tier3_total = sum(s["total"] for m, s in by_model.items() if "opus" in m.lower())
    total = tier1_total + tier2_total + tier3_total or 1

    lines += [
        "",
        f"**Escalation tier-1→2**: {tier2_total / total:.1%}  ",
        f"**Escalation tier-2→3**: {tier3_total / (tier2_total or 1):.1%}  ",
        f"**Total cost**: ${sum(s['cost_usd'] for s in by_model.values()):.4f}",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("attempts_json", type=Path)
    p.add_argument("--out", type=Path, default=None)
    args = p.parse_args(argv)

    attempts = _load(args.attempts_json)
    table = build_table(attempts)
    if args.out:
        args.out.write_text(table + "\n")
    else:
        print(table)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
