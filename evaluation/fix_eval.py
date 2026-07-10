"""Phase 4 / Phase 6 — fix-quality benchmark.

For every detected vuln (true positive: agent.json ∩ ground_truth.json),
generate a fix with each candidate model, apply the patch in a sandbox copy
of the source tree, re-scan with semgrep+bandit, and score:
  - fix_accuracy: % vulns where the original CWE no longer appears in the
                  patched file (bandit/semgrep re-scan, no line tol).
  - fix_safety:   % patches that still parse (Python: ast, JS: node --check).
  - cost:         tokens_in / tokens_out / wallclock_ms per model.

All LLM calls go through agent.llm.cache.CachedClient — first run pays full
token cost, every rerun reads from $CACHE_ROOT/llm_responses/.

Model spec: "provider:model_id"
  ollama:deepseek-coder:6.7b
  ollama:qwen2.5-coder:1.5b
  anthropic:claude-haiku-4-5-20251001
  anthropic:claude-sonnet-4-6
  hf:Qwen/Qwen2.5-Coder-1.5B               (loads via transformers)
  hf:Qwen/Qwen2.5-Coder-1.5B+<adapter>     (with LoRA adapter dir)
"""
from __future__ import annotations

import argparse
import csv
import dataclasses
import json
import logging
import os
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from agent.llm import prompts
from agent.llm.cache import CachedClient
from agent.llm.clients.base import LLMResponse
from agent.security.scanners import bandit as bandit_scanner
from agent.security.scanners import semgrep as semgrep_scanner
from evaluation import metrics as eval_metrics
from evaluation import patcher as patch_mod

logger = logging.getLogger("fix_eval")

REPO_ROOT = Path(__file__).resolve().parent.parent

# (input_per_1M_tokens, output_per_1M_tokens) in USD — April 2026 rates
_COST_PER_1M: dict[str, tuple[float, float]] = {
    "claude-haiku-4-5-20251001": (1.00, 5.00),
    "claude-sonnet-4-6":         (3.00, 15.00),
    "claude-opus-4-6":           (15.00, 75.00),
    "gpt-4o":                    (5.00, 15.00),
    "gpt-4o-mini":               (0.15,  0.60),
}

def _cost_for(model_id: str, tokens_in: int, tokens_out: int) -> float:
    rates = _COST_PER_1M.get(model_id)
    if rates is None:
        return 0.0
    return (tokens_in * rates[0] + tokens_out * rates[1]) / 1_000_000
DATASETS_DIR = REPO_ROOT / "evaluation" / "datasets"
DEFAULT_CACHE_DIR = REPO_ROOT / ".cache" / "llm_responses"

_LANG_BY_EXT = {
    ".py": "python", ".js": "javascript", ".ts": "typescript",
    ".jsx": "javascript", ".tsx": "typescript",
}


@dataclass
class FixAttempt:
    dataset: str
    vuln_index: int
    file: str
    line: int
    cwe: str
    model_spec: str
    parse_ok: bool
    fixed: bool
    fixed_reason: str
    tokens_in: int
    tokens_out: int
    latency_ms: int
    cost_usd: float
    rescan_findings: int
    cache_hit: bool
    error: str | None = None


@dataclass
class ModelSummary:
    model_spec: str
    attempts: int = 0
    fixed: int = 0
    parse_ok: int = 0
    tokens_in: int = 0
    tokens_out: int = 0
    latency_ms: int = 0
    cost_usd: float = 0.0
    cache_hits: int = 0
    errors: int = 0

    @property
    def fix_accuracy(self) -> float:
        return self.fixed / self.attempts if self.attempts else 0.0

    @property
    def fix_safety(self) -> float:
        return self.parse_ok / self.attempts if self.attempts else 0.0


def language_for(path: str) -> str:
    for ext, lang in _LANG_BY_EXT.items():
        if path.endswith(ext):
            return lang
    return ""


def is_paid(model_spec: str) -> bool:
    return model_spec.startswith("anthropic:") or model_spec.startswith("openai:")


def load_truth_and_agent(dataset_dir: Path) -> tuple[list[dict], list[dict]]:
    truth = json.loads((dataset_dir / "ground_truth.json").read_text())
    agent_path = dataset_dir / "agent.json"
    if not agent_path.exists():
        logger.warning("no agent.json in %s — TP set empty", dataset_dir.name)
        return truth, []
    return truth, json.loads(agent_path.read_text())


def true_positives(
    ground_truth: list[dict],
    agent_findings: list[dict],
    line_tolerance: int = 3,
) -> list[dict]:
    """Return ground-truth entries that the agent successfully detected.

    Mirrors evaluation.metrics._matches; one ground-truth entry can be
    matched at most once.
    """
    tps: list[dict] = []
    matched_truth: set[int] = set()
    for f in agent_findings:
        for idx, t in enumerate(ground_truth):
            if idx in matched_truth:
                continue
            if eval_metrics._matches(f, t, line_tolerance):
                matched_truth.add(idx)
                tps.append(t)
                break
    return tps


def build_client(model_spec: str, cache_dir: Path):
    """Return a CachedClient wrapping the right upstream."""
    if ":" not in model_spec:
        raise ValueError(f"bad model spec '{model_spec}', expected provider:model_id")
    provider, model_id = model_spec.split(":", 1)

    if provider == "ollama":
        from agent.llm.clients.ollama import OllamaClient
        upstream = OllamaClient(model=model_id)
    elif provider == "anthropic":
        from agent.llm.clients.anthropic import AnthropicClient
        upstream = AnthropicClient(model=model_id)
    elif provider == "hf":
        # Optional "+<adapter_path>" suffix for LoRA adapters.
        adapter = None
        if "+" in model_id:
            model_id, adapter = model_id.split("+", 1)
        from agent.llm.clients.hf_local import HFLocalClient
        upstream = HFLocalClient(model_id=model_id, adapter_path=adapter)
    else:
        raise ValueError(f"unknown provider '{provider}'")

    return CachedClient(upstream, cache_dir=cache_dir)


def rescan_file(workdir: Path, target_relpath: str, cwe: str, line_tol: int = 100) -> tuple[bool, int]:
    """Re-scan workdir, return (cwe_still_present_in_target_file, total_findings_in_file).

    line_tol is intentionally large — patch may shift lines. We say "fixed"
    when no finding with that CWE survives in the target file at all.
    """
    findings: list[dict] = []
    for runner in (bandit_scanner, semgrep_scanner):
        try:
            res, scan_errors = runner.run(str(workdir), timeout=120)
            for err in scan_errors:
                logger.warning("rescan %s reported an error: %s", runner.NAME, err)
            findings.extend(f.to_dict() for f in res)
        except Exception as exc:
            logger.warning("rescan %s failed: %s", runner.NAME, exc)

    target_findings = []
    for f in findings:
        f_file = (f.get("file") or "")
        try:
            f_rel = str(Path(f_file).resolve().relative_to(workdir.resolve()))
        except (ValueError, OSError):
            f_rel = f_file
        if f_rel == target_relpath or f_rel.endswith("/" + target_relpath):
            target_findings.append(f)

    cwe_present = any(eval_metrics._cwes_match(f.get("cwe", ""), cwe) for f in target_findings)
    return cwe_present, len(target_findings)


def _close_train_shape_fence(text: str) -> str:
    """The train-shape prompt ends with an *open* ```\\n fence, so the model's
    output is `<code>\\n```\\n<maybe more>`. Truncate at the first standalone
    ``` line so the patcher gets pure code, no stray fence markers."""
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if line.strip() == "```":
            return "\n".join(lines[:i])
    return text


def _is_adapter_spec(model_spec: str) -> bool:
    """A `hf:<base>+<adapter>` spec means we're talking to the QLoRA adapter
    trained in Phase 5. That adapter was trained on a different prompt shape
    (see training/train_lora.py:INSTRUCTION_TEMPLATE) and collapses to
    immediate-EOS on fix_single_file.j2 — so it gets its own template."""
    return model_spec.startswith("hf:") and "+" in model_spec.split(":", 1)[1]


def render_fix_prompt(vuln: dict, file_content: str, model_spec: str = "") -> str:
    if _is_adapter_spec(model_spec):
        return prompts.render(
            "fix_single_file_train_shape",
            file_content=file_content,
        )
    return prompts.render(
        "fix_single_file",
        file_path=vuln["file"],
        language=language_for(vuln["file"]),
        issue_description=vuln.get("description", ""),
        scanner_finding={
            "scanner": "ground_truth",
            "rule_id": vuln.get("rule_id", ""),
            "severity": vuln.get("severity", ""),
            "cwe": vuln.get("cwe", ""),
        },
        file_content=file_content,
    )


def run_one(
    dataset: str,
    vuln_index: int,
    vuln: dict,
    source_root: Path,
    workdir_root: Path,
    model_spec: str,
    client: CachedClient,
    max_tokens: int,
) -> FixAttempt:
    target_rel = vuln["file"]
    target_path = source_root / target_rel
    file_content = target_path.read_text(encoding="utf-8")
    prompt = render_fix_prompt(vuln, file_content, model_spec=model_spec)

    workdir = workdir_root / model_spec.replace("/", "_").replace(":", "_") / f"vuln_{vuln_index:03d}"

    attempt = FixAttempt(
        dataset=dataset, vuln_index=vuln_index, file=target_rel,
        line=int(vuln.get("line") or 0), cwe=vuln.get("cwe", ""),
        model_spec=model_spec, parse_ok=False, fixed=False,
        fixed_reason="", tokens_in=0, tokens_out=0, latency_ms=0,
        cost_usd=0.0, rescan_findings=0, cache_hit=False,
    )

    pre_misses = client.misses
    # Adapter is heavily overfit on bigvul; greedy decoding is more reliable
    # for it than the default 0.2 sampling. Other models keep the default.
    complete_kwargs: dict[str, Any] = {"max_tokens": max_tokens}
    if _is_adapter_spec(model_spec):
        complete_kwargs["temperature"] = 0.0
    try:
        resp: LLMResponse = client.complete(prompt, **complete_kwargs)
    except Exception as exc:
        attempt.error = f"{type(exc).__name__}: {exc}"
        logger.warning("LLM call failed %s vuln %s: %s", model_spec, vuln_index, attempt.error)
        return attempt

    attempt.cache_hit = client.misses == pre_misses
    attempt.tokens_in = resp.tokens_in
    attempt.tokens_out = resp.tokens_out
    attempt.latency_ms = resp.latency_ms
    model_id = model_spec.split(":", 1)[-1] if ":" in model_spec else model_spec
    attempt.cost_usd = _cost_for(model_id, resp.tokens_in, resp.tokens_out)

    if not resp.text.strip():
        attempt.error = "empty response"
        return attempt

    new_content = resp.text
    if _is_adapter_spec(model_spec):
        new_content = _close_train_shape_fence(new_content)

    try:
        patch = patch_mod.apply_full_file_replacement(
            source_root=source_root,
            target_relpath=target_rel,
            new_content=new_content,
            workdir_root=workdir,
        )
    except Exception as exc:
        attempt.error = f"patch failed: {exc}"
        return attempt

    attempt.parse_ok = patch.parse_ok
    if not patch.parse_ok:
        attempt.fixed = False
        attempt.fixed_reason = f"parse fail: {patch.parse_error}"
        return attempt

    cwe_present, n_findings = rescan_file(patch.workdir, target_rel, attempt.cwe)
    attempt.rescan_findings = n_findings
    attempt.fixed = not cwe_present
    attempt.fixed_reason = (
        f"CWE {attempt.cwe} no longer in {target_rel}"
        if not cwe_present else f"CWE {attempt.cwe} still flagged"
    )
    return attempt


def evaluate(
    datasets: list[str],
    models: list[str],
    out_dir: Path,
    cache_dir: Path,
    cap_paid_fixes: int = 30,
    max_tokens: int = 1000,
) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    workdir_root = out_dir / "workdirs"
    workdir_root.mkdir(parents=True, exist_ok=True)

    all_attempts: list[FixAttempt] = []
    summaries: dict[str, ModelSummary] = {m: ModelSummary(model_spec=m) for m in models}
    paid_count: dict[str, int] = {m: 0 for m in models}
    # Build clients once per model — HFLocalClient lazy-loads a 4-bit model and
    # rebuilding per-attempt would reload weights every call.
    clients: dict[str, CachedClient] = {m: build_client(m, cache_dir) for m in models}

    for ds_name in datasets:
        ds_dir = DATASETS_DIR / ds_name
        if not ds_dir.is_dir():
            logger.warning("skip missing dataset %s", ds_name)
            continue
        truth, agent_findings = load_truth_and_agent(ds_dir)
        tps = true_positives(truth, agent_findings)
        logger.info("dataset %s: %d TPs out of %d ground truth", ds_name, len(tps), len(truth))

        source_root = ds_dir / "source"
        if not source_root.is_dir():
            logger.warning("dataset %s has no source/, skipping", ds_name)
            continue

        for vuln_idx, vuln in enumerate(tps):
            for model_spec in models:
                if is_paid(model_spec) and paid_count[model_spec] >= cap_paid_fixes:
                    logger.info("paid cap reached for %s, skipping vuln %d", model_spec, vuln_idx)
                    continue
                t0 = time.monotonic()
                client = clients[model_spec]
                attempt = run_one(
                    dataset=ds_name, vuln_index=vuln_idx, vuln=vuln,
                    source_root=source_root, workdir_root=workdir_root,
                    model_spec=model_spec, client=client, max_tokens=max_tokens,
                )
                all_attempts.append(attempt)
                summaries[model_spec].attempts += 1
                summaries[model_spec].tokens_in += attempt.tokens_in
                summaries[model_spec].tokens_out += attempt.tokens_out
                summaries[model_spec].latency_ms += attempt.latency_ms
                summaries[model_spec].cost_usd += attempt.cost_usd
                if attempt.cache_hit:
                    summaries[model_spec].cache_hits += 1
                if attempt.error:
                    summaries[model_spec].errors += 1
                if attempt.parse_ok:
                    summaries[model_spec].parse_ok += 1
                if attempt.fixed:
                    summaries[model_spec].fixed += 1
                if is_paid(model_spec) and not attempt.cache_hit:
                    paid_count[model_spec] += 1
                logger.info(
                    "  %s ds=%s vuln=%d cwe=%s fixed=%s parse=%s tokens=%d/%d t=%.1fs%s",
                    model_spec, ds_name, vuln_idx, attempt.cwe,
                    attempt.fixed, attempt.parse_ok,
                    attempt.tokens_in, attempt.tokens_out,
                    time.monotonic() - t0,
                    " (cache)" if attempt.cache_hit else "",
                )

    _write_attempts_json(all_attempts, out_dir / "attempts.json")
    _write_attempts_csv(all_attempts, out_dir / "attempts.csv")
    summary_md = _write_summary_md(summaries, out_dir / "summary.md")
    return {
        "attempts": len(all_attempts),
        "summary_md": str(summary_md),
        "by_model": {m: dataclasses.asdict(s) for m, s in summaries.items()},
    }


def _write_attempts_json(attempts: list[FixAttempt], path: Path) -> Path:
    path.write_text(json.dumps([asdict(a) for a in attempts], indent=2), encoding="utf-8")
    return path


def _write_attempts_csv(attempts: list[FixAttempt], path: Path) -> Path:
    if not attempts:
        path.write_text("", encoding="utf-8")
        return path
    fields = list(asdict(attempts[0]).keys())
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for a in attempts:
            w.writerow(asdict(a))
    return path


def _write_summary_md(summaries: dict[str, ModelSummary], path: Path) -> Path:
    lines = [
        "# Fix-quality summary",
        "",
        "| model | attempts | fix_accuracy | fix_safety | tokens_in | tokens_out | cost_usd | latency_ms | cache_hits | errors |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for m, s in summaries.items():
        lines.append(
            f"| `{m}` | {s.attempts} | {s.fix_accuracy:.3f} | {s.fix_safety:.3f} "
            f"| {s.tokens_in} | {s.tokens_out} | ${s.cost_usd:.4f} "
            f"| {s.latency_ms} | {s.cache_hits} | {s.errors} |"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--datasets", required=True, help="comma-separated dataset dir names")
    p.add_argument("--models", required=True, help="comma-separated provider:model_id specs")
    p.add_argument("--out", required=True, type=Path, help="output dir for results")
    p.add_argument("--cache-dir", type=Path, default=DEFAULT_CACHE_DIR)
    p.add_argument("--cap-paid-fixes", type=int, default=30)
    p.add_argument("--max-tokens", type=int, default=1000)
    p.add_argument("--log-level", default="INFO")
    args = p.parse_args(argv)

    logging.basicConfig(
        level=args.log_level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )

    datasets = [d.strip() for d in args.datasets.split(",") if d.strip()]
    models = [m.strip() for m in args.models.split(",") if m.strip()]

    result = evaluate(
        datasets=datasets,
        models=models,
        out_dir=args.out,
        cache_dir=args.cache_dir,
        cap_paid_fixes=args.cap_paid_fixes,
        max_tokens=args.max_tokens,
    )
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
