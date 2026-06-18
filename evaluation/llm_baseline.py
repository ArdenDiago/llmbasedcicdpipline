"""Zero-shot LLM detection baseline (item #2).

Sends each source file from a dataset's source/ directory to a chosen LLM
in a single zero-shot prompt asking it to list security vulnerabilities.
Writes output as <llm_name>_baseline.json in the dataset directory.

Usage:
    python evaluation/llm_baseline.py \\
        --dataset python_vulns_extended \\
        --model anthropic:claude-sonnet-4-6 \\
        --out-name sonnet_baseline

The LLM is asked to return a JSON array of findings in the standard format:
  [{"file": "...", "line": N, "cwe": "CWE-XX", "message": "...", ...}, ...]

Cost note: each source file is a separate call. Tokens tracked and reported.
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

logger = logging.getLogger("llm_baseline")

REPO_ROOT = Path(__file__).resolve().parent.parent
DATASETS_DIR = REPO_ROOT / "evaluation" / "datasets"

_SYSTEM_PROMPT = """\
You are a security code reviewer. Analyse the provided source file for \
security vulnerabilities. Return ONLY a JSON array — no prose, no markdown \
fences. Each element must have these fields:
  file       (string, filename only)
  line       (integer, 1-based line number of the vulnerability)
  cwe        (string, e.g. "CWE-89")
  severity   ("low" | "medium" | "high")
  confidence ("low" | "medium" | "high")
  message    (string, one-sentence description)

If you find no vulnerabilities return an empty array [].
"""

_USER_TEMPLATE = """\
File: {filename}

```
{content}
```
"""

# (input_per_1M, output_per_1M) in USD
_COST_PER_1M: dict[str, tuple[float, float]] = {
    "claude-haiku-4-5-20251001": (1.00, 5.00),
    "claude-sonnet-4-6":         (3.00, 15.00),
    "claude-opus-4-8":           (15.00, 75.00),
    "gpt-4o":                    (5.00, 15.00),
    "gpt-4o-mini":               (0.15,  0.60),
}


def _build_client(model_spec: str):
    provider, model_id = model_spec.split(":", 1)
    if provider == "anthropic":
        from agent.llm.clients.anthropic import AnthropicClient
        return AnthropicClient(model=model_id), model_id
    if provider == "openai":
        from agent.llm.clients.openai import OpenAIClient
        return OpenAIClient(model=model_id), model_id
    if provider == "ollama":
        from agent.llm.clients.ollama import OllamaClient
        return OllamaClient(model=model_id), model_id
    raise ValueError(f"unsupported provider: {provider}")


def _cost(model_id: str, tokens_in: int, tokens_out: int) -> float:
    rates = _COST_PER_1M.get(model_id)
    return (tokens_in * rates[0] + tokens_out * rates[1]) / 1_000_000 if rates else 0.0


def run(dataset: str, model_spec: str, out_name: str) -> Path:
    ds_dir = DATASETS_DIR / dataset
    source_dir = ds_dir / "source"
    if not source_dir.is_dir():
        raise FileNotFoundError(f"No source/ in {ds_dir}")

    client, model_id = _build_client(model_spec)

    findings: list[dict] = []
    total_in = total_out = 0
    total_cost = 0.0

    source_files = sorted(source_dir.iterdir())
    for src_file in source_files:
        if src_file.suffix not in (".py", ".js", ".ts", ".go", ".java", ".rb"):
            continue
        content = src_file.read_text(encoding="utf-8", errors="replace")
        prompt = _SYSTEM_PROMPT + "\n\n" + _USER_TEMPLATE.format(
            filename=src_file.name, content=content
        )
        try:
            resp = client.complete(prompt, max_tokens=2000)
        except Exception as exc:
            logger.warning("LLM call failed for %s: %s", src_file.name, exc)
            continue

        total_in += resp.tokens_in
        total_out += resp.tokens_out
        cost = _cost(model_id, resp.tokens_in, resp.tokens_out)
        total_cost += cost
        logger.info(
            "%s: %d in / %d out / $%.4f", src_file.name, resp.tokens_in, resp.tokens_out, cost
        )

        raw = resp.text.strip()
        # Strip markdown fences if model added them despite instructions
        if raw.startswith("```"):
            raw = raw.split("\n", 1)[-1].rsplit("```", 1)[0].strip()
        try:
            file_findings = json.loads(raw)
            if not isinstance(file_findings, list):
                raise ValueError("expected JSON array")
        except (json.JSONDecodeError, ValueError) as exc:
            logger.warning("could not parse JSON from %s response: %s", src_file.name, exc)
            continue

        for f in file_findings:
            f.setdefault("scanner", model_spec)
            f.setdefault("file", src_file.name)
            f.setdefault("extra", {})
            findings.append(f)

    out_path = ds_dir / f"{out_name}.json"
    out_path.write_text(json.dumps(findings, indent=2), encoding="utf-8")

    logger.info(
        "wrote %d findings to %s | total tokens %d/%d | cost $%.4f",
        len(findings), out_path, total_in, total_out, total_cost,
    )
    return out_path


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--dataset", required=True)
    p.add_argument("--model", required=True, help="provider:model_id")
    p.add_argument("--out-name", default=None, help="output basename (default: <model>_baseline)")
    p.add_argument("--log-level", default="INFO")
    args = p.parse_args(argv)

    logging.basicConfig(
        level=args.log_level, format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )

    out_name = args.out_name or (args.model.split(":")[1] if ":" in args.model else args.model) + "_baseline"
    out_path = run(dataset=args.dataset, model_spec=args.model, out_name=out_name)
    print(str(out_path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
