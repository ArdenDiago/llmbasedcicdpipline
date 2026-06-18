"""Diagnostic: does the Phase 5 LoRA adapter generate fluent text when given
the *training* prompt shape, while collapsing to immediate-EOS on the
*inference* shape?

If A (training-shape) produces real tokens and B (inference-shape) produces
~0 tokens, the hypothesis in finding_lora_prompt_mismatch.md is confirmed
and the fix is to align fix_single_file.j2 with INSTRUCTION_TEMPLATE.

Run:
    python scripts/diag_lora_prompt_shape.py \
        --adapter runs/20260428T122020Z/phase5/lora/final
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from agent.llm import prompts as agent_prompts  # noqa: E402

# Mirror INSTRUCTION_TEMPLATE from training/train_lora.py, but stop just
# before the {fixed} slot so the model has to complete the rewrite.
TRAIN_PROMPT_PREFIX = (
    "You are a security-aware code repair assistant. "
    "The following code contains a vulnerability. "
    "Rewrite it to remove the vulnerability while preserving behaviour.\n\n"
    "### Vulnerable code:\n```\n{buggy}\n```\n\n"
    "### Fixed code:\n```\n"
)

VULN_FILE = REPO_ROOT / "evaluation/datasets/python_vulns/source/sql_injection.py"
VULN_DESC = "SQL injection via string concatenation"
VULN_CWE = "CWE-89"


def build_prompts(buggy: str) -> dict[str, str]:
    train_shape = TRAIN_PROMPT_PREFIX.format(buggy=buggy.strip())
    infer_shape = agent_prompts.render(
        "fix_single_file",
        file_path="sql_injection.py",
        language="python",
        issue_description=VULN_DESC,
        scanner_finding={
            "scanner": "ground_truth",
            "rule_id": "B608",
            "severity": "high",
            "cwe": VULN_CWE,
        },
        file_content=buggy,
    )
    return {"train_shape": train_shape, "infer_shape": infer_shape}


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--adapter", required=True, type=Path)
    p.add_argument("--base-model", default="Qwen/Qwen2.5-Coder-1.5B")
    p.add_argument("--max-new-tokens", type=int, default=200)
    p.add_argument("--temperature", type=float, default=0.2)
    args = p.parse_args()

    if not (args.adapter / "adapter_config.json").is_file():
        print(f"ERR: no adapter at {args.adapter}", file=sys.stderr)
        return 2

    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
    from peft import PeftModel

    print(f"loading {args.base_model} (4-bit) + adapter {args.adapter}", file=sys.stderr)
    bnb = BitsAndBytesConfig(
        load_in_4bit=True, bnb_4bit_quant_type="nf4",
        bnb_4bit_compute_dtype=torch.bfloat16,
    )
    tok = AutoTokenizer.from_pretrained(args.base_model)
    if tok.pad_token_id is None:
        tok.pad_token = tok.eos_token
    mdl = AutoModelForCausalLM.from_pretrained(
        args.base_model, quantization_config=bnb,
        device_map="auto", torch_dtype=torch.bfloat16,
    )
    mdl = PeftModel.from_pretrained(mdl, str(args.adapter))
    mdl.eval()

    buggy = VULN_FILE.read_text(encoding="utf-8")
    prompts_by_shape = build_prompts(buggy)

    for shape, prompt in prompts_by_shape.items():
        inputs = tok(prompt, return_tensors="pt", truncation=True, max_length=4096).to(mdl.device)
        tokens_in = int(inputs.input_ids.shape[1])
        t0 = time.monotonic()
        with torch.no_grad():
            out = mdl.generate(
                **inputs,
                max_new_tokens=args.max_new_tokens,
                do_sample=args.temperature > 0,
                temperature=max(args.temperature, 1e-5),
                pad_token_id=tok.pad_token_id,
            )
        new_tokens = out[0, tokens_in:]
        text = tok.decode(new_tokens, skip_special_tokens=True)
        latency_ms = int((time.monotonic() - t0) * 1000)

        print("=" * 72)
        print(f"SHAPE: {shape}")
        print(f"  prompt_tokens={tokens_in}  out_tokens={int(new_tokens.shape[0])}  latency_ms={latency_ms}")
        print(f"  output (first 800 chars):")
        print("-" * 72)
        print(text[:800])
        print("=" * 72)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
