"""Phase 5 — QLoRA fine-tune of Qwen2.5-Coder-1.5B on a vuln-fix dataset.

Designed to fit a 6GB laptop GPU (RTX 3050):
  - 4-bit NF4 base via bitsandbytes
  - LoRA r=16, alpha=32 on attention + MLP projections
  - bf16 + grad checkpointing + per-device batch=1, grad-accum=8
  - 800 steps default (~2h on 3050 for 1.5B/4-bit)

Defensive about dataset shape: HF vuln-fix datasets vary wildly. The script
auto-detects (buggy, fixed) column pairs from a small allowlist; if it can't
find any usable text, logs and exits 0 so downstream phases (6, 7) still run.

Resumable: HF Trainer writes checkpoints; rerunning the same --output-dir
picks up the latest.
"""
from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

logger = logging.getLogger("train_lora")

# Pairs of (buggy_col, fixed_col) we know about. First match wins.
_KNOWN_COLUMN_PAIRS = [
    ("func_before", "func_after"),
    ("vulnerable_code", "fixed_code"),
    ("buggy_code", "fixed_code"),
    ("source_before", "source_after"),
    ("code_before", "code_after"),
    ("before", "after"),
]

INSTRUCTION_TEMPLATE = (
    "You are a security-aware code repair assistant. "
    "The following code contains a vulnerability. "
    "Rewrite it to remove the vulnerability while preserving behaviour.\n\n"
    "### Vulnerable code:\n```\n{buggy}\n```\n\n"
    "### Fixed code:\n```\n{fixed}\n```\n"
)


def _pick_columns(features: dict) -> tuple[str, str] | None:
    cols = set(features.keys())
    for buggy, fixed in _KNOWN_COLUMN_PAIRS:
        if buggy in cols and fixed in cols:
            return buggy, fixed
    return None


def _format_example(ex: dict, buggy_col: str, fixed_col: str) -> str | None:
    b, f = ex.get(buggy_col), ex.get(fixed_col)
    if not isinstance(b, str) or not isinstance(f, str):
        return None
    if not b.strip() or not f.strip():
        return None
    if b == f:
        return None
    # crude length cap to keep sequences manageable
    if len(b) > 4000 or len(f) > 4000:
        return None
    return INSTRUCTION_TEMPLATE.format(buggy=b.strip(), fixed=f.strip())


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--base-model", default="Qwen/Qwen2.5-Coder-1.5B")
    p.add_argument("--dataset", default="euisuh15/CVEFixes")
    p.add_argument("--dataset-fraction", type=float, default=0.05)
    p.add_argument(
        "--language-filter", default=None,
        help="comma-separated language values to keep, e.g. 'Python,JavaScript'. "
             "Requires --language-column to exist in the dataset. Applied before "
             "--dataset-fraction, so the fraction is taken from the filtered pool.",
    )
    p.add_argument(
        "--language-column", default="language",
        help="column name holding the per-example language label",
    )
    p.add_argument("--output-dir", required=True, type=Path)
    p.add_argument("--max-steps", type=int, default=800)
    p.add_argument("--per-device-batch-size", type=int, default=1)
    p.add_argument("--gradient-accumulation-steps", type=int, default=8)
    p.add_argument("--learning-rate", type=float, default=2e-4)
    p.add_argument("--lora-r", type=int, default=16)
    p.add_argument("--lora-alpha", type=int, default=32)
    p.add_argument("--max-seq-length", type=int, default=1024)
    p.add_argument("--num-workers", type=int, default=4)
    p.add_argument("--logging-dir", type=Path)
    p.add_argument("--bf16", action="store_true", default=True)
    p.add_argument("--gradient-checkpointing", action="store_true", default=True)
    args = p.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )

    args.output_dir.mkdir(parents=True, exist_ok=True)

    # Late imports so failures are caught here, not at module import.
    # Exit codes signal *real* phase status:
    #   0 = trained successfully
    #   2 = unrecoverable precondition failure (deps, dataset, GPU) — this is
    #       NOT silent success. The driver MUST treat it as failure so the
    #       sentinel layout reflects reality.
    try:
        import torch
        from datasets import load_dataset
        from transformers import (
            AutoModelForCausalLM,
            AutoTokenizer,
            BitsAndBytesConfig,
            TrainingArguments,
        )
        from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
        from trl import SFTTrainer, SFTConfig
    except Exception as exc:
        logger.error("missing training dep: %s — phase 5 cannot run", exc)
        return 2

    if not torch.cuda.is_available():
        logger.error("CUDA not available — refusing to QLoRA train on CPU")
        return 2

    dataset_path = Path(args.dataset)
    is_local = dataset_path.exists()
    lang_filter = (
        {v.strip() for v in args.language_filter.split(",") if v.strip()}
        if args.language_filter else None
    )

    try:
        if lang_filter:
            # Need the full pool before filtering, since the language match
            # rate isn't known ahead of time and may not be uniform across
            # the dataset — slicing by percent first could silently drop
            # most (or all) matching rows.
            logger.info("loading full dataset %s (language filter active)…", args.dataset)
            if is_local:
                raw = load_dataset("parquet", data_dir=str(dataset_path), split="train")
            else:
                raw = load_dataset(args.dataset, split="train")
            before = len(raw)
            raw = raw.filter(lambda ex: ex.get(args.language_column) in lang_filter)
            logger.info(
                "language filter %s on column %r: %d/%d rows kept",
                sorted(lang_filter), args.language_column, len(raw), before,
            )
            n_keep = max(1, int(round(len(raw) * args.dataset_fraction)))
            raw = raw.select(range(min(n_keep, len(raw))))
            logger.info("dataset-fraction=%g of filtered pool -> %d rows", args.dataset_fraction, len(raw))
        else:
            logger.info("loading dataset %s (fraction=%g)…", args.dataset, args.dataset_fraction)
            pct = max(1, int(round(args.dataset_fraction * 100)))
            split = f"train[:{pct}%]"
            if is_local:
                raw = load_dataset("parquet", data_dir=str(dataset_path), split=split)
            else:
                raw = load_dataset(args.dataset, split=split)
    except Exception as exc:
        logger.error("dataset load failed (%s) — phase 5 cannot run", exc)
        return 2

    pair = _pick_columns(raw.features)
    if pair is None:
        logger.error(
            "dataset %s has no known (buggy, fixed) columns; cols=%s",
            args.dataset, list(raw.features.keys()),
        )
        return 2
    buggy_col, fixed_col = pair
    logger.info("using columns: buggy=%s fixed=%s", buggy_col, fixed_col)

    texts: list[str] = []
    for ex in raw:
        t = _format_example(ex, buggy_col, fixed_col)
        if t:
            texts.append(t)
    logger.info("training on %d examples", len(texts))
    if not texts:
        logger.error("no usable examples after filtering")
        return 2

    from datasets import Dataset
    train_ds = Dataset.from_dict({"text": texts})

    logger.info("loading base model %s in 4-bit…", args.base_model)
    bnb = BitsAndBytesConfig(
        load_in_4bit=True, bnb_4bit_quant_type="nf4",
        bnb_4bit_compute_dtype=torch.bfloat16,
    )
    tok = AutoTokenizer.from_pretrained(args.base_model)
    if tok.pad_token_id is None:
        tok.pad_token = tok.eos_token
    model = AutoModelForCausalLM.from_pretrained(
        args.base_model, quantization_config=bnb,
        device_map="auto", torch_dtype=torch.bfloat16,
    )
    model = prepare_model_for_kbit_training(model)

    lora = LoraConfig(
        r=args.lora_r, lora_alpha=args.lora_alpha, lora_dropout=0.05,
        bias="none", task_type="CAUSAL_LM",
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
    )
    model = get_peft_model(model, lora)
    model.print_trainable_parameters()

    cfg = SFTConfig(
        output_dir=str(args.output_dir),
        num_train_epochs=1,
        max_steps=args.max_steps,
        per_device_train_batch_size=args.per_device_batch_size,
        gradient_accumulation_steps=args.gradient_accumulation_steps,
        learning_rate=args.learning_rate,
        bf16=args.bf16,
        gradient_checkpointing=args.gradient_checkpointing,
        logging_steps=10,
        save_steps=100,
        save_total_limit=2,
        report_to=["tensorboard"] if args.logging_dir else [],
        logging_dir=str(args.logging_dir) if args.logging_dir else None,
        max_length=args.max_seq_length,
        dataset_text_field="text",
        packing=False,
        dataloader_num_workers=args.num_workers,
        warmup_ratio=0.03,
        lr_scheduler_type="cosine",
    )
    trainer = SFTTrainer(model=model, train_dataset=train_ds, args=cfg, processing_class=tok)

    # Resume if a checkpoint exists.
    ckpts = sorted(args.output_dir.glob("checkpoint-*"))
    resume = bool(ckpts)
    if resume:
        logger.info("resuming from %s", ckpts[-1])
    trainer.train(resume_from_checkpoint=resume)

    trainer.save_model(str(args.output_dir / "final"))
    logger.info("saved adapter to %s", args.output_dir / "final")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
