#!/usr/bin/env bash
# Dataset-swap experiment: same canonical LoRA hyperparameters as v2
# (r=16, alpha=32, lr=2e-4), but trained on hitoshura25/cvefixes filtered to
# Python+JavaScript instead of bigvul's C/C++-dominated corpus. Isolates
# dataset as the only changed variable, to test the distribution-shift
# hypothesis from EXPERIMENTS_SUMMARY.md / Paper/paper §6.
#
# Pre-req: the 3 raw parquet shards must already be downloaded to
# .cache/datasets/cvefixes_pyjs_raw/ (direct HTTPS to the resolve URLs,
# bypassing the much slower xet-protocol path load_dataset() uses by default
# on this machine's throttled link).
set -euo pipefail

REPO="/home/arden/Coding/LLMAssistedVulnerabilityDetection/Project"
RUN_DIR="$REPO/runs/20260617T072213Z"
RAW_DIR="$REPO/.cache/datasets/cvefixes_pyjs_raw"
DATASETS="python_vulns,python_vulns_extended,js_vulns,js_vulns_extended"
SLUG="cvefixes_pyjs"
BRANCH="experiment/lora-cvefixes-pyjs"

cd "$REPO"
# shellcheck disable=SC1091
source ../.venv/bin/activate
git checkout main

echo "=== waiting for shard downloads to finish @ $(date -u +%FT%TZ) ==="
EXPECTED=(210464790 440521625 580129539)
SHARDS=("shard_0000.parquet" "shard_0001.parquet" "shard_0002.parquet")
for i in 0 1 2; do
  while [[ ! -f "$RAW_DIR/${SHARDS[$i]}" ]] || [[ "$(stat -c%s "$RAW_DIR/${SHARDS[$i]}" 2>/dev/null || echo 0)" -lt "${EXPECTED[$i]}" ]]; do
    sleep 10
  done
  echo "  ${SHARDS[$i]} complete ($(stat -c%s "$RAW_DIR/${SHARDS[$i]}") bytes)"
done
echo "=== all shards downloaded @ $(date -u +%FT%TZ) ==="

echo "=== measuring real usable example count (mirrors train_lora.py filters) ==="
USABLE=$(python - <<'PY'
from datasets import load_dataset

raw = load_dataset("parquet", data_dir="/home/arden/Coding/LLMAssistedVulnerabilityDetection/Project/.cache/datasets/cvefixes_pyjs_raw", split="train")
print(f"total raw rows: {len(raw)}", flush=True)

target = {"Python", "JavaScript"}
filtered = raw.filter(lambda ex: ex.get("language") in target)
print(f"python+javascript rows: {len(filtered)}", flush=True)

usable = 0
for ex in filtered:
    b, f = ex.get("vulnerable_code"), ex.get("fixed_code")
    if not isinstance(b, str) or not isinstance(f, str) or not b.strip() or not f.strip():
        continue
    if b == f:
        continue
    if len(b) > 4000 or len(f) > 4000:
        continue
    usable += 1
print(f"usable after train_lora.py filters: {usable}", flush=True)
print(f"USABLE_COUNT={usable}")
PY
)
echo "$USABLE"
N=$(echo "$USABLE" | grep -oP 'USABLE_COUNT=\K\d+')
if [[ -z "$N" || "$N" -lt 20 ]]; then
  echo "=== too few usable examples ($N) — aborting, not a meaningful experiment ==="
  exit 1
fi

# effective batch size = per-device-batch(1) * grad-accum(8) = 8
STEPS=$(( (N + 7) / 8 ))
if [[ "$STEPS" -lt 30 ]]; then STEPS=30; fi
echo "=== usable=$N -> ~1 epoch = $STEPS steps (effective batch 8) ==="

echo "=== [$SLUG] training: r=16 alpha=32 lr=2e-4 steps=$STEPS (cvefixes Python+JS) @ $(date -u +%FT%TZ) ==="
t0=$(date +%s)
python -m training.train_lora \
  --base-model "Qwen/Qwen2.5-Coder-1.5B" \
  --dataset "$RAW_DIR" \
  --language-filter "Python,JavaScript" \
  --language-column "language" \
  --dataset-fraction 1.0 \
  --output-dir "$RUN_DIR/phase5_${SLUG}/lora" \
  --max-steps "$STEPS" \
  --per-device-batch-size 1 \
  --gradient-accumulation-steps 8 \
  --learning-rate 2e-4 \
  --lora-r 16 --lora-alpha 32 \
  --num-workers 4 \
  --logging-dir "$RUN_DIR/phase5_${SLUG}/tb" \
  > "$RUN_DIR/5_lora_${SLUG}.log" 2>&1
t1=$(date +%s)
echo "=== [$SLUG] training done in $((t1 - t0))s, re-evaluating ==="

adapter="$RUN_DIR/phase5_${SLUG}/lora/final"
python -m evaluation.fix_eval \
  --datasets "$DATASETS" \
  --models "hf:Qwen/Qwen2.5-Coder-1.5B,hf:Qwen/Qwen2.5-Coder-1.5B+${adapter}" \
  --cap-paid-fixes 0 \
  --cache-dir "$REPO/.cache/llm_responses" \
  --max-tokens 1000 \
  --out "$RUN_DIR/phase6_${SLUG}"
t2=$(date +%s)
echo "=== [$SLUG] eval done in $((t2 - t1))s, committing on $BRANCH ==="

git checkout -b "$BRANCH" main
git add "$RUN_DIR/5_lora_${SLUG}.log" "$RUN_DIR/phase6_${SLUG}/"
git commit -m "exp: LoRA on cvefixes Python+JS subset (r=16 alpha=32 lr=2e-4 steps=$STEPS)

Dataset-swap experiment: same canonical hyperparameters as v2, but trained
on hitoshura25/cvefixes filtered to Python+JavaScript ($N usable examples)
instead of bigvul, to test whether distribution shift (bigvul's C/C++
patches vs our Python/JS benchmark) explains the rank/lr-grid plateau
documented in EXPERIMENTS_SUMMARY.md.

$(cat "$RUN_DIR/phase6_${SLUG}/summary.md")"
git checkout main
echo "=== [$SLUG] total $((t2 - t0))s, complete @ $(date -u +%FT%TZ) ==="
