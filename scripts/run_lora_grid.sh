#!/usr/bin/env bash
# Ad hoc LoRA hyperparameter grid — NOT wired into run_all_day.sh, run manually:
#   bash scripts/run_lora_grid.sh
#
# Continues the rank/learning-rate ablation started on main (v2: r=16 a=32
# lr=2e-4 920 steps) and on branch experiment/lora-r32-lr2e4 (r=32 a=64
# lr=2e-4 300 steps — tied base exactly, same as v2). Both prior results tied
# the untouched base model at fix_accuracy=0.506/fix_safety=1.000 on the
# 79-attempt expanded benchmark; this grid tests whether a lower learning
# rate (instead of just more capacity) breaks the tie in either direction.
#
# Each cell: trains a fresh adapter into its own phase5_<slug>/ dir (never
# reuses another cell's output dir — train_lora.py auto-resumes from
# checkpoints in the same --output-dir, which would silently chain onto the
# wrong run), re-evaluates base vs that adapter on the same expanded dataset
# list used throughout, then commits the result on its own experiment/<slug>
# branch and returns to main. Nothing is merged automatically.
#
# Safe to interrupt and re-run: a cell is skipped if its branch already
# exists (so a half-finished cell whose branch wasn't created yet will
# re-run from scratch; a cell that got as far as the branch+commit will not).
#
# Estimated time: ~300 steps/cell at ~7.8s/step (observed on this GPU) ≈ 39min
# training + ~5-10min re-eval + ~1min branch/commit overhead ≈ ~45-50min/cell.
# 3 cells ≈ 2h15m-2h30m total, sequential (single GPU).
set -euo pipefail

REPO="/home/arden/Coding/LLMAssistedVulnerabilityDetection/Project"
RUN_DIR="$REPO/runs/20260617T072213Z"
DATASETS="python_vulns,python_vulns_extended,js_vulns,js_vulns_extended"

cd "$REPO"
# shellcheck disable=SC1091
source ../.venv/bin/activate
git checkout main

# slug : lora_r : lora_alpha : learning_rate : max_steps
EXPERIMENTS=(
  "r16-lowlr:16:32:1e-4:300"
  "r32-lowlr:32:64:1e-4:300"
  "r64-lowlr:64:128:1e-4:300"
)

for spec in "${EXPERIMENTS[@]}"; do
  IFS=':' read -r slug r alpha lr steps <<< "$spec"
  branch="experiment/lora-$slug"
  dirslug="${slug//-/_}"

  if git rev-parse --verify "$branch" &>/dev/null; then
    echo "=== [$slug] branch $branch already exists, skipping ==="
    continue
  fi

  echo "=== [$slug] training: r=$r alpha=$alpha lr=$lr steps=$steps @ $(date -u +%FT%TZ) ==="
  t0=$(date +%s)
  python -m training.train_lora \
    --base-model "Qwen/Qwen2.5-Coder-1.5B" \
    --dataset "bstee615/bigvul" \
    --dataset-fraction 1.0 \
    --output-dir "$RUN_DIR/phase5_${dirslug}/lora" \
    --max-steps "$steps" \
    --per-device-batch-size 1 \
    --gradient-accumulation-steps 8 \
    --learning-rate "$lr" \
    --lora-r "$r" --lora-alpha "$alpha" \
    --num-workers 4 \
    --logging-dir "$RUN_DIR/phase5_${dirslug}/tb" \
    > "$RUN_DIR/5_lora_${dirslug}.log" 2>&1
  t1=$(date +%s)
  echo "=== [$slug] training done in $((t1 - t0))s, re-evaluating ==="

  adapter="$RUN_DIR/phase5_${dirslug}/lora/final"
  python -m evaluation.fix_eval \
    --datasets "$DATASETS" \
    --models "hf:Qwen/Qwen2.5-Coder-1.5B,hf:Qwen/Qwen2.5-Coder-1.5B+${adapter}" \
    --cap-paid-fixes 0 \
    --cache-dir "$REPO/.cache/llm_responses" \
    --max-tokens 1000 \
    --out "$RUN_DIR/phase6_${dirslug}"
  t2=$(date +%s)
  echo "=== [$slug] eval done in $((t2 - t1))s, committing on $branch ==="

  git checkout -b "$branch" main
  git add "$RUN_DIR/5_lora_${dirslug}.log" "$RUN_DIR/phase6_${dirslug}/"
  git commit -m "exp: LoRA $slug (r=$r alpha=$alpha lr=$lr steps=$steps)

$(cat "$RUN_DIR/phase6_${dirslug}/summary.md")"
  git checkout main
  echo "=== [$slug] total $((t2 - t0))s ==="
done

echo "=== grid complete @ $(date -u +%FT%TZ) ==="
