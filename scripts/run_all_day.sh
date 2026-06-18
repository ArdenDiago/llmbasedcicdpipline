#!/usr/bin/env bash
# Top-level day-long driver. See RUN_PLAN.md.
#
# Behaviour:
#   - One run dir per invocation: runs/<UTC stamp>/. Reuses an existing dir if
#     RUN_DIR is set in env (lets you resume after a crash).
#   - Each phase writes a .log + .done sentinel. If .done exists, skip.
#   - STATUS.md is rewritten after every phase transition.
#   - set -u + trap dump partial state on failure.
#
# Phase 3 (OWASP Java) is intentionally skipped — Java/Maven setup is too
# brittle for unattended runs. See RUN_PLAN.md "minimum viable full-day run".
set -euo pipefail

REPO="${REPO:-/home/arden/Coding/LLMAssistedVulnerabilityDetection/Project}"
cd "$REPO"

# .env lives at the repo root, one level up from Project/.
ENV_FILE="$REPO/../.env"

# Load .env if present; normalise HF_token → HF_TOKEN for huggingface_hub.
if [[ -f "$ENV_FILE" ]]; then
  set +u
  # shellcheck disable=SC2046
  export $(grep -v '^#' "$ENV_FILE" | xargs) 2>/dev/null || true
  set -u
fi
# HuggingFace reads HF_TOKEN (uppercase). Support both spellings.
if [[ -z "${HF_TOKEN:-}" && -n "${HF_token:-}" ]]; then
  export HF_TOKEN="$HF_token"
fi

# Pick a run dir — new by default, reused on resume.
if [[ -z "${RUN_DIR:-}" ]]; then
  STAMP=$(date -u +%Y%m%dT%H%M%SZ)
  RUN_DIR="$REPO/runs/$STAMP"
fi
mkdir -p "$RUN_DIR/phase1/results" "$RUN_DIR/phase1/reports" \
         "$RUN_DIR/phase2" "$RUN_DIR/phase4" \
         "$RUN_DIR/phase5/lora" "$RUN_DIR/phase5/tb" \
         "$RUN_DIR/phase6"
export RUN_DIR

# Driver-wide log tee (everything not inside a phase still lands here).
DRIVER_LOG="$RUN_DIR/driver.log"
exec > >(tee -a "$DRIVER_LOG") 2>&1

log() { printf "[%s] %s\n" "$(date -u +%FT%TZ)" "$*"; }

# Cache layout — see RUN_PLAN.md
export CACHE_ROOT="$REPO/.cache"
mkdir -p \
  "$CACHE_ROOT/hf" "$CACHE_ROOT/datasets" "$CACHE_ROOT/ollama" \
  "$CACHE_ROOT/llm_responses" "$CACHE_ROOT/scanner_outputs" "$CACHE_ROOT/torch"
export HF_HOME="$CACHE_ROOT/hf"
export HF_DATASETS_CACHE="$CACHE_ROOT/datasets"
export TRANSFORMERS_CACHE="$CACHE_ROOT/hf"
export TORCH_HOME="$CACHE_ROOT/torch"
export OMP_NUM_THREADS=10
export MKL_NUM_THREADS=10
export TOKENIZERS_PARALLELISM=true
export CUDA_VISIBLE_DEVICES=0
export PYTHONPATH="$REPO:${PYTHONPATH:-}"

# shellcheck disable=SC1091
source ../.venv/bin/activate

write_status() {
  local md="$RUN_DIR/STATUS.md"
  {
    echo "# Run status — $(basename "$RUN_DIR")"
    echo ""
    echo "Last updated: $(date -u +%FT%TZ)"
    echo ""
    echo "| phase | sentinel | status |"
    echo "|---|---|---|"
    for s in 0_setup 1_multiseed 2_cwe 4_fix 5_lora 6_reeval 7_aggregate; do
      if [[ -f "$RUN_DIR/$s.done" ]]; then
        printf "| %s | %s.done | ✓ done |\n" "$s" "$s"
      elif [[ -f "$RUN_DIR/$s.skipped" ]]; then
        printf "| %s | %s.skipped | — skipped (precondition not met) |\n" "$s" "$s"
      elif [[ -f "$RUN_DIR/$s.failed" ]]; then
        printf "| %s | %s.failed | ✗ failed — see %s.log |\n" "$s" "$s" "$s"
      elif [[ -f "$RUN_DIR/$s.log" ]]; then
        printf "| %s | (none) | running/failed — see %s.log |\n" "$s" "$s"
      else
        printf "| %s | (none) | pending |\n" "$s"
      fi
    done
    echo ""
    echo "Driver log: \`driver.log\`"
  } > "$md"
}
trap write_status EXIT

phase() {
  local sentinel="$1"; shift
  local title="$1"; shift
  if [[ -f "$RUN_DIR/$sentinel.done" ]]; then
    log "SKIP $title — sentinel exists"
    return 0
  fi
  if [[ -f "$RUN_DIR/$sentinel.failed" ]]; then
    log "SKIP $title — previously failed (delete $sentinel.failed to retry)"
    return 0
  fi
  log "BEGIN $title"
  local logf="$RUN_DIR/$sentinel.log"
  if "$@" >"$logf" 2>&1; then
    log "OK    $title (log: $sentinel.log)"
    write_status
  else
    local rc=$?
    log "FAIL  $title (rc=$rc, log: $sentinel.log) — continuing to next phase"
    : > "$RUN_DIR/$sentinel.failed"
    write_status
    return 0   # never abort the whole run on a single phase failure
  fi
}

# ---- Phase 0 ----------------------------------------------------------------
phase 0_setup "Phase 0 — env + prefetch" \
  bash scripts/00_setup.sh

# Phase 0 wrote its own log via tee inside the script. Mirror sentinel guard:
[[ -f "$RUN_DIR/0_setup.done" ]] || log "WARN Phase 0 did not finish cleanly"

# ---- Phase 1 — 10-seed detection benchmark ---------------------------------
run_phase1() {
  for seed in 1 2 3 4 5 6 7 8 9 10; do
    if [[ -f "$RUN_DIR/phase1/seed_${seed}.done" ]]; then
      echo "seed $seed already done"; continue
    fi
    echo ">>> seed $seed @ $(date -u +%FT%TZ)"
    python -m evaluation.run_benchmark --scan \
      --results-dir "$RUN_DIR/phase1/results" \
      --reports-dir "$RUN_DIR/phase1/reports"
    touch "$RUN_DIR/phase1/seed_${seed}.done"
  done
  python -m evaluation.aggregate_seeds \
    "$RUN_DIR/phase1/results" \
    --out "$RUN_DIR/phase1/summary.md"
  touch "$RUN_DIR/1_multiseed.done"
}
phase 1_multiseed "Phase 1 — multi-seed detection benchmark" run_phase1

# ---- Phase 2 — per-CWE breakdown -------------------------------------------
run_phase2() {
  python -m evaluation.cwe_report \
    --datasets-dir "$REPO/evaluation/datasets" \
    --out "$RUN_DIR/phase2/reports/per-cwe.md"
  touch "$RUN_DIR/2_cwe.done"
}
mkdir -p "$RUN_DIR/phase2/reports"
phase 2_cwe "Phase 2 — per-CWE breakdown" run_phase2

# ---- Phase 4 — fix-quality benchmark ---------------------------------------
# Free-only run by default. Set ENABLE_PAID=1 to add Haiku (capped).
run_phase4() {
  local models="ollama:deepseek-coder:6.7b,ollama:qwen2.5-coder:1.5b"
  if [[ "${ENABLE_PAID:-0}" == "1" ]]; then
    models+=",anthropic:claude-haiku-4-5-20251001"
  fi
  python -m evaluation.fix_eval \
    --datasets python_vulns,python_vulns_extended,js_vulns,js_vulns_extended \
    --models "$models" \
    --cap-paid-fixes 30 \
    --cache-dir "$CACHE_ROOT/llm_responses" \
    --max-tokens 1000 \
    --out "$RUN_DIR/phase4"
  touch "$RUN_DIR/4_fix.done"
}
phase 4_fix "Phase 4 — fix-quality benchmark" run_phase4

# ---- Phase 5 — QLoRA fine-tune ---------------------------------------------
run_phase5() {
  python -m training.train_lora \
    --base-model "Qwen/Qwen2.5-Coder-1.5B" \
    --dataset "bstee615/bigvul" \
    --dataset-fraction 1.0 \
    --output-dir "$RUN_DIR/phase5/lora" \
    --max-steps 920 \
    --per-device-batch-size 1 \
    --gradient-accumulation-steps 8 \
    --learning-rate 2e-4 \
    --lora-r 16 --lora-alpha 32 \
    --num-workers 4 \
    --logging-dir "$RUN_DIR/phase5/tb" \
    && touch "$RUN_DIR/5_lora.done"
}
phase 5_lora "Phase 5 — QLoRA fine-tune" run_phase5

# ---- Phase 6 — re-eval finetuned model -------------------------------------
run_phase6() {
  local adapter="$RUN_DIR/phase5/lora/final"
  if [[ ! -d "$adapter" ]]; then
    # Fall back to latest checkpoint dir if Phase 5 didn't write 'final'.
    adapter=$(ls -d "$RUN_DIR/phase5/lora"/checkpoint-* 2>/dev/null | sort | tail -n1 || true)
  fi
  if [[ -z "$adapter" || ! -d "$adapter" ]]; then
    echo "no LoRA adapter found — skipping phase 6"
    touch "$RUN_DIR/6_reeval.skipped"
    return 0
  fi
  local models="hf:Qwen/Qwen2.5-Coder-1.5B,hf:Qwen/Qwen2.5-Coder-1.5B+${adapter}"
  python -m evaluation.fix_eval \
    --datasets python_vulns,python_vulns_extended,js_vulns,js_vulns_extended \
    --models "$models" \
    --cap-paid-fixes 0 \
    --cache-dir "$CACHE_ROOT/llm_responses" \
    --max-tokens 1000 \
    --out "$RUN_DIR/phase6" \
    && touch "$RUN_DIR/6_reeval.done"
}
phase 6_reeval "Phase 6 — re-eval finetuned model" run_phase6

# ---- Phase 7 — aggregate ---------------------------------------------------
run_phase7() {
  python -m evaluation.aggregate \
    --run-dir "$RUN_DIR" \
    --out "$RUN_DIR/REPORT.md" \
    && touch "$RUN_DIR/7_aggregate.done"
}
phase 7_aggregate "Phase 7 — aggregate report" run_phase7

log "ALL PHASES ATTEMPTED — see $RUN_DIR/STATUS.md"
write_status
