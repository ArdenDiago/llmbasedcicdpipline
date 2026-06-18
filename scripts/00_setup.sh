#!/usr/bin/env bash
# Phase 0 — environment + cache prefetch.
# Idempotent: re-running skips already-installed pip packages, already-pulled
# Ollama models, and already-cached HF artefacts.
set -euo pipefail

REPO="${REPO:-/home/arden/Coding/LLMAssistedVulnerabilityDetection/Project}"
RUN_DIR="${RUN_DIR:?RUN_DIR must be set}"
PHASE_LOG="$RUN_DIR/0_setup.log"
exec > >(tee -a "$PHASE_LOG") 2>&1

echo "=== PHASE 0: setup @ $(date -u +%FT%TZ) ==="

cd "$REPO"
# shellcheck disable=SC1091
source ../.venv/bin/activate

# 0.0 start ollama service if not already running
echo "--- 0.0 ollama service ---"
if ! ollama list &>/dev/null; then
  echo "starting ollama serve in background…"
  setsid ollama serve >> "$RUN_DIR/ollama.log" 2>&1 &
  disown
  OLLAMA_PID=$!
  echo "ollama pid=$OLLAMA_PID"
  # wait up to 15s for it to come up
  for i in $(seq 1 15); do
    sleep 1
    ollama list &>/dev/null && echo "ollama ready after ${i}s" && break
    [[ $i -eq 15 ]] && echo "WARN: ollama not responding after 15s — model pulls may fail"
  done
else
  echo "ollama already running"
fi

# 0.1 sanity
echo "--- 0.1 sanity ---"
python -V
which semgrep bandit ollama
nvidia-smi --query-gpu=name,memory.free --format=csv,noheader || echo "no gpu visible"

# 0.2 install missing pip deps. --quiet to keep log readable.
echo "--- 0.2 pip install ---"
pip install --quiet --upgrade pip wheel
# torch first — pin to a CUDA build that matches the local driver.
# Try plain index first (works if user already has cuda wheels); fall back to
# the official CUDA 12.1 index. Keep going on failure — Phase 5 will be the
# only thing that needs torch and we'd rather log + continue than die here.
if ! python -c "import torch" 2>/dev/null; then
  echo "installing torch (cuda 12.1)…"
  pip install --quiet \
    --index-url https://download.pytorch.org/whl/cu121 \
    "torch>=2.4" || echo "WARN: torch install failed; phase 5 will be skipped"
fi
pip install --quiet \
  "transformers>=4.45" "datasets>=3.0" "peft>=0.13" "accelerate>=1.0" \
  "bitsandbytes>=0.44" "trl>=0.11" "scikit-learn" "ollama" "anthropic" \
  "PyYAML" "Jinja2" || echo "WARN: some hf deps failed; will retry per-phase"

python -c "import torch; print('torch', torch.__version__, 'cuda', torch.cuda.is_available())" || true
python -c "import transformers, datasets, peft; print('hf stack ok')" || true

# 0.3 ollama models — pull if missing
echo "--- 0.3 ollama models ---"
have_model() { ollama list 2>/dev/null | awk '{print $1}' | grep -qx "$1"; }
for m in deepseek-coder:6.7b qwen2.5-coder:1.5b; do
  if have_model "$m"; then
    echo "✓ $m already present"
  else
    echo "pulling $m …"
    ollama pull "$m" || echo "WARN: pull failed for $m"
  fi
done

# 0.4 prefetch HF base model + datasets (cached → free on rerun)
echo "--- 0.4 hf prefetch ---"
export HF_HOME="$REPO/.cache/hf"
export HF_DATASETS_CACHE="$REPO/.cache/datasets"
export TRANSFORMERS_CACHE="$REPO/.cache/hf"
mkdir -p "$HF_HOME" "$HF_DATASETS_CACHE"

python - <<'PY' || echo "WARN: HF prefetch partial — phases 5/6 may degrade"
import os, sys
os.environ.setdefault("HF_HUB_DISABLE_PROGRESS_BARS", "1")
# Forward the HF token so gated datasets (CVEFixes) are accessible.
hf_tok = os.environ.get("HF_TOKEN") or os.environ.get("HF_token")
if hf_tok:
    os.environ["HF_TOKEN"] = hf_tok
    print(f"HF_TOKEN set (len={len(hf_tok)})")

from transformers import AutoTokenizer, AutoModelForCausalLM
m = "Qwen/Qwen2.5-Coder-1.5B"
print(f"prefetching tokenizer + model: {m}")
AutoTokenizer.from_pretrained(m)
AutoModelForCausalLM.from_pretrained(m, torch_dtype="auto")
print("base model cached")

from datasets import load_dataset
for ds in ("bstee615/bigvul",):
    try:
        load_dataset(ds, split="train[:1%]")
        print(f"dataset cached: {ds}")
    except Exception as exc:
        print(f"WARN: dataset {ds} prefetch failed: {exc}")
PY

echo "=== PHASE 0 done @ $(date -u +%FT%TZ) ==="
touch "$RUN_DIR/0_setup.done"
