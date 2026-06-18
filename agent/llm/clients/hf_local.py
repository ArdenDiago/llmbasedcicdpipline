"""Local HF transformers client (used for the QLoRA fine-tuned Qwen).

Loads a base model in 4-bit (NF4) and optionally attaches a LoRA adapter dir
for inference. Implements the LLMClient protocol so it can be dropped into
fix_eval alongside Ollama / Anthropic clients.

Heavy import — only imported lazily by build_client when first requested.
"""
from __future__ import annotations

import hashlib
import logging
import os
import time
from typing import Any

from .base import LLMResponse, audit

logger = logging.getLogger(__name__)


def _adapter_fingerprint(adapter_path: str) -> str:
    """Short hash of the adapter weights so retrains into the same directory
    (e.g. always named .../final) don't collide in the response cache."""
    weights = os.path.join(adapter_path, "adapter_model.safetensors")
    h = hashlib.sha256()
    with open(weights, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()[:12]


class HFLocalClient:
    name = "hf_local"

    def __init__(self, model_id: str, adapter_path: str | None = None):
        if adapter_path:
            self.model = f"{model_id}+{os.path.basename(adapter_path)}:{_adapter_fingerprint(adapter_path)}"
        else:
            self.model = model_id
        self._model_id = model_id
        self._adapter_path = adapter_path
        self._tok = None
        self._mdl = None

    def _load(self) -> None:
        if self._mdl is not None:
            return
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig

        logger.info("loading %s (4-bit) …", self._model_id)
        bnb = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=torch.bfloat16,
        )
        self._tok = AutoTokenizer.from_pretrained(self._model_id)
        if self._tok.pad_token_id is None:
            self._tok.pad_token = self._tok.eos_token
        self._mdl = AutoModelForCausalLM.from_pretrained(
            self._model_id,
            quantization_config=bnb,
            device_map="auto",
            torch_dtype=torch.bfloat16,
        )
        if self._adapter_path:
            from peft import PeftModel
            logger.info("attaching LoRA adapter %s", self._adapter_path)
            self._mdl = PeftModel.from_pretrained(self._mdl, self._adapter_path)
        self._mdl.eval()

    def complete(self, prompt: str, max_tokens: int, temperature: float = 0.2) -> LLMResponse:
        self._load()
        import torch

        start = time.monotonic()
        inputs = self._tok(prompt, return_tensors="pt", truncation=True, max_length=4096).to(self._mdl.device)
        tokens_in = int(inputs.input_ids.shape[1])
        gen_kwargs: dict[str, Any] = dict(
            max_new_tokens=max_tokens,
            do_sample=temperature > 0,
            temperature=max(temperature, 1e-5),
            pad_token_id=self._tok.pad_token_id,
        )
        with torch.no_grad():
            out = self._mdl.generate(**inputs, **gen_kwargs)
        new_tokens = out[0, tokens_in:]
        text = self._tok.decode(new_tokens, skip_special_tokens=True)
        tokens_out = int(new_tokens.shape[0])
        latency_ms = int((time.monotonic() - start) * 1000)
        resp = LLMResponse(
            text=text, model=self.model,
            tokens_in=tokens_in, tokens_out=tokens_out, latency_ms=latency_ms,
        )
        audit(resp)
        return resp
