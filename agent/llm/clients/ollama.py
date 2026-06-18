"""Ollama client (DeepSeek Coder / CodeLLaMA — primary, free, local)."""
from __future__ import annotations

import os
import time
from typing import Any

from .base import LLMResponse, audit

DEFAULT_MODEL = "deepseek-coder:6.7b"


class OllamaClient:
    name = "ollama"

    def __init__(self, model: str = DEFAULT_MODEL, host: str | None = None, client: Any = None):
        self.model = model
        self.host = host or os.environ.get("OLLAMA_HOST", "http://localhost:11434")
        if client is not None:
            self._client = client
        else:
            import ollama  # lazy import so tests can skip

            self._client = ollama.Client(host=self.host)

    def complete(self, prompt: str, max_tokens: int, temperature: float = 0.2) -> LLMResponse:
        start = time.monotonic()
        raw = self._client.generate(
            model=self.model,
            prompt=prompt,
            options={"num_predict": max_tokens, "temperature": temperature},
        )
        latency_ms = int((time.monotonic() - start) * 1000)
        resp = LLMResponse(
            text=_field(raw, "response") or "",
            model=_field(raw, "model") or self.model,
            tokens_in=int(_field(raw, "prompt_eval_count") or 0),
            tokens_out=int(_field(raw, "eval_count") or 0),
            latency_ms=latency_ms,
        )
        audit(resp)
        return resp


def _field(obj: Any, key: str) -> Any:
    if isinstance(obj, dict):
        return obj.get(key)
    return getattr(obj, key, None)
