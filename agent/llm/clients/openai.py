"""OpenAI client — benchmark only per CLAUDE.md. Not used in the live pipeline."""
from __future__ import annotations

import os
import time
from typing import Any

from .base import LLMResponse, audit


class OpenAIClient:
    name = "openai"

    def __init__(self, model: str = "gpt-4o", api_key: str | None = None, client: Any = None):
        self.model = model
        if client is not None:
            self._client = client
        else:
            from openai import OpenAI  # lazy import

            self._client = OpenAI(api_key=api_key or os.environ.get("OPENAI_API_KEY"))

    def complete(self, prompt: str, max_tokens: int, temperature: float = 0.2) -> LLMResponse:
        start = time.monotonic()
        resp = self._client.chat.completions.create(
            model=self.model,
            max_tokens=max_tokens,
            temperature=temperature,
            messages=[{"role": "user", "content": prompt}],
        )
        latency_ms = int((time.monotonic() - start) * 1000)
        choice = resp.choices[0]
        usage = getattr(resp, "usage", None)
        out = LLMResponse(
            text=getattr(choice.message, "content", "") or "",
            model=self.model,
            tokens_in=int(getattr(usage, "prompt_tokens", 0) or 0),
            tokens_out=int(getattr(usage, "completion_tokens", 0) or 0),
            latency_ms=latency_ms,
        )
        audit(out)
        return out
