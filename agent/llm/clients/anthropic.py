"""Anthropic client (Haiku / Sonnet / Opus)."""
from __future__ import annotations

import os
import time
from typing import Any

from .base import LLMResponse, audit


class AnthropicClient:
    name = "anthropic"

    def __init__(self, model: str, api_key: str | None = None, client: Any = None):
        self.model = model
        if client is not None:
            self._client = client
        else:
            from anthropic import Anthropic  # lazy import

            self._client = Anthropic(api_key=api_key or os.environ.get("ANTHROPIC_API_KEY"))

    def complete(self, prompt: str, max_tokens: int, temperature: float = 0.2) -> LLMResponse:
        start = time.monotonic()
        msg = self._client.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            temperature=temperature,
            messages=[{"role": "user", "content": prompt}],
        )
        latency_ms = int((time.monotonic() - start) * 1000)
        text = _extract_text(msg)
        usage = getattr(msg, "usage", None)
        resp = LLMResponse(
            text=text,
            model=self.model,
            tokens_in=int(getattr(usage, "input_tokens", 0) or 0),
            tokens_out=int(getattr(usage, "output_tokens", 0) or 0),
            latency_ms=latency_ms,
        )
        audit(resp)
        return resp


def _extract_text(msg: Any) -> str:
    content = getattr(msg, "content", None) or []
    parts: list[str] = []
    for block in content:
        text = getattr(block, "text", None)
        if text:
            parts.append(text)
    return "".join(parts)
