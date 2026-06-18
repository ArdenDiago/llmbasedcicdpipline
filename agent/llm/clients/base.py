"""Common LLM response shape + audit logging."""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Protocol

logger = logging.getLogger("agent.llm")


@dataclass
class LLMResponse:
    text: str
    model: str
    tokens_in: int
    tokens_out: int
    latency_ms: int


class LLMClient(Protocol):
    name: str

    def complete(self, prompt: str, max_tokens: int, temperature: float = 0.2) -> LLMResponse: ...


def audit(resp: LLMResponse) -> None:
    """Log every call per CLAUDE.md: model, tokens_in, tokens_out, latency."""
    logger.info(
        "llm_call model=%s tokens_in=%d tokens_out=%d latency_ms=%d",
        resp.model,
        resp.tokens_in,
        resp.tokens_out,
        resp.latency_ms,
    )
