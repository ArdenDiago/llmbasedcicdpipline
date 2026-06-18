"""Content-addressed LLM response cache.

Wraps any LLMClient. Key = sha256(model + prompt + max_tokens + temperature).
On hit, returns cached LLMResponse without calling the upstream — critical for
Phase 4 fix-eval reruns (don't re-pay for tokens, makes runs deterministic).

Usage:
    from agent.llm.cache import CachedClient
    client = CachedClient(real_client, cache_dir=Path(".cache/llm_responses"))
"""
from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .clients.base import LLMResponse

logger = logging.getLogger(__name__)


class CachedClient:
    """Drop-in wrapper that satisfies the LLMClient Protocol."""

    def __init__(self, upstream: Any, cache_dir: Path):
        self.upstream = upstream
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.hits = 0
        self.misses = 0

    @property
    def name(self) -> str:
        return f"cached:{getattr(self.upstream, 'name', 'unknown')}"

    @property
    def model(self) -> str:
        return getattr(self.upstream, "model", "unknown")

    def complete(self, prompt: str, max_tokens: int, temperature: float = 0.2) -> LLMResponse:
        key = self._key(prompt, max_tokens, temperature)
        path = self.cache_dir / f"{key}.json"
        if path.exists():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                self.hits += 1
                logger.debug("llm_cache HIT %s model=%s", key[:12], data.get("model"))
                return LLMResponse(**data)
            except Exception as exc:
                logger.warning("llm_cache corrupt %s: %s — refetching", path.name, exc)

        resp = self.upstream.complete(prompt, max_tokens=max_tokens, temperature=temperature)
        self.misses += 1
        try:
            path.write_text(json.dumps(asdict(resp)), encoding="utf-8")
        except Exception as exc:
            logger.warning("llm_cache write failed %s: %s", path.name, exc)
        return resp

    def _key(self, prompt: str, max_tokens: int, temperature: float) -> str:
        h = hashlib.sha256()
        h.update(self.model.encode("utf-8"))
        h.update(b"\x00")
        h.update(str(max_tokens).encode("utf-8"))
        h.update(b"\x00")
        h.update(f"{temperature:.4f}".encode("utf-8"))
        h.update(b"\x00")
        h.update(prompt.encode("utf-8"))
        return h.hexdigest()
