"""Jinja2 prompt template loader.

Templates live in agent/llm/prompts/*.j2. Per CLAUDE.md, keep logic out of
templates and never modify without re-running the evaluation suite.
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, StrictUndefined, TemplateNotFound

TEMPLATE_DIR = Path(__file__).parent / "prompts"


@lru_cache(maxsize=1)
def _env() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        undefined=StrictUndefined,
        keep_trailing_newline=True,
        autoescape=False,
    )


def render(name: str, **context: Any) -> str:
    try:
        tmpl = _env().get_template(f"{name}.j2")
    except TemplateNotFound as exc:
        raise KeyError(f"unknown prompt: {name}") from exc
    return tmpl.render(**context)


def available() -> list[str]:
    return sorted(p.stem for p in TEMPLATE_DIR.glob("*.j2"))
