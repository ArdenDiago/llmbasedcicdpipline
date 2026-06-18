"""Load config/model_balancing.yml with ${ENV:-default} expansion."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

_ENV_RE = re.compile(r"\$\{([A-Z0-9_]+)(?::-([^}]*))?\}")

DEFAULT_CONFIG_PATH = Path("config/model_balancing.yml")


@dataclass
class TaskConfig:
    name: str
    primary: str
    fallback: str | None
    last_resort: str | None
    max_tokens_in: int
    max_tokens_out: int


@dataclass
class EscalationConfig:
    confidence_threshold: float
    max_attempts: int
    opus_min_attempt: int


@dataclass
class BalancingConfig:
    models: dict[str, dict[str, Any]]
    tasks: dict[str, TaskConfig]
    escalation: EscalationConfig

    def task(self, name: str) -> TaskConfig:
        if name not in self.tasks:
            raise KeyError(f"unknown task: {name}")
        return self.tasks[name]


def load(path: str | Path = DEFAULT_CONFIG_PATH) -> BalancingConfig:
    text = Path(path).read_text(encoding="utf-8")
    text = _expand_env(text)
    data = yaml.safe_load(text) or {}

    tasks = {}
    for name, raw in (data.get("tasks") or {}).items():
        tasks[name] = TaskConfig(
            name=name,
            primary=raw["primary"],
            fallback=raw.get("fallback"),
            last_resort=raw.get("last_resort"),
            max_tokens_in=int(raw.get("max_tokens_in", 0)),
            max_tokens_out=int(raw.get("max_tokens_out", 0)),
        )
    esc_raw = data.get("escalation") or {}
    escalation = EscalationConfig(
        confidence_threshold=float(esc_raw.get("confidence_threshold", 0.5)),
        max_attempts=int(esc_raw.get("max_attempts", 3)),
        opus_min_attempt=int(esc_raw.get("opus_min_attempt", 3)),
    )
    return BalancingConfig(models=data.get("models") or {}, tasks=tasks, escalation=escalation)


def _expand_env(text: str) -> str:
    def repl(m: re.Match[str]) -> str:
        name, default = m.group(1), m.group(2)
        return os.environ.get(name, default if default is not None else "")

    return _ENV_RE.sub(repl, text)
