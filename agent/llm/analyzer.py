"""LLM analyzer — orchestrates the escalation chain per CLAUDE.md.

Flow:
  1. DeepSeek (Ollama) generates a fix (attempt 1).
  2. Self-evaluate confidence from the response.
  3. If confidence < threshold → Haiku classifies the issue (attempt 2).
  4. If classifier says "complex" → Sonnet generates the fix (attempt 2).
  5. Only if Sonnet failed → Opus (attempt 3, LAST RESORT).

Every LLM call is logged with model/tokens/latency via clients.base.audit,
and also recorded in the returned FixProposal.audit list.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any

from . import confidence, prompts
from .clients.base import LLMClient, LLMResponse
from .config import BalancingConfig

logger = logging.getLogger(__name__)


@dataclass
class AuditEntry:
    attempt: int
    model: str
    stage: str  # "fix" | "classify" | "evaluate"
    tokens_in: int
    tokens_out: int
    latency_ms: int
    confidence: float | None = None


@dataclass
class FixProposal:
    diff: str
    confidence: float
    model_used: str
    attempts: int
    rationale: str | None = None
    audit: list[AuditEntry] = field(default_factory=list)
    error: str | None = None


@dataclass
class CascadeStats:
    """Aggregate tier-routing counts across N findings."""
    total: int = 0
    tier1_resolved: int = 0   # DeepSeek succeeded (attempts == 1)
    tier2_resolved: int = 0   # Haiku+Sonnet succeeded (attempts == 2)
    tier3_resolved: int = 0   # Opus used (attempts == 3)
    spurious: int = 0         # Haiku classified as spurious

    @property
    def escalation_rate_1to2(self) -> float:
        return (self.total - self.tier1_resolved) / self.total if self.total else 0.0

    @property
    def escalation_rate_2to3(self) -> float:
        eligible = self.total - self.tier1_resolved - self.spurious
        return self.tier3_resolved / eligible if eligible else 0.0

    def record(self, proposal: "FixProposal") -> None:
        self.total += 1
        if proposal.rationale == "classified as spurious":
            self.spurious += 1
        elif proposal.attempts == 1:
            self.tier1_resolved += 1
        elif proposal.attempts == 2:
            self.tier2_resolved += 1
        else:
            self.tier3_resolved += 1


@dataclass
class ClientSet:
    deepseek: LLMClient
    haiku: LLMClient
    sonnet: LLMClient
    opus: LLMClient


def analyze_finding(
    finding: dict[str, Any],
    file_contents: str,
    repo_full_name: str,
    commit_sha: str,
    clients: ClientSet,
    config: BalancingConfig,
) -> FixProposal:
    task = config.task("single_file_fix")
    threshold = config.escalation.confidence_threshold
    opus_min = config.escalation.opus_min_attempt
    max_attempts = config.escalation.max_attempts

    audit: list[AuditEntry] = []

    # Attempt 1: DeepSeek.
    fix_prompt = prompts.render(
        "fix_single_file",
        file_path=finding.get("file", ""),
        language=_language_for(finding.get("file", "")),
        issue_description=finding.get("message", ""),
        scanner_finding=finding,
        file_content=file_contents,
    )
    resp = clients.deepseek.complete(fix_prompt, max_tokens=task.max_tokens_out)
    score = confidence.extract_score(resp.text)
    audit.append(_entry(1, resp, "fix", score))

    if not confidence.should_escalate(score, threshold):
        return FixProposal(
            diff=resp.text,
            confidence=score or 0.0,
            model_used=resp.model,
            attempts=1,
            audit=audit,
        )

    if max_attempts < 2:
        return FixProposal(
            diff=resp.text, confidence=score or 0.0, model_used=resp.model,
            attempts=1, audit=audit, error="escalation disabled",
        )

    # Attempt 2a: Haiku classifies.
    classify_prompt = prompts.render(
        "classify_error",
        file_path=finding.get("file", ""),
        line_number=finding.get("line") or 0,
        error_message=finding.get("message", ""),
        traceback=finding.get("snippet"),
    )
    class_resp = clients.haiku.complete(
        classify_prompt, max_tokens=100,  # error_classification budget
    )
    category = _parse_category(class_resp.text)
    audit.append(_entry(2, class_resp, "classify", None))

    if category == "spurious":
        return FixProposal(
            diff="", confidence=0.0, model_used=class_resp.model,
            attempts=2, audit=audit, rationale="classified as spurious",
        )

    # Attempt 2b: Sonnet generates (regardless of simple/complex — Haiku is
    # a triage check, not a code generator per the model balancing table).
    sonnet_resp = clients.sonnet.complete(fix_prompt, max_tokens=task.max_tokens_out)
    sonnet_score = confidence.extract_score(sonnet_resp.text)
    audit.append(_entry(2, sonnet_resp, "fix", sonnet_score))

    if not confidence.should_escalate(sonnet_score, threshold):
        return FixProposal(
            diff=sonnet_resp.text,
            confidence=sonnet_score or 0.0,
            model_used=sonnet_resp.model,
            attempts=2,
            audit=audit,
        )

    if max_attempts < opus_min:
        return FixProposal(
            diff=sonnet_resp.text, confidence=sonnet_score or 0.0,
            model_used=sonnet_resp.model, attempts=2, audit=audit,
            error="max_attempts below opus_min",
        )

    # Attempt 3: Opus — LAST RESORT.
    logger.warning("escalating to Opus — last resort, attempt 3")
    opus_resp = clients.opus.complete(fix_prompt, max_tokens=task.max_tokens_out)
    opus_score = confidence.extract_score(opus_resp.text)
    audit.append(_entry(3, opus_resp, "fix", opus_score))

    return FixProposal(
        diff=opus_resp.text,
        confidence=opus_score or 0.0,
        model_used=opus_resp.model,
        attempts=3,
        audit=audit,
    )


_LANG_BY_EXT = {
    ".py": "python", ".js": "javascript", ".ts": "typescript",
    ".jsx": "javascript", ".tsx": "typescript", ".go": "go",
    ".rb": "ruby", ".java": "java", ".rs": "rust",
}


def _language_for(path: str) -> str:
    for ext, lang in _LANG_BY_EXT.items():
        if path.endswith(ext):
            return lang
    return ""


def _entry(attempt: int, resp: LLMResponse, stage: str, score: float | None) -> AuditEntry:
    return AuditEntry(
        attempt=attempt,
        model=resp.model,
        stage=stage,
        tokens_in=resp.tokens_in,
        tokens_out=resp.tokens_out,
        latency_ms=resp.latency_ms,
        confidence=score,
    )


def _parse_category(text: str) -> str:
    for candidate in _json_objects(text):
        try:
            obj = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict) and "category" in obj:
            return str(obj["category"]).lower()
    return "complex"  # safe default — escalate


def _json_objects(text: str) -> list[str]:
    out, depth, start = [], 0, -1
    for i, ch in enumerate(text):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start != -1:
                out.append(text[start : i + 1])
                start = -1
    return out
