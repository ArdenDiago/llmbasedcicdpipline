"""LLM analyzer — orchestrates the escalation chain per CLAUDE.md.

Flow:
  1. DeepSeek (Ollama) generates a fix (attempt 1).
  2. Haiku scores that fix's confidence via confidence_eval.j2 (see note below).
  3. If confidence < threshold → Haiku classifies the issue (attempt 2).
  4. If classifier says "spurious" → stop, no fix needed.
  5. Otherwise Sonnet generates the fix (attempt 2), scored by Haiku again.
  6. Only if Sonnet's fix also scores below threshold → Opus (attempt 3,
     LAST RESORT).

Confidence scoring is always done by Haiku (root CLAUDE.md's model-balancing
table assigns "confidence scoring" to Haiku specifically), never by having a
fix-generating model self-report: fix_single_file.j2 explicitly instructs
"Respond with ONLY the corrected file content, no explanation", so a
generating model's own response never contains a usable score, and a model
grading its own fix is a weaker signal than an independent evaluator anyway.

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

# Rough chars-per-token heuristic — no tokenizer dependency. Good enough to
# stop a large file from silently blowing past a task's max_tokens_in budget
# (previously unenforced anywhere: the "Token budget per task" table in
# CLAUDE.md was documentation with no corresponding guard in code).
_CHARS_PER_TOKEN = 4


def _truncate_for_budget(text: str, max_tokens: int) -> str:
    if max_tokens <= 0 or not text:
        return text
    max_chars = max_tokens * _CHARS_PER_TOKEN
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "\n... [truncated to fit token budget] ...\n"


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
        file_content=_truncate_for_budget(file_contents, task.max_tokens_in),
    )
    resp = clients.deepseek.complete(fix_prompt, max_tokens=task.max_tokens_out)
    audit.append(_entry(1, resp, "fix", None))
    score = _evaluate_confidence(
        clients, config, finding, file_contents, resp.text, audit, attempt=1,
    )

    if not confidence.should_escalate(score, threshold):
        return FixProposal(
            diff=resp.text,
            confidence=score or 0.0,
            model_used=resp.model,
            attempts=1,
            audit=audit,
        )

    if max_attempts < 2 or task.fallback is None:
        # task.fallback is None means model_balancing.yml doesn't authorize
        # a fallback model for this task at all — config.task(...) is the
        # source of truth for escalation eligibility, not just documentation.
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
    classify_task = config.task("error_classification")
    class_resp = clients.haiku.complete(
        classify_prompt, max_tokens=classify_task.max_tokens_out,
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
    audit.append(_entry(2, sonnet_resp, "fix", None))
    sonnet_score = _evaluate_confidence(
        clients, config, finding, file_contents, sonnet_resp.text, audit, attempt=2,
    )

    if not confidence.should_escalate(sonnet_score, threshold):
        return FixProposal(
            diff=sonnet_resp.text,
            confidence=sonnet_score or 0.0,
            model_used=sonnet_resp.model,
            attempts=2,
            audit=audit,
        )

    if max_attempts < opus_min or task.last_resort is None:
        # task.last_resort is None means this task isn't authorized to reach
        # Opus at all per model_balancing.yml — previously this branch was
        # gated only on the global escalation.max_attempts/opus_min_attempt
        # counters, so Opus was reachable for every task regardless of
        # whether its YAML entry declared a last_resort model.
        return FixProposal(
            diff=sonnet_resp.text, confidence=sonnet_score or 0.0,
            model_used=sonnet_resp.model, attempts=2, audit=audit,
            error="max_attempts below opus_min",
        )

    # Attempt 3: Opus — LAST RESORT. Nothing left to escalate to, so this
    # score is for accurate reporting only, not a routing decision.
    logger.warning("escalating to Opus — last resort, attempt 3")
    opus_resp = clients.opus.complete(fix_prompt, max_tokens=task.max_tokens_out)
    audit.append(_entry(3, opus_resp, "fix", None))
    opus_score = _evaluate_confidence(
        clients, config, finding, file_contents, opus_resp.text, audit, attempt=3,
    )

    return FixProposal(
        diff=opus_resp.text,
        confidence=opus_score or 0.0,
        model_used=opus_resp.model,
        attempts=3,
        audit=audit,
    )


def _evaluate_confidence(
    clients: ClientSet,
    config: BalancingConfig,
    finding: dict[str, Any],
    original_code: str,
    fixed_code: str,
    audit: list[AuditEntry],
    attempt: int,
) -> float | None:
    """Score a candidate fix's confidence via confidence_eval.j2, always
    through Haiku (see the module docstring for why)."""
    eval_task = config.task("confidence_eval")
    # Split the input budget between the two code blocks the template embeds.
    half_budget = eval_task.max_tokens_in // 2
    eval_prompt = prompts.render(
        "confidence_eval",
        issue_description=finding.get("message", ""),
        language=_language_for(finding.get("file", "")),
        original_code=_truncate_for_budget(original_code, half_budget),
        fixed_code=_truncate_for_budget(fixed_code, half_budget),
    )
    eval_resp = clients.haiku.complete(eval_prompt, max_tokens=eval_task.max_tokens_out)
    score = confidence.extract_score(eval_resp.text)
    audit.append(_entry(attempt, eval_resp, "evaluate", score))
    return score


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
    for candidate in confidence.json_candidates(text):
        try:
            obj = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict) and "category" in obj:
            return str(obj["category"]).lower()
    return "complex"  # safe default — escalate
