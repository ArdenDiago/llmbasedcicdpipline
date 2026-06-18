"""End-to-end orchestrator: sandbox envelope → LLM fixes → PRs.

Consumes the envelope emitted by agent.sandbox.collector.collect() and
runs each high-severity scanner finding through the LLM analyzer, then
hands the proposed patch to the PR creator.

Designed so unit tests can inject stubs for file reads, LLM clients,
validation, and GitHub I/O. No network calls happen here by default.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .llm import analyzer
from .llm.config import BalancingConfig
from .llm.prompts import render as render_prompt
from .pr import creator, github_api
from .security.normalize import severity_rank

logger = logging.getLogger(__name__)

DEFAULT_MIN_SEVERITY = "medium"

FileReader = Callable[[Path, str], str]
ValidateFn = Callable[[Path], bool]
PRBodyRenderer = Callable[[dict[str, Any], analyzer.FixProposal], str]


@dataclass
class PipelineResult:
    processed: int
    created: list[creator.PRResult] = field(default_factory=list)
    skipped: list[dict[str, Any]] = field(default_factory=list)

    def summary(self) -> dict[str, int]:
        return {
            "processed": self.processed,
            "created": sum(1 for r in self.created if r.created),
            "skipped": len(self.skipped),
        }


def default_file_reader(repo_path: Path, rel: str) -> str:
    return (repo_path / rel).read_text(encoding="utf-8", errors="replace")


def default_pr_body(finding: dict[str, Any], fix: analyzer.FixProposal) -> str:
    return render_prompt(
        "pr_body",
        finding=finding,
        fix_summary=fix.rationale or "See diff.",
        confidence=f"{fix.confidence:.2f}",
        model_used=fix.model_used,
    )


def _eligible(finding: dict[str, Any], min_severity: str) -> bool:
    return severity_rank(finding.get("severity")) >= severity_rank(min_severity)


def run(
    envelope: dict[str, Any],
    repo_path: Path,
    clients: analyzer.ClientSet,
    config: BalancingConfig,
    validate: ValidateFn,
    github_client: github_api._GithubLike | None = None,
    file_reader: FileReader = default_file_reader,
    pr_body: PRBodyRenderer = default_pr_body,
    min_severity: str = DEFAULT_MIN_SEVERITY,
    base_branch: str = "main",
) -> PipelineResult:
    dispatch = envelope.get("dispatch") or {}
    repo_full_name = dispatch.get("repo_full_name")
    commit_sha = dispatch.get("commit_sha") or ""
    if not repo_full_name:
        raise ValueError("envelope missing dispatch.repo_full_name")

    findings = _extract_findings(envelope)
    result = PipelineResult(processed=0)

    for finding in findings:
        if not _eligible(finding, min_severity):
            result.skipped.append({"finding": finding, "reason": "below min_severity"})
            continue

        try:
            file_contents = file_reader(repo_path, finding.get("file", ""))
        except OSError as exc:
            logger.warning("skip finding: cannot read %s: %s", finding.get("file"), exc)
            result.skipped.append({"finding": finding, "reason": f"read error: {exc}"})
            continue

        result.processed += 1

        fix = analyzer.analyze_finding(
            finding=finding,
            file_contents=file_contents,
            repo_full_name=repo_full_name,
            commit_sha=commit_sha,
            clients=clients,
            config=config,
        )

        if fix.error or not fix.diff.strip():
            result.skipped.append(
                {"finding": finding, "reason": fix.error or "no diff"}
            )
            continue

        body = pr_body(finding, fix)
        req = creator.PRRequest(
            finding=finding,
            diff=fix.diff,
            confidence=fix.confidence,
            model_used=fix.model_used,
            repo_path=repo_path,
            repo_full_name=repo_full_name,
            base_branch=base_branch,
            commit_sha=commit_sha,
            pr_body=body,
        )
        result.created.append(creator.create_pr(req, validate=validate, client=github_client))

    return result


def _extract_findings(envelope: dict[str, Any]) -> list[dict[str, Any]]:
    scanners = envelope.get("scanners")
    if scanners is None:
        return []
    if isinstance(scanners, dict) and "findings" in scanners:
        return list(scanners["findings"])
    if isinstance(scanners, list):
        return list(scanners)
    return []
