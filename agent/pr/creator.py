"""Orchestrates PR creation: branch → patch → validate → commit → push → PR.

Follows the flow in agent/pr/CLAUDE.md. Validation runs the test suite
against the patched clone; a failing suite aborts PR creation.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from . import brancher, committer, github_api

logger = logging.getLogger(__name__)

FIX_TITLE_MAX = 72


@dataclass
class PRRequest:
    finding: dict[str, Any]
    diff: str
    confidence: float
    model_used: str
    repo_path: Path
    repo_full_name: str
    base_branch: str
    commit_sha: str
    pr_body: str


@dataclass
class PRResult:
    created: bool
    branch: str
    pr: github_api.PullRequestRef | None = None
    skipped_reason: str | None = None


ValidateFn = Callable[[Path], bool]


def _title_for(finding: dict[str, Any]) -> str:
    scanner = finding.get("scanner", "unknown")
    rule = finding.get("rule_id", "unknown")
    file = finding.get("file", "")
    desc = f"{rule} in {file}" if file else rule
    title = f"fix({scanner}): {desc}"
    return title[:FIX_TITLE_MAX]


def _labels_for(finding: dict[str, Any]) -> list[str]:
    severity = (finding.get("severity") or "info").lower()
    return ["automated-fix", "security", severity]


def create_pr(
    req: PRRequest,
    validate: ValidateFn,
    client: github_api._GithubLike | None = None,
) -> PRResult:
    """Run the full PR creation workflow.

    `validate` runs the project's test suite against the patched clone and
    returns True if tests pass. A False result aborts PR creation per
    CLAUDE.md ("NEVER create a PR if validation tests fail").
    """
    if not req.diff.strip():
        return PRResult(created=False, branch="", skipped_reason="empty diff")

    branch = brancher.branch_name(
        scanner=req.finding.get("scanner", "unknown"),
        rule_id=req.finding.get("rule_id", "unknown"),
        file=req.finding.get("file", ""),
        line=req.finding.get("line"),
        commit_sha=req.commit_sha,
    )

    committer.create_branch(req.repo_path, branch, base=req.base_branch)
    committer.apply_patch(req.repo_path, req.diff)

    if not validate(req.repo_path):
        return PRResult(
            created=False,
            branch=branch,
            skipped_reason="validation tests failed",
        )

    message = committer.commit_message(req.finding, req.confidence, req.model_used)
    committer.commit_all(req.repo_path, message)
    committer.push(req.repo_path, branch)

    gh = client or github_api.default_client()
    pr = github_api.create_pull_request(
        client=gh,
        repo_full_name=req.repo_full_name,
        title=_title_for(req.finding),
        body=req.pr_body,
        head=branch,
        base=req.base_branch,
        labels=_labels_for(req.finding),
    )
    return PRResult(created=True, branch=branch, pr=pr)
