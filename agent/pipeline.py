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
from .sandbox.container import REPO_BIND_PATH
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


def _relativize(rel: str) -> str:
    """Scanners run inside the sandbox container, where the checkout is
    bind-mounted read-only at REPO_BIND_PATH ("/workspace") — see
    container.py — so every finding's "file" field is an absolute path
    under that mount, not a path relative to repo_path (the *host*
    directory clone.py created, which has a different, per-run name).
    `repo_path / rel` silently discards repo_path for an absolute rel
    (pathlib join semantics), so without stripping the mount prefix first,
    a file read would try "/workspace/..." on the host — which doesn't
    exist there — and a PR write (creator.py's write_full_file, which uses
    a finding's "file" field the same way) would resolve outside repo_path
    entirely and get rejected as "escapes repo". Shared by every consumer
    of a finding's "file" field (file_reader, the fix/PR-body prompts,
    creator.py's write target, branch naming, commit messages) so they all
    see the same relative path instead of each needing its own copy of
    this strip. evaluation/scan.py's _relativize() hits the same
    absolute-path issue for its own (offline, non-live) purposes."""
    rel_path = Path(rel)
    if rel_path.is_absolute():
        try:
            rel_path = rel_path.relative_to(REPO_BIND_PATH)
        except ValueError:
            pass
    return str(rel_path)


def default_file_reader(repo_path: Path, rel: str) -> str:
    return (repo_path / _relativize(rel)).read_text(encoding="utf-8", errors="replace")


def default_pr_body(
    finding: dict[str, Any],
    fix: analyzer.FixProposal,
    haiku_client: analyzer.LLMClient,
    max_tokens: int = 500,
) -> str:
    """pr_body.j2 is an LLM *prompt* ("Generate a concise pull request
    description...", ending with a format template using literal
    placeholders like {scanner}/{one paragraph} for the model to fill in),
    not a Jinja2 output template — those single-brace placeholders are
    instructions to the model, not template variables, so rendering the
    template alone and returning it directly (a prior bug) would put a PR
    body's worth of unfilled instructions and literal "{one paragraph}"
    text on every real PR. Root CLAUDE.md documents PR body generation as
    a Haiku task; this actually calls Haiku with the rendered prompt."""
    prompt = render_prompt(
        "pr_body",
        finding=finding,
        fix_summary=fix.rationale or "See changed file.",
        confidence=f"{fix.confidence:.2f}",
        model_used=fix.model_used,
    )
    resp = haiku_client.complete(prompt, max_tokens=max_tokens)
    return resp.text


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
    pr_body: PRBodyRenderer | None = None,
    min_severity: str = DEFAULT_MIN_SEVERITY,
    base_branch: str | None = None,
) -> PipelineResult:
    dispatch = envelope.get("dispatch") or {}
    repo_full_name = dispatch.get("repo_full_name")
    commit_sha = dispatch.get("commit_sha") or ""
    if not repo_full_name:
        raise ValueError("envelope missing dispatch.repo_full_name")

    # base_branch defaults to whatever branch was actually pushed
    # (envelope["dispatch"]["branch"], populated by collector.collect() from
    # the webhook payload) rather than hardcoding "main" — a fix generated
    # against a non-main branch's file content must be committed against
    # that same branch's tip, not main's, or the patch is applied to the
    # wrong version of the file. An explicit base_branch argument still
    # overrides this (e.g. for tests or a caller that wants main regardless).
    effective_base_branch = base_branch or dispatch.get("branch") or "main"

    if pr_body is None:
        # Bind the actual Haiku client for this run so the default renderer
        # can make a real LLM call, without forcing every PRBodyRenderer
        # (including test overrides, which are 2-arg) to accept a clients
        # parameter.
        pr_body_task = config.tasks.get("pr_body")
        pr_body_max_tokens = pr_body_task.max_tokens_out if pr_body_task else 500

        def pr_body_fn(finding: dict[str, Any], fix: analyzer.FixProposal) -> str:
            return default_pr_body(finding, fix, clients.haiku, max_tokens=pr_body_max_tokens)
    else:
        pr_body_fn = pr_body

    findings = _extract_findings(envelope)
    result = PipelineResult(processed=0)

    for finding in findings:
        if not _eligible(finding, min_severity):
            result.skipped.append({"finding": finding, "reason": "below min_severity"})
            continue

        # Every downstream consumer (prompts, PR title/body, branch naming,
        # commit messages, and creator.py's write target) must see the same
        # repo-relative path, not the sandbox's "/workspace/..." mount path
        # — see _relativize()'s docstring for why creator.py's write would
        # otherwise reject every real finding as "escapes repo".
        finding = {**finding, "file": _relativize(finding.get("file", ""))}

        try:
            file_contents = file_reader(repo_path, finding.get("file", ""))
        except OSError as exc:
            logger.warning("skip finding: cannot read %s: %s", finding.get("file"), exc)
            result.skipped.append({"finding": finding, "reason": f"read error: {exc}"})
            continue

        result.processed += 1

        # analyze_finding() and pr_body_fn() both do real LLM I/O (Ollama,
        # Haiku/Sonnet/Opus) against a shared client set used across every
        # finding in this loop — one finding's transient failure (a timeout,
        # an unreachable Ollama host, a malformed API response) must not
        # abort processing of the rest of the batch, matching the same
        # isolation create_pr() already gets below.
        try:
            fix = analyzer.analyze_finding(
                finding=finding,
                file_contents=file_contents,
                repo_full_name=repo_full_name,
                commit_sha=commit_sha,
                clients=clients,
                config=config,
            )

            if fix.error or not fix.fixed_content.strip():
                # fix.rationale carries a more specific reason than the
                # generic fallback (e.g. "classified as spurious") when a
                # tier stopped without an actual error — surface it so
                # PipelineResult.skipped distinguishes "not a real issue"
                # from "the model returned empty text."
                result.skipped.append(
                    {"finding": finding, "reason": fix.error or fix.rationale or "no fix content"}
                )
                continue

            body = pr_body_fn(finding, fix)
        except Exception as exc:
            logger.warning("skip finding: analysis failed: %s", exc)
            result.skipped.append({"finding": finding, "reason": f"analysis error: {exc}"})
            continue

        req = creator.PRRequest(
            finding=finding,
            fixed_content=fix.fixed_content,
            confidence=fix.confidence,
            model_used=fix.model_used,
            repo_path=repo_path,
            repo_full_name=repo_full_name,
            base_branch=effective_base_branch,
            commit_sha=commit_sha,
            pr_body=body,
        )
        # create_pr() does real git/GitHub I/O against a repo_path shared
        # across every finding in this loop — one finding's git failure
        # (e.g. a push conflict, a GitHub API error) must not abort
        # processing of the rest of the batch.
        try:
            result.created.append(creator.create_pr(req, validate=validate, client=github_client))
        except creator.committer.BranchAlreadyExistsError:
            # Branch names are deterministic (brancher.branch_name() hashes
            # file+line+commit_sha), so a webhook retry or manager restart
            # reproducing this exact finding pushes to a branch that already
            # exists — that almost certainly means a PR for it was already
            # opened, not a real failure, so this gets a clearer skip reason
            # than the generic git-error branch below.
            logger.info("skip finding: branch already exists, PR likely already open")
            result.skipped.append({"finding": finding, "reason": "pr likely already exists"})
        except Exception as exc:
            logger.warning("skip finding: create_pr failed: %s", exc)
            result.skipped.append({"finding": finding, "reason": f"create_pr error: {exc}"})

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
