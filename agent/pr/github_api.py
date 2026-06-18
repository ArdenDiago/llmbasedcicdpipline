"""Thin PyGitHub wrapper for PR creation + labeling.

Kept dependency-light so tests can substitute a stub Github object.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Any, Protocol

logger = logging.getLogger(__name__)


class _RepoLike(Protocol):
    def create_pull(self, title: str, body: str, head: str, base: str) -> Any: ...


class _GithubLike(Protocol):
    def get_repo(self, full_name: str) -> _RepoLike: ...


@dataclass
class PullRequestRef:
    number: int
    html_url: str
    head: str
    base: str


def default_client() -> _GithubLike:
    from github import Github  # PyGitHub

    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise RuntimeError("GITHUB_TOKEN is required to create pull requests")
    return Github(token)


def create_pull_request(
    client: _GithubLike,
    repo_full_name: str,
    title: str,
    body: str,
    head: str,
    base: str,
    labels: list[str] | None = None,
) -> PullRequestRef:
    if base in {head}:
        raise ValueError("head and base branches must differ")
    if not title or not body:
        raise ValueError("title and body are required")

    repo = client.get_repo(repo_full_name)
    pr = repo.create_pull(title=title, body=body, head=head, base=base)

    if labels:
        try:
            pr.add_to_labels(*labels)
        except Exception:  # labels are nice-to-have, not critical
            logger.exception("failed to add labels %s to PR %s", labels, pr.number)

    return PullRequestRef(
        number=pr.number,
        html_url=pr.html_url,
        head=head,
        base=base,
    )
