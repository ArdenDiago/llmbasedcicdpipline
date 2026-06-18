"""Normalize sandbox results into the shape the LLM layer consumes."""
from __future__ import annotations

from typing import Any

from .container import SandboxResult


def collect(payload: dict[str, Any], result: SandboxResult) -> dict[str, Any]:
    """Produce the JSON envelope handed to the LLM layer.

    Keeps the dispatch context alongside the sandbox outcome so downstream
    consumers don't need to correlate by side channels.
    """
    return {
        "dispatch": {
            "repo_full_name": payload.get("repo_full_name"),
            "repo_url": payload.get("repo_url"),
            "branch": payload.get("branch"),
            "commit_sha": payload.get("commit_sha"),
            "pusher": payload.get("pusher"),
            "changed_files": payload.get("changed_files", []),
        },
        "sandbox": {
            "container_id": result.container_id,
            "exit_code": result.exit_code,
            "timed_out": result.timed_out,
            "error": result.error,
        },
        "tests": (result.results or {}).get("tests") if result.results else None,
        "scanners": (result.results or {}).get("scanners") if result.results else None,
        "raw": result.results,
    }
