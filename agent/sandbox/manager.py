"""Sandbox manager — HTTP entry point that orchestrates ephemeral containers.

Receives push dispatches from the webhook listener, runs a sandbox for each,
and returns the collected results envelope. Containers are always torn down.
"""
from __future__ import annotations

import logging
import os
import shutil
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from . import clone, collector, container, image

logger = logging.getLogger(__name__)

DEFAULT_PORT = 3001
DEFAULT_IMAGE_ENV = "SANDBOX_IMAGE"


class DispatchPayload(BaseModel):
    repo_url: str | None = None
    repo_full_name: str | None = None
    branch: str | None = None
    commit_sha: str | None = None
    pusher: str | None = None
    changed_files: list[str] = Field(default_factory=list)


def _docker_client():
    import docker  # imported lazily so unit tests can skip without daemon

    return docker.from_env()


def create_app(docker_client_factory=_docker_client, clone_repo_fn=clone.clone_repo) -> FastAPI:
    app = FastAPI(title="llm-cicd-sandbox", version="0.1.0")

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {"ok": True}

    @app.post("/dispatch", status_code=200)
    def dispatch(payload: DispatchPayload) -> dict[str, Any]:
        if not payload.repo_full_name or not payload.commit_sha:
            raise HTTPException(
                status_code=400,
                detail="repo_full_name and commit_sha are required",
            )

        image_ref = os.environ.get(DEFAULT_IMAGE_ENV, image.DEFAULT_IMAGE)
        logger.info(
            "dispatch %s@%s sha=%s image=%s",
            payload.repo_full_name,
            payload.branch,
            (payload.commit_sha or "")[:7],
            image_ref,
        )

        try:
            client = docker_client_factory()
        except Exception as exc:
            logger.exception("docker client init failed")
            raise HTTPException(status_code=503, detail=f"docker unavailable: {exc}") from exc

        try:
            image.ensure_image(client, image_ref)
        except Exception as exc:
            logger.exception("image ensure failed")
            raise HTTPException(status_code=502, detail=f"image unavailable: {exc}") from exc

        # Clone happens on the host, before the network-isolated sandbox
        # container exists (see agent/sandbox/clone.py). Without a repo_url
        # we fall back to the stub path rather than failing the dispatch —
        # some webhook payloads may legitimately omit it.
        repo_path: Path | None = None
        if payload.repo_url:
            try:
                repo_path = clone_repo_fn(payload.repo_url, payload.commit_sha)
            except Exception as exc:
                logger.exception("repo clone failed")
                raise HTTPException(status_code=502, detail=f"repo clone failed: {exc}") from exc

        try:
            result = container.run_sandbox(
                client, payload.model_dump(), image_ref, repo_path=repo_path
            )
        finally:
            if repo_path is not None:
                shutil.rmtree(repo_path, ignore_errors=True)

        return collector.collect(payload.model_dump(), result)

    return app


app = create_app()


def main() -> None:
    import uvicorn

    port = int(os.environ.get("SANDBOX_PORT", DEFAULT_PORT))
    log_level = os.environ.get("LOG_LEVEL", "info").lower()
    uvicorn.run(app, host="0.0.0.0", port=port, log_level=log_level)


if __name__ == "__main__":
    main()
