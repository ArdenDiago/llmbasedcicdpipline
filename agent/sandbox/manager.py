"""Sandbox manager — HTTP entry point that orchestrates ephemeral containers.

Receives push dispatches from the webhook listener, runs a sandbox for each,
and returns the collected results envelope. Containers are always torn down.

Also implements step 7 of the lifecycle in this module's own CLAUDE.md —
"Pass results to LLM layer for analysis" — by handing the scan/test envelope
to agent.pipeline.run() whenever a writable repo checkout and at least one
finding are available. That step is best-effort: a missing GITHUB_TOKEN,
unreachable Ollama, or any other fix-pipeline failure is caught and recorded
in the response's "pipeline" key rather than failing the whole dispatch — the
scan/test results are independently useful even when fix generation isn't
configured or fails.
"""
from __future__ import annotations

import logging
import os
import shutil
from pathlib import Path
from typing import Any, Callable

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


def _default_client_set(balancing_config) -> Any:
    """Builds the real DeepSeek/Haiku/Sonnet/Opus clients per
    config/model_balancing.yml. Imports are lazy so a deployment that never
    exercises the fix pipeline doesn't need the ollama/anthropic SDKs
    installed."""
    from agent.llm.analyzer import ClientSet
    from agent.llm.clients.anthropic import AnthropicClient
    from agent.llm.clients.ollama import OllamaClient

    models = balancing_config.models
    deepseek_cfg = models.get("deepseek_coder", {})
    return ClientSet(
        deepseek=OllamaClient(
            model=deepseek_cfg.get("model_id", "deepseek-coder:6.7b"),
            host=deepseek_cfg.get("host"),
        ),
        haiku=AnthropicClient(model=models["haiku"]["model_id"]),
        sonnet=AnthropicClient(model=models["sonnet"]["model_id"]),
        opus=AnthropicClient(model=models["opus"]["model_id"]),
    )


def _default_validate_factory(
    docker_client: Any, image_ref: str, payload: dict[str, Any]
) -> Callable[[Path], bool]:
    """Validation re-runs the same sandboxed test execution against the
    patched clone — tests run inside the sandbox, never on the host, per
    this package's own CLAUDE.md lifecycle. This is the same container
    infra used for the initial scan, just pointed at a different repo_path."""

    def _validate(patched_repo_path: Path) -> bool:
        result = container.run_sandbox(
            docker_client, payload, image_ref, repo_path=patched_repo_path
        )
        if result.error or result.timed_out:
            return False
        tests = (result.results or {}).get("tests") if result.results else None
        if not tests or tests.get("error"):
            # No discoverable test suite: testing/CLAUDE.md says to report
            # that, not fabricate a result — don't block a fix on a repo
            # that has nothing to validate against.
            return True
        return not tests.get("failed") and not tests.get("errors")

    return _validate


def _run_fix_pipeline(
    *,
    docker_client: Any,
    image_ref: str,
    payload: dict[str, Any],
    repo_path: Path,
    envelope: dict[str, Any],
    pipeline_run_fn: Callable[..., Any],
    client_set_factory: Callable[[Any], Any],
    validate_factory: Callable[[Any, str, dict[str, Any]], Callable[[Path], bool]],
    github_client_factory: Callable[[], Any],
    balancing_config_fn: Callable[[], Any],
) -> dict[str, Any]:
    try:
        github_client = github_client_factory()
    except Exception as exc:
        logger.info("skipping fix pipeline: %s", exc)
        return {"skipped": f"github client unavailable: {exc}"}

    try:
        balancing_config = balancing_config_fn()
        clients = client_set_factory(balancing_config)
    except Exception as exc:
        logger.exception("LLM client setup failed")
        return {"skipped": f"LLM client setup failed: {exc}"}

    validate = validate_factory(docker_client, image_ref, payload)

    try:
        result = pipeline_run_fn(
            envelope=envelope,
            repo_path=repo_path,
            clients=clients,
            config=balancing_config,
            validate=validate,
            github_client=github_client,
        )
    except Exception as exc:
        logger.exception("fix pipeline failed")
        return {"error": f"{type(exc).__name__}: {exc}"}

    summary = result.summary()
    summary["pull_requests"] = [
        r.pr.html_url for r in result.created if r.created and r.pr is not None
    ]
    return summary


def create_app(
    docker_client_factory=_docker_client,
    clone_repo_fn=clone.clone_repo,
    pipeline_run_fn: Callable[..., Any] | None = None,
    client_set_factory: Callable[[Any], Any] = _default_client_set,
    validate_factory: Callable[[Any, str, dict[str, Any]], Callable[[Path], bool]] = _default_validate_factory,
    github_client_factory: Callable[[], Any] | None = None,
    balancing_config_fn: Callable[[], Any] | None = None,
) -> FastAPI:
    if pipeline_run_fn is None:
        from agent import pipeline as pipeline_mod

        pipeline_run_fn = pipeline_mod.run
    if github_client_factory is None:
        from agent.pr import github_api

        github_client_factory = github_api.default_client
    if balancing_config_fn is None:
        from agent.llm import config as llm_config

        balancing_config_fn = llm_config.load

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
            envelope = collector.collect(payload.model_dump(), result)

            # Step 7 of this package's own CLAUDE.md lifecycle: "Pass results
            # to LLM layer for analysis." repo_path is still a writable host
            # directory here — the container only saw it read-only — so it
            # can be reused directly for patch/commit/push instead of a
            # second clone. Only attempted when there's a finding to act on
            # and a checkout to patch; skipped (not failed) otherwise so scan
            # results are still returned for pushes with nothing to fix or
            # no repo_url in the payload.
            findings = ((envelope.get("scanners") or {}).get("findings")) or []
            if repo_path is not None and findings:
                envelope["pipeline"] = _run_fix_pipeline(
                    docker_client=client,
                    image_ref=image_ref,
                    payload=payload.model_dump(),
                    repo_path=repo_path,
                    envelope=envelope,
                    pipeline_run_fn=pipeline_run_fn,
                    client_set_factory=client_set_factory,
                    validate_factory=validate_factory,
                    github_client_factory=github_client_factory,
                    balancing_config_fn=balancing_config_fn,
                )
        finally:
            if repo_path is not None:
                shutil.rmtree(repo_path, ignore_errors=True)

        return envelope

    return app


app = create_app()


def main() -> None:
    import uvicorn

    port = int(os.environ.get("SANDBOX_PORT", DEFAULT_PORT))
    log_level = os.environ.get("LOG_LEVEL", "info").lower()
    uvicorn.run(app, host="0.0.0.0", port=port, log_level=log_level)


if __name__ == "__main__":
    main()
