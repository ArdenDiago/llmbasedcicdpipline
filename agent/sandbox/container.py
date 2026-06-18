"""Ephemeral container lifecycle for the sandbox.

Each push event gets one container. The container runs a constrained workload
and is destroyed regardless of outcome. Security constraints follow the
sandbox CLAUDE.md: no privileged mode, all capabilities dropped, no host
volume mounts except a writable results dir, network disabled, PID isolation,
10 minute hard timeout.
"""
from __future__ import annotations

import json
import logging
import shlex
import tempfile
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SECONDS = 600
DEFAULT_CPU_LIMIT = 2
DEFAULT_MEM_LIMIT = "2g"
RESULTS_FILENAME = "results.json"


@dataclass
class SandboxResult:
    container_id: str
    exit_code: int
    stdout: str
    stderr: str
    results: dict[str, Any] | None
    timed_out: bool = False
    error: str | None = None
    logs_path: str | None = field(default=None, repr=False)


def _runner_command(payload: dict[str, Any]) -> list[str]:
    """Return the command run inside the sandbox.

    Placeholder until testing/security modules are wired: writes a stub
    results document so the end-to-end path is verifiable.
    """
    stub = {
        "stage": "sandbox_stub",
        "received": {
            "repo_full_name": payload.get("repo_full_name"),
            "branch": payload.get("branch"),
            "commit_sha": payload.get("commit_sha"),
            "changed_files_count": len(payload.get("changed_files", []) or []),
        },
        "tests": None,
        "scanners": None,
    }
    script = (
        f"mkdir -p /results && "
        f"printf '%s' {shlex.quote(json.dumps(stub))} > /results/{RESULTS_FILENAME} && "
        f"cat /results/{RESULTS_FILENAME}"
    )
    return ["sh", "-c", script]


def run_sandbox(
    client,
    payload: dict[str, Any],
    image: str,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    cpu_limit: int = DEFAULT_CPU_LIMIT,
    mem_limit: str = DEFAULT_MEM_LIMIT,
) -> SandboxResult:
    """Run an ephemeral sandbox container and return its results.

    The container is always removed — even on error or timeout.
    """
    container = None
    results_host_dir = Path(tempfile.mkdtemp(prefix=f"sandbox-{uuid.uuid4().hex[:8]}-"))
    try:
        container = client.containers.create(
            image=image,
            command=_runner_command(payload),
            detach=True,
            network_disabled=True,
            read_only=True,
            tmpfs={"/tmp": "size=64m"},
            volumes={str(results_host_dir): {"bind": "/results", "mode": "rw"}},
            mem_limit=mem_limit,
            nano_cpus=cpu_limit * 1_000_000_000,
            cap_drop=["ALL"],
            security_opt=["no-new-privileges:true"],
            pids_limit=256,
            privileged=False,
            user="65534:65534",  # nobody:nogroup
            labels={"managed-by": "llm-cicd-agent", "kind": "sandbox"},
        )
        container.start()

        timed_out = False
        exit_code = -1
        try:
            wait_result = container.wait(timeout=timeout_seconds)
            exit_code = wait_result.get("StatusCode", -1)
        except Exception as wait_exc:
            logger.warning("sandbox wait failed/timed out: %s", wait_exc)
            timed_out = True
            try:
                container.kill()
            except Exception:
                pass

        stdout = _safe_logs(container, stdout=True, stderr=False)
        stderr = _safe_logs(container, stdout=False, stderr=True)

        results = _read_results(results_host_dir / RESULTS_FILENAME)

        return SandboxResult(
            container_id=container.id or "",
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            results=results,
            timed_out=timed_out,
            logs_path=str(results_host_dir),
        )
    except Exception as exc:
        logger.exception("sandbox run failed")
        return SandboxResult(
            container_id=getattr(container, "id", "") or "",
            exit_code=-1,
            stdout="",
            stderr="",
            results=None,
            timed_out=False,
            error=f"{exc.__class__.__name__}: {exc}",
            logs_path=str(results_host_dir),
        )
    finally:
        if container is not None:
            try:
                container.remove(force=True)
            except Exception as cleanup_exc:
                logger.warning("container cleanup failed: %s", cleanup_exc)


def _safe_logs(container, *, stdout: bool, stderr: bool) -> str:
    try:
        data = container.logs(stdout=stdout, stderr=stderr)
        if isinstance(data, bytes):
            return data.decode("utf-8", errors="replace")
        return str(data)
    except Exception as exc:
        logger.warning("failed to read container logs: %s", exc)
        return ""


def _read_results(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        logger.warning("results.json not valid JSON: %s", exc)
        return None
