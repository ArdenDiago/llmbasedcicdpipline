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
REPO_BIND_PATH = "/workspace"

# Runs inside the sandbox container once a repo checkout is mounted read-only
# at REPO_BIND_PATH. Requires the `agent` package + its deps on PATH, which is
# true for the control-plane image (see Project/Dockerfile) reused here as the
# sandbox image (agent/sandbox/image.py). No network calls happen here — the
# container starts with network_disabled=True; the clone already happened on
# the host (agent/sandbox/clone.py) before this container was created.
_REPO_RUNNER_SCRIPT = """
import json, os
from dataclasses import asdict

from agent.testing import runner as test_runner
from agent.security import run_scan

path = "{repo_path}"

try:
    tests = asdict(test_runner.run(path))
except Exception as exc:
    tests = {{"framework": "unknown", "error": f"{{type(exc).__name__}}: {{exc}}"}}

try:
    scanners = run_scan.run_all(path)
except Exception as exc:
    scanners = {{"error": f"{{type(exc).__name__}}: {{exc}}"}}

os.makedirs("/results", exist_ok=True)
with open("/results/{results_filename}", "w") as f:
    json.dump({{"tests": tests, "scanners": scanners}}, f)
""".strip()


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
    wait_error: str | None = None  # set whenever container.wait() raised, timeout or not


def _runner_command(payload: dict[str, Any], repo_mounted: bool) -> list[str]:
    """Return the command run inside the sandbox.

    When no repo checkout is mounted (repo_mounted=False), falls back to a
    stub results document so the end-to-end dispatch path stays verifiable
    without a real clone (e.g. no repo_url in the payload).
    """
    if repo_mounted:
        script = _REPO_RUNNER_SCRIPT.format(
            repo_path=REPO_BIND_PATH, results_filename=RESULTS_FILENAME
        )
        return ["python", "-c", script]

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
    repo_path: Path | None = None,
) -> SandboxResult:
    """Run an ephemeral sandbox container and return its results.

    If repo_path is given (a host directory already checked out to the
    target commit — see agent/sandbox/clone.py), it is bind-mounted
    read-only at REPO_BIND_PATH and the container runs the real test +
    security scanners against it. Otherwise the container runs the stub
    path (no repo available to scan). The container is always removed —
    even on error or timeout.
    """
    container = None
    results_host_dir = Path(tempfile.mkdtemp(prefix=f"sandbox-{uuid.uuid4().hex[:8]}-"))
    # mkdtemp defaults to 0700, owned by the host user. The container always
    # runs as the fixed unprivileged UID 65534 (nobody), which matches
    # neither owner nor group here, so it cannot write results.json without
    # opening up the "other" bits. This directory is ephemeral, host-local,
    # and holds nothing but this run's own scan/test JSON output.
    results_host_dir.chmod(0o777)
    volumes = {str(results_host_dir): {"bind": "/results", "mode": "rw"}}
    if repo_path is not None:
        volumes[str(repo_path)] = {"bind": REPO_BIND_PATH, "mode": "ro"}
    try:
        container = client.containers.create(
            image=image,
            command=_runner_command(payload, repo_mounted=repo_path is not None),
            detach=True,
            network_disabled=True,
            read_only=True,
            tmpfs={"/tmp": "size=64m"},
            volumes=volumes,
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
        wait_error: str | None = None
        exit_code = -1
        try:
            wait_result = container.wait(timeout=timeout_seconds)
            exit_code = wait_result.get("StatusCode", -1)
        except Exception as wait_exc:
            wait_error = f"{type(wait_exc).__name__}: {wait_exc}"
            # docker-py doesn't raise a single dedicated exception type for
            # "the timeout_seconds deadline was hit" vs. a transient docker
            # daemon/connection error — both surface as some Exception from
            # this call. Only *report* it as a real timeout when the
            # exception itself says so; otherwise keep timed_out=False and
            # preserve the real error in wait_error so callers (e.g.
            # collector.py) don't conflate "the container legitimately ran
            # out of time" with "docker's API hiccuped."
            logger.warning("sandbox container.wait() failed: %s", wait_error)
            if "timeout" in type(wait_exc).__name__.lower() or "timeout" in str(wait_exc).lower():
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
            wait_error=wait_error,
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
