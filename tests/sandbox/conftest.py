from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from unittest.mock import MagicMock


@dataclass
class FakeContainer:
    id: str = "fake-container-id"
    exit_code: int = 0
    stdout: bytes = b""
    stderr: bytes = b""
    wait_timeout: bool = False
    started: bool = False
    removed: bool = False
    killed: bool = False
    results_payload: dict[str, Any] | None = None
    _bind_path: str | None = field(default=None, repr=False)

    def start(self) -> None:
        self.started = True
        # Emulate the container writing results.json into the mounted dir.
        if self._bind_path and self.results_payload is not None:
            import json
            import os

            os.makedirs(self._bind_path, exist_ok=True)
            with open(os.path.join(self._bind_path, "results.json"), "w") as f:
                json.dump(self.results_payload, f)

    def wait(self, timeout: int | None = None) -> dict[str, int]:
        if self.wait_timeout:
            raise TimeoutError("container wait timed out")
        return {"StatusCode": self.exit_code}

    def logs(self, *, stdout: bool = True, stderr: bool = False) -> bytes:
        if stdout and not stderr:
            return self.stdout
        if stderr and not stdout:
            return self.stderr
        return self.stdout + self.stderr

    def kill(self) -> None:
        self.killed = True

    def remove(self, force: bool = False) -> None:
        self.removed = True


class FakeDockerClient:
    def __init__(self, container: FakeContainer | None = None, image_missing: bool = False):
        self._container = container or FakeContainer()
        self.images = MagicMock()
        if image_missing:
            self.images.get.side_effect = RuntimeError("not found")
            self.images.pull.return_value = MagicMock(id="pulled-image")
        else:
            self.images.get.return_value = MagicMock(id="existing-image")

        self.containers = MagicMock()
        self.containers.create.side_effect = self._create_container

    def _create_container(self, **kwargs):
        volumes = kwargs.get("volumes") or {}
        for host_path, spec in volumes.items():
            if spec.get("bind") == "/results":
                self._container._bind_path = host_path
                break
        self.last_create_kwargs = kwargs
        return self._container
