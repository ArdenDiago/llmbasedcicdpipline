from __future__ import annotations

from fastapi.testclient import TestClient

from agent.sandbox.manager import create_app

from .conftest import FakeContainer, FakeDockerClient


VALID_DISPATCH = {
    "repo_url": "https://github.com/octocat/Hello-World.git",
    "repo_full_name": "octocat/Hello-World",
    "branch": "main",
    "commit_sha": "abc123def456abc123def456abc123def4567890",
    "pusher": "octocat",
    "changed_files": ["app/auth.py"],
}


def _client_with_fake_docker(container: FakeContainer | None = None):
    fake_docker = FakeDockerClient(container=container or FakeContainer(
        exit_code=0,
        results_payload={"stage": "sandbox_stub", "tests": None, "scanners": None},
    ))
    app = create_app(docker_client_factory=lambda: fake_docker)
    return TestClient(app), fake_docker


def test_health_endpoint():
    client, _ = _client_with_fake_docker()
    res = client.get("/health")
    assert res.status_code == 200
    assert res.json() == {"ok": True}


def test_dispatch_happy_path():
    client, fake_docker = _client_with_fake_docker()

    res = client.post("/dispatch", json=VALID_DISPATCH)

    assert res.status_code == 200
    envelope = res.json()
    assert envelope["dispatch"]["repo_full_name"] == "octocat/Hello-World"
    assert envelope["sandbox"]["exit_code"] == 0
    assert envelope["raw"]["stage"] == "sandbox_stub"
    assert fake_docker._container.started is True
    assert fake_docker._container.removed is True


def test_dispatch_rejects_missing_fields():
    client, _ = _client_with_fake_docker()

    res = client.post("/dispatch", json={"branch": "main"})

    assert res.status_code == 400
    assert "required" in res.json()["detail"]


def test_dispatch_returns_503_when_docker_unavailable():
    def boom():
        raise RuntimeError("docker daemon unreachable")

    app = create_app(docker_client_factory=boom)
    client = TestClient(app, raise_server_exceptions=False)

    res = client.post("/dispatch", json=VALID_DISPATCH)

    assert res.status_code == 503
    assert "docker" in res.json()["detail"].lower()
