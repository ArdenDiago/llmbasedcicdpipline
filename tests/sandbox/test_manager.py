from __future__ import annotations

from pathlib import Path

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


def _fake_clone(tmp_path_factory):
    """Return a clone_repo_fn stub that never touches the network."""
    calls = []
    created_dirs: list[Path] = []

    def _clone(repo_url: str, commit_sha: str) -> Path:
        calls.append((repo_url, commit_sha))
        d = tmp_path_factory.mktemp("cloned-repo")
        (d / "marker.txt").write_text("fake checkout")
        created_dirs.append(d)
        return d

    _clone.calls = calls
    _clone.created_dirs = created_dirs
    return _clone


def _client_with_fake_docker(
    container: FakeContainer | None = None, clone_repo_fn=None, tmp_path_factory=None,
):
    fake_docker = FakeDockerClient(container=container or FakeContainer(
        exit_code=0,
        results_payload={"stage": "sandbox_stub", "tests": None, "scanners": None},
    ))
    fake_clone = clone_repo_fn or _fake_clone(tmp_path_factory)
    app = create_app(docker_client_factory=lambda: fake_docker, clone_repo_fn=fake_clone)
    return TestClient(app), fake_docker, fake_clone


def test_health_endpoint(tmp_path_factory):
    client, _, _ = _client_with_fake_docker(tmp_path_factory=tmp_path_factory)
    res = client.get("/health")
    assert res.status_code == 200
    assert res.json() == {"ok": True}


def test_dispatch_happy_path(tmp_path_factory):
    client, fake_docker, fake_clone = _client_with_fake_docker(tmp_path_factory=tmp_path_factory)

    res = client.post("/dispatch", json=VALID_DISPATCH)

    assert res.status_code == 200
    envelope = res.json()
    assert envelope["dispatch"]["repo_full_name"] == "octocat/Hello-World"
    assert envelope["sandbox"]["exit_code"] == 0
    assert envelope["raw"]["stage"] == "sandbox_stub"
    assert fake_docker._container.started is True
    assert fake_docker._container.removed is True
    # The clone step ran with the dispatch's repo_url/commit_sha...
    assert fake_clone.calls == [
        (VALID_DISPATCH["repo_url"], VALID_DISPATCH["commit_sha"])
    ]
    # ...and the sandbox saw a second (read-only) volume for the checkout.
    volumes = fake_docker.last_create_kwargs["volumes"]
    assert len(volumes) == 2
    ro_binds = [v for v in volumes.values() if v["mode"] == "ro"]
    assert len(ro_binds) == 1
    assert ro_binds[0]["bind"] == "/workspace"


def test_dispatch_cleans_up_cloned_dir_after_run(tmp_path_factory):
    client, _, fake_clone = _client_with_fake_docker(tmp_path_factory=tmp_path_factory)

    client.post("/dispatch", json=VALID_DISPATCH)

    assert len(fake_clone.created_dirs) == 1
    assert not fake_clone.created_dirs[0].exists()


def test_dispatch_skips_clone_without_repo_url(tmp_path_factory):
    client, fake_docker, fake_clone = _client_with_fake_docker(tmp_path_factory=tmp_path_factory)
    dispatch = {**VALID_DISPATCH, "repo_url": None}

    res = client.post("/dispatch", json=dispatch)

    assert res.status_code == 200
    assert fake_clone.calls == []
    volumes = fake_docker.last_create_kwargs["volumes"]
    assert len(volumes) == 1


def test_dispatch_returns_502_when_clone_fails(tmp_path_factory):
    def failing_clone(repo_url: str, commit_sha: str):
        raise RuntimeError("repository not found")

    client, _, _ = _client_with_fake_docker(
        clone_repo_fn=failing_clone, tmp_path_factory=tmp_path_factory
    )

    res = client.post("/dispatch", json=VALID_DISPATCH)

    assert res.status_code == 502
    assert "clone" in res.json()["detail"].lower()


def test_dispatch_rejects_missing_fields(tmp_path_factory):
    client, _, _ = _client_with_fake_docker(tmp_path_factory=tmp_path_factory)

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
