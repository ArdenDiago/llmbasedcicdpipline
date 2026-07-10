from __future__ import annotations

import stat

from agent.sandbox import container

from .conftest import FakeContainer, FakeDockerClient


PAYLOAD = {
    "repo_full_name": "octocat/Hello-World",
    "repo_url": "https://github.com/octocat/Hello-World.git",
    "branch": "main",
    "commit_sha": "abc123def456abc123def456abc123def4567890",
    "pusher": "octocat",
    "changed_files": ["app/auth.py", "app/main.py"],
}


def test_run_sandbox_happy_path():
    fake = FakeContainer(
        exit_code=0,
        stdout=b'{"stage": "sandbox_stub"}',
        results_payload={"stage": "sandbox_stub", "tests": None, "scanners": None},
    )
    client = FakeDockerClient(container=fake)

    result = container.run_sandbox(client, PAYLOAD, image="python:3.12-slim")

    assert result.exit_code == 0
    assert result.timed_out is False
    assert result.error is None
    assert result.results == {"stage": "sandbox_stub", "tests": None, "scanners": None}
    assert fake.started is True
    assert fake.removed is True


def test_run_sandbox_applies_security_constraints():
    client = FakeDockerClient(container=FakeContainer(results_payload={}))

    container.run_sandbox(client, PAYLOAD, image="python:3.12-slim")

    kwargs = client.last_create_kwargs
    assert kwargs["network_disabled"] is True
    assert kwargs["read_only"] is True
    assert kwargs["privileged"] is False
    assert kwargs["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in kwargs["security_opt"]
    assert kwargs["mem_limit"] == "2g"
    assert kwargs["nano_cpus"] == 2 * 1_000_000_000
    assert kwargs["user"] == "65534:65534"
    # /results is the only writable host-bound mount; /tmp is tmpfs only.
    volumes = kwargs["volumes"]
    assert len(volumes) == 1
    binds = list(volumes.values())[0]
    assert binds["bind"] == "/results"
    assert binds["mode"] == "rw"
    assert "/tmp" in kwargs["tmpfs"]


def test_run_sandbox_timeout_flags_and_kills():
    fake = FakeContainer(wait_timeout=True, results_payload={})
    client = FakeDockerClient(container=fake)

    result = container.run_sandbox(client, PAYLOAD, image="python:3.12-slim")

    assert result.timed_out is True
    assert fake.killed is True
    assert fake.removed is True


def test_run_sandbox_cleans_up_on_exception():
    client = FakeDockerClient()
    client.containers.create.side_effect = RuntimeError("boom")

    result = container.run_sandbox(client, PAYLOAD, image="python:3.12-slim")

    assert result.error is not None
    assert "boom" in result.error
    assert result.exit_code == -1


def test_run_sandbox_handles_missing_results_json(tmp_path, monkeypatch):
    fake = FakeContainer(exit_code=0, results_payload=None)
    client = FakeDockerClient(container=fake)

    result = container.run_sandbox(client, PAYLOAD, image="python:3.12-slim")

    assert result.results is None
    assert result.exit_code == 0


def test_run_sandbox_results_dir_is_writable_by_other_users():
    """mkdtemp defaults to 0700, which the sandbox's unprivileged UID 65534
    can't write into once bind-mounted — regression test for a bug where
    the container crashed with PermissionError writing results.json."""
    client = FakeDockerClient(container=FakeContainer(results_payload={}))

    container.run_sandbox(client, PAYLOAD, image="python:3.12-slim")

    results_host_dir = list(client.last_create_kwargs["volumes"].keys())[0]
    mode = stat.S_IMODE(container.Path(results_host_dir).stat().st_mode)
    assert mode & stat.S_IWOTH


def test_run_sandbox_without_repo_path_uses_stub_command():
    client = FakeDockerClient(container=FakeContainer(results_payload={}))

    container.run_sandbox(client, PAYLOAD, image="python:3.12-slim")

    kwargs = client.last_create_kwargs
    assert kwargs["command"][0] == "sh"
    assert len(kwargs["volumes"]) == 1


def test_run_sandbox_with_repo_path_mounts_readonly_and_runs_real_scanners(tmp_path):
    client = FakeDockerClient(container=FakeContainer(results_payload={}))
    repo_path = tmp_path / "checkout"
    repo_path.mkdir()

    container.run_sandbox(
        client, PAYLOAD, image="llm-cicd-agent:latest", repo_path=repo_path,
    )

    kwargs = client.last_create_kwargs
    volumes = kwargs["volumes"]
    assert len(volumes) == 2
    assert volumes[str(repo_path)] == {"bind": "/workspace", "mode": "ro"}
    assert kwargs["command"][:2] == ["python", "-c"]
    script = kwargs["command"][2]
    assert "/workspace" in script
    assert "run_scan" in script
    assert "test_runner" in script
