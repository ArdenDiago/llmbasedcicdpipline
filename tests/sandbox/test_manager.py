from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from agent.pipeline import PipelineResult
from agent.pr import creator, github_api
from agent.sandbox.manager import _default_validate_factory, create_app

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
    **create_app_kwargs,
):
    fake_docker = FakeDockerClient(container=container or FakeContainer(
        exit_code=0,
        results_payload={"stage": "sandbox_stub", "tests": None, "scanners": None},
    ))
    fake_clone = clone_repo_fn or _fake_clone(tmp_path_factory)
    app = create_app(
        docker_client_factory=lambda: fake_docker, clone_repo_fn=fake_clone,
        **create_app_kwargs,
    )
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


_FINDING = {
    "scanner": "bandit", "rule_id": "B105", "severity": "high",
    "file": "app/auth.py", "line": 45, "message": "hardcoded password",
}


def _container_with_findings() -> FakeContainer:
    return FakeContainer(
        exit_code=1,
        results_payload={
            "tests": {"framework": "pytest", "total": 1, "passed": 1, "failed": 0, "errors": 0},
            "scanners": {"target": "/workspace", "findings": [_FINDING], "errors": []},
        },
    )


def test_dispatch_runs_fix_pipeline_when_findings_present(tmp_path_factory):
    """Regression test for the CRITICAL finding that the sandbox result was
    always discarded — nothing in the live dispatch path ever called
    agent.pipeline.run(). This proves /dispatch now wires the scan envelope
    through to the fix pipeline and surfaces its outcome in the response."""
    calls = {}

    def fake_pipeline_run(**kwargs):
        calls["envelope"] = kwargs["envelope"]
        calls["repo_path"] = kwargs["repo_path"]
        pr = github_api.PullRequestRef(number=1, html_url="https://x/pr/1", head="fix/x", base="main")
        return PipelineResult(
            processed=1,
            created=[creator.PRResult(created=True, branch="fix/x", pr=pr)],
            skipped=[],
        )

    client, fake_docker, fake_clone = _client_with_fake_docker(
        container=_container_with_findings(),
        tmp_path_factory=tmp_path_factory,
        pipeline_run_fn=fake_pipeline_run,
        client_set_factory=lambda cfg: object(),
        validate_factory=lambda *a, **k: (lambda p: True),
        github_client_factory=lambda: object(),
        balancing_config_fn=lambda: object(),
    )

    res = client.post("/dispatch", json=VALID_DISPATCH)

    assert res.status_code == 200
    envelope = res.json()
    assert envelope["scanners"]["findings"] == [_FINDING]
    assert envelope["pipeline"] == {
        "processed": 1, "created": 1, "skipped": 0,
        "pull_requests": ["https://x/pr/1"],
    }
    # The envelope handed to pipeline.run() is exactly what a caller
    # downstream of collector.collect() would expect (dispatch + scanners).
    assert calls["envelope"]["dispatch"]["repo_full_name"] == "octocat/Hello-World"
    assert calls["repo_path"] == fake_clone.created_dirs[0]


def test_dispatch_skips_pipeline_when_no_findings(tmp_path_factory):
    client, _, _ = _client_with_fake_docker(tmp_path_factory=tmp_path_factory)

    res = client.post("/dispatch", json=VALID_DISPATCH)

    assert res.status_code == 200
    assert "pipeline" not in res.json()


def test_dispatch_records_skip_reason_when_github_token_missing(tmp_path_factory):
    def missing_token():
        raise RuntimeError("GITHUB_TOKEN is required to create pull requests")

    client, _, _ = _client_with_fake_docker(
        container=_container_with_findings(),
        tmp_path_factory=tmp_path_factory,
        github_client_factory=missing_token,
    )

    res = client.post("/dispatch", json=VALID_DISPATCH)

    assert res.status_code == 200
    envelope = res.json()
    assert "GITHUB_TOKEN" in envelope["pipeline"]["skipped"]


def test_dispatch_records_error_without_failing_whole_response_when_pipeline_raises(
    tmp_path_factory,
):
    """A fix-pipeline failure (bad patch, git error, LLM API error) must not
    take down the scan/test results, which are independently valid."""
    def boom(**kwargs):
        raise RuntimeError("ollama unreachable")

    client, _, _ = _client_with_fake_docker(
        container=_container_with_findings(),
        tmp_path_factory=tmp_path_factory,
        pipeline_run_fn=boom,
        client_set_factory=lambda cfg: object(),
        validate_factory=lambda *a, **k: (lambda p: True),
        github_client_factory=lambda: object(),
        balancing_config_fn=lambda: object(),
    )

    res = client.post("/dispatch", json=VALID_DISPATCH)

    assert res.status_code == 200
    envelope = res.json()
    assert envelope["sandbox"]["exit_code"] == 1  # scan/test results still intact
    assert "ollama unreachable" in envelope["pipeline"]["error"]


def test_dispatch_skips_pipeline_without_repo_url(tmp_path_factory):
    """No repo_url means no writable clone to patch — the fix pipeline needs
    real disk to apply patches to, so it must be skipped, not attempted
    against a directory that was never created."""
    dispatch = {**VALID_DISPATCH, "repo_url": None}
    calls = []

    client, _, _ = _client_with_fake_docker(
        container=_container_with_findings(),
        tmp_path_factory=tmp_path_factory,
        pipeline_run_fn=lambda **kw: calls.append(1),
    )

    res = client.post("/dispatch", json=dispatch)

    assert res.status_code == 200
    assert "pipeline" not in res.json()
    assert calls == []


def _validate_with_tests_result(tests_value, tmp_path_factory) -> bool:
    fake_docker = FakeDockerClient(container=FakeContainer(
        exit_code=0,
        results_payload={"tests": tests_value, "scanners": {"findings": []}},
    ))
    validate = _default_validate_factory(fake_docker, "img:tag", {"repo_full_name": "o/r"})
    return validate(tmp_path_factory.mktemp("patched-repo"))


def test_validate_passes_when_no_test_framework_detected(tmp_path_factory):
    """Regression test: 'no test suite exists' (the case testing/CLAUDE.md
    explicitly says should not fabricate a failure) must still pass
    validation."""
    assert _validate_with_tests_result(
        {"framework": "unknown", "error": "no supported test framework detected"},
        tmp_path_factory,
    ) is True


def test_validate_passes_when_framework_detected_but_unsupported(tmp_path_factory):
    assert _validate_with_tests_result(
        {"framework": "mocha", "error": "unsupported framework: mocha"},
        tmp_path_factory,
    ) is True


def test_validate_fails_when_test_runner_could_not_execute(tmp_path_factory):
    """Regression test for the CRITICAL finding that a test suite EXISTING
    but failing to execute (missing runner binary, no network for `npx
    jest` under network_disabled=True, a timeout, pytest failing to emit
    its report, ...) was silently treated the same as 'no test suite
    found' — letting an unverifiable fix pass validation as if it had been
    confirmed safe."""
    assert _validate_with_tests_result(
        {"framework": "jest", "error": "runner binary not found: [Errno 2] ..."},
        tmp_path_factory,
    ) is False
    assert _validate_with_tests_result(
        {"framework": "pytest", "error": "pytest did not produce a report (plugin missing?)"},
        tmp_path_factory,
    ) is False


def test_validate_fails_when_tests_result_missing_entirely(tmp_path_factory):
    assert _validate_with_tests_result(None, tmp_path_factory) is False


def test_validate_passes_when_tests_pass(tmp_path_factory):
    assert _validate_with_tests_result(
        {"framework": "pytest", "total": 3, "passed": 3, "failed": 0, "errors": 0},
        tmp_path_factory,
    ) is True


def test_validate_fails_when_tests_fail(tmp_path_factory):
    assert _validate_with_tests_result(
        {"framework": "pytest", "total": 3, "passed": 2, "failed": 1, "errors": 0},
        tmp_path_factory,
    ) is False
