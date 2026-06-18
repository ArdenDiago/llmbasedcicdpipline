from __future__ import annotations

from agent.sandbox.collector import collect
from agent.sandbox.container import SandboxResult


PAYLOAD = {
    "repo_full_name": "octocat/Hello-World",
    "repo_url": "https://github.com/octocat/Hello-World.git",
    "branch": "main",
    "commit_sha": "abc123",
    "pusher": "octocat",
    "changed_files": ["a.py"],
}


def test_collect_merges_dispatch_and_sandbox_result():
    result = SandboxResult(
        container_id="cid",
        exit_code=0,
        stdout="ok",
        stderr="",
        results={"tests": {"passed": 1}, "scanners": [{"rule_id": "B105"}]},
    )

    envelope = collect(PAYLOAD, result)

    assert envelope["dispatch"]["repo_full_name"] == "octocat/Hello-World"
    assert envelope["sandbox"]["container_id"] == "cid"
    assert envelope["sandbox"]["exit_code"] == 0
    assert envelope["tests"] == {"passed": 1}
    assert envelope["scanners"] == [{"rule_id": "B105"}]


def test_collect_handles_missing_results():
    result = SandboxResult(
        container_id="cid",
        exit_code=-1,
        stdout="",
        stderr="",
        results=None,
        error="ImageNotFound: foo",
    )

    envelope = collect(PAYLOAD, result)

    assert envelope["tests"] is None
    assert envelope["scanners"] is None
    assert envelope["sandbox"]["error"] == "ImageNotFound: foo"
