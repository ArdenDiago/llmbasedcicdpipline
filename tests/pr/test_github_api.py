import pytest

from agent.pr import github_api


class _PR:
    def __init__(self, number=7, url="https://x/y/pull/7"):
        self.number = number
        self.html_url = url
        self.labels_added = []

    def add_to_labels(self, *labels):
        self.labels_added.extend(labels)


class _Repo:
    def __init__(self, pr: _PR):
        self.pr = pr
        self.create_pull_calls = []

    def create_pull(self, title, body, head, base):
        self.create_pull_calls.append(dict(title=title, body=body, head=head, base=base))
        return self.pr


class _Client:
    def __init__(self, repo: _Repo):
        self.repo = repo

    def get_repo(self, full_name):
        self.requested = full_name
        return self.repo


def test_create_pull_request_happy_path():
    pr = _PR()
    repo = _Repo(pr)
    client = _Client(repo)

    ref = github_api.create_pull_request(
        client=client,
        repo_full_name="owner/repo",
        title="fix(bandit): B105",
        body="body",
        head="fix/bandit-b105-deadbeef",
        base="main",
        labels=["automated-fix", "security", "high"],
    )

    assert ref.number == 7
    assert ref.html_url.endswith("/pull/7")
    assert client.requested == "owner/repo"
    assert repo.create_pull_calls[0]["head"] == "fix/bandit-b105-deadbeef"
    assert pr.labels_added == ["automated-fix", "security", "high"]


def test_create_pull_request_rejects_same_branch():
    client = _Client(_Repo(_PR()))
    with pytest.raises(ValueError):
        github_api.create_pull_request(
            client=client, repo_full_name="o/r",
            title="t", body="b", head="main", base="main",
        )


def test_create_pull_request_requires_title_and_body():
    client = _Client(_Repo(_PR()))
    with pytest.raises(ValueError):
        github_api.create_pull_request(
            client=client, repo_full_name="o/r",
            title="", body="b", head="h", base="main",
        )


def test_label_failure_does_not_raise(monkeypatch):
    class _PRBadLabels(_PR):
        def add_to_labels(self, *labels):
            raise RuntimeError("labels API down")

    client = _Client(_Repo(_PRBadLabels()))
    ref = github_api.create_pull_request(
        client=client, repo_full_name="o/r",
        title="t", body="b", head="h", base="main",
        labels=["security"],
    )
    assert ref.number == 7


def test_default_client_requires_token(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    with pytest.raises(RuntimeError, match="GITHUB_TOKEN"):
        github_api.default_client()
