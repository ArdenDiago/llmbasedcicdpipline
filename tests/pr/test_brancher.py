from agent.pr import brancher


def test_branch_name_is_deterministic():
    a = brancher.branch_name("bandit", "B105", "app/auth.py", 45, "deadbeef")
    b = brancher.branch_name("bandit", "B105", "app/auth.py", 45, "deadbeef")
    assert a == b


def test_branch_name_prefix_and_format():
    name = brancher.branch_name("bandit", "B105", "app/auth.py", 45, "deadbeef")
    assert name.startswith("fix/bandit-b105-")
    assert len(name.rsplit("-", 1)[-1]) == 8


def test_branch_name_slugifies_rule_id():
    name = brancher.branch_name("semgrep", "python.lang.BAD_THING", "a.py", 1, "c0ffee")
    assert "python-lang-bad-thing" in name


def test_branch_name_handles_missing_line():
    name = brancher.branch_name("trivy", "CVE-2024-0001", "Dockerfile", None, "abc123")
    assert name.startswith("fix/trivy-cve-2024-0001-")


def test_different_findings_produce_different_branches():
    a = brancher.branch_name("bandit", "B105", "a.py", 1, "sha1")
    b = brancher.branch_name("bandit", "B105", "b.py", 1, "sha1")
    assert a != b
