import pytest

from agent.llm import prompts


def test_available_lists_all_six_templates():
    names = prompts.available()
    for required in (
        "classify_error", "fix_single_file", "fix_multi_file",
        "security_analysis", "pr_body", "confidence_eval",
    ):
        assert required in names


def test_render_fix_single_file():
    out = prompts.render(
        "fix_single_file",
        file_path="app/auth.py",
        language="python",
        issue_description="hardcoded password",
        scanner_finding={"scanner": "bandit", "rule_id": "B105", "severity": "low", "cwe": "CWE-259"},
        file_content="password = 'admin123'",
    )
    assert "app/auth.py" in out
    assert "bandit" in out
    assert "password = 'admin123'" in out


def test_render_unknown_template_raises():
    with pytest.raises(KeyError):
        prompts.render("no_such_template")
