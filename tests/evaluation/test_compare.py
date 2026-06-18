from evaluation import compare


def _f(file, rule, line=None):
    return {"file": file, "rule_id": rule, "line": line, "severity": "high"}


def test_compare_returns_row_per_tool():
    truth = [_f("a.py", "B105", 10), _f("b.py", "B301", 5)]
    tools = {
        "agent": [_f("a.py", "B105", 10), _f("b.py", "B301", 5)],
        "semgrep": [_f("a.py", "B105", 10)],
        "checkov": [],
    }
    rows = compare.compare("owasp-py", truth, tools)
    by_tool = {r.tool: r for r in rows}
    assert by_tool["agent"].tp == 2 and by_tool["agent"].fn == 0
    assert by_tool["semgrep"].tp == 1 and by_tool["semgrep"].fn == 1
    assert by_tool["checkov"].tp == 0 and by_tool["checkov"].fn == 2
    assert by_tool["agent"].dataset == "owasp-py"
