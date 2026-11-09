from evaluation import fix_eval


def test_true_positive_pairs_keeps_detecting_finding_and_matches_true_positives():
    truth = [
        {"file": "a.py", "line": 7, "cwe": "CWE-78"},
        {"file": "a.py", "line": 30, "cwe": "CWE-89"},
    ]
    agent = [
        {"scanner": "bandit", "rule_id": "B602", "severity": "high", "file": "a.py", "line": 8, "cwe": "CWE-78"},
        {"scanner": "bandit", "rule_id": "B404", "severity": "low", "file": "a.py", "line": 1, "cwe": "CWE-78"},
    ]
    pairs = fix_eval.true_positive_pairs(truth, agent)
    assert [(t["line"], f["rule_id"]) for t, f in pairs] == [(7, "B602")]
    assert fix_eval.true_positives(truth, agent) == [truth[0]]


def test_incomplete_rescan_is_never_scored_as_fixed(tmp_path, monkeypatch):
    def boom(path, timeout=120):
        raise RuntimeError("scanner crashed")
    monkeypatch.setattr(fix_eval.bandit_scanner, "run", boom)
    monkeypatch.setattr(fix_eval.semgrep_scanner, "run", lambda p, timeout=120: ([], []))
    findings, status = fix_eval.rescan_with_status(tmp_path, "a.py")
    assert status == {"bandit": "error", "semgrep": "ok"}
    assert fix_eval.rescan_file(tmp_path, "a.py", "CWE-78") == (True, 0)


def test_train_shape_base_uses_adapter_conditions():
    spec = "hf:Qwen/Qwen2.5-Coder-1.5B@train-shape"
    assert fix_eval._uses_train_shape(spec) and not fix_eval._is_adapter_spec(spec)
    vuln = {"file": "a.py", "cwe": "CWE-78", "rule_id": "B602", "severity": "high", "description": "shell"}
    assert fix_eval.render_fix_prompt(vuln, "x=1\n", spec) == fix_eval.render_fix_prompt(vuln, "x=1\n", "hf:b+ad")
    assert "CWE-78" not in fix_eval.render_fix_prompt(vuln, "x=1\n", spec)
