from dataclasses import dataclass

from evaluation import metrics


def _f(file, rule, line=None, severity="high"):
    return {"file": file, "rule_id": rule, "line": line, "severity": severity}


def test_perfect_detection():
    truth = [_f("a.py", "B105", 10), _f("b.py", "B301", 5)]
    found = [_f("a.py", "B105", 10), _f("b.py", "B301", 5)]
    d = metrics.detection(found, truth)
    assert d.true_positives == 2
    assert d.false_positives == 0
    assert d.false_negatives == 0
    assert d.detection_rate == 1.0
    assert d.f1 == 1.0


def test_line_tolerance():
    truth = [_f("a.py", "B105", 10)]
    found = [_f("a.py", "B105", 12)]  # 2 lines off, within default tolerance 3
    d = metrics.detection(found, truth, line_tolerance=3)
    assert d.true_positives == 1


def test_line_tolerance_exceeded_is_false_positive():
    truth = [_f("a.py", "B105", 10)]
    found = [_f("a.py", "B105", 20)]
    d = metrics.detection(found, truth, line_tolerance=3)
    assert d.true_positives == 0
    assert d.false_positives == 1
    assert d.false_negatives == 1


def test_false_positive_and_false_negative_counts():
    truth = [_f("a.py", "B105", 10), _f("b.py", "B301", 5)]
    found = [_f("a.py", "B105", 10), _f("c.py", "X999", 1)]
    d = metrics.detection(found, truth)
    assert d.true_positives == 1
    assert d.false_positives == 1
    assert d.false_negatives == 1
    assert d.precision == 0.5
    assert d.recall == 0.5


def test_empty_inputs_yield_zero():
    d = metrics.detection([], [])
    assert d.detection_rate == 0.0
    assert d.f1 == 0.0


def test_fix_quality():
    records = [
        metrics.FixRecord(resolved=True, broke_tests=False),
        metrics.FixRecord(resolved=True, broke_tests=True),
        metrics.FixRecord(resolved=False, broke_tests=False),
    ]
    m = metrics.fix_quality(records)
    assert m.total_attempted == 3
    assert m.resolved == 2
    assert m.broke_tests == 1
    assert round(m.fix_accuracy, 3) == round(2 / 3, 3)
    assert round(m.fix_safety, 3) == round(2 / 3, 3)


def test_cost_from_audit_aggregates_by_model():
    @dataclass
    class E:
        model: str
        tokens_in: int
        tokens_out: int

    audit = [
        E("deepseek", 100, 50),
        E("deepseek", 200, 100),
        E("haiku", 300, 200),
    ]
    c = metrics.cost_from_audit(audit)
    assert c.tokens_in == 600
    assert c.tokens_out == 350
    assert c.total_tokens == 950
    assert c.by_model == {"deepseek": 450, "haiku": 500}


def test_each_truth_matched_at_most_once():
    truth = [_f("a.py", "B105", 10)]
    found = [_f("a.py", "B105", 10), _f("a.py", "B105", 10)]
    d = metrics.detection(found, truth)
    assert d.true_positives == 1
    assert d.false_positives == 1


def _t_cwe(file, cwe, line=None):
    return {"file": file, "rule_id": "", "cwe": cwe, "line": line, "severity": "high"}


def _f_cwe(file, cwe, line=None, rule="X"):
    return {"file": file, "rule_id": rule, "cwe": cwe, "line": line, "severity": "high"}


def test_cwe_only_truth_matches_finding_with_same_cwe():
    truth = [_t_cwe("a.py", "CWE-89", 10)]
    found = [_f_cwe("a.py", "CWE-89", 10, rule="B608")]
    d = metrics.detection(found, truth)
    assert d.true_positives == 1
    assert d.false_negatives == 0


def test_cwe_parent_alias_matches():
    # Truth uses broader CWE-798; scanner emits child CWE-259.
    truth = [_t_cwe("secrets.py", "CWE-798", 3)]
    found = [_f_cwe("secrets.py", "CWE-259", 3, rule="B105")]
    d = metrics.detection(found, truth)
    assert d.true_positives == 1


def test_cwe_mismatch_is_false_positive():
    truth = [_t_cwe("a.py", "CWE-89", 10)]
    found = [_f_cwe("a.py", "CWE-95", 10, rule="X")]
    d = metrics.detection(found, truth)
    assert d.true_positives == 0
    assert d.false_positives == 1
    assert d.false_negatives == 1
