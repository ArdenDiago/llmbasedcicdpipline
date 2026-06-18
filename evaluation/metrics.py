"""Metric calculators for agent vs ground-truth evaluation.

A finding matches a ground-truth vuln when (file, rule_id) aligns and
the reported line is within `line_tolerance` lines of the truth.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

DEFAULT_LINE_TOLERANCE = 3

# Narrow set of well-known CWE parent links — lets ground truth use the
# broader category while still matching scanners that emit the specific child.
# Keys are children, values are parents. Matching is bidirectional.
_CWE_PARENT = {
    "CWE-259": "CWE-798",   # Hardcoded password ⊂ Hardcoded credentials
    "CWE-321": "CWE-798",   # Hardcoded crypto key ⊂ Hardcoded credentials
    "CWE-916": "CWE-327",   # Weak password hash ⊂ Broken/risky crypto
    "CWE-326": "CWE-327",   # Inadequate encryption strength ⊂ Broken crypto
    "CWE-328": "CWE-327",   # Reversible one-way hash ⊂ Broken crypto
}


def _cwes_match(a: str, b: str) -> bool:
    if not a or not b:
        return False
    if a == b:
        return True
    return _CWE_PARENT.get(a) == b or _CWE_PARENT.get(b) == a


@dataclass
class DetectionMetrics:
    true_positives: int
    false_positives: int
    false_negatives: int

    @property
    def detection_rate(self) -> float:
        denom = self.true_positives + self.false_negatives
        return self.true_positives / denom if denom else 0.0

    @property
    def false_positive_rate(self) -> float:
        denom = self.true_positives + self.false_positives
        return self.false_positives / denom if denom else 0.0

    @property
    def precision(self) -> float:
        denom = self.true_positives + self.false_positives
        return self.true_positives / denom if denom else 0.0

    @property
    def recall(self) -> float:
        return self.detection_rate

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return (2 * p * r / (p + r)) if (p + r) else 0.0


@dataclass
class FixMetrics:
    total_attempted: int
    resolved: int
    broke_tests: int

    @property
    def fix_accuracy(self) -> float:
        return self.resolved / self.total_attempted if self.total_attempted else 0.0

    @property
    def fix_safety(self) -> float:
        if not self.total_attempted:
            return 0.0
        return 1.0 - (self.broke_tests / self.total_attempted)


@dataclass
class CostMetrics:
    tokens_in: int = 0
    tokens_out: int = 0
    by_model: dict[str, int] = field(default_factory=dict)

    @property
    def total_tokens(self) -> int:
        return self.tokens_in + self.tokens_out


def _key(f: dict[str, Any]) -> tuple[str, str]:
    return (f.get("file", ""), f.get("rule_id", ""))


def _matches(found: dict[str, Any], truth: dict[str, Any], tol: int) -> bool:
    if found.get("file", "") != truth.get("file", ""):
        return False

    truth_rule = truth.get("rule_id") or ""
    truth_cwe = truth.get("cwe") or ""
    found_rule = found.get("rule_id") or ""
    found_cwe = found.get("cwe") or ""

    rule_match = bool(truth_rule) and truth_rule == found_rule
    cwe_match = _cwes_match(truth_cwe, found_cwe)
    if not (rule_match or cwe_match):
        return False

    fl, tl = found.get("line"), truth.get("line")
    if fl is None or tl is None:
        return True
    return abs(int(fl) - int(tl)) <= tol


def detection(
    found: Iterable[dict[str, Any]],
    truth: Iterable[dict[str, Any]],
    line_tolerance: int = DEFAULT_LINE_TOLERANCE,
) -> DetectionMetrics:
    found_list = list(found)
    truth_list = list(truth)
    matched_truth: set[int] = set()
    tp = 0
    fp = 0

    for f in found_list:
        hit = None
        for idx, t in enumerate(truth_list):
            if idx in matched_truth:
                continue
            if _matches(f, t, line_tolerance):
                hit = idx
                break
        if hit is not None:
            matched_truth.add(hit)
            tp += 1
        else:
            fp += 1

    fn = len(truth_list) - len(matched_truth)
    return DetectionMetrics(true_positives=tp, false_positives=fp, false_negatives=fn)


@dataclass
class FixRecord:
    resolved: bool
    broke_tests: bool


def fix_quality(records: Iterable[FixRecord]) -> FixMetrics:
    records = list(records)
    return FixMetrics(
        total_attempted=len(records),
        resolved=sum(1 for r in records if r.resolved),
        broke_tests=sum(1 for r in records if r.broke_tests),
    )


def cost_from_audit(audit_entries: Iterable[Any]) -> CostMetrics:
    m = CostMetrics()
    for e in audit_entries:
        tokens_in = int(getattr(e, "tokens_in", 0))
        tokens_out = int(getattr(e, "tokens_out", 0))
        model = str(getattr(e, "model", "unknown"))
        m.tokens_in += tokens_in
        m.tokens_out += tokens_out
        m.by_model[model] = m.by_model.get(model, 0) + tokens_in + tokens_out
    return m
