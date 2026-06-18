"""Extract a 0.0-1.0 confidence score from an LLM response."""
from __future__ import annotations

import json
import re

_JSON_SCORE_KEYS = ("confidence", "confidence_score", "score")
_REGEX = re.compile(
    r"(?i)\b(?:confidence|confidence[_\s]score|score)\s*[:=]\s*([0-9]*\.?[0-9]+)"
)


def extract_score(text: str) -> float | None:
    """Return a float in [0,1] or None if no usable score is found."""
    if not text:
        return None

    # 1. Try JSON first — cheapest and most reliable.
    for candidate in _json_candidates(text):
        try:
            obj = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            for k in _JSON_SCORE_KEYS:
                if k in obj:
                    val = _coerce(obj[k])
                    if val is not None:
                        return val

    # 2. Regex fallback.
    m = _REGEX.search(text)
    if m:
        return _coerce(m.group(1))
    return None


def should_escalate(score: float | None, threshold: float = 0.5) -> bool:
    """Escalate when we have no score OR the score is below threshold."""
    if score is None:
        return True
    return score < threshold


def _coerce(v) -> float | None:
    try:
        f = float(v)
    except (TypeError, ValueError):
        return None
    if f < 0.0 or f > 1.0:
        # Treat 0-100 as percentage.
        if 0 <= f <= 100:
            f = f / 100.0
        else:
            return None
    return f


def _json_candidates(text: str) -> list[str]:
    """Yield top-level JSON object substrings."""
    out = []
    depth = 0
    start = -1
    for i, ch in enumerate(text):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start != -1:
                out.append(text[start : i + 1])
                start = -1
    return out
