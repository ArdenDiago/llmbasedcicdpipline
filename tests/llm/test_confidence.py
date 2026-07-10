from agent.llm import confidence


def test_extract_score_from_json():
    assert confidence.extract_score('{"confidence": 0.83}') == 0.83
    assert confidence.extract_score('prose {"score": 0.2} more') == 0.2


def test_extract_score_from_regex():
    assert confidence.extract_score("My confidence: 0.7 in this fix") == 0.7
    assert confidence.extract_score("score = 0.45") == 0.45


def test_extract_score_handles_percentage():
    assert confidence.extract_score('{"confidence": 75}') == 0.75


def test_extract_score_returns_none_when_missing():
    assert confidence.extract_score("no score here") is None
    assert confidence.extract_score("") is None


def test_extract_score_ignores_unbalanced_braces_inside_json_string_values():
    """Regression test: naive brace-counting (not aware of string literals)
    truncates the JSON candidate at a stray '}' embedded in a string value
    (e.g. a 'reasoning' field quoting a code snippet), so json.loads() on
    the truncated slice fails and extraction silently falls through to the
    regex fallback — which then grabs the *first* 'confidence: N' pattern
    anywhere in the text, including a decoy inside that same reasoning
    string, rather than the real "confidence" key. Old (string-unaware)
    behavior would return 0.99 (the decoy); correct behavior returns 0.42
    (the actual confidence field)."""
    text = (
        '{"reasoning": "note: confidence: 0.99 mentioned only as an example, '
        'plus a stray closing brace here } for good measure", '
        '"confidence": 0.42}'
    )
    assert confidence.extract_score(text) == 0.42


def test_json_candidates_recovers_correct_object_despite_embedded_braces():
    candidates = confidence.json_candidates(
        'prefix {"a": "text with { and } inside"} suffix {"confidence": 0.5}'
    )
    assert '{"confidence": 0.5}' in candidates


def test_should_escalate_below_threshold():
    assert confidence.should_escalate(0.3) is True
    assert confidence.should_escalate(0.5) is False
    assert confidence.should_escalate(0.9) is False
    assert confidence.should_escalate(None) is True
