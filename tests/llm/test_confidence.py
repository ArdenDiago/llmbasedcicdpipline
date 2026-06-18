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


def test_should_escalate_below_threshold():
    assert confidence.should_escalate(0.3) is True
    assert confidence.should_escalate(0.5) is False
    assert confidence.should_escalate(0.9) is False
    assert confidence.should_escalate(None) is True
