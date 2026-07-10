from __future__ import annotations

from pathlib import Path

from agent.security import cache


def test_hash_source_dir_stable_across_calls(tmp_path: Path):
    (tmp_path / "a.py").write_text("x = 1\n")
    (tmp_path / "b.py").write_text("y = 2\n")
    h1 = cache.hash_source_dir(tmp_path)
    h2 = cache.hash_source_dir(tmp_path)
    assert h1 == h2


def test_hash_source_dir_changes_when_content_changes(tmp_path: Path):
    (tmp_path / "a.py").write_text("x = 1\n")
    before = cache.hash_source_dir(tmp_path)
    (tmp_path / "a.py").write_text("x = 2\n")
    after = cache.hash_source_dir(tmp_path)
    assert before != after


def test_hash_source_dir_changes_when_file_added(tmp_path: Path):
    (tmp_path / "a.py").write_text("x = 1\n")
    before = cache.hash_source_dir(tmp_path)
    (tmp_path / "b.py").write_text("y = 2\n")
    after = cache.hash_source_dir(tmp_path)
    assert before != after


def test_run_all_cached_second_call_skips_run_all_fn(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "a.py").write_text("x = 1\n")
    cache_dir = tmp_path / "cache"

    calls = []

    def fake_run_all(target_path, **kwargs):
        calls.append(target_path)
        return {"target": target_path, "findings": [{"rule_id": "R1"}]}

    first = cache.run_all_cached(fake_run_all, str(source), cache_dir=cache_dir)
    second = cache.run_all_cached(fake_run_all, str(source), cache_dir=cache_dir)

    assert first == second == {"target": str(source), "findings": [{"rule_id": "R1"}]}
    assert len(calls) == 1  # second call was a cache hit


def test_run_all_cached_reruns_when_source_changes(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "a.py").write_text("x = 1\n")
    cache_dir = tmp_path / "cache"

    calls = []

    def fake_run_all(target_path, **kwargs):
        calls.append(target_path)
        return {"findings": [{"call": len(calls)}]}

    cache.run_all_cached(fake_run_all, str(source), cache_dir=cache_dir)
    (source / "a.py").write_text("x = 2\n")  # source changed
    cache.run_all_cached(fake_run_all, str(source), cache_dir=cache_dir)

    assert len(calls) == 2


def test_run_all_cached_reruns_when_scanner_version_changes(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "a.py").write_text("x = 1\n")
    cache_dir = tmp_path / "cache"

    calls = []

    def fake_run_all(target_path, **kwargs):
        calls.append(target_path)
        return {"findings": []}

    cache.run_all_cached(fake_run_all, str(source), cache_dir=cache_dir, scanner_version="v1")
    cache.run_all_cached(fake_run_all, str(source), cache_dir=cache_dir, scanner_version="v2")

    assert len(calls) == 2
