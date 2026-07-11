from pathlib import Path

from evaluation import patcher


def _make_source(tmp_path: Path) -> Path:
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("password = 'admin123'\n")
    return source


def test_apply_full_file_replacement_writes_cleaned_content(tmp_path: Path):
    source = _make_source(tmp_path)
    result = patcher.apply_full_file_replacement(
        source_root=source, target_relpath="app.py",
        new_content="password = get_secret()\n",
        workdir_root=tmp_path / "work",
    )
    assert result.parse_ok is True
    assert result.target_file.read_text() == "password = get_secret()"


def test_apply_full_file_replacement_rejects_content_blank_only_after_fence_stripping(
    tmp_path: Path,
):
    """Regression test: a degenerate fenced response like '```python\\n\\n```'
    is non-blank as raw text, so fix_eval.py's `resp.text.strip()` guard
    (checked before this function is ever called) doesn't catch it.
    strip_fences() reduces it to "", and ast.parse("") is valid Python (an
    empty module) — so without this check, _validate() would silently
    record an empty file as "parses cleanly," inflating fix_safety (and
    potentially fix_accuracy) for what is actually a non-answer."""
    source = _make_source(tmp_path)
    result = patcher.apply_full_file_replacement(
        source_root=source, target_relpath="app.py",
        new_content="```python\n\n```",
        workdir_root=tmp_path / "work",
    )
    assert result.parse_ok is False
    assert result.parse_error == "empty content after fence-stripping"


def test_apply_full_file_replacement_flags_syntax_error(tmp_path: Path):
    source = _make_source(tmp_path)
    result = patcher.apply_full_file_replacement(
        source_root=source, target_relpath="app.py",
        new_content="def f(:\n    pass\n",
        workdir_root=tmp_path / "work",
    )
    assert result.parse_ok is False
    assert "syntax" in result.parse_error
