from pathlib import Path

from evaluation import report
from evaluation.compare import ComparisonRow


def _row(tool="agent"):
    return ComparisonRow(
        dataset="d", tool=tool, tp=3, fp=1, fn=1,
        detection_rate=0.75, precision=0.75, recall=0.75, f1=0.75,
    )


def test_write_csv_headers_and_row(tmp_path: Path):
    out = report.write_csv([_row("agent"), _row("semgrep")], tmp_path / "out.csv")
    text = out.read_text()
    lines = text.strip().splitlines()
    assert lines[0] == ",".join(report.CSV_HEADERS)
    assert len(lines) == 3
    assert "agent" in lines[1]
    assert "0.750" in lines[1]


def test_write_markdown_includes_rows(tmp_path: Path):
    out = report.write_markdown([_row("agent")], tmp_path / "out.md", title="T")
    text = out.read_text()
    assert text.startswith("# T\n")
    assert "| dataset |" in text
    assert "agent" in text
    assert "0.750" in text


def test_write_csv_creates_parent_dir(tmp_path: Path):
    out = report.write_csv([_row()], tmp_path / "nested" / "dir" / "out.csv")
    assert out.exists()
