"""Run scanners against a dataset's source/ tree and write per-tool JSON.

Produces three files in the dataset directory:
  - agent.json            : agent's combined output (all scanners deduped)
  - bandit_baseline.json  : bandit alone (Python only)
  - semgrep_baseline.json : semgrep alone (multi-language)

File paths in each finding are rewritten to be relative to source/, matching
the paths used in ground_truth.json.
"""
from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path

from agent.security import run_scan
from agent.security.scanners import bandit, semgrep

logger = logging.getLogger(__name__)


def scan_dataset(dataset_dir: Path, timeout: int = 180) -> dict[str, Path]:
    source = dataset_dir / "source"
    if not source.is_dir():
        raise FileNotFoundError(f"no source/ in {dataset_dir}")

    written: dict[str, Path] = {}

    written["agent"] = _write_agent(dataset_dir, source, timeout)

    for tool, runner in (("bandit", bandit), ("semgrep", semgrep)):
        try:
            findings, scan_errors = runner.run(str(source), timeout=timeout)
            for err in scan_errors:
                logger.warning("%s reported an error scanning %s: %s", tool, source, err)
        except FileNotFoundError as exc:
            logger.warning("%s not installed: %s", tool, exc)
            findings = []
        except subprocess.TimeoutExpired:
            logger.warning("%s timed out on %s", tool, source)
            findings = []
        written[tool] = _write_findings(
            dataset_dir / f"{tool}_baseline.json",
            [f.to_dict() for f in findings],
            source,
        )

    return written


def _write_agent(dataset_dir: Path, source: Path, timeout: int) -> Path:
    result = run_scan.run_all(str(source), per_scanner_timeout=timeout)
    return _write_findings(
        dataset_dir / "agent.json",
        result.get("findings", []),
        source,
    )


def _write_findings(path: Path, findings: list[dict], source: Path) -> Path:
    rewritten = [_relativize(f, source) for f in findings]
    path.write_text(json.dumps(rewritten, indent=2) + "\n", encoding="utf-8")
    return path


def _relativize(finding: dict, source: Path) -> dict:
    file_path = finding.get("file") or ""
    if not file_path:
        return finding
    try:
        rel = Path(file_path).resolve().relative_to(source.resolve())
        finding = dict(finding)
        finding["file"] = str(rel)
    except ValueError:
        pass
    return finding


__all__ = ["scan_dataset"]
