"""Security scan orchestrator.

CLI:
    python agent/security/run_scan.py --path <dir>

Runs the enabled scanners in parallel (one thread each), enforces per-scanner
and total timeouts, normalizes findings, dedupes by (file,line,rule_id), and
prints a unified JSON envelope to stdout.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import logging
import subprocess
import sys
import time
from typing import Any

from . import normalize
from .scanners import bandit, gitleaks, semgrep, trivy

logger = logging.getLogger(__name__)

SCANNERS = {
    bandit.NAME: bandit,
    gitleaks.NAME: gitleaks,
    semgrep.NAME: semgrep,
    trivy.NAME: trivy,
}

DEFAULT_PER_SCANNER_TIMEOUT = 180
DEFAULT_TOTAL_TIMEOUT = 480


def run_all(
    target_path: str,
    enabled: list[str] | None = None,
    per_scanner_timeout: int = DEFAULT_PER_SCANNER_TIMEOUT,
    total_timeout: int = DEFAULT_TOTAL_TIMEOUT,
) -> dict[str, Any]:
    names = enabled or list(SCANNERS.keys())
    missing = [n for n in names if n not in SCANNERS]
    if missing:
        raise ValueError(f"unknown scanner(s): {missing}")

    started = time.monotonic()
    findings: list[normalize.Finding] = []
    errors: list[dict[str, Any]] = []
    scanner_status: dict[str, str] = {n: "pending" for n in names}

    # Deliberately not a `with ThreadPoolExecutor() as pool:` block: the
    # context manager's __exit__ always calls shutdown(wait=True), which
    # blocks until every submitted thread finishes regardless of any timeout
    # handled inside the block — silently defeating total_timeout entirely
    # (the function would take as long as the slowest scanner no matter what).
    # concurrent.futures.wait(..., timeout=...) below returns (done, not_done)
    # sets atomically at the deadline without raising, so results that
    # completed before the deadline are never skipped/discarded the way an
    # as_completed()-plus-TimeoutError loop can (that loop aborts entirely on
    # the exception, dropping any already-finished-but-not-yet-processed
    # future). shutdown(wait=False, cancel_futures=True) then lets run_all()
    # return promptly at total_timeout instead of blocking further.
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=len(names) or 1)
    futures = {
        pool.submit(_safe_run, name, target_path, per_scanner_timeout): name
        for name in names
    }
    done, not_done = concurrent.futures.wait(futures, timeout=total_timeout)

    for fut in done:
        name = futures[fut]
        try:
            scanner_findings, scan_errors = fut.result()
        except Exception as exc:  # defensive — _safe_run catches
            scanner_status[name] = "error"
            errors.append({"scanner": name, "error": f"{type(exc).__name__}: {exc}"})
            continue
        if scan_errors:
            # Still keep whatever findings *did* come back — a per-file
            # parse error doesn't mean every other file's results are
            # invalid, and discarding them would recreate the same "silent
            # 0 findings" problem this is fixing.
            scanner_status[name] = "error"
            errors.extend({"scanner": name, "error": e} for e in scan_errors)
        else:
            scanner_status[name] = "ok"
        findings.extend(scanner_findings)

    for fut in not_done:
        name = futures[fut]
        scanner_status[name] = "timeout"
        errors.append({"scanner": name, "error": "total timeout exceeded"})
        fut.cancel()

    pool.shutdown(wait=False, cancel_futures=True)

    deduped = normalize.dedupe(findings)
    return {
        "target": target_path,
        "scanners": scanner_status,
        "findings": [f.to_dict() for f in deduped],
        "errors": errors,
        "stats": {
            "total_findings": len(findings),
            "deduped_findings": len(deduped),
            "duration_seconds": round(time.monotonic() - started, 3),
        },
    }


def _safe_run(name: str, target_path: str, timeout: int) -> tuple[list[normalize.Finding], list[str]]:
    module = SCANNERS[name]
    try:
        return module.run(target_path, timeout=timeout)
    except FileNotFoundError as exc:
        return [], [f"{name} binary not found: {exc}"]
    except subprocess.TimeoutExpired:
        return [], [f"{name} timed out after {timeout}s"]
    except Exception as exc:
        logger.exception("scanner %s failed", name)
        return [], [f"{type(exc).__name__}: {exc}"]


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Run security scanners and emit unified JSON")
    p.add_argument("--path", required=True, help="Target directory to scan")
    p.add_argument(
        "--scanners",
        nargs="*",
        choices=sorted(SCANNERS.keys()),
        help="Subset of scanners to run (default: all)",
    )
    p.add_argument("--per-scanner-timeout", type=int, default=DEFAULT_PER_SCANNER_TIMEOUT)
    p.add_argument("--total-timeout", type=int, default=DEFAULT_TOTAL_TIMEOUT)
    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    result = run_all(
        args.path,
        enabled=args.scanners,
        per_scanner_timeout=args.per_scanner_timeout,
        total_timeout=args.total_timeout,
    )
    json.dump(result, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
