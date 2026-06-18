"""Sniff the test framework from repo contents.

Priority: Go → Jest → pytest. Returns None when no signal is found.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

PYTEST_MARKERS = ("pytest.ini", "pyproject.toml", "setup.cfg", "tox.ini", "conftest.py")


def detect_framework(path: str | Path) -> str | None:
    root = Path(path)
    if not root.exists():
        return None

    if (root / "go.mod").exists() or _has_any_suffix(root, "_test.go"):
        return "gotest"

    pkg_json = root / "package.json"
    if pkg_json.exists() and _package_uses_jest(pkg_json):
        return "jest"

    if _looks_like_pytest(root):
        return "pytest"

    return None


def _looks_like_pytest(root: Path) -> bool:
    for marker in PYTEST_MARKERS:
        if (root / marker).exists():
            if marker == "pyproject.toml":
                try:
                    text = (root / marker).read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue
                if "pytest" in text:
                    return True
                continue
            return True
    if _has_any_suffix(root, "_test.py") or _has_prefix(root, "test_"):
        return True
    return False


def _package_uses_jest(pkg_json: Path) -> bool:
    try:
        data = json.loads(pkg_json.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    deps = {**(data.get("dependencies") or {}), **(data.get("devDependencies") or {})}
    if "jest" in deps:
        return True
    scripts = data.get("scripts") or {}
    return any("jest" in str(v) for v in scripts.values())


def _has_any_suffix(root: Path, suffix: str, max_files: int = 2000) -> bool:
    count = 0
    for p in root.rglob(f"*{suffix}"):
        if p.is_file():
            return True
        count += 1
        if count >= max_files:
            break
    return False


def _has_prefix(root: Path, prefix: str, max_files: int = 2000) -> bool:
    count = 0
    for p in root.rglob(f"{prefix}*.py"):
        if p.is_file():
            return True
        count += 1
        if count >= max_files:
            break
    return False
