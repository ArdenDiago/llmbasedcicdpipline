from __future__ import annotations

import json
from pathlib import Path

from agent.testing import detect


def test_detect_gotest_from_go_mod(tmp_path: Path):
    (tmp_path / "go.mod").write_text("module example.com/app\n")
    assert detect.detect_framework(tmp_path) == "gotest"


def test_detect_gotest_from_test_files(tmp_path: Path):
    (tmp_path / "math_test.go").write_text("package app\n")
    assert detect.detect_framework(tmp_path) == "gotest"


def test_detect_jest_from_package_json_dependency(tmp_path: Path):
    (tmp_path / "package.json").write_text(
        json.dumps({"devDependencies": {"jest": "^29.0.0"}})
    )
    assert detect.detect_framework(tmp_path) == "jest"


def test_detect_jest_from_script(tmp_path: Path):
    (tmp_path / "package.json").write_text(
        json.dumps({"scripts": {"test": "jest --ci"}})
    )
    assert detect.detect_framework(tmp_path) == "jest"


def test_detect_pytest_from_marker(tmp_path: Path):
    (tmp_path / "pytest.ini").write_text("[pytest]\n")
    assert detect.detect_framework(tmp_path) == "pytest"


def test_detect_pytest_from_pyproject_mention(tmp_path: Path):
    (tmp_path / "pyproject.toml").write_text("[tool.pytest.ini_options]\n")
    assert detect.detect_framework(tmp_path) == "pytest"


def test_detect_pytest_ignores_pyproject_without_pytest(tmp_path: Path):
    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n")
    assert detect.detect_framework(tmp_path) is None


def test_detect_pytest_from_test_file_name(tmp_path: Path):
    (tmp_path / "test_math.py").write_text("def test_add(): pass\n")
    assert detect.detect_framework(tmp_path) == "pytest"


def test_detect_returns_none_when_no_signal(tmp_path: Path):
    (tmp_path / "README.md").write_text("hello\n")
    assert detect.detect_framework(tmp_path) is None


def test_detect_gotest_priority_over_pytest(tmp_path: Path):
    (tmp_path / "go.mod").write_text("module x\n")
    (tmp_path / "pytest.ini").write_text("[pytest]\n")
    assert detect.detect_framework(tmp_path) == "gotest"
