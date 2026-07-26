"""Regression checks for bounded external tooling and executable pins."""

from __future__ import annotations

import ast
import hashlib
import re
from pathlib import Path

import pytest

from seedtools import vendor_tools

ROOT = Path(__file__).resolve().parent.parent


def test_all_runtime_and_seedtool_external_calls_have_timeouts():
    missing: list[str] = []
    paths = sorted((ROOT / "substratum").rglob("*.py"))
    paths.extend(sorted((ROOT / "seedtools").rglob("*.py")))

    for path in paths:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            if node.func.attr not in {"run", "urlopen"}:
                continue
            if not any(keyword.arg == "timeout" for keyword in node.keywords):
                missing.append(f"{path.relative_to(ROOT)}:{node.lineno}")

    assert missing == [], f"external calls without timeout: {missing}"


def test_vendored_executable_pins_are_complete_sha256_values():
    pins = (
        vendor_tools.CHDMAN_EXE_SHA256,
        vendor_tools.WIT_EXE_SHA256,
        vendor_tools.MAXCSO_EXE_SHA256,
    )
    assert len(set(pins)) == len(pins)
    assert all(re.fullmatch(r"[0-9a-f]{64}", pin) for pin in pins)


def test_check_pin_rejects_byte_drift(tmp_path):
    tool = tmp_path / "tool.exe"
    tool.write_bytes(b"pinned bytes")
    exact = hashlib.sha256(b"pinned bytes").hexdigest()
    vendor_tools.check_pin(tool, exact, "test tool")

    tool.write_bytes(b"drifted bytes")
    with pytest.raises(SystemExit, match="sha256 drift"):
        vendor_tools.check_pin(tool, exact, "test tool")
