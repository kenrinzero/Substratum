"""Regression checks for bounded external tooling and executable pins."""

from __future__ import annotations

import ast
import hashlib
import re
from pathlib import Path

import pytest

from seedtools import stage_saturn_homebrew_anchor, vendor_tools

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
        vendor_tools.ECM_EXE_SHA256,
        vendor_tools.UNECM_EXE_SHA256,
        vendor_tools.CTRTOOL_EXE_SHA256,
        vendor_tools.THREEDSTOOL_EXE_SHA256,
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


def test_saturn_stager_ecm_record_encoding_and_address_origin():
    assert stage_saturn_homebrew_anchor._encode_type_count(1, 411) == b"\xed\x0c"
    assert stage_saturn_homebrew_anchor._encode_type_count(
        0, 0xFFFFFFFF
    ) == bytes.fromhex("fcffffff3f")
    assert stage_saturn_homebrew_anchor._address_for_lba(0) == bytes.fromhex(
        "000200"
    )


def test_ecm_release_asset_and_binary_banner_versions_are_both_explicit():
    assert vendor_tools.ECM_RELEASE == "v1.3.1"
    assert vendor_tools.ECM_BANNER.endswith("v1.3.0")
    assert vendor_tools.UNECM_BANNER.endswith("v1.3.0")


def test_3ds_tools_are_keyless_executable_only_provisioners():
    assert vendor_tools.CTRTOOL_BANNER.startswith("CTRTool v1.3.0")
    assert vendor_tools.THREEDSTOOL_BANNER == "3dstool 1.2.6 by dnasdw"
    source = (ROOT / "seedtools" / "vendor_tools.py").read_text(encoding="utf-8")
    assert "ext_key.txt" not in source
