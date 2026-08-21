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
        vendor_tools.DOLPHIN_TOOL_EXE_SHA256,
        vendor_tools.NKIT_EXE_SHA256,
    )
    assert len(set(pins)) == len(pins)
    assert all(re.fullmatch(r"[0-9a-f]{64}", pin) for pin in pins)


def test_every_vendored_executable_has_a_pin_and_is_checked():
    """The completeness test above only covers pins it is told about, so it
    silently under-covered when `dolphin-tool` and `nkit` were vendored. This
    derives the tool set from the module instead: every `vendor_<tool>`
    function must name an `*_EXE_SHA256` constant and pass it to `check_pin`,
    so a new vendored tool cannot ship without an executable-level pin.
    """
    source = (ROOT / "seedtools" / "vendor_tools.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    vendors = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name.startswith("vendor_")
    ]
    assert len(vendors) >= 8, [v.name for v in vendors]

    missing = []
    for fn in vendors:
        pinned = {
            arg.id
            for call in ast.walk(fn)
            if isinstance(call, ast.Call)
            and isinstance(call.func, ast.Name)
            and call.func.id == "check_pin"
            for arg in call.args
            if isinstance(arg, ast.Name) and arg.id.endswith("_EXE_SHA256")
        }
        if not pinned:
            missing.append(fn.name)
        else:
            for pin in pinned:
                assert re.fullmatch(
                    r"[0-9a-f]{64}", getattr(vendor_tools, pin)
                ), f"{fn.name}: {pin} is not a full sha256"

    assert missing == [], (
        f"vendor functions with no executable-level check_pin: {missing}"
    )


def test_already_vendored_fast_path_still_verifies_the_binary():
    """Every `vendor_<tool>` early-returns when the executable is already on
    disk. That branch must verify the bytes, or a drifted binary is silently
    accepted — the gap that let `nkit` run unpinned.
    """
    source = (ROOT / "seedtools" / "vendor_tools.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    unguarded = []
    for fn in tree.body:
        if not (isinstance(fn, ast.FunctionDef) and fn.name.startswith("vendor_")):
            continue
        for node in ast.walk(fn):
            # an `if <exe>.is_file(): ... return` fast path
            if not isinstance(node, ast.If):
                continue
            returns_early = any(
                isinstance(inner, ast.Return) for inner in ast.walk(node)
            )
            tests_presence = any(
                isinstance(c, ast.Call)
                and isinstance(c.func, ast.Attribute)
                and c.func.attr in {"is_file", "exists"}
                for c in ast.walk(node.test)
            )
            if not (returns_early and tests_presence):
                continue
            checks = any(
                isinstance(c, ast.Call)
                and isinstance(c.func, ast.Name)
                and c.func.id == "check_pin"
                for c in ast.walk(node)
            )
            if not checks:
                unguarded.append(f"{fn.name}:{node.lineno}")

    assert unguarded == [], (
        f"already-vendored fast paths that skip check_pin: {unguarded}"
    )


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
