#!/usr/bin/env python3
"""Stage Cubic Ninja partition 0 as metadata-only decrypted NCCH proof.

Usage:
    uv run python seedtools/stage_3ds_ncch_retail_anchor.py [<ncch-file>]

The runtime normalizer is not imported. Fixture truth comes independently
from pinned ctrtool's NCCH report plus pinned 3dstool's extracted opaque
regions. Retail bytes stay gitignored; only the canonical manifest and
provenance commit.
"""

from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from seedtools import vendor_tools  # noqa: E402
from substratum.contract import (  # noqa: E402
    FileEntry,
    FileSource,
    FileTree,
    canonical_manifest,
)

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_NCCH = (
    ROOT
    / "fixtures"
    / "3ds_cci"
    / "cubic-ninja"
    / "reference"
    / "partition0.cxi"
)
OUTPUT = ROOT / "fixtures" / "3ds_ncch" / "cubic-ninja"

GENERATOR = "stage_3ds_ncch_retail_anchor v1"
EXPECTED_SIZE = 86_430_720
EXPECTED_SHA256 = (
    "b805cdfdf2965e8a6f90990982bf7386ba755811bea52c5d0902bbb799a6af80"
)
EXPECTED_TITLE_ID = "0004000000034300"
EXPECTED_PRODUCT_CODE = "CTR-P-AQNJ"
EXPECTED_REGIONS = {
    "extendedheader.bin": {
        "offset": 512,
        "size": 2_048,
        "sha256": (
            "f6d8a5193e7bed1fc1c7e3aa0733e2f3e8c4eca6d534f9e07de0c1af0350cc3d"
        ),
    },
    "plain.bin": {
        "offset": 2_560,
        "size": 512,
        "sha256": (
            "b46a299ba59fe45420f113a65957867199b6125595141f944e12fc7d0ee4b556"
        ),
    },
    "exefs.bin": {
        "offset": 3_072,
        "size": 1_452_032,
        "sha256": (
            "8ab4d508067648723505888a15fa203d0867da714de9a7e7409c816b8911b155"
        ),
    },
    "romfs.bin": {
        "offset": 1_455_104,
        "size": 84_975_616,
        "sha256": (
            "09ed1f54e53a3bec3711b33eb3e4ee3993e004fe5786bb79357af5db66566de5"
        ),
    },
}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_range(path: Path, offset: int, size: int) -> str:
    digest = hashlib.sha256()
    remaining = size
    with path.open("rb") as fh:
        fh.seek(offset)
        while remaining:
            chunk = fh.read(min(1 << 20, remaining))
            if not chunk:
                raise SystemExit("short read while hashing an NCCH region")
            digest.update(chunk)
            remaining -= len(chunk)
    return digest.hexdigest()


def _run_text(command: list[str], *, require_success: bool = True) -> str:
    process = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=vendor_tools.TOOL_TIMEOUT_SECONDS,
    )
    output = process.stdout + process.stderr
    if require_success and process.returncode != 0:
        raise SystemExit(
            f"tool failed with exit {process.returncode}: {command[0]}\n{output}"
        )
    return output


def _check_tools() -> tuple[Path, Path]:
    ctrtool = ROOT / "tools" / "ctrtool" / "ctrtool.exe"
    three_ds_tool = ROOT / "tools" / "3dstool" / "3dstool.exe"
    if not ctrtool.is_file() or not three_ds_tool.is_file():
        raise SystemExit(
            "pinned 3DS tools are absent; run "
            "`uv run python seedtools/vendor_tools.py 3ds`"
        )
    vendor_tools.check_pin(
        ctrtool, vendor_tools.CTRTOOL_EXE_SHA256, "ctrtool exe"
    )
    vendor_tools.check_pin(
        three_ds_tool, vendor_tools.THREEDSTOOL_EXE_SHA256, "3dstool exe"
    )
    if vendor_tools.CTRTOOL_BANNER not in _run_text(
        [str(ctrtool), "--help"], require_success=False
    ):
        raise SystemExit("ctrtool version banner drift")
    three_ds_banner = _run_text(
        [str(three_ds_tool), "--help"], require_success=False
    ).strip().splitlines()[0]
    if three_ds_banner != vendor_tools.THREEDSTOOL_BANNER:
        raise SystemExit("3dstool version banner drift")
    return ctrtool, three_ds_tool


def _hex_field(output: str, label: str) -> int:
    match = re.search(rf"^{re.escape(label)}:\s+0x([0-9A-Fa-f]+)$", output, re.M)
    if match is None:
        raise SystemExit(f"ctrtool omitted {label}")
    return int(match.group(1), 16)


def _ctrtool_regions(ctrtool: Path, ncch: Path) -> dict[str, dict[str, int | str]]:
    output = _run_text([str(ctrtool), "-v", "-y", str(ncch)])
    required_patterns = {
        "NCCH identity": r"^Header:\s+NCCH$",
        "known modified signature": r"^Signature: \(FAIL\)",
        "format version": r"^FormatVersion:\s+2$",
        "title ID": rf"^Title id:\s+{EXPECTED_TITLE_ID}$",
        "product code": rf"^Product code:\s+{EXPECTED_PRODUCT_CODE}$",
        "decrypted flag": r"^ > Crypto Key\s+None$",
        "extended-header integrity": r"^Exheader hash: \(GOOD\)",
        "ExeFS integrity": r"^ExeFS hash: \(GOOD\)",
        "RomFS integrity": r"^RomFS hash: \(GOOD\)",
    }
    for description, pattern in required_patterns.items():
        if re.search(pattern, output, re.M) is None:
            raise SystemExit(f"ctrtool {description} check failed")

    if _hex_field(output, "Content size") != EXPECTED_SIZE:
        raise SystemExit("ctrtool NCCH content-size drift")
    exheader_size = _hex_field(output, "Exheader size")
    if exheader_size != 0x400:
        raise SystemExit("ctrtool extended-header size drift")
    if _hex_field(output, "Logo offset") or _hex_field(output, "Logo size"):
        raise SystemExit("unexpected standalone logo region")

    regions: dict[str, dict[str, int | str]] = {
        "extendedheader.bin": {
            "offset": 0x200,
            "size": exheader_size + 0x400,
        },
        "plain.bin": {
            "offset": _hex_field(output, "Plain region offset"),
            "size": _hex_field(output, "Plain region size"),
        },
        "exefs.bin": {
            "offset": _hex_field(output, "ExeFS offset"),
            "size": _hex_field(output, "ExeFS size"),
        },
        "romfs.bin": {
            "offset": _hex_field(output, "RomFS offset"),
            "size": _hex_field(output, "RomFS size"),
        },
    }
    expected_ranges = {
        path: {"offset": values["offset"], "size": values["size"]}
        for path, values in EXPECTED_REGIONS.items()
    }
    if regions != expected_ranges:
        raise SystemExit(f"ctrtool NCCH region table drift: {regions}")
    return regions


def _extract_regions(three_ds_tool: Path, ncch: Path, destination: Path) -> None:
    paths = {
        name: destination / name
        for name in (*EXPECTED_REGIONS, "logo.bin")
    }
    command = [
        str(three_ds_tool),
        "-x",
        "-t",
        "cxi",
        "-f",
        str(ncch),
        "--extendedheader",
        str(paths["extendedheader.bin"]),
        "--plainregion",
        str(paths["plain.bin"]),
        "--logoregion",
        str(paths["logo.bin"]),
        "--exefs",
        str(paths["exefs.bin"]),
        "--romfs",
        str(paths["romfs.bin"]),
    ]
    _run_text(command)
    if paths["logo.bin"].exists():
        raise SystemExit("3dstool unexpectedly extracted a standalone logo")

    for name, expected in EXPECTED_REGIONS.items():
        extracted = paths[name]
        if not extracted.is_file():
            raise SystemExit(f"3dstool did not extract {name}")
        if extracted.stat().st_size != expected["size"]:
            raise SystemExit(f"3dstool size mismatch for {name}")
        extracted_sha = _sha256(extracted)
        if extracted_sha != expected["sha256"]:
            raise SystemExit(f"3dstool hash mismatch for {name}")
        direct_sha = _sha256_range(ncch, expected["offset"], expected["size"])
        if direct_sha != extracted_sha:
            raise SystemExit(
                f"3dstool bytes differ from direct NCCH range for {name}"
            )


def main() -> None:
    if len(sys.argv) > 2:
        raise SystemExit(__doc__)
    ncch = Path(sys.argv[1]).resolve() if len(sys.argv) == 2 else DEFAULT_NCCH
    if not ncch.is_file():
        raise SystemExit(f"decrypted NCCH not found: {ncch}")
    if ncch.stat().st_size != EXPECTED_SIZE:
        raise SystemExit(
            f"NCCH size {ncch.stat().st_size} != validated size {EXPECTED_SIZE}"
        )
    source_sha256 = _sha256(ncch)
    if source_sha256 != EXPECTED_SHA256:
        raise SystemExit("NCCH SHA-256 does not match the validated anchor")

    ctrtool, three_ds_tool = _check_tools()
    regions = _ctrtool_regions(ctrtool, ncch)

    OUTPUT.mkdir(parents=True, exist_ok=True)
    reference = OUTPUT / "reference"
    with tempfile.TemporaryDirectory(prefix="substratum-3ds-ncch-") as temp:
        extracted = Path(temp)
        _extract_regions(three_ds_tool, ncch, extracted)
        if reference.exists():
            shutil.rmtree(reference)
        reference.mkdir()
        for name in EXPECTED_REGIONS:
            shutil.copy2(extracted / name, reference / name)

    entries = tuple(
        FileEntry(
            path=name,
            kind="file",
            offset=int(values["offset"]),
            size=int(values["size"]),
        )
        for name, values in regions.items()
    )
    tools = {
        "3dstool": vendor_tools.THREEDSTOOL_BANNER,
        "ctrtool": vendor_tools.CTRTOOL_BANNER,
        "generator": GENERATOR,
    }
    tree = FileTree(FileSource(ncch), "3ds-ncch", entries)
    manifest = canonical_manifest(tree, ncch.name, source_sha256, tools)
    manifest_path = OUTPUT / "expected.manifest.json"
    manifest_path.write_bytes(manifest)
    print(
        f"validated {ncch.name}: {EXPECTED_SIZE} bytes, "
        f"{len(entries)} opaque NCCH regions\n"
        f"manifest -> {manifest_path}\n"
        f"reference bytes (gitignored) -> {reference}"
    )


if __name__ == "__main__":
    main()
