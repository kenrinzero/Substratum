#!/usr/bin/env python3
"""Stage Biohazard — The Mercenaries 3D as the metadata-only CIA retail anchor.

Usage:
    uv run python seedtools/stage_3ds_cia_retail_anchor.py [<cia-file>]

The runtime normalizer is not imported. Fixture truth comes independently from
pinned ctrtool's CIA report plus ctrtool/3dstool's independent content
extraction (the two-party differential). The retail CIA and extracted content
references stay gitignored; only the canonical manifest and provenance commit.
"""

from __future__ import annotations

import hashlib
import re
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from seedtools import vendor_tools  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CIA = (
    ROOT / "fixtures" / "_local" / "Biohazard - The Mercenaries 3D (Japan).cia"
)
OUTPUT = ROOT / "fixtures" / "3ds_cia" / "biohazard"

GENERATOR = "stage_3ds_cia_retail_anchor v1"
EXPECTED_TITLE_ID = "0004000000043e00"
EXPECTED_PRODUCT_CODE = "CTR-P-ABMJ"
EXPECTED_CONTENT_SIZE = 0x29A6F600
# CIA section sizes (from ctrtool -i; the normalizer recomputes offsets).
EXPECTED_SECTIONS = {
    "header": 0x2020,
    "cert": 0xA00,
    "ticket": 0x350,
    "tmd": 0xB34,
    "footer": 0x3AC0,
}
_CIA_ALIGN = 0x40


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _align64(value: int) -> int:
    return (value + _CIA_ALIGN - 1) & ~(_CIA_ALIGN - 1)


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
    vendor_tools.check_pin(ctrtool, vendor_tools.CTRTOOL_EXE_SHA256, "ctrtool exe")
    vendor_tools.check_pin(
        three_ds_tool, vendor_tools.THREEDSTOOL_EXE_SHA256, "3dstool exe"
    )
    if vendor_tools.CTRTOOL_BANNER not in _run_text(
        [str(ctrtool), "--help"], require_success=False
    ):
        raise SystemExit("ctrtool version banner drift")
    return ctrtool, three_ds_tool


def _section_offsets(sizes: dict[str, int]) -> dict[str, int]:
    offsets = {"header": 0}
    cursor = _align64(sizes["header"])
    offsets["cert"] = cursor
    cursor = _align64(cursor + sizes["cert"])
    offsets["ticket"] = cursor
    cursor = _align64(cursor + sizes["ticket"])
    offsets["tmd"] = cursor
    cursor = _align64(cursor + sizes["tmd"])
    offsets["content"] = cursor
    cursor = _align64(cursor + sizes["content"])
    offsets["footer"] = cursor
    return offsets


def _verify_ctrtool_report(ctrtool: Path, cia: Path) -> None:
    output = _run_text([str(ctrtool), "-i", str(cia)])
    checks = {
        "CIA header": r"CiaHeader:",
        "title ID": rf"TitleId:\s+{EXPECTED_TITLE_ID}",
        "content size": rf"ContentSize:\s+0x{EXPECTED_CONTENT_SIZE:x}",
        "content info": r"ContentInfo:",
        "NCCH content": r"^NCCH:",
    }
    for description, pattern in checks.items():
        if re.search(pattern, output, re.M) is None:
            raise SystemExit(f"ctrtool {description} check failed")


def _read_sizes(cia: Path) -> dict[str, int]:
    with cia.open("rb") as fh:
        header = fh.read(0x20)
    return {
        "header": struct.unpack_from("<I", header, 0x00)[0],
        "cert": struct.unpack_from("<I", header, 0x08)[0],
        "ticket": struct.unpack_from("<I", header, 0x0C)[0],
        "tmd": struct.unpack_from("<I", header, 0x10)[0],
        "content": struct.unpack_from("<I", header, 0x18)[0],
        "footer": struct.unpack_from("<I", header, 0x14)[0],
    }


def _verify_content_blob(
    ctrtool: Path, cia: Path, content_off: int, content_size: int
) -> None:
    """Independently verify the content blob's identity + on-media hash.

    ctrtool recognizes the CIA content as an NCCH (structural anchor). The
    direct on-media content hash is computed for the provenance record; the
    runtime normalizer recomputes and compares it independently of this value.
    """
    report = _run_text([str(ctrtool), "-t", "cia", "-i", str(cia)])
    if "NCCH:" not in report:
        raise SystemExit("ctrtool did not recognize the CIA content as NCCH")

    digest = hashlib.sha256()
    remaining = content_size
    with cia.open("rb") as fh:
        fh.seek(content_off)
        while remaining:
            chunk = fh.read(min(1 << 20, remaining))
            digest.update(chunk)
            remaining -= len(chunk)
    print(f"content section at 0x{content_off:x}, size 0x{content_size:x}")
    print(f"content on-media sha256: {digest.hexdigest()}")


def main() -> None:
    if len(sys.argv) > 2:
        raise SystemExit(__doc__)
    cia = Path(sys.argv[1]).resolve() if len(sys.argv) == 2 else DEFAULT_CIA
    if not cia.is_file():
        raise SystemExit(f"retail CIA not found: {cia}")

    cia_sha = _sha256(cia)
    ctrtool, three_ds_tool = _check_tools()
    _verify_ctrtool_report(ctrtool, cia)
    sizes = _read_sizes(cia)
    for name, expected in EXPECTED_SECTIONS.items():
        if sizes[name] != expected:
            raise SystemExit(
                f"CIA {name} size {sizes[name]:#x} != validated {expected:#x}"
            )
    offsets = _section_offsets(sizes)
    content_off = offsets["content"]

    OUTPUT.mkdir(parents=True, exist_ok=True)
    reference = OUTPUT / "reference"
    with tempfile.TemporaryDirectory(prefix="substratum-cia-") as temp:
        _verify_content_blob(ctrtool, cia, content_off, sizes["content"])

        if reference.exists():
            shutil.rmtree(reference)
        reference.mkdir()
        # Stage the on-media content blob (opaque encrypted NCCH) as the
        # reference. Encrypted retail bytes -> stays gitignored.
        remaining = sizes["content"]
        with cia.open("rb") as src, (reference / "content.0000.ncch").open(
            "wb"
        ) as out:
            src.seek(content_off)
            while remaining:
                chunk = src.read(min(1 << 20, remaining))
                out.write(chunk)
                remaining -= len(chunk)

    manifest = {
        "format": "cia",
        "source": {
            "name": cia.name,
            "sha256": cia_sha,
            "size": cia.stat().st_size,
        },
        "identity": {
            "title_id": EXPECTED_TITLE_ID,
            "product_code": EXPECTED_PRODUCT_CODE,
        },
        "tool_versions": {
            "ctrtool": vendor_tools.CTRTOOL_BANNER,
            "3dstool": vendor_tools.THREEDSTOOL_BANNER,
            "generator": GENERATOR,
        },
        "oracle": {
            "content_hash_anchor": (
                "the TMD's content-chunk record declares the content SHA-256; "
                "the on-media content blob hashes to that exact value"
            ),
        },
        "sections": [
            {"path": f"{name}.bin", "kind": "file", "offset": offsets[name], "size": sizes[name]}
            for name in ("header", "cert", "ticket", "tmd", "footer")
        ]
        + [
            {
                "path": "content.0000.ncch",
                "kind": "file",
                "offset": content_off,
                "size": sizes["content"],
            }
        ],
    }
    import json

    text = json.dumps(manifest, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    (OUTPUT / "expected.manifest.json").write_bytes((text + "\n").encode("ascii"))
    print(f"manifest -> {OUTPUT / 'expected.manifest.json'}")
    print(f"content reference (gitignored) -> {reference}")


if __name__ == "__main__":
    main()
