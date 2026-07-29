#!/usr/bin/env python3
"""Stage Biohazard — The Mercenaries 3D as the encrypted-NCCH retail anchor.

Usage:
    uv run python seedtools/stage_3ds_ncch_enc_retail_anchor.py [<cia-file>]

The runtime normalizer is not imported. Fixture truth comes independently from
the pinned ctrtool and 3dstool both decrypting the same encrypted NCCH content:
their region extractions must be byte-identical (the genuine two-party
differential). The retail CIA and all decrypted references stay gitignored;
only the canonical manifest and provenance commit.

The encrypted NCCH content slice is located inside the CIA by parsing the CIA
header (header + cert + ticket + TMD precede the content section, which is
64-byte aligned). Only that NCCH layer is exercised here — CIA container
parsing as a whole is a separate later unit.
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
OUTPUT = ROOT / "fixtures" / "3ds_ncch_enc" / "biohazard"

GENERATOR = "stage_3ds_ncch_enc_retail_anchor v1"
EXPECTED_TITLE_ID = "0004000000043e00"
EXPECTED_PRODUCT_CODE = "CTR-P-ABMJ"
EXPECTED_CONTENT_SIZE = 0x29A6F600  # encrypted NCCH content size

# Region offsets/sizes from ctrtool -v on the encrypted content (on-media units).
REGIONS = {
    "extendedheader.bin": {"offset": 0x200, "size": 0x800},
    "plain.bin": {"offset": 0xA00, "size": 0x200},
    "exefs.bin": {"offset": 0xC00, "size": 0x50FA00},
    "romfs.bin": {"offset": 0x510600, "size": 0x2955F000},
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
    vendor_tools.check_pin(ctrtool, vendor_tools.CTRTOOL_EXE_SHA256, "ctrtool exe")
    vendor_tools.check_pin(
        three_ds_tool, vendor_tools.THREEDSTOOL_EXE_SHA256, "3dstool exe"
    )
    # ctrtool prints its banner to stdout/stderr and exits nonzero on --help;
    # only the banner presence is asserted (mirrors stage_3ds_ncch_retail_anchor).
    if vendor_tools.CTRTOOL_BANNER not in _run_text(
        [str(ctrtool), "--help"], require_success=False
    ):
        raise SystemExit("ctrtool version banner drift")
    return ctrtool, three_ds_tool


def _locate_encrypted_ncch(cia: Path) -> tuple[int, int]:
    """Parse the CIA header and return (content_offset, content_size)."""
    with cia.open("rb") as fh:
        header = fh.read(0x20)
    header_size = struct.unpack_from("<I", header, 0x00)[0]
    cert_size = struct.unpack_from("<I", header, 0x08)[0]
    tik_size = struct.unpack_from("<I", header, 0x0C)[0]
    tmd_size = struct.unpack_from("<I", header, 0x10)[0]
    content_size = struct.unpack_from("<I", header, 0x18)[0]
    if content_size != EXPECTED_CONTENT_SIZE:
        raise SystemExit(
            f"CIA content size {content_size:#x} != validated {EXPECTED_CONTENT_SIZE:#x}"
        )
    # Content section is 64-byte aligned after header + cert + tik + tmd.
    raw = header_size + cert_size + tik_size + tmd_size
    content_offset = ((raw + 0x3F) // 0x40) * 0x40
    # The footer trails the content; derive offset from the tail as the
    # authoritative check (CIA alignment quirks make the head computation
    # advisory only).
    footer_size = struct.unpack_from("<I", header, 0x14)[0]
    file_size = cia.stat().st_size
    content_offset = file_size - footer_size - content_size
    if content_offset < raw:
        raise SystemExit("CIA content offset computed below the metadata region")
    # Sanity: NCCH magic sits plaintext at content_offset + 0x100.
    with cia.open("rb") as fh:
        fh.seek(content_offset + 0x100)
        if fh.read(4) != b"NCCH":
            raise SystemExit("NCCH magic not found at the computed content offset")
    return content_offset, content_size


def _slice_encrypted_ncch(cia: Path, offset: int, size: int, dest: Path) -> None:
    remaining = size
    with cia.open("rb") as src, dest.open("wb") as out:
        src.seek(offset)
        while remaining:
            chunk = src.read(min(1 << 20, remaining))
            if not chunk:
                raise SystemExit("short read while slicing the encrypted NCCH")
            out.write(chunk)
            remaining -= len(chunk)


def _verify_crypto_metadata(ctrtool: Path, ncch: Path) -> None:
    """Confirm the anchor is standard-encrypted via ctrtool's report."""
    output = _run_text([str(ctrtool), "-v", "-y", str(ncch)])
    checks = {
        "NCCH magic": r"^Header:\s+NCCH$",
        "format version 2": r"^FormatVersion:\s+2$",
        "title ID": rf"^Title id:\s+{EXPECTED_TITLE_ID}$",
        "product code": rf"^Product code:\s+{EXPECTED_PRODUCT_CODE}$",
        "standard crypto": r"^ > Crypto Key\s+Secure \(0\)$",
        "no seed": r"^Title seed check:\s+00000000$",
    }
    for description, pattern in checks.items():
        if re.search(pattern, output, re.M) is None:
            raise SystemExit(f"ctrtool {description} check failed")


def _ctrtool_decrypt(ctrtool: Path, ncch: Path, dest: Path) -> None:
    """Decrypt + extract every region via ctrtool (default mode decrypts)."""
    _run_text(
        [
            str(ctrtool),
            "-t",
            "ncch",
            "--exheader",
            str(dest / "extendedheader.bin"),
            "--plainrgn",
            str(dest / "plain.bin"),
            "--exefs",
            str(dest / "exefs.bin"),
            "--romfs",
            str(dest / "romfs.bin"),
            str(ncch),
        ]
    )


def _threedstool_decrypt(three_ds_tool: Path, ncch: Path, dest: Path) -> None:
    """Independently decrypt + extract via 3dstool (the second party)."""
    result = subprocess.run(
        [
            str(three_ds_tool),
            "-x",
            "-t",
            "cxi",
            "-f",
            str(ncch),
            "--extendedheader",
            str(dest / "extendedheader.bin"),
            "--plainregion",
            str(dest / "plain.bin"),
            "--exefs",
            str(dest / "exefs.bin"),
            "--romfs",
            str(dest / "romfs.bin"),
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=vendor_tools.TOOL_TIMEOUT_SECONDS,
    )
    # 3dstool returns nonzero when an absent region (logo here) is requested;
    # verify the four expected regions all extracted instead of relying on rc.
    for name in REGIONS:
        if not (dest / name).is_file():
            raise SystemExit(
                f"3dstool did not extract {name}: {result.stdout}{result.stderr}"
            )


def _two_party_check(ctrtool_dir: Path, threedstool_dir: Path) -> None:
    """Both tools must decrypt every region to byte-identical bytes."""
    for name in REGIONS:
        ctr = ctrtool_dir / name
        tds = threedstool_dir / name
        if not ctr.is_file() or not tds.is_file():
            raise SystemExit(f"missing decrypted {name} from one tool")
        h_ctr = _sha256(ctr)
        h_tds = _sha256(tds)
        if h_ctr != h_tds:
            raise SystemExit(
                f"two-party mismatch for {name}: ctrtool={h_ctr} 3dstool={h_tds}"
            )
    print("two-party differential GREEN: ctrtool and 3dstool decrypt identically")


def main() -> None:
    if len(sys.argv) > 2:
        raise SystemExit(__doc__)
    cia = Path(sys.argv[1]).resolve() if len(sys.argv) == 2 else DEFAULT_CIA
    if not cia.is_file():
        raise SystemExit(f"retail CIA not found: {cia}")

    cia_sha = _sha256(cia)
    ctrtool, three_ds_tool = _check_tools()
    content_offset, content_size = _locate_encrypted_ncch(cia)

    OUTPUT.mkdir(parents=True, exist_ok=True)
    reference = OUTPUT / "reference"
    with tempfile.TemporaryDirectory(prefix="substratum-ncch-enc-") as temp:
        tmp = Path(temp)
        ncch = tmp / "enc_content.ncch"
        _slice_encrypted_ncch(cia, content_offset, content_size, ncch)
        _verify_crypto_metadata(ctrtool, ncch)

        ctrtool_out = tmp / "ctrtool"
        threedstool_out = tmp / "3dstool"
        ctrtool_out.mkdir()
        threedstool_out.mkdir()
        _ctrtool_decrypt(ctrtool, ncch, ctrtool_out)
        _threedstool_decrypt(three_ds_tool, ncch, threedstool_out)
        _two_party_check(ctrtool_out, threedstool_out)

        # Stage the gitignored decrypted references.
        if reference.exists():
            shutil.rmtree(reference)
        reference.mkdir()
        for name in REGIONS:
            shutil.copy2(ctrtool_out / name, reference / name)

    manifest = {
        "format": "3ds-ncch-enc",
        "source": {
            "name": cia.name,
            "sha256": cia_sha,
            "size": cia.stat().st_size,
            "content_offset": content_offset,
            "content_size": content_size,
        },
        "identity": {
            "title_id": EXPECTED_TITLE_ID,
            "product_code": EXPECTED_PRODUCT_CODE,
            "crypto": "standard (Secure 0, keyslot 0x2C)",
            "seed_encrypted": False,
        },
        "tool_versions": {
            "ctrtool": vendor_tools.CTRTOOL_BANNER,
            "3dstool": vendor_tools.THREEDSTOOL_BANNER,
            "generator": GENERATOR,
        },
        "oracle": {
            "two_party_differential": (
                "ctrtool and 3dstool independently decrypt the encrypted NCCH "
                "content to byte-identical exheader/plain/exefs/romfs regions"
            ),
        },
        "regions": [
            {"path": name, "kind": "file", "offset": r["offset"], "size": r["size"]}
            for name, r in sorted(REGIONS.items())
        ],
    }
    import json

    manifest_path = OUTPUT / "expected.manifest.json"
    text = json.dumps(manifest, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    manifest_path.write_bytes((text + "\n").encode("ascii"))
    print(f"manifest -> {manifest_path}")
    print(f"decrypted references (gitignored) -> {reference}")


if __name__ == "__main__":
    main()
