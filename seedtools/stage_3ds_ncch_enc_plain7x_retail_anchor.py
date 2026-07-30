#!/usr/bin/env python3
"""Stage Kobayashi as the plain-7.x encrypted-NCCH retail anchor.

Usage:
    uv run python seedtools/stage_3ds_ncch_enc_plain7x_retail_anchor.py [<cci-file>]

The runtime normalizer is not imported. Fixture truth comes independently from
the pinned ctrtool and 3dstool both decrypting the same plain-7.x NCCH slice:
their region extractions must be byte-identical (the genuine two-party
differential), with the one documented refinement — ctrtool and 3dstool
disagree only on ExeFS inter-file *padding*, never on file content, so the
two-party check compares each ExeFS file's content sub-range rather than the
whole ExeFS region (docs/3DS-KEYED-WORK.md § Plain-7.x two-party finding).

The input is a CCI/``.3ds`` (game-card dump), not a CIA: the encrypted NCCH is
partition 0, sliced via the NCSD partition table at offset 0x120. The retail
CCI and all decrypted references stay gitignored; only the canonical manifest
and provenance commit.
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
DEFAULT_CCI = (
    ROOT
    / "fixtures"
    / "_local"
    / "3DS1333 - Kobayashi ga Kawai Sugite Tsurai!! Game Demo Kyun Moe MAX ga Tomara Nai (Japan).3ds"
)
OUTPUT = ROOT / "fixtures" / "3ds_ncch_enc" / "kobayashi"

GENERATOR = "stage_3ds_ncch_enc_plain7x_retail_anchor v1"
EXPECTED_TITLE_ID = "0004000000168700"
EXPECTED_PRODUCT_CODE = "CTR-P-ABKJ"  # confirmed via ctrtool at staging
_MEDIA_UNIT = 0x200

# Region offsets/sizes from ctrtool on the partition-0 NCCH (on-media units).
# Unlike the Biohazard (CIA) anchor, this CCI title carries a logo region.
REGIONS = {
    "extendedheader.bin": {"offset": 0x200, "size": 0x800},
    "logo.bin": {"offset": 0xA00, "size": 0x2000},
    "plain.bin": {"offset": 0x2A00, "size": 0x200},
    "exefs.bin": {"offset": 0x2C00, "size": 0x18F600},
    "romfs.bin": {"offset": 0x193000, "size": 0x40397000},
}

# ExeFS files (entry name -> (offset_in_exefs, size)) read from the decrypted
# ExeFS header at staging. The two-party check compares `.code` and `icon`
# content byte-for-byte; `banner` is EXCLUDED because 3dstool strips a banner
# signature region (banner+0x130 / +0x1ff, ~207 bytes) that ctrtool preserves
# — a documented tooling difference, not a decrypt disagreement. The banner's
# correctness is carried by the NCCH protected-hash validation at the composed
# three_ds_ncch gate, with ctrtool as its oracle.
EXEFS_FILES = {
    ".code": (0x0, 0x15E130),
    "icon": (0x18BC00, 0x36C0),
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
                raise SystemExit("short read while hashing a region")
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
    if vendor_tools.CTRTOOL_BANNER not in _run_text(
        [str(ctrtool), "--help"], require_success=False
    ):
        raise SystemExit("ctrtool version banner drift")
    return ctrtool, three_ds_tool


def _locate_partition0(cci: Path) -> tuple[int, int]:
    """Parse the NCSD partition table and return partition 0 (offset, size)."""
    with cci.open("rb") as fh:
        # NCSD magic at 0x100; partition table at 0x120 (8 entries, 8 bytes each).
        fh.seek(0x100)
        if fh.read(4) != b"NCSD":
            raise SystemExit("CCI missing NCSD magic at 0x100")
        fh.seek(0x120)  # partition 0 entry
        off_units, size_units = struct.unpack_from("<II", fh.read(8), 0)
    if not off_units or not size_units:
        raise SystemExit("CCI partition 0 is empty")
    offset = off_units * _MEDIA_UNIT
    # Partition 0's size field in the table is in media units of declared
    # content; the on-media slice is the NCCH content. Validate via NCCH magic.
    with cci.open("rb") as fh:
        fh.seek(offset + 0x100)
        if fh.read(4) != b"NCCH":
            raise SystemExit("NCCH magic not found at partition 0 + 0x100")
        # Content size in NCCH units lives at NCCH + 0x104 (units of block_size).
        fh.seek(offset + 0x104)
        content_units = struct.unpack_from("<I", fh.read(4), 0)[0]
        fh.seek(offset + 0x118)
        block_size_log = fh.read(1)[0]
    block_size = 1 << (block_size_log + 9)
    content_size = content_units * block_size
    return offset, content_size


def _slice_encrypted_ncch(cci: Path, offset: int, size: int, dest: Path) -> None:
    remaining = size
    with cci.open("rb") as src, dest.open("wb") as out:
        src.seek(offset)
        while remaining:
            chunk = src.read(min(1 << 20, remaining))
            if not chunk:
                raise SystemExit("short read while slicing the encrypted NCCH")
            out.write(chunk)
            remaining -= len(chunk)


def _verify_crypto_metadata(ctrtool: Path, ncch: Path) -> None:
    """Confirm the anchor is plain-7.x (Secure 1, no seed) via ctrtool's report."""
    output = _run_text([str(ctrtool), "-v", "-y", str(ncch)])
    checks = {
        "NCCH magic": r"^Header:\s+NCCH$",
        "format version 2": r"^FormatVersion:\s+2$",
        "title ID": rf"^Title id:\s+{EXPECTED_TITLE_ID}$",
        "plain-7.x crypto": r"^ > Crypto Key\s+Secure \(1\)$",
        "no seed": r"^Title seed check:\s+00000000$",
    }
    for description, pattern in checks.items():
        if re.search(pattern, output, re.M) is None:
            raise SystemExit(f"ctrtool {description} check failed")


def _ctrtool_decrypt(ctrtool: Path, ncch: Path, dest: Path) -> None:
    _run_text(
        [
            str(ctrtool),
            "-t",
            "ncch",
            "--exheader",
            str(dest / "extendedheader.bin"),
            "--logo",
            str(dest / "logo.bin"),
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
            "--logo",
            str(dest / "logo.bin"),
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
    # 3dstool may return nonzero for ancillary reasons; verify every expected
    # region extracted instead of relying on rc.
    for name in REGIONS:
        if not (dest / name).is_file():
            raise SystemExit(
                f"3dstool did not extract {name}: {result.stdout}{result.stderr}"
            )


def _two_party_check(ctrtool_dir: Path, threedstool_dir: Path) -> None:
    """Genuine two-party content oracle on every region ctrtool and 3dstool
    agree on.

    extendedheader/plain/romfs are whole-region identical. `.code` and `icon`
    ExeFS file content is byte-identical. `banner` is excluded: 3dstool strips
    a banner signature region (banner+0x130 / +0x1ff, ~207 bytes) that ctrtool
    preserves — a documented tooling difference. The banner's correctness is
    carried by the NCCH protected-hash validation at the composed gate, with
    ctrtool as its oracle.
    """
    for name in ("extendedheader.bin", "logo.bin", "plain.bin", "romfs.bin"):
        ctr = ctrtool_dir / name
        tds = threedstool_dir / name
        if _sha256(ctr) != _sha256(tds):
            raise SystemExit(f"two-party mismatch for {name}")

    ctr_exefs = ctrtool_dir / "exefs.bin"
    tds_exefs = threedstool_dir / "exefs.bin"
    for fname, (foff, fsize) in EXEFS_FILES.items():
        c = _sha256_range(ctr_exefs, foff, fsize)
        t = _sha256_range(tds_exefs, foff, fsize)
        if c != t:
            raise SystemExit(
                f"two-party ExeFS content mismatch for {fname}: "
                f"ctrtool={c} 3dstool={t}"
            )
    print(
        "two-party differential GREEN: ctrtool and 3dstool decrypt identically "
        "on .code/icon/plain/logo/extendedheader/romfs (banner excluded; 3dstool "
        "strips its signature region)"
    )


def main() -> None:
    if len(sys.argv) > 2:
        raise SystemExit(__doc__)
    cci = Path(sys.argv[1]).resolve() if len(sys.argv) == 2 else DEFAULT_CCI
    if not cci.is_file():
        raise SystemExit(f"retail CCI not found: {cci}")

    cci_sha = _sha256(cci)
    ctrtool, three_ds_tool = _check_tools()
    part_offset, content_size = _locate_partition0(cci)

    OUTPUT.mkdir(parents=True, exist_ok=True)
    reference = OUTPUT / "reference"
    with tempfile.TemporaryDirectory(prefix="substratum-ncch-enc-7x-") as temp:
        tmp = Path(temp)
        ncch = tmp / "enc_content.ncch"
        _slice_encrypted_ncch(cci, part_offset, content_size, ncch)
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
            "name": cci.name,
            "sha256": cci_sha,
            "size": cci.stat().st_size,
            "content_offset": part_offset,
            "content_size": content_size,
        },
        "identity": {
            "title_id": EXPECTED_TITLE_ID,
            "product_code": EXPECTED_PRODUCT_CODE,
            "crypto": "plain-7.x (Secure 1, keyslot 0x25)",
            "seed_encrypted": False,
        },
        "tool_versions": {
            "ctrtool": vendor_tools.CTRTOOL_BANNER,
            "3dstool": vendor_tools.THREEDSTOOL_BANNER,
            "generator": GENERATOR,
        },
        "oracle": {
            "two_party_differential": (
                "ctrtool and 3dstool independently decrypt the plain-7.x NCCH "
                "content to byte-identical exheader/plain/romfs regions and "
                "byte-identical .code/icon ExeFS content; banner is ctrtool-only "
                "(3dstool strips a banner signature region it does not render), "
                "with banner correctness carried by the NCCH protected-hash "
                "validation at the composed three_ds_ncch gate"
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
