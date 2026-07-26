#!/usr/bin/env python3
"""Stage Slinga Save Game Copier 3.7.1 as a Saturn raw-disc fixture.

Usage:
    python seedtools/stage_saturn_homebrew_anchor.py <game.iso>

The upstream release supplies a cooked MODE1/2048 ISO. This stager:

1. requires the exact GPL-3.0 release asset pinned below;
2. writes the minimal ECM records for its 2048-byte sectors;
3. lets pinned UNECM independently reconstruct complete 2352-byte
   Mode-1 sectors, including EDC, reserved bytes, and P/Q ECC;
4. requires pinned ECM to classify every reconstructed sector as Mode 1
   with zero literal bytes, then round-trips the canonical ECM byte-exactly;
5. authors the expected filesystem manifest from pycdlib records,
   cross-checks it against 7-Zip, and takes reference bytes from 7-Zip.

ECM's release is tagged v1.3.1, while its pinned binaries report v1.3.0.
Both facts are deliberate provenance and are checked by vendor_tools.py.
"""

from __future__ import annotations

import re
import shutil
import struct
import subprocess
import sys
import tempfile
from importlib.metadata import version as dist_version
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from seedtools.make_iso_fixture import (
    entries_from_pycdlib,
    extract_reference,
    listing_from_7z,
    sevenzip_version,
)
from seedtools.vendor_tools import (
    ECM_BANNER,
    ECM_RELEASE,
    UNECM_BANNER,
    run_banner,
    sha256_of as tool_sha256_of,
)

from substratum.contract import FileSource, FileTree, canonical_manifest, sha256_of

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "fixtures" / "saturn_dc_raw" / "save-game-copier-3.7.1"
ECM_EXE = ROOT / "tools" / "ecm" / "ecm.exe"
UNECM_EXE = ROOT / "tools" / "ecm" / "unecm.exe"

UPSTREAM_SIZE = 843_776
UPSTREAM_SHA256 = "e1832e07d4e8273f0db45bcd61fbacffac21468554f87c328619a66a5f4871a8"
UPSTREAM_LICENSE_SHA256 = (
    "3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986"
)
RAW_SIZE = 969_024
RAW_SHA256 = "8392e7d6f6e9606ba91b502191dc0ee9972fbd729e41697c26a098e35f7a239e"
SECTOR_USER_SIZE = 2048
SECTOR_RAW_SIZE = 2352
LEAD_IN_SECTORS = 150
STAGER = "stage_saturn_homebrew_anchor v1"
ECM_TOOL_VERSION = f"ECM/UNECM v1.3.0 ({ECM_RELEASE} release asset)"
TOOL_TIMEOUT_SECONDS = 300


def _bcd(value: int) -> int:
    if not 0 <= value <= 99:
        raise ValueError(f"value outside two-digit BCD range: {value}")
    return ((value // 10) << 4) | (value % 10)


def _address_for_lba(lba: int) -> bytes:
    absolute = lba + LEAD_IN_SECTORS
    minute, remainder = divmod(absolute, 75 * 60)
    second, frame = divmod(remainder, 75)
    return bytes((_bcd(minute), _bcd(second), _bcd(frame)))


def _encode_type_count(record_type: int, count_minus_one: int) -> bytes:
    """Encode ECM's two-bit record type plus variable-width count."""
    if not 0 <= record_type <= 3:
        raise ValueError(f"invalid ECM record type: {record_type}")
    if not 0 <= count_minus_one <= 0xFFFFFFFF:
        raise ValueError(f"invalid ECM count: {count_minus_one}")

    first = ((count_minus_one & 0x1F) << 2) | record_type
    count_minus_one >>= 5
    encoded = bytearray()
    while count_minus_one:
        encoded.append(first | 0x80)
        first = count_minus_one & 0x7F
        count_minus_one >>= 7
    encoded.append(first)
    return bytes(encoded)


def _write_bootstrap_ecm(iso_path: Path, ecm_path: Path) -> int:
    size = iso_path.stat().st_size
    if size == 0 or size % SECTOR_USER_SIZE:
        raise SystemExit(f"{iso_path} is not a non-empty 2048-byte-sector image")
    sector_count = size // SECTOR_USER_SIZE

    with iso_path.open("rb") as source, ecm_path.open("wb") as out:
        out.write(b"ECM\x00")
        out.write(_encode_type_count(1, sector_count - 1))
        for lba in range(sector_count):
            user = source.read(SECTOR_USER_SIZE)
            if len(user) != SECTOR_USER_SIZE:
                raise SystemExit(f"short read at ISO sector {lba}")
            out.write(_address_for_lba(lba))
            out.write(user)
        out.write(_encode_type_count(0, 0xFFFFFFFF))
        out.write(b"\x00\x00\x00\x00")
    return sector_count


def _run(cmd: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=check,
        timeout=TOOL_TIMEOUT_SECONDS,
    )


def _combined(result: subprocess.CompletedProcess[str]) -> str:
    return result.stdout + result.stderr


def _require_tools() -> None:
    if not ECM_EXE.is_file() or not UNECM_EXE.is_file():
        raise SystemExit(
            "pinned ECM tools are absent; run "
            "`uv run python seedtools/vendor_tools.py ecm` first"
        )
    if run_banner([str(ECM_EXE)]) != ECM_BANNER:
        raise SystemExit("ecm.exe banner drift; re-run vendor_tools.py ecm")
    if run_banner([str(UNECM_EXE)]) != UNECM_BANNER:
        raise SystemExit("unecm.exe banner drift; re-run vendor_tools.py ecm")


def build_valid_mode1_raw(
    iso_path: Path,
    raw_path: Path,
    *,
    expected_raw_sha256: str | None = None,
) -> tuple[int, str]:
    """Use UNECM to reconstruct and ECM to independently verify raw sectors."""
    _require_tools()
    raw_path.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="substratum-ecm-") as temp_name:
        temp = Path(temp_name)
        bootstrap = temp / "bootstrap.ecm"
        probe_raw = temp / "probe.bin"
        canonical = temp / "canonical.ecm"
        roundtrip = temp / "roundtrip.bin"
        sector_count = _write_bootstrap_ecm(iso_path, bootstrap)

        # UNECM's output checksum covers the fully reconstructed raw stream.
        # Ask the pinned tool for it once, patch the bootstrap, then require a
        # clean decode. The failed probe is temporary and never accepted.
        probe = _run([str(UNECM_EXE), str(bootstrap), str(probe_raw)], check=False)
        probe_text = _combined(probe)
        match = re.search(
            r"EDC error \(([0-9A-F]{8}), should be 00000000\)", probe_text
        )
        if probe.returncode == 0 or match is None:
            raise SystemExit(f"unexpected UNECM checksum probe result:\n{probe_text}")
        expected_size = sector_count * SECTOR_RAW_SIZE
        if not probe_raw.is_file() or probe_raw.stat().st_size != expected_size:
            raise SystemExit("UNECM checksum probe did not emit the complete raw image")

        output_edc = int(match.group(1), 16)
        with bootstrap.open("r+b") as out:
            out.seek(-4, 2)
            out.write(struct.pack("<I", output_edc))

        decoded = _run([str(UNECM_EXE), str(bootstrap), str(raw_path)])
        if "Done; file is OK" not in _combined(decoded):
            raise SystemExit(f"UNECM did not accept the corrected stream:\n{_combined(decoded)}")
        if raw_path.stat().st_size != expected_size:
            raise SystemExit(
                f"raw size mismatch: got {raw_path.stat().st_size}, expected {expected_size}"
            )

        raw_sha = tool_sha256_of(raw_path)
        if expected_raw_sha256 is not None and raw_sha != expected_raw_sha256:
            raise SystemExit(
                f"raw sha256 mismatch: got {raw_sha}, expected {expected_raw_sha256}"
            )

        encoded = _run([str(ECM_EXE), "-v", str(raw_path), str(canonical)])
        report = _combined(encoded)
        expected_counts = {
            "Literal bytes": 0,
            "Mode 1 sectors": sector_count,
            "Mode 2 form 1 sectors": 0,
            "Mode 2 form 2 sectors": 0,
        }
        for label, expected in expected_counts.items():
            match = re.search(rf"{re.escape(label)}\.*\s+(\d+)", report)
            if match is None or int(match.group(1)) != expected:
                raise SystemExit(
                    f"ECM classification mismatch for {label}: expected {expected}\n{report}"
                )

        _run([str(UNECM_EXE), str(canonical), str(roundtrip)])
        if tool_sha256_of(roundtrip) != raw_sha:
            raise SystemExit("ECM/UNECM canonical round-trip changed the raw image")

    return sector_count, raw_sha


def _assert_listing_agrees(iso_path: Path, entries) -> None:
    listing = listing_from_7z(iso_path)
    authored = {entry.path: (entry.kind, entry.size) for entry in entries}
    if set(authored) != set(listing):
        raise SystemExit(
            "REJECTED - 7z/pycdlib listing mismatch: "
            f"{sorted(set(authored) ^ set(listing))[:10]}"
        )
    for path, (kind, size) in authored.items():
        zkind, zsize = listing[path]
        if kind != zkind or (kind == "file" and size != zsize):
            raise SystemExit(
                f"REJECTED - 7z/pycdlib disagree on {path}: "
                f"{kind},{size} vs {zkind},{zsize}"
            )


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    source = Path(sys.argv[1]).resolve()
    if not source.is_file():
        raise SystemExit(f"source ISO does not exist: {source}")
    if source.stat().st_size != UPSTREAM_SIZE:
        raise SystemExit(
            f"upstream size mismatch: got {source.stat().st_size}, expected {UPSTREAM_SIZE}"
        )
    source_sha = sha256_of(source)
    if source_sha != UPSTREAM_SHA256:
        raise SystemExit(
            f"upstream sha256 mismatch: got {source_sha}, expected {UPSTREAM_SHA256}"
        )
    license_path = source.with_name("LICENSE")
    if not license_path.is_file():
        raise SystemExit(
            f"source license is absent: place the upstream LICENSE beside {source.name}"
        )
    license_sha = sha256_of(license_path)
    if license_sha != UPSTREAM_LICENSE_SHA256:
        raise SystemExit(
            "upstream LICENSE sha256 mismatch: "
            f"got {license_sha}, expected {UPSTREAM_LICENSE_SHA256}"
        )

    with tempfile.TemporaryDirectory(prefix="substratum-saturn-homebrew-") as temp_name:
        temp = Path(temp_name)
        iso_path = temp / "game.iso"
        raw_path = temp / "game_2352.bin"
        reference = temp / "reference"
        shutil.copyfile(source, iso_path)

        sector_count, raw_sha = build_valid_mode1_raw(
            iso_path, raw_path, expected_raw_sha256=RAW_SHA256
        )
        if raw_path.stat().st_size != RAW_SIZE:
            raise SystemExit(
                f"pinned raw size mismatch: got {raw_path.stat().st_size}, expected {RAW_SIZE}"
            )

        entries = entries_from_pycdlib(iso_path)
        _assert_listing_agrees(iso_path, entries)
        extract_reference(iso_path, reference)
        for entry in entries:
            if entry.kind != "file":
                continue
            ref = reference / entry.path
            if not ref.is_file() or ref.stat().st_size != entry.size:
                raise SystemExit(f"reference bytes missing/short for {entry.path}")

        tools = {
            "7z": sevenzip_version(),
            "ecm": ECM_TOOL_VERSION,
            "generator": STAGER,
            "pycdlib": dist_version("pycdlib"),
        }
        tree = FileTree(
            source=FileSource(iso_path),
            format="saturn-dc-raw",
            entries=tuple(entries),
        )
        manifest = canonical_manifest(
            tree, raw_path.name, sha256_of(iso_path), tools
        )

        OUT.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(iso_path, OUT / iso_path.name)
        shutil.copyfile(raw_path, OUT / raw_path.name)
        shutil.copyfile(license_path, OUT / "LICENSE")
        (OUT / "expected.manifest.json").write_bytes(manifest)
        destination_reference = OUT / "reference"
        if destination_reference.exists():
            shutil.rmtree(destination_reference)
        shutil.copytree(reference, destination_reference)

    print(
        f"staged {OUT} ({sector_count} valid Mode-1 sectors; raw sha256 {raw_sha})\n"
        f"{sum(1 for entry in entries if entry.kind == 'file')} files / "
        f"{sum(1 for entry in entries if entry.kind == 'dir')} dirs; tools={tools}\n"
        f"provenance remains in {OUT / 'PROVENANCE.md'}"
    )


if __name__ == "__main__":
    main()
