#!/usr/bin/env python3
"""Stage the King's Field PS1 retail anchor as metadata-only proof.

Usage:
    python seedtools/stage_ps1_retail_anchor.py [<bin-file>]

The default source is the operator drop under fixtures/_local/. Retail
bytes never enter Git. This script independently:

1. verifies the supplied Redump hashes and strict one-track CUE;
2. validates every raw sector and writes a temporary 2048-byte ISO view;
3. requires Form 2 to occur exactly at sectors 12-15 with zero payloads;
4. has chdman accept and verify the original BIN/CUE;
5. cross-checks pycdlib metadata against 7-Zip and extracts gitignored
   reference bytes for the four-check runtime gate;
6. commits only the canonical metadata manifest.

It deliberately does not import substratum.formats.ps1_bincue: fixture
truth must remain independent of the parser under test (AGENTS.md § 3).
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import sys
import tempfile
import zlib
from importlib.metadata import version as dist_version
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from make_iso_fixture import (  # noqa: E402
    entries_from_pycdlib,
    extract_reference,
    listing_from_7z,
    sevenzip_version,
)
from substratum.contract import (  # noqa: E402
    FileSource,
    FileTree,
    canonical_manifest,
    sha256_of,
)

ROOT = Path(__file__).resolve().parent.parent
CHDMAN = ROOT / "tools" / "chdman" / "chdman.exe"
DEFAULT_BIN = (
    ROOT
    / "fixtures"
    / "_local"
    / "King's Field (Japan)"
    / "King's Field (Japan)"
    / "King's Field (Japan).bin"
)
OUTPUT = ROOT / "fixtures" / "ps1_bincue" / "kings-field"

GENERATOR = "stage_ps1_retail_anchor v1"
TOOL_TIMEOUT_SECONDS = 300
SECTOR = 2352
SYNC = b"\x00" + b"\xff" * 10 + b"\x00"
FORM2_BIT = 0x20
FORM2_PAYLOAD_START = 24
FORM2_PAYLOAD_END = 2348
FORM2_SECTORS = (12, 13, 14, 15)

EXPECTED_SIZE = 30_378_432
EXPECTED_HASHES = {
    "crc32": "54c8f64a",
    "md5": "c2b8b1652407c6c8107b0c93e20624a6",
    "sha1": "00bfd94ce99bf214b03bdaa07de99b9ca1466550",
    "sha256": "ae74beba377d686bfaa292ea40df8ade4454ec3139c2b5152364e02aac90b3d9",
}
EXPECTED_CUE_SHA256 = (
    "955b14c0a14254dd2866c0ee0ab15e02906f8020120295f6a681a62aeeb90ab7"
)


def _hashes(path: Path) -> dict[str, str]:
    crc = 0
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            crc = zlib.crc32(chunk, crc)
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return {
        "crc32": f"{crc & 0xffffffff:08x}",
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
    }


def _validate_cue(bin_path: Path) -> Path:
    cue_path = bin_path.with_suffix(".cue")
    if not cue_path.is_file():
        raise SystemExit(f"CUE sibling not found: {cue_path}")
    if sha256_of(cue_path) != EXPECTED_CUE_SHA256:
        raise SystemExit(
            f"CUE SHA-256 does not match the validated anchor: {cue_path}"
        )
    expected = (
        f'FILE "{bin_path.name}" BINARY\n'
        "  TRACK 01 MODE2/2352\n"
        "    INDEX 01 00:00:00\n"
    )
    actual = cue_path.read_text("utf-8").replace("\r\n", "\n")
    if actual != expected:
        raise SystemExit("CUE is not the validated single-track MODE2/2352 layout")
    return cue_path


def _decode_and_validate(bin_path: Path, iso_path: Path) -> None:
    if bin_path.stat().st_size != EXPECTED_SIZE:
        raise SystemExit(
            f"BIN size {bin_path.stat().st_size} != validated size {EXPECTED_SIZE}"
        )
    actual_hashes = _hashes(bin_path)
    if actual_hashes != EXPECTED_HASHES:
        raise SystemExit(
            f"BIN hashes do not match the validated Redump anchor: {actual_hashes}"
        )

    form2: list[int] = []
    n_sectors = EXPECTED_SIZE // SECTOR
    with bin_path.open("rb") as src, iso_path.open("wb") as dst:
        for sector in range(n_sectors):
            raw = src.read(SECTOR)
            if len(raw) != SECTOR:
                raise SystemExit(f"short read at raw sector {sector}")
            if raw[:12] != SYNC or raw[15] != 2:
                raise SystemExit(f"invalid Mode-2 envelope at raw sector {sector}")
            if raw[16:20] != raw[20:24]:
                raise SystemExit(f"XA subheader copies differ at raw sector {sector}")
            if raw[18] & FORM2_BIT:
                form2.append(sector)
                if any(raw[FORM2_PAYLOAD_START:FORM2_PAYLOAD_END]):
                    raise SystemExit(f"non-zero Form-2 payload at raw sector {sector}")
            dst.write(raw[24:2072])

    if tuple(form2) != FORM2_SECTORS:
        raise SystemExit(
            f"Form-2 sectors {form2} != validated system-area set {FORM2_SECTORS}"
        )


def _chdman_version() -> str:
    if not CHDMAN.is_file():
        raise SystemExit(f"chdman not vendored at {CHDMAN}")
    result = subprocess.run(
        [str(CHDMAN), "--help"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=TOOL_TIMEOUT_SECONDS,
    )
    first = result.stdout.splitlines()[0]
    if "manager " not in first:
        raise SystemExit(f"cannot parse chdman banner: {first!r}")
    return first.split("manager ", 1)[1].strip()


def _chdman_accept(cue_path: Path, chd_path: Path) -> None:
    subprocess.run(
        [str(CHDMAN), "createcd", "-i", str(cue_path), "-o", str(chd_path)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=TOOL_TIMEOUT_SECONDS,
        check=True,
    )
    info = subprocess.run(
        [str(CHDMAN), "info", "-i", str(chd_path)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=TOOL_TIMEOUT_SECONDS,
        check=True,
    ).stdout
    if "MODE2_RAW" not in info:
        raise SystemExit("chdman did not identify the retail track as MODE2_RAW")
    subprocess.run(
        [str(CHDMAN), "verify", "-i", str(chd_path)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=TOOL_TIMEOUT_SECONDS,
        check=True,
    )


def _cross_check_entries(iso_path: Path):
    entries = entries_from_pycdlib(iso_path)
    listing = listing_from_7z(iso_path)

    # 7-Zip presents ISO identifiers through Win32 filename rules, which
    # remove a trailing dot from a component (for example E0.;1 -> E0).
    # pycdlib preserves the on-disc identifier. Compare through a
    # collision-checked Windows presentation key, while keeping pycdlib's
    # canonical names and offsets in the published manifest.
    def presentation_key(path: str) -> str:
        return "/".join(part.rstrip(" .") for part in path.split("/"))

    pycdlib_view = {
        presentation_key(entry.path): (entry.kind, entry.size) for entry in entries
    }
    sevenzip_view = {
        presentation_key(path): value for path, value in listing.items()
    }
    if len(pycdlib_view) != len(entries) or len(sevenzip_view) != len(listing):
        raise SystemExit("Windows filename normalization caused a path collision")
    if set(pycdlib_view) != set(sevenzip_view):
        delta = sorted(set(pycdlib_view) ^ set(sevenzip_view))
        raise SystemExit(f"7z/pycdlib listing mismatch: {delta[:10]}")
    for path, (kind, size) in pycdlib_view.items():
        seven_kind, seven_size = sevenzip_view[path]
        if seven_kind != kind or (kind == "file" and seven_size != size):
            raise SystemExit(
                f"7z/pycdlib disagree on {path}: "
                f"{kind},{size} vs {seven_kind},{seven_size}"
            )
    return entries


def main() -> None:
    if len(sys.argv) > 2:
        raise SystemExit(__doc__)
    bin_path = Path(sys.argv[1]).resolve() if len(sys.argv) == 2 else DEFAULT_BIN
    if not bin_path.is_file():
        raise SystemExit(f"retail BIN not found: {bin_path}")
    cue_path = _validate_cue(bin_path)
    OUTPUT.mkdir(parents=True, exist_ok=True)
    reference = OUTPUT / "reference"
    if reference.exists():
        shutil.rmtree(reference)

    with tempfile.TemporaryDirectory(prefix="substratum-ps1-anchor-") as temp:
        temp_path = Path(temp)
        iso_path = temp_path / "kings-field.iso"
        chd_path = temp_path / "kings-field.chd"
        _decode_and_validate(bin_path, iso_path)
        _chdman_accept(cue_path, chd_path)
        entries = _cross_check_entries(iso_path)
        extract_reference(iso_path, reference)

        for entry in entries:
            if entry.kind == "file":
                extracted = reference / entry.path
                if not extracted.is_file() or extracted.stat().st_size != entry.size:
                    raise SystemExit(f"reference bytes missing/short for {entry.path}")

        tools = {
            "7z": sevenzip_version(),
            "chdman": _chdman_version(),
            "pycdlib": dist_version("pycdlib"),
            "generator": GENERATOR,
        }
        tree = FileTree(
            source=FileSource(iso_path),
            format="ps1-bincue",
            entries=tuple(entries),
        )
        manifest = canonical_manifest(
            tree, bin_path.name, sha256_of(iso_path), tools
        )
        (OUTPUT / "expected.manifest.json").write_bytes(manifest)

    print(
        f"validated {bin_path.name}: {EXPECTED_SIZE // SECTOR} sectors, "
        f"Form 2 only at {FORM2_SECTORS}; {len(entries)} ISO9660 entries\n"
        f"manifest -> {OUTPUT / 'expected.manifest.json'}\n"
        f"reference bytes (gitignored) -> {reference}"
    )


if __name__ == "__main__":
    main()
