#!/usr/bin/env python3
"""Stage the Gallop Racer 2001 PS2 retail ISO as metadata-only proof.

Usage:
    python seedtools/stage_iso9660_retail_anchor.py [<iso-file>]

The default source is the operator drop under fixtures/_local/. Retail
bytes never enter Git. This script independently:

1. verifies the supplied image against its public preservation hashes;
2. cross-checks pycdlib metadata against pinned 7-Zip;
3. extracts gitignored 7-Zip reference bytes for the four-check gate;
4. verifies the internal Gallop Racer 2001 / SLUS-20255 identity;
5. commits only the canonical metadata manifest.

It deliberately does not import substratum.formats.iso9660: fixture truth
must remain independent of the parser under test (AGENTS.md section 3).
"""

from __future__ import annotations

import hashlib
import shutil
import sys
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
)

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_ISO = (
    ROOT
    / "fixtures"
    / "_local"
    / "Gallop Racer 2001 (USA)"
    / "Gallop Racer 2001 (USA).iso"
)
OUTPUT = ROOT / "fixtures" / "iso9660" / "gallop-racer-2001"

GENERATOR = "stage_iso9660_retail_anchor v1"
EXPECTED_SIZE = 790_986_752
EXPECTED_HASHES = {
    "crc32": "77f06762",
    "md5": "79d3630668c55f2cabebf326f1a631d8",
    "sha1": "8ac72dc8cfeb8879e44bf22706a109d064d9c5cf",
    "sha256": "d0b02a886a77491f5636c5bce4f163d6c7922ff23b8ce57e208f6a56a18d2a64",
}
BOOT_EXECUTABLE = "SLUS_202.55"
EXPECTED_SYSTEM_CNF = (
    b"BOOT2 = cdrom0:\\SLUS_202.55;1\n"
    b"VER   = 1.00\n"
    b"VMODE = NTSC\n"
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


def _cross_check_entries(iso_path: Path):
    entries = entries_from_pycdlib(iso_path)
    listing = listing_from_7z(iso_path)
    pycdlib_view = {
        entry.path: (entry.kind, entry.size) for entry in entries
    }
    if pycdlib_view != listing:
        delta = sorted(set(pycdlib_view) ^ set(listing))
        if delta:
            raise SystemExit(f"7z/pycdlib listing mismatch: {delta[:10]}")
        disagreements = [
            path
            for path in pycdlib_view
            if pycdlib_view[path] != listing[path]
        ]
        raise SystemExit(
            f"7z/pycdlib metadata mismatch: {disagreements[:10]}"
        )
    return entries


def _verify_reference(entries, reference: Path) -> None:
    by_path = {entry.path: entry for entry in entries}
    required = {"SYSTEM.CNF", BOOT_EXECUTABLE}
    if missing := required - set(by_path):
        raise SystemExit(f"PS2 ISO lacks identity files: {sorted(missing)}")

    for entry in entries:
        if entry.kind == "file":
            extracted = reference / entry.path
            if not extracted.is_file() or extracted.stat().st_size != entry.size:
                raise SystemExit(f"reference bytes missing/short for {entry.path}")

    system_cnf = (reference / "SYSTEM.CNF").read_bytes()
    if system_cnf != EXPECTED_SYSTEM_CNF:
        raise SystemExit(
            "SYSTEM.CNF does not identify Gallop Racer 2001 / "
            "SLUS-20255 / NTSC version 1.00"
        )


def main() -> None:
    if len(sys.argv) > 2:
        raise SystemExit(__doc__)
    iso_path = Path(sys.argv[1]).resolve() if len(sys.argv) == 2 else DEFAULT_ISO
    if not iso_path.is_file():
        raise SystemExit(f"retail ISO not found: {iso_path}")
    if iso_path.stat().st_size != EXPECTED_SIZE:
        raise SystemExit(
            f"ISO size {iso_path.stat().st_size} != validated size {EXPECTED_SIZE}"
        )
    actual_hashes = _hashes(iso_path)
    if actual_hashes != EXPECTED_HASHES:
        raise SystemExit(
            f"ISO hashes do not match the validated anchor: {actual_hashes}"
        )

    OUTPUT.mkdir(parents=True, exist_ok=True)
    reference = OUTPUT / "reference"
    if reference.exists():
        shutil.rmtree(reference)

    entries = _cross_check_entries(iso_path)
    extract_reference(iso_path, reference)
    _verify_reference(entries, reference)

    tools = {
        "7z": sevenzip_version(),
        "pycdlib": dist_version("pycdlib"),
        "generator": GENERATOR,
    }
    tree = FileTree(
        source=FileSource(iso_path),
        format="iso9660",
        entries=tuple(entries),
    )
    manifest = canonical_manifest(
        tree, iso_path.name, actual_hashes["sha256"], tools
    )
    manifest_path = OUTPUT / "expected.manifest.json"
    manifest_path.write_bytes(manifest)

    print(
        f"validated {iso_path.name}: {EXPECTED_SIZE} bytes, "
        f"{sum(entry.kind == 'file' for entry in entries)} files / "
        f"{sum(entry.kind == 'dir' for entry in entries)} dirs\n"
        f"manifest -> {manifest_path}\n"
        f"reference bytes (gitignored) -> {reference}"
    )


if __name__ == "__main__":
    main()
