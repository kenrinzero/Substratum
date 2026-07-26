#!/usr/bin/env python3
"""Stage the Ape Escape PSP retail CSO as metadata-only proof.

Usage:
    python seedtools/stage_cso_retail_anchor.py [<cso-file>]

The default source is the operator drop under fixtures/_local/. Retail
bytes never enter Git. This script independently:

1. verifies the Internet Archive member's published carrier fixity;
2. decodes the CISO with pinned maxcso into a temporary ISO;
3. cross-checks pycdlib metadata against 7-Zip;
4. extracts gitignored 7-Zip reference bytes for the four-check gate;
5. verifies the internal Ape Escape / UCES00045 identity;
6. commits only the canonical metadata manifest.

It deliberately does not import substratum.formats.cso: fixture truth
must remain independent of the parser under test (AGENTS.md § 3).
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
MAXCSO = ROOT / "tools" / "maxcso" / "maxcso.exe"
DEFAULT_CSO = ROOT / "fixtures" / "_local" / "cso" / "Ape Escape (EU).cso"
OUTPUT = ROOT / "fixtures" / "cso" / "ape-escape"

GENERATOR = "stage_cso_retail_anchor v1"
TOOL_TIMEOUT_SECONDS = 600
EXPECTED_SIZE = 396_382_256
EXPECTED_HASHES = {
    "crc32": "72dd6463",
    "md5": "b9e4a4df9c7490340dba9635e49189b1",
    "sha1": "4c9fd7d991069a161311945b8e60f3fb0a40dfbd",
    "sha256": "2298624db25dc7615b1fc69605824f635a59202827107de74988255b56d505f1",
}


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


def _maxcso_version() -> str:
    if not MAXCSO.is_file():
        raise SystemExit(f"maxcso not vendored at {MAXCSO}")
    result = subprocess.run(
        [str(MAXCSO), "--version"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=TOOL_TIMEOUT_SECONDS,
    )
    banner = (result.stdout + result.stderr).strip()
    if not banner.startswith("maxcso "):
        raise SystemExit(f"cannot parse maxcso banner: {banner!r}")
    return banner.split()[-1]


def _decode(cso_path: Path, iso_path: Path) -> None:
    if cso_path.stat().st_size != EXPECTED_SIZE:
        raise SystemExit(
            f"CSO size {cso_path.stat().st_size} != Archive member size {EXPECTED_SIZE}"
        )
    actual_hashes = _hashes(cso_path)
    if actual_hashes != EXPECTED_HASHES:
        raise SystemExit(
            f"CSO hashes do not match the Archive member: {actual_hashes}"
        )
    subprocess.run(
        [str(MAXCSO), "--decompress", str(cso_path), "-o", str(iso_path)],
        capture_output=True,
        check=True,
        timeout=TOOL_TIMEOUT_SECONDS,
    )


def _cross_check_entries(iso_path: Path):
    entries = entries_from_pycdlib(iso_path)
    listing = listing_from_7z(iso_path)

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


def _verify_reference(entries, reference: Path) -> None:
    by_path = {entry.path: entry for entry in entries}
    for entry in entries:
        if entry.kind == "file":
            extracted = reference / entry.path
            if not extracted.is_file() or extracted.stat().st_size != entry.size:
                raise SystemExit(f"reference bytes missing/short for {entry.path}")

    required = {"PSP_GAME/PARAM.SFO", "UMD_DATA.BIN"}
    if missing := required - set(by_path):
        raise SystemExit(f"decoded PSP ISO lacks identity files: {sorted(missing)}")
    param = (reference / by_path["PSP_GAME/PARAM.SFO"].path).read_bytes()
    umd_data = (reference / by_path["UMD_DATA.BIN"].path).read_bytes()
    if (
        b"Ape Escape" not in param
        or b"UCES00045" not in param
        or b"1.00" not in param
    ):
        raise SystemExit(
            "PARAM.SFO does not identify Ape Escape / UCES00045 / version 1.00"
        )
    if b"UCES-00045" not in umd_data:
        raise SystemExit("UMD_DATA.BIN does not identify UCES-00045")


def main() -> None:
    if len(sys.argv) > 2:
        raise SystemExit(__doc__)
    cso_path = Path(sys.argv[1]).resolve() if len(sys.argv) == 2 else DEFAULT_CSO
    if not cso_path.is_file():
        raise SystemExit(f"retail CSO not found: {cso_path}")
    OUTPUT.mkdir(parents=True, exist_ok=True)
    reference = OUTPUT / "reference"
    if reference.exists():
        shutil.rmtree(reference)

    with tempfile.TemporaryDirectory(prefix="substratum-cso-anchor-") as temp:
        iso_path = Path(temp) / "ape-escape.iso"
        _decode(cso_path, iso_path)
        entries = _cross_check_entries(iso_path)
        extract_reference(iso_path, reference)
        _verify_reference(entries, reference)

        tools = {
            "7z": sevenzip_version(),
            "maxcso": _maxcso_version(),
            "pycdlib": dist_version("pycdlib"),
            "generator": GENERATOR,
        }
        tree = FileTree(
            source=FileSource(iso_path),
            format="cso",
            entries=tuple(entries),
        )
        decoded_sha256 = sha256_of(iso_path)
        manifest = canonical_manifest(
            tree, cso_path.name, decoded_sha256, tools
        )
        (OUTPUT / "expected.manifest.json").write_bytes(manifest)
        decoded_size = iso_path.stat().st_size

    print(
        f"validated {cso_path.name}: {EXPECTED_SIZE} carrier bytes -> "
        f"{decoded_size} decoded bytes ({decoded_sha256}); "
        f"{len(entries)} ISO9660 entries\n"
        f"manifest -> {OUTPUT / 'expected.manifest.json'}\n"
        f"reference bytes (gitignored) -> {reference}"
    )


if __name__ == "__main__":
    main()
