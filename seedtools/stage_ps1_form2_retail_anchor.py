#!/usr/bin/env python3
"""Stage the BursTrick PS1 mixed-XA retail anchor as metadata-only proof.

Usage:
    python seedtools/stage_ps1_form2_retail_anchor.py [<bin-file>]

The default source is the operator drop under fixtures/_local/. Retail
bytes never enter Git. This script independently:

1. verifies the Archive-matched carrier hashes and strict one-track CUE;
2. validates every raw sector and writes a temporary 2048-byte ISO view;
3. proves the expected 60,666 genuine Form-2 sectors and representative
   XA metadata;
4. has chdman accept and verify the original BIN/CUE;
5. cross-checks pycdlib metadata against 7-Zip and extracts gitignored
   reference bytes for the four-check runtime gate;
6. commits only the canonical metadata manifest.

It deliberately does not import substratum.formats.ps1_bincue: fixture
truth must remain independent of the parser under test (AGENTS.md § 3).
"""

from __future__ import annotations

import shutil
import sys
import tempfile
from importlib.metadata import version as dist_version
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from make_iso_fixture import extract_reference, sevenzip_version  # noqa: E402
from stage_ps1_retail_anchor import (  # noqa: E402
    FORM2_BIT,
    SECTOR,
    SYNC,
    _chdman_accept,
    _chdman_version,
    _cross_check_entries,
    _hashes,
)
from substratum.contract import (  # noqa: E402
    FileSource,
    FileTree,
    canonical_manifest,
    sha256_of,
)

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_BIN = (
    ROOT
    / "fixtures"
    / "_local"
    / "bin-chd-playstation"
    / "BursTrick - Wake Boarding!! (USA).bin"
)
OUTPUT = ROOT / "fixtures" / "ps1_bincue" / "burstrick"

GENERATOR = "stage_ps1_form2_retail_anchor v1"
EXPECTED_SIZE = 369_842_592
EXPECTED_HASHES = {
    "crc32": "969e9f78",
    "md5": "6f55001cffb01ec619ff2d726a134fff",
    "sha1": "c6e9d6c0685b67614891166b515ba666ef05892d",
    "sha256": "21f02044173b2298199fb3d0adf1673520a3b044fd61e7f0b7b1f30a0b90ce40",
}
EXPECTED_CUE_SHA256 = (
    "c37e5918d9eaaf7ceedb456210d60e98c3d515bf23b2dc909c83bf7b82b9a445"
)
EXPECTED_FORM2_COUNT = 60_666
EXPECTED_FORM2_FIRST = (12, 13, 14, 15, 5555)
EXPECTED_FORM2_LAST = (132_832, 132_837, 132_838, 132_839, 132_840)
REPRESENTATIVE_SECTOR = 24_829
REPRESENTATIVE_XA = (1, 0, 0x64, 1)


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


def _decode_and_validate(bin_path: Path, iso_path: Path) -> tuple[int, ...]:
    if bin_path.stat().st_size != EXPECTED_SIZE:
        raise SystemExit(
            f"BIN size {bin_path.stat().st_size} != validated size {EXPECTED_SIZE}"
        )
    actual_hashes = _hashes(bin_path)
    if actual_hashes != EXPECTED_HASHES:
        raise SystemExit(
            f"BIN hashes do not match the validated Archive member: {actual_hashes}"
        )

    form2: list[int] = []
    representative_xa: tuple[int, int, int, int] | None = None
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
            if sector == REPRESENTATIVE_SECTOR:
                representative_xa = (raw[16], raw[17], raw[18], raw[19])
            # The contract's ordinary ByteView is intentionally fixed-width:
            # every raw sector contributes its first 2048 payload bytes.
            dst.write(raw[24:2072])

    if len(form2) != EXPECTED_FORM2_COUNT:
        raise SystemExit(
            f"Form-2 count {len(form2)} != validated count {EXPECTED_FORM2_COUNT}"
        )
    if tuple(form2[:5]) != EXPECTED_FORM2_FIRST:
        raise SystemExit(f"unexpected first Form-2 sectors: {form2[:5]}")
    if tuple(form2[-5:]) != EXPECTED_FORM2_LAST:
        raise SystemExit(f"unexpected last Form-2 sectors: {form2[-5:]}")
    if representative_xa != REPRESENTATIVE_XA:
        raise SystemExit(
            f"sector {REPRESENTATIVE_SECTOR} XA metadata "
            f"{representative_xa} != {REPRESENTATIVE_XA}"
        )
    return tuple(form2)


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

    with tempfile.TemporaryDirectory(prefix="substratum-ps1-form2-anchor-") as temp:
        temp_path = Path(temp)
        iso_path = temp_path / "burstrick.iso"
        chd_path = temp_path / "burstrick.chd"
        form2 = _decode_and_validate(bin_path, iso_path)
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
        f"{len(form2)} Form 2; {len(entries)} ISO9660 entries\n"
        f"manifest -> {OUTPUT / 'expected.manifest.json'}\n"
        f"reference bytes (gitignored) -> {reference}"
    )


if __name__ == "__main__":
    main()
