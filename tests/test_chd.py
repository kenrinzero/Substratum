"""S3 gate tests for the chd normalizer (NORMALIZERS.md row `chd`).

The chd normalizer returns a ByteView (DESIGN.md §1 composition rule:
one layer, never recurse).  The test wraps that ByteView through
normalize_iso9660 to get a FileTree for the four-check gate.

Expected manifest entries are the pre-compression iso manifest entries
(authored independently by pycdlib/7z at S1 time — not derived from the
parser under test).  Reference bytes are the iso reference bytes
(decompressed disc is byte-identical).  Tool pins include chdman 0.288.
"""

import json
from pathlib import Path

import jsonschema

from substratum.contract import FileSource, FileTree, ByteView, sha256_of
from substratum.formats.chd import normalize_chd, sniff
from substratum.formats.iso9660 import normalize_iso9660
from substratum.verify import run_checks

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "fixtures" / "chd" / "supertux"
ISO_REF = ROOT / "fixtures" / "iso9660" / "supertux" / "reference"

# Tool versions — match what canonical_manifest will emit.
# source.sha256 and source.size come from the decompressed output
# (byte-identical to original ISO); source.name identifies the input .chd.
TOOLS = {
    "chdman": "0.288 (mame0288)",
    "7z": "7-Zip 26.02 (x64) 2026-06-25",
    "pycdlib": "1.16.0",
}


def _normalize_chd_to_tree(source):
    """Wrapper for run_checks: CHD -> ByteView -> iso9660 -> FileTree."""
    view = normalize_chd(source)  # ByteView over decompressed .bin
    tree = normalize_iso9660(view.source)  # FileTree over the .bin
    # Override format to "chd" so the manifest records the container.
    return FileTree(source=tree.source, format="chd", entries=tree.entries)


def checks():
    """Run the four-check gate on the CHD fixture."""
    iso_path = ROOT / "fixtures" / "iso9660" / "supertux" / "supertux.iso"
    return run_checks(
        _normalize_chd_to_tree,
        FIXTURE / "supertux.chd",
        FIXTURE / "expected.manifest.json",
        ISO_REF,
        "supertux.chd",
        sha256_of(iso_path),  # decompressed data = original ISO sha256
        TOOLS,
    )


def test_chd_is_green():
    """The full four-check gate passes on the CHD fixture."""
    assert checks() == []


def test_sniff():
    """CHD magic detection."""
    assert sniff(FileSource(FIXTURE / "supertux.chd"))
    assert not sniff(FileSource(ROOT / "fixtures" / "toy" / "toy.bin"))
    assert not sniff(FileSource(
        ROOT / "fixtures" / "iso9660" / "supertux" / "supertux.iso"
    ))


def test_expected_manifest_validates_against_schema():
    schema = json.loads((ROOT / "schema" / "manifest.schema.json").read_text("utf-8"))
    doc = json.loads((FIXTURE / "expected.manifest.json").read_text("ascii"))
    jsonschema.Draft202012Validator(schema).validate(doc)
    assert doc["format"] == "chd"
    kinds = {e["kind"] for e in doc["entries"]}
    assert kinds == {"file", "dir"}


def test_normalize_chd_returns_bytemeasure():
    """normalize_chd returns a ByteView, not a FileTree (composition rule)."""
    view = normalize_chd(FIXTURE / "supertux.chd")
    assert isinstance(view, ByteView)
    assert view.format == "chd"
    # size matches the decompressed ISO
    assert view.source.size() == 21823488


def test_decompressed_data_matches_original():
    """The decompressed CHD data is byte-identical to the original ISO."""
    view = normalize_chd(FIXTURE / "supertux.chd")
    iso = ROOT / "fixtures" / "iso9660" / "supertux" / "supertux.iso"
    # spot-check: read the PVD area
    pvd_chd = view.source.read_at(16 * 2048, 2048)
    with iso.open("rb") as fh:
        fh.seek(16 * 2048)
        pvd_iso = fh.read(2048)
    assert pvd_chd == pvd_iso


def test_corrupted_chd_is_structural_red(tmp_path):
    """A corrupted CHD (broken magic) fails structurally."""
    bad = tmp_path / "corrupt.chd"
    data = bytearray((FIXTURE / "supertux.chd").read_bytes())
    data[0] ^= 0xFF  # break magic
    bad.write_bytes(bytes(data))
    problems = run_checks(
        _normalize_chd_to_tree,
        bad,
        FIXTURE / "expected.manifest.json",
        ISO_REF,
        "supertux.chd",
        sha256_of(ROOT / "fixtures" / "iso9660" / "supertux" / "supertux.iso"),
        TOOLS,
    )
    assert problems and any(p.startswith("structural:") for p in problems)
