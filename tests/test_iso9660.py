"""S1 gate tests for the iso9660 normalizer (NORMALIZERS.md row `iso9660`).

Expected manifests were authored by seedtools/make_iso_fixture.py from
pycdlib's records (second reader), cross-checked against 7-Zip's listing;
reference bytes are 7-Zip's extraction (the differential tool). Nothing
here derives truth from the parser under test.
"""

import json
from pathlib import Path

import jsonschema
import pytest

from substratum.contract import FileSource, sha256_of
from substratum.formats.iso9660 import normalize_iso9660, sniff
from substratum.verify import run_checks

ROOT = Path(__file__).resolve().parent.parent
SYN = ROOT / "fixtures" / "iso9660" / "synthetic"

# pinned at unit time (recorded in NORMALIZERS.md row; re-authoring on a
# drifted tool changes the expected manifest and fails check 2 loudly)
TOOLS = {
    "7z": "7-Zip 26.02 (x64) 2026-06-25",
    "pycdlib": "1.16.0",
    "generator": "make_iso_fixture v1",
}


def checks(fixture=None):
    fixture = fixture or SYN / "synthetic.iso"
    return run_checks(
        normalize_iso9660,
        fixture,
        SYN / "expected.manifest.json",
        SYN / "reference",
        "synthetic.iso",
        sha256_of(SYN / "synthetic.iso"),
        TOOLS,
    )


def test_synthetic_iso_is_green():
    assert checks() == []


def _staged_fixture_dirs():
    base = ROOT / "fixtures" / "iso9660"
    return sorted(
        d for d in base.iterdir()
        if d.is_dir() and (d / "expected.manifest.json").exists()
    )


@pytest.mark.parametrize("fixture_dir", _staged_fixture_dirs(), ids=lambda d: d.name)
def test_staged_fixture_is_green(fixture_dir):
    """Every staged fixture dir (synthetic + homebrew) passes the full gate.
    Tool pins come from the staged manifest; entries, sha256, and reference
    bytes are still independently authored."""
    expected = fixture_dir / "expected.manifest.json"
    doc = json.loads(expected.read_text("ascii"))
    iso = fixture_dir / doc["source"]["name"]
    assert run_checks(
        normalize_iso9660,
        iso,
        expected,
        fixture_dir / "reference",
        doc["source"]["name"],
        sha256_of(iso),
        doc["tool_versions"],
    ) == []


def test_corrupted_pvd_is_structural_red(tmp_path):
    bad = tmp_path / "synthetic.iso"
    data = bytearray((SYN / "synthetic.iso").read_bytes())
    data[16 * 2048 + 1] ^= 0xFF  # break "CD001" in the PVD
    bad.write_bytes(bytes(data))
    problems = checks(fixture=bad)
    assert problems and problems[0].startswith("structural:")


def test_truncated_image_is_structural_red(tmp_path):
    bad = tmp_path / "synthetic.iso"
    bad.write_bytes((SYN / "synthetic.iso").read_bytes()[: 20 * 2048])
    problems = checks(fixture=bad)
    assert problems and problems[0].startswith("structural:")


def test_sniff():
    assert sniff(FileSource(SYN / "synthetic.iso"))
    assert not sniff(FileSource(ROOT / "fixtures" / "toy" / "toy.bin"))


def test_expected_manifest_validates_against_schema():
    schema = json.loads((ROOT / "schema" / "manifest.schema.json").read_text("utf-8"))
    doc = json.loads((SYN / "expected.manifest.json").read_text("ascii"))
    jsonschema.Draft202012Validator(schema).validate(doc)
    assert doc["format"] == "iso9660"
    kinds = {e["kind"] for e in doc["entries"]}
    assert kinds == {"file", "dir"}


def test_version_suffix_stripped_and_paths_posix():
    tree = normalize_iso9660(SYN / "synthetic.iso")
    paths = [e.path for e in tree.entries]
    assert not any(";" in p or "\\" in p or p.startswith("/") for p in paths)
    assert "DATA/SUB/C.DAT" in paths


def test_zero_byte_file_reads_empty():
    tree = normalize_iso9660(SYN / "synthetic.iso")
    empty = next(e for e in tree.files() if e.path == "DATA/EMPTY.BIN")
    assert empty.size == 0 and tree.read(empty) == b""
