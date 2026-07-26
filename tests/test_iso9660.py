"""S1 gate tests for the iso9660 normalizer (NORMALIZERS.md row `iso9660`).

Expected manifests were authored by seedtools/make_iso_fixture.py from
pycdlib's records (second reader), cross-checked against 7-Zip's listing;
reference bytes are 7-Zip's extraction (the differential tool). Nothing
here derives truth from the parser under test.
"""

import json
import struct
from pathlib import Path

import jsonschema
import pytest

from substratum.contract import FileSource, sha256_of
from substratum.formats.iso9660 import normalize_iso9660, sniff
from substratum.verify import run_checks
from tests.assertions import assert_structural_failure

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
    assert_structural_failure(problems, "lacks CD001 standard identifier")


def test_truncated_image_is_structural_red(tmp_path):
    bad = tmp_path / "synthetic.iso"
    bad.write_bytes((SYN / "synthetic.iso").read_bytes()[: 20 * 2048])
    problems = checks(fixture=bad)
    assert_structural_failure(problems, "out of bounds")


@pytest.mark.parametrize("name", [b"", b".", b"..", b"../X", b"..\\X"])
def test_invalid_path_component_is_structural_red(tmp_path, name):
    bad = tmp_path / "synthetic.iso"
    data = bytearray((SYN / "synthetic.iso").read_bytes())
    name_at = data.index(b"DATA", 23 * 2048)
    record_at = name_at - 33
    data[record_at + 32] = len(name)
    data[name_at : name_at + 4] = name.ljust(4, b"\x00")
    bad.write_bytes(data)

    assert_structural_failure(
        checks(fixture=bad),
        "invalid ISO9660 path component",
    )


def test_directory_record_claiming_bytes_past_extent_is_structural_red(tmp_path):
    bad = tmp_path / "synthetic.iso"
    data = bytearray((SYN / "synthetic.iso").read_bytes())
    root_length_at = 16 * 2048 + 156 + 10
    truncated_length = 190 + 36
    struct.pack_into("<I", data, root_length_at, truncated_length)
    struct.pack_into(">I", data, root_length_at + 4, truncated_length)
    bad.write_bytes(data)

    assert_structural_failure(
        checks(fixture=bad),
        "directory record claims 46 bytes with only 36 remaining",
    )


def _file_record(name: bytes, length: int) -> bytes:
    record = bytearray(length)
    record[0] = length
    struct.pack_into("<I", record, 2, 30)
    struct.pack_into(">I", record, 6, 30)
    record[32] = len(name)
    record[33 : 33 + len(name)] = name
    return bytes(record)


def test_directory_record_crossing_logical_block_is_structural_red(tmp_path):
    bad = tmp_path / "synthetic.iso"
    data = bytearray((SYN / "synthetic.iso").read_bytes())
    root_length_at = 16 * 2048 + 156 + 10
    struct.pack_into("<I", data, root_length_at, 4096)
    struct.pack_into(">I", data, root_length_at + 4, 4096)

    root_at = 23 * 2048
    for index in range(8):
        start = root_at + index * 254
        data[start : start + 254] = _file_record(
            f"F{index}".encode("ascii"),
            254,
        )
    crossing_at = root_at + 8 * 254
    data[crossing_at : crossing_at + 34] = _file_record(b"X", 34)
    data[crossing_at + 34] = 0
    bad.write_bytes(data)

    assert_structural_failure(
        checks(fixture=bad),
        "directory record crosses logical block boundary",
    )


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
