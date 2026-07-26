"""Gate tests for the Wii U8 archive (.arc) normalizer (NORMALIZERS.md row `wii-u8-arc`).

The expected manifest was authored by seedtools/make_wii_u8_arc_fixture.py.
Since we are using D1 = structural self-consistency, there are no third-party
tool dependencies needed to run these checks.
"""

from __future__ import annotations

import json
import struct
from pathlib import Path

import jsonschema
import pytest

from substratum.contract import FileEntry, FileSource, FileTree, sha256_of
from substratum.formats.wii_u8_arc import normalize_wii_u8_arc, sniff
from substratum.verify import run_checks
from tests.assertions import assert_structural_failure

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "fixtures" / "wii_u8_arc" / "synthetic"
ARC = FIXTURE / "archive.arc"
REFERENCE = FIXTURE / "reference"

TOOLS = {
    "self-consistency": "structural-proof",
    "generator": "make_wii_u8_arc_fixture v1",
}

def _checks(normalize_fn=normalize_wii_u8_arc, fixture=ARC):
    return run_checks(
        normalize_fn,
        fixture,
        FIXTURE / "expected.manifest.json",
        REFERENCE,
        "archive.arc",
        sha256_of(ARC),
        TOOLS,
    )

def test_wii_u8_arc_is_green():
    """The full four-check gate passes on the synthetic U8 archive."""
    assert _checks() == []

def test_sniff():
    """Verify sniff detects U8 archives by tag."""
    assert sniff(FileSource(ARC))
    assert not sniff(FileSource(ROOT / "fixtures" / "toy" / "toy.bin"))

def test_returns_filetree():
    """Verify normalize returns a FileTree with correct format."""
    tree = normalize_wii_u8_arc(ARC)
    assert isinstance(tree, FileTree)
    assert tree.format == "wii-u8-arc"

def test_decoded_files_byte_equal_reference():
    """Verify individual files read through the FileTree equal the reference bytes."""
    tree = normalize_wii_u8_arc(ARC)
    app_entry = next(e for e in tree.entries if e.path == "BOOT/APP.BIN")
    content = tree.read(app_entry)
    ref_content = (REFERENCE / "BOOT/APP.BIN").read_bytes()
    assert content == ref_content
    assert len(content) == 10000

def test_composed_tree_matches_expected():
    """Verify the entire generated tree structure matches the expected manifest."""
    tree = normalize_wii_u8_arc(ARC)
    expected = json.loads((FIXTURE / "expected.manifest.json").read_text("ascii"))
    got_paths = sorted(e.path for e in tree.entries)
    want_paths = sorted(e["path"] for e in expected["entries"])
    assert got_paths == want_paths

def test_expected_manifest_validates_against_schema():
    schema = json.loads((ROOT / "schema" / "manifest.schema.json").read_text("utf-8"))
    doc = json.loads((FIXTURE / "expected.manifest.json").read_text("ascii"))
    jsonschema.Draft202012Validator(schema).validate(doc)
    assert doc["format"] == "wii-u8-arc"
    assert doc["source"]["name"] == "archive.arc"
    assert doc["source"]["size"] == ARC.stat().st_size


def _minimal_u8_archive(name: bytes) -> bytes:
    metadata = bytearray(24) + b"\x00" + name + b"\x00"
    metadata[0] = 1
    struct.pack_into(">I", metadata, 8, 2)
    metadata[12] = 0
    metadata[13:16] = (1).to_bytes(3, "big")
    struct.pack_into(">I", metadata, 16, 0x80)

    archive = bytearray(0x80)
    struct.pack_into(">IIII", archive, 0, 0x55AA382D, 0x20, len(metadata), 0x80)
    archive[0x20 : 0x20 + len(metadata)] = metadata
    return bytes(archive)


@pytest.mark.parametrize("name", [b"", b".", b"..", b"../X", b"..\\X"])
def test_invalid_path_component_is_structural_red(tmp_path, name):
    bad = tmp_path / "bad.arc"
    bad.write_bytes(_minimal_u8_archive(name))

    with pytest.raises(ValueError, match="invalid U8 path component"):
        normalize_wii_u8_arc(bad)


# --- structural reds (bounded discipline) --------------------------------

def test_corrupted_tag_is_structural_red(tmp_path):
    bad = tmp_path / "bad.arc"
    data = bytearray(ARC.read_bytes())
    data[0] ^= 0xFF
    bad.write_bytes(bytes(data))
    problems = _checks(normalize_wii_u8_arc, fixture=bad)
    assert_structural_failure(problems, "not a Wii U8 archive")

def test_yaz0_refused(tmp_path):
    bad = tmp_path / "bad.arc"
    data = bytearray(ARC.read_bytes())
    # prepend Yaz0 magic
    data[0:4] = b"Yaz0"
    bad.write_bytes(bytes(data))
    with pytest.raises(ValueError, match="not a Wii U8 archive"):
        normalize_wii_u8_arc(bad)

def test_bad_node_type_refused(tmp_path):
    bad = tmp_path / "bad.arc"
    data = bytearray(ARC.read_bytes())
    # Root node is at offset 0x20. Byte 0 is its type. Set it to 0 (file) instead of 1 (dir).
    data[0x20] = 0
    bad.write_bytes(bytes(data))
    with pytest.raises(ValueError, match="root node is not a directory"):
        normalize_wii_u8_arc(bad)

def test_file_out_of_bounds_refused(tmp_path):
    bad = tmp_path / "bad.arc"
    data = bytearray(ARC.read_bytes())
    # Corrupt Node 3's offset to exceed archive size
    # Node 3 is at 0x20 + 2 * 12 = 0x38. Bytes 4-7 is its data_offset.
    struct.pack_into(">I", data, 0x38 + 4, len(data) + 10)
    bad.write_bytes(bytes(data))
    problems = _checks(normalize_wii_u8_arc, fixture=bad)
    assert_structural_failure(problems, "exceeds archive size")

def test_truncated_refused(tmp_path):
    bad = tmp_path / "bad.arc"
    # Chop off some bytes from the end of archive
    data = ARC.read_bytes()[:-100]
    bad.write_bytes(data)
    with pytest.raises(ValueError, match="exceeds archive size"):
        normalize_wii_u8_arc(bad)

def test_cycle_refused(tmp_path):
    bad = tmp_path / "bad.arc"
    data = bytearray(ARC.read_bytes())
    # Node 2 (BOOT dir) is at 0x20 + 1 * 12 = 0x2C. Bytes 8-11 is next/last.
    # Set next/last = 1 (before itself), which is a cycle.
    struct.pack_into(">I", data, 0x2C + 8, 1)
    bad.write_bytes(bytes(data))
    with pytest.raises(ValueError, match="invalid next/last"):
        normalize_wii_u8_arc(bad)

# --- red-team: wrong-offset slicer (the load-bearing mutant) -------------

def test_wrong_slice_slicer_dies():
    """A mutant normalizer that shifts file offsets. Must fail the gate check."""
    def normalize_mutant(source):
        tree = normalize_wii_u8_arc(source)
        mutated_entries = []
        for e in tree.entries:
            if e.kind == "file":
                # Shift offset of non-empty files backward by 1 byte to keep in bounds
                shift = -1 if e.size > 0 else 0
                mutated_entries.append(FileEntry(path=e.path, kind=e.kind, offset=e.offset + shift, size=e.size))
            else:
                mutated_entries.append(e)
        return FileTree(source=tree.source, format=tree.format, entries=tuple(mutated_entries))

    problems = _checks(normalize_mutant)
    assert problems
    # It must fail check 2 (manifest) and/or check 4 (fidelity)
    assert any(p.startswith("manifest:") or p.startswith("fidelity:") for p in problems)
