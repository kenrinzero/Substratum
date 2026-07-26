"""Gate tests for the decrypted-only 3DS NCCH section normalizer."""

from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

import jsonschema
import pytest

from substratum import normalize
from substratum.contract import FileEntry, FileSource, FileTree, sha256_of
from substratum.formats.three_ds_ncch import normalize_3ds_ncch, sniff
from substratum.verify import run_checks

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "fixtures" / "3ds_ncch" / "cubic-ninja"
NCCH = (
    ROOT
    / "fixtures"
    / "3ds_cci"
    / "cubic-ninja"
    / "reference"
    / "partition0.cxi"
)
REFERENCE = FIXTURE / "reference"

NCCH_SIZE = 86_430_720
NCCH_SHA256 = (
    "b805cdfdf2965e8a6f90990982bf7386ba755811bea52c5d0902bbb799a6af80"
)
TOOLS = {
    "3dstool": "3dstool 1.2.6 by dnasdw",
    "ctrtool": "CTRTool v1.3.0 (C) jakcron",
    "generator": "stage_3ds_ncch_retail_anchor v1",
}

skip_if_no_ncch_anchor = pytest.mark.skipif(
    not NCCH.exists() or not REFERENCE.exists(),
    reason="Cubic Ninja partition 0 or gitignored NCCH region references absent",
)


def _make_ncch() -> bytes:
    """Build a small decrypted v2 NCCH exercising every region type."""
    image = bytearray(0x1600)
    image[0x100:0x104] = b"NCCH"
    struct.pack_into("<I", image, 0x104, len(image) // 0x200)
    struct.pack_into("<Q", image, 0x108, 0x0004000000000001)
    image[0x110:0x112] = b"ZZ"
    struct.pack_into("<H", image, 0x112, 2)
    struct.pack_into("<Q", image, 0x118, 0x0004000000000001)
    image[0x150:0x160] = b"CTR-P-TEST\x00\x00\x00\x00\x00\x00"

    image[0x200:0x600] = b"E" * 0x400
    image[0x600:0xA00] = b"A" * 0x400
    image[0xA00:0xC00] = b"P" * 0x200
    image[0xC00:0xE00] = b"L" * 0x200
    image[0xE00:0x1000] = b"X" * 0x200
    image[0x1000:0x1200] = b"x" * 0x200
    image[0x1200:0x1400] = b"R" * 0x200
    image[0x1400:0x1600] = b"r" * 0x200

    image[0x130:0x150] = hashlib.sha256(image[0xC00:0xE00]).digest()
    image[0x160:0x180] = hashlib.sha256(image[0x200:0x600]).digest()
    struct.pack_into("<I", image, 0x180, 0x400)
    image[0x18C] = 1
    image[0x18D] = 3
    image[0x18E] = 0
    image[0x18F] = 0x04
    struct.pack_into("<II", image, 0x190, 5, 1)
    struct.pack_into("<II", image, 0x198, 6, 1)
    struct.pack_into("<III", image, 0x1A0, 7, 2, 1)
    struct.pack_into("<III", image, 0x1B0, 9, 2, 1)
    image[0x1C0:0x1E0] = hashlib.sha256(image[0xE00:0x1000]).digest()
    image[0x1E0:0x200] = hashlib.sha256(image[0x1200:0x1400]).digest()
    return bytes(image)


def _write_ncch(tmp_path: Path, data: bytes | bytearray) -> Path:
    path = tmp_path / "partition0.cxi"
    path.write_bytes(data)
    return path


def test_minimal_decrypted_ncch_returns_opaque_regions(tmp_path):
    ncch = _write_ncch(tmp_path, _make_ncch())
    tree = normalize_3ds_ncch(ncch)

    assert isinstance(tree, FileTree)
    assert tree.format == "3ds-ncch"
    assert tree.entries == (
        FileEntry("extendedheader.bin", "file", 0x200, 0x800),
        FileEntry("plain.bin", "file", 0xA00, 0x200),
        FileEntry("logo.bin", "file", 0xC00, 0x200),
        FileEntry("exefs.bin", "file", 0xE00, 0x400),
        FileEntry("romfs.bin", "file", 0x1200, 0x400),
    )
    assert tree.read(tree.entries[0]) == b"E" * 0x400 + b"A" * 0x400
    assert tree.read(tree.entries[-1]) == b"R" * 0x200 + b"r" * 0x200


def test_sniff_and_public_dispatch(tmp_path):
    ncch = _write_ncch(tmp_path, _make_ncch())
    source = FileSource(ncch)
    assert sniff(source)
    assert not sniff(FileSource(ROOT / "fixtures" / "toy" / "toy.bin"))

    auto = normalize(ncch)
    pinned = normalize(source, format="3ds-ncch")
    assert isinstance(auto, FileTree) and auto.format == "3ds-ncch"
    assert pinned.entries == auto.entries


def test_absent_optional_regions_are_omitted(tmp_path):
    data = bytearray(_make_ncch())
    struct.pack_into("<I", data, 0x180, 0)
    data[0x160:0x180] = b"\x00" * 0x20
    struct.pack_into("<II", data, 0x198, 0, 0)
    data[0x130:0x150] = b"\x00" * 0x20
    tree = normalize_3ds_ncch(_write_ncch(tmp_path, data))
    assert {entry.path for entry in tree.entries} == {
        "plain.bin",
        "exefs.bin",
        "romfs.bin",
    }


def test_bad_magic_is_structural_red(tmp_path):
    data = bytearray(_make_ncch())
    data[0x100:0x104] = b"NOPE"
    with pytest.raises(ValueError, match="not a 3DS NCCH image"):
        normalize_3ds_ncch(_write_ncch(tmp_path, data))


def test_declared_content_size_mismatch_is_structural_red(tmp_path):
    data = bytearray(_make_ncch())
    struct.pack_into("<I", data, 0x104, len(data) // 0x200 + 1)
    with pytest.raises(ValueError, match="declared NCCH content size"):
        normalize_3ds_ncch(_write_ncch(tmp_path, data))


def test_prototype_format_is_structural_red(tmp_path):
    data = bytearray(_make_ncch())
    struct.pack_into("<H", data, 0x112, 1)
    with pytest.raises(ValueError, match="prototype format version 1"):
        normalize_3ds_ncch(_write_ncch(tmp_path, data))


def test_seeded_crypto_is_structural_red(tmp_path):
    data = bytearray(_make_ncch())
    data[0x18F] = 0x24
    with pytest.raises(ValueError, match="seed-encrypted NCCH"):
        normalize_3ds_ncch(_write_ncch(tmp_path, data))


def test_encrypted_ncch_is_structural_red(tmp_path):
    data = bytearray(_make_ncch())
    data[0x18F] = 0
    with pytest.raises(ValueError, match="encrypted NCCH"):
        normalize_3ds_ncch(_write_ncch(tmp_path, data))


def test_invalid_extended_header_size_is_structural_red(tmp_path):
    data = bytearray(_make_ncch())
    struct.pack_into("<I", data, 0x180, 0x200)
    with pytest.raises(ValueError, match="invalid extended-header size"):
        normalize_3ds_ncch(_write_ncch(tmp_path, data))


def test_half_empty_region_is_structural_red(tmp_path):
    data = bytearray(_make_ncch())
    struct.pack_into("<II", data, 0x190, 0, 1)
    with pytest.raises(ValueError, match="half-empty plain region"):
        normalize_3ds_ncch(_write_ncch(tmp_path, data))


def test_absent_region_cannot_have_protected_blocks(tmp_path):
    data = bytearray(_make_ncch())
    struct.pack_into("<III", data, 0x1A0, 0, 0, 1)
    with pytest.raises(ValueError, match="absent ExeFS has protected blocks"):
        normalize_3ds_ncch(_write_ncch(tmp_path, data))


def test_protected_hash_span_cannot_exceed_region(tmp_path):
    data = bytearray(_make_ncch())
    struct.pack_into("<I", data, 0x1A8, 3)
    with pytest.raises(ValueError, match="ExeFS protected hash span"):
        normalize_3ds_ncch(_write_ncch(tmp_path, data))


def test_overlapping_regions_are_structural_red(tmp_path):
    data = bytearray(_make_ncch())
    struct.pack_into("<II", data, 0x198, 5, 1)
    with pytest.raises(ValueError, match="logo region overlaps plain region"):
        normalize_3ds_ncch(_write_ncch(tmp_path, data))


def test_region_out_of_bounds_is_structural_red(tmp_path):
    data = bytearray(_make_ncch())
    struct.pack_into("<III", data, 0x1B0, 10, 3, 1)
    with pytest.raises(ValueError, match="RomFS range .* exceeds NCCH size"):
        normalize_3ds_ncch(_write_ncch(tmp_path, data))


@pytest.mark.parametrize(
    ("offset", "reason"),
    [
        (0x200, "extended-header hash mismatch"),
        (0xC00, "logo hash mismatch"),
        (0xE00, "ExeFS protected hash mismatch"),
        (0x1200, "RomFS protected hash mismatch"),
    ],
)
def test_declared_hash_mismatch_is_structural_red(tmp_path, offset, reason):
    data = bytearray(_make_ncch())
    data[offset] ^= 0xFF
    with pytest.raises(ValueError, match=reason):
        normalize_3ds_ncch(_write_ncch(tmp_path, data))


def test_cubic_ninja_metadata_manifest_is_valid():
    schema = json.loads((ROOT / "schema" / "manifest.schema.json").read_text("utf-8"))
    doc = json.loads((FIXTURE / "expected.manifest.json").read_text("ascii"))
    jsonschema.Draft202012Validator(schema).validate(doc)
    assert doc["format"] == "3ds-ncch"
    assert doc["source"] == {
        "name": "partition0.cxi",
        "sha256": NCCH_SHA256,
        "size": NCCH_SIZE,
    }
    assert doc["tool_versions"] == TOOLS
    assert doc["entries"] == [
        {
            "kind": "file",
            "offset": 3_072,
            "path": "exefs.bin",
            "size": 1_452_032,
        },
        {
            "kind": "file",
            "offset": 512,
            "path": "extendedheader.bin",
            "size": 2_048,
        },
        {
            "kind": "file",
            "offset": 2_560,
            "path": "plain.bin",
            "size": 512,
        },
        {
            "kind": "file",
            "offset": 1_455_104,
            "path": "romfs.bin",
            "size": 84_975_616,
        },
    ]


@skip_if_no_ncch_anchor
def test_cubic_ninja_ncch_anchor_is_green():
    assert run_checks(
        normalize_3ds_ncch,
        NCCH,
        FIXTURE / "expected.manifest.json",
        REFERENCE,
        NCCH.name,
        NCCH_SHA256,
        TOOLS,
    ) == []


@skip_if_no_ncch_anchor
def test_cubic_ninja_ncch_fixity_and_region_identity():
    assert NCCH.stat().st_size == NCCH_SIZE
    assert sha256_of(NCCH) == NCCH_SHA256
    tree = normalize_3ds_ncch(NCCH)
    assert [entry.path for entry in tree.entries] == [
        "extendedheader.bin",
        "plain.bin",
        "exefs.bin",
        "romfs.bin",
    ]
    assert tree.entries[-1].offset + tree.entries[-1].size == NCCH_SIZE


@skip_if_no_ncch_anchor
def test_wrong_slice_mutant_dies_at_manifest_or_fidelity():
    def normalize_mutant(source):
        tree = normalize_3ds_ncch(source)
        entries = list(tree.entries)
        exefs = next(entry for entry in entries if entry.path == "exefs.bin")
        index = entries.index(exefs)
        entries[index] = FileEntry(
            exefs.path, exefs.kind, exefs.offset + 1, exefs.size
        )
        return FileTree(tree.source, tree.format, tuple(entries))

    problems = run_checks(
        normalize_mutant,
        NCCH,
        FIXTURE / "expected.manifest.json",
        REFERENCE,
        NCCH.name,
        NCCH_SHA256,
        TOOLS,
    )
    assert any(
        problem.startswith(("manifest:", "fidelity:")) for problem in problems
    )
