"""Gate tests for the unkeyed Wii encrypted-partition-table normalizer."""

from __future__ import annotations

import json
import struct
from pathlib import Path

import jsonschema
import pytest

from substratum import normalize
from substratum.contract import FileEntry, FileSource, FileTree, sha256_of
from substratum.formats.wii_disc import normalize_wii_disc, sniff
from substratum.verify import run_checks

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "fixtures" / "wii_disc" / "munchables"
ISO = ROOT / "fixtures" / "_local" / "The Munchables (USA).iso"
REFERENCE = FIXTURE / "reference"

ISO_SIZE = 4_699_979_776
ISO_SHA256 = (
    "64c012f35d0c8b97e34c13e47060550b36d89fc36bed2691661cfdf108671cbb"
)
TOOLS = {
    "generator": "stage_wii_disc_retail_anchor v1",
    "wit": (
        "Wiimms ISO Tool v3.05a r8638 cygwin64 - Dirk Clemens - 2022-08-27"
    ),
}

skip_if_no_wii_anchor = pytest.mark.skipif(
    not ISO.exists() or not REFERENCE.exists(),
    reason="The Munchables ISO or gitignored partition references absent",
)


def _set_partition_header(image: bytearray, base: int) -> None:
    struct.pack_into(">I", image, base + 0x2A4, 0x208)
    struct.pack_into(">I", image, base + 0x2A8, 0x2C0 // 4)
    struct.pack_into(">I", image, base + 0x2AC, 0xA00)
    struct.pack_into(">I", image, base + 0x2B0, 0x4E0 // 4)
    struct.pack_into(">I", image, base + 0x2B4, 0x8000 // 4)
    struct.pack_into(">I", image, base + 0x2B8, 0x20000 // 4)
    struct.pack_into(">I", image, base + 0x2BC, 0x8000 // 4)


def _make_wii_disc() -> bytes:
    image = bytearray(0xB0000)
    image[0:6] = b"TEST01"
    struct.pack_into(">I", image, 0x18, 0x5D1C9EA3)
    struct.pack_into(">II", image, 0x40000, 2, 0x40020 // 4)

    update_base = 0x50000
    data_base = 0x80000
    struct.pack_into(">II", image, 0x40020, update_base // 4, 1)
    struct.pack_into(">II", image, 0x40028, data_base // 4, 0)
    image[update_base : update_base + 0x28000] = b"U" * 0x28000
    image[data_base : data_base + 0x28000] = b"D" * 0x28000
    _set_partition_header(image, update_base)
    _set_partition_header(image, data_base)
    return bytes(image)


def _write_disc(tmp_path: Path, data: bytes | bytearray) -> Path:
    path = tmp_path / "game.iso"
    path.write_bytes(data)
    return path


def test_minimal_wii_disc_returns_opaque_partition_slices(tmp_path):
    disc = _write_disc(tmp_path, _make_wii_disc())
    tree = normalize_wii_disc(disc)

    assert isinstance(tree, FileTree)
    assert tree.format == "wii-disc"
    assert tree.entries == (
        FileEntry("partition-update.bin", "file", 0x50000, 0x28000),
        FileEntry("partition-data.bin", "file", 0x80000, 0x28000),
    )
    source = disc.read_bytes()
    assert tree.read(tree.entries[0]) == source[0x50000:0x78000]
    assert tree.read(tree.entries[1]) == source[0x80000:0xA8000]


def test_sniff_and_public_dispatch(tmp_path):
    disc = _write_disc(tmp_path, _make_wii_disc())
    source = FileSource(disc)
    assert sniff(source)
    assert not sniff(FileSource(ROOT / "fixtures" / "toy" / "toy.bin"))

    auto = normalize(disc)
    pinned = normalize(source, format="wii-disc")
    assert auto.format == "wii-disc"
    assert pinned.entries == auto.entries


def test_bad_magic_is_structural_red(tmp_path):
    data = bytearray(_make_wii_disc())
    data[0x18:0x1C] = b"NOPE"
    with pytest.raises(ValueError, match="missing Wii disc magic"):
        normalize_wii_disc(_write_disc(tmp_path, data))


def test_empty_partition_directory_is_structural_red(tmp_path):
    data = bytearray(_make_wii_disc())
    data[0x40000:0x40020] = b"\0" * 0x20
    with pytest.raises(ValueError, match="no Wii partitions"):
        normalize_wii_disc(_write_disc(tmp_path, data))


@pytest.mark.parametrize(
    ("count", "offset"),
    [(1, 0), (0, 0x40020 // 4)],
)
def test_half_empty_partition_group_is_structural_red(
    tmp_path, count, offset
):
    data = bytearray(_make_wii_disc())
    struct.pack_into(">II", data, 0x40000, count, offset)
    with pytest.raises(ValueError, match="half-empty partition group 0"):
        normalize_wii_disc(_write_disc(tmp_path, data))


def test_partition_table_cannot_overlap_address_table(tmp_path):
    data = bytearray(_make_wii_disc())
    struct.pack_into(">I", data, 0x40004, 0x40000 // 4)
    with pytest.raises(ValueError, match="partition table 0 overlaps"):
        normalize_wii_disc(_write_disc(tmp_path, data))


def test_partition_tables_cannot_overlap_each_other(tmp_path):
    data = bytearray(_make_wii_disc())
    struct.pack_into(">II", data, 0x40008, 1, 0x40024 // 4)
    with pytest.raises(ValueError, match="partition tables overlap"):
        normalize_wii_disc(_write_disc(tmp_path, data))


def test_unknown_partition_type_is_structural_red(tmp_path):
    data = bytearray(_make_wii_disc())
    struct.pack_into(">I", data, 0x40024, 99)
    with pytest.raises(ValueError, match="unknown Wii partition type 99"):
        normalize_wii_disc(_write_disc(tmp_path, data))


def test_known_channel_partition_type_is_supported(tmp_path):
    data = bytearray(_make_wii_disc())
    struct.pack_into(">I", data, 0x40024, 2)
    tree = normalize_wii_disc(_write_disc(tmp_path, data))
    assert tree.entries[0].path == "partition-channel.bin"


def test_partition_count_is_bounded_before_table_materialization(tmp_path):
    data = bytearray(_make_wii_disc())
    struct.pack_into(">I", data, 0x40000, 4)
    with pytest.raises(ValueError, match="maximum supported is 3"):
        normalize_wii_disc(_write_disc(tmp_path, data))


def test_duplicate_partition_type_is_structural_red(tmp_path):
    data = bytearray(_make_wii_disc())
    struct.pack_into(">I", data, 0x4002C, 1)
    with pytest.raises(ValueError, match="duplicate UPDATE partition"):
        normalize_wii_disc(_write_disc(tmp_path, data))


def test_zero_partition_offset_is_structural_red(tmp_path):
    data = bytearray(_make_wii_disc())
    struct.pack_into(">I", data, 0x40020, 0)
    with pytest.raises(ValueError, match="zero offset"):
        normalize_wii_disc(_write_disc(tmp_path, data))


def test_partition_header_out_of_bounds_is_structural_red(tmp_path):
    data = bytearray(_make_wii_disc())
    struct.pack_into(">I", data, 0x40020, (len(data) - 0x100) // 4)
    with pytest.raises(ValueError, match="partition header exceeds disc"):
        normalize_wii_disc(_write_disc(tmp_path, data))


def test_half_empty_partition_data_range_is_structural_red(tmp_path):
    data = bytearray(_make_wii_disc())
    struct.pack_into(">I", data, 0x50000 + 0x2B8, 0)
    with pytest.raises(ValueError, match="half-empty UPDATE data range"):
        normalize_wii_disc(_write_disc(tmp_path, data))


def test_partition_data_cannot_overlap_header(tmp_path):
    data = bytearray(_make_wii_disc())
    struct.pack_into(">I", data, 0x50000 + 0x2B8, 0x200 // 4)
    with pytest.raises(ValueError, match="UPDATE data region overlaps"):
        normalize_wii_disc(_write_disc(tmp_path, data))


def test_partition_range_out_of_bounds_is_structural_red(tmp_path):
    data = bytearray(_make_wii_disc())
    struct.pack_into(">I", data, 0x80000 + 0x2BC, 0x40000 // 4)
    with pytest.raises(ValueError, match="DATA partition range .* exceeds disc"):
        normalize_wii_disc(_write_disc(tmp_path, data))


def test_partition_ranges_cannot_overlap(tmp_path):
    data = bytearray(_make_wii_disc())
    data[0x70000:0x98000] = b"D" * 0x28000
    _set_partition_header(data, 0x70000)
    struct.pack_into(">I", data, 0x40028, 0x70000 // 4)
    with pytest.raises(ValueError, match="DATA partition overlaps UPDATE"):
        normalize_wii_disc(_write_disc(tmp_path, data))


def test_tmd_range_must_precede_encrypted_data(tmp_path):
    data = bytearray(_make_wii_disc())
    struct.pack_into(">I", data, 0x50000 + 0x2A4, 0x2000)
    struct.pack_into(">I", data, 0x50000 + 0x2A8, 0x1F000 // 4)
    with pytest.raises(ValueError, match="UPDATE TMD range"):
        normalize_wii_disc(_write_disc(tmp_path, data))


def test_partition_metadata_ranges_cannot_overlap(tmp_path):
    data = bytearray(_make_wii_disc())
    struct.pack_into(">I", data, 0x50000 + 0x2B0, 0x300 // 4)
    with pytest.raises(ValueError, match="UPDATE metadata ranges overlap"):
        normalize_wii_disc(_write_disc(tmp_path, data))


def test_munchables_metadata_manifest_is_valid():
    schema = json.loads((ROOT / "schema" / "manifest.schema.json").read_text("utf-8"))
    doc = json.loads((FIXTURE / "expected.manifest.json").read_text("ascii"))
    jsonschema.Draft202012Validator(schema).validate(doc)
    assert doc["format"] == "wii-disc"
    assert doc["source"] == {
        "name": "The Munchables (USA).iso",
        "sha256": ISO_SHA256,
        "size": ISO_SIZE,
    }
    assert doc["tool_versions"] == TOOLS
    assert doc["entries"] == [
        {
            "kind": "file",
            "offset": 260_046_848,
            "path": "partition-data.bin",
            "size": 4_424_728_576,
        },
        {
            "kind": "file",
            "offset": 327_680,
            "path": "partition-update.bin",
            "size": 187_334_656,
        },
    ]


@skip_if_no_wii_anchor
def test_munchables_wii_disc_anchor_is_green():
    assert run_checks(
        normalize_wii_disc,
        ISO,
        FIXTURE / "expected.manifest.json",
        REFERENCE,
        ISO.name,
        ISO_SHA256,
        TOOLS,
    ) == []


@skip_if_no_wii_anchor
def test_munchables_fixity_and_partition_identity():
    assert ISO.stat().st_size == ISO_SIZE
    assert sha256_of(ISO) == ISO_SHA256
    tree = normalize_wii_disc(ISO)
    assert tree.entries == (
        FileEntry("partition-update.bin", "file", 0x50000, 0xB2A8000),
        FileEntry("partition-data.bin", "file", 0xF800000, 0x107BC0000),
    )


@skip_if_no_wii_anchor
def test_wrong_slice_mutant_dies_at_manifest_or_fidelity():
    def normalize_mutant(source):
        tree = normalize_wii_disc(source)
        entries = list(tree.entries)
        data = next(entry for entry in entries if entry.path == "partition-data.bin")
        index = entries.index(data)
        entries[index] = FileEntry(
            data.path, data.kind, data.offset + 1, data.size - 1
        )
        return FileTree(tree.source, tree.format, tuple(entries))

    problems = run_checks(
        normalize_mutant,
        ISO,
        FIXTURE / "expected.manifest.json",
        REFERENCE,
        ISO.name,
        ISO_SHA256,
        TOOLS,
    )
    assert any(
        problem.startswith(("manifest:", "fidelity:")) for problem in problems
    )
