"""Gate tests for the one-layer 3DS CCI/NCSD normalizer.

The runtime exposes the NCCH partitions as opaque slices.  It deliberately
does not parse NCCH regions, ExeFS, or RomFS: those are later caller-visible
normalization layers.
"""

from __future__ import annotations

import json
import struct
from pathlib import Path

import jsonschema
import pytest

from substratum import normalize
from substratum.contract import FileEntry, FileSource, FileTree, sha256_of
from substratum.formats.three_ds_cci import normalize_3ds_cci, sniff
from substratum.verify import run_checks

ROOT = Path(__file__).resolve().parent.parent
RETAIL_FIXTURE = ROOT / "fixtures" / "3ds_cci" / "cubic-ninja"
RETAIL_CCI = ROOT / "fixtures" / "_local" / "Cubic Ninja (Japan).3ds"
RETAIL_REFERENCE = RETAIL_FIXTURE / "reference"

RETAIL_SIZE = 134_217_728
RETAIL_SHA256 = (
    "929a675e4dedd315fd6ef5565e6d97b3fd7cd281171c14f2fa0a5163b7096b42"
)
RETAIL_TOOLS = {
    "3dstool": "3dstool 1.2.6 by dnasdw",
    "ctrtool": "CTRTool v1.3.0 (C) jakcron",
    "generator": "stage_3ds_cci_retail_anchor v1",
}

skip_if_no_retail_anchor = pytest.mark.skipif(
    not RETAIL_CCI.exists() or not RETAIL_REFERENCE.exists(),
    reason="Cubic Ninja retail CCI or gitignored partition references absent",
)


def _make_cci(
    partitions: tuple[tuple[int, int, int], ...] = (
        (0, 2, 0x0004000000000001),
        (7, 4, 0x8000000000000002),
    ),
) -> bytes:
    """Build a minimal structural CCI.

    Partition tuples are ``(slot, offset_media_units, partition_id)``.
    Every synthetic partition is two 0x200-byte media units.
    """
    media_units = max(offset + 2 for _, offset, _ in partitions)
    image = bytearray(media_units * 0x200)
    image[0x100:0x104] = b"NCSD"
    struct.pack_into("<I", image, 0x104, media_units)
    for slot, offset_units, partition_id in partitions:
        struct.pack_into("<II", image, 0x120 + slot * 8, offset_units, 2)
        struct.pack_into("<Q", image, 0x190 + slot * 8, partition_id)
        partition_at = offset_units * 0x200
        image[partition_at + 0x100 : partition_at + 0x104] = b"NCCH"
        struct.pack_into("<I", image, partition_at + 0x104, 2)
        struct.pack_into("<Q", image, partition_at + 0x108, partition_id)
        image[partition_at + 0x200 : partition_at + 0x400] = bytes([slot + 1]) * 0x200
    return bytes(image)


def _write_cci(tmp_path: Path, data: bytes | bytearray) -> Path:
    path = tmp_path / "game.3ds"
    path.write_bytes(data)
    return path


def test_minimal_cci_returns_opaque_partition_slices(tmp_path):
    cci = _write_cci(tmp_path, _make_cci())
    tree = normalize_3ds_cci(cci)

    assert isinstance(tree, FileTree)
    assert tree.format == "3ds-cci"
    assert tree.entries == (
        FileEntry("partition0.cxi", "file", 0x400, 0x400),
        FileEntry("partition7.cfa", "file", 0x800, 0x400),
    )
    assert tree.read(tree.entries[0])[0x100:0x104] == b"NCCH"
    assert tree.read(tree.entries[1])[0x200:] == b"\x08" * 0x200


def test_sniff_and_public_dispatch(tmp_path):
    cci = _write_cci(tmp_path, _make_cci())
    source = FileSource(cci)
    assert sniff(source)
    assert not sniff(FileSource(ROOT / "fixtures" / "toy" / "toy.bin"))

    auto = normalize(cci)
    pinned = normalize(source, format="3ds-cci")
    assert isinstance(auto, FileTree) and auto.format == "3ds-cci"
    assert pinned.entries == auto.entries


def test_bad_ncsd_magic_is_structural_red(tmp_path):
    data = bytearray(_make_cci())
    data[0x100:0x104] = b"NOPE"
    with pytest.raises(ValueError, match="not a 3DS CCI/NCSD image"):
        normalize_3ds_cci(_write_cci(tmp_path, data))


def test_declared_media_size_mismatch_is_structural_red(tmp_path):
    data = bytearray(_make_cci())
    struct.pack_into("<I", data, 0x104, len(data) // 0x200 + 1)
    with pytest.raises(ValueError, match="declared media size"):
        normalize_3ds_cci(_write_cci(tmp_path, data))


@pytest.mark.parametrize(("offset_units", "size_units"), [(2, 0), (0, 2)])
def test_half_empty_partition_entry_is_structural_red(
    tmp_path, offset_units, size_units
):
    data = bytearray(_make_cci())
    struct.pack_into("<II", data, 0x120, offset_units, size_units)
    with pytest.raises(ValueError, match="half-empty partition entry"):
        normalize_3ds_cci(_write_cci(tmp_path, data))


def test_image_without_partitions_is_structural_red(tmp_path):
    data = bytearray(_make_cci())
    data[0x120:0x160] = b"\x00" * 0x40
    data[0x190:0x1D0] = b"\x00" * 0x40
    with pytest.raises(ValueError, match="contains no partitions"):
        normalize_3ds_cci(_write_cci(tmp_path, data))


def test_overlapping_partitions_are_structural_red(tmp_path):
    data = bytearray(_make_cci())
    struct.pack_into("<II", data, 0x120 + 7 * 8, 3, 2)
    with pytest.raises(ValueError, match="overlaps partition"):
        normalize_3ds_cci(_write_cci(tmp_path, data))


def test_out_of_bounds_partition_is_structural_red(tmp_path):
    data = bytearray(_make_cci())
    struct.pack_into("<II", data, 0x120 + 7 * 8, len(data) // 0x200, 2)
    with pytest.raises(ValueError, match="exceeds CCI size"):
        normalize_3ds_cci(_write_cci(tmp_path, data))


def test_bad_ncch_magic_is_structural_red(tmp_path):
    data = bytearray(_make_cci())
    data[0x800 + 0x100 : 0x800 + 0x104] = b"NOPE"
    with pytest.raises(ValueError, match="partition 7 lacks NCCH magic"):
        normalize_3ds_cci(_write_cci(tmp_path, data))


def test_ncch_declared_size_mismatch_is_structural_red(tmp_path):
    data = bytearray(_make_cci())
    struct.pack_into("<I", data, 0x400 + 0x104, 3)
    with pytest.raises(ValueError, match="partition 0 NCCH size"):
        normalize_3ds_cci(_write_cci(tmp_path, data))


def test_duplicate_partition_ids_are_structural_red(tmp_path):
    data = bytearray(_make_cci())
    first_id = struct.unpack_from("<Q", data, 0x190)[0]
    struct.pack_into("<Q", data, 0x190 + 7 * 8, first_id)
    struct.pack_into("<Q", data, 0x800 + 0x108, first_id)
    with pytest.raises(ValueError, match="duplicates partition ID"):
        normalize_3ds_cci(_write_cci(tmp_path, data))


def test_partition_id_must_match_ncch_title_id(tmp_path):
    data = bytearray(_make_cci())
    struct.pack_into("<Q", data, 0x800 + 0x108, 0x8000000000000099)
    with pytest.raises(ValueError, match="NCSD ID does not match NCCH title ID"):
        normalize_3ds_cci(_write_cci(tmp_path, data))


def test_empty_slot_cannot_carry_partition_id(tmp_path):
    data = bytearray(_make_cci())
    struct.pack_into("<Q", data, 0x190 + 1 * 8, 0x1234)
    with pytest.raises(ValueError, match="empty partition slot 1 has nonzero ID"):
        normalize_3ds_cci(_write_cci(tmp_path, data))


def test_cubic_ninja_metadata_manifest_is_valid():
    schema = json.loads((ROOT / "schema" / "manifest.schema.json").read_text("utf-8"))
    doc = json.loads(
        (RETAIL_FIXTURE / "expected.manifest.json").read_text("ascii")
    )
    jsonschema.Draft202012Validator(schema).validate(doc)
    assert doc["format"] == "3ds-cci"
    assert doc["source"] == {
        "name": "Cubic Ninja (Japan).3ds",
        "sha256": RETAIL_SHA256,
        "size": RETAIL_SIZE,
    }
    assert doc["tool_versions"] == RETAIL_TOOLS
    assert doc["entries"] == [
        {
            "kind": "file",
            "offset": 16_384,
            "path": "partition0.cxi",
            "size": 86_430_720,
        },
        {
            "kind": "file",
            "offset": 86_447_104,
            "path": "partition7.cfa",
            "size": 5_116_416,
        },
    ]


@skip_if_no_retail_anchor
def test_cubic_ninja_retail_anchor_is_green():
    assert run_checks(
        normalize_3ds_cci,
        RETAIL_CCI,
        RETAIL_FIXTURE / "expected.manifest.json",
        RETAIL_REFERENCE,
        RETAIL_CCI.name,
        RETAIL_SHA256,
        RETAIL_TOOLS,
    ) == []


@skip_if_no_retail_anchor
def test_cubic_ninja_fixity_and_partition_identity():
    assert RETAIL_CCI.stat().st_size == RETAIL_SIZE
    assert sha256_of(RETAIL_CCI) == RETAIL_SHA256
    tree = normalize_3ds_cci(RETAIL_CCI)
    assert tree.entries[0].offset + tree.entries[0].size == tree.entries[1].offset
    assert tree.read(tree.entries[0])[0x100:0x104] == b"NCCH"
    assert tree.read(tree.entries[1])[0x100:0x104] == b"NCCH"


@skip_if_no_retail_anchor
def test_wrong_slice_mutant_dies_at_manifest_or_fidelity():
    def normalize_mutant(source):
        tree = normalize_3ds_cci(source)
        entries = list(tree.entries)
        first = entries[0]
        entries[0] = FileEntry(
            first.path, first.kind, first.offset + 1, first.size
        )
        return FileTree(tree.source, tree.format, tuple(entries))

    problems = run_checks(
        normalize_mutant,
        RETAIL_CCI,
        RETAIL_FIXTURE / "expected.manifest.json",
        RETAIL_REFERENCE,
        RETAIL_CCI.name,
        RETAIL_SHA256,
        RETAIL_TOOLS,
    )
    assert any(
        problem.startswith(("manifest:", "fidelity:")) for problem in problems
    )
