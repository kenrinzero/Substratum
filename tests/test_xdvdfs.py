"""Gate tests for the Xbox XDVDFS filesystem normalizer (NORMALIZERS.md row `xdvdfs`).

The expected manifest was authored by seedtools/make_xdvdfs_fixture.py.
Since the design spec recommends D1 = structural self-consistency, the
fixture uses a synthetic tier-1 image and no external differential tooling.
"""

from __future__ import annotations

import json
import struct
from pathlib import Path

import jsonschema
import pytest

from substratum.contract import FileEntry, FileSource, FileTree, sha256_of
from substratum.formats.xdvdfs import normalize_xdvdfs, sniff
from substratum.verify import run_checks

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "fixtures" / "xdvdfs" / "synthetic"
IMAGE = FIXTURE / "game.xiso"
REFERENCE = FIXTURE / "reference"

TOOLS = {
    "self-consistency": "structural-proof",
    "generator": "make_xdvdfs_fixture v1",
}


def _checks(normalize_fn=normalize_xdvdfs, fixture=IMAGE):
    return run_checks(
        normalize_fn,
        fixture,
        FIXTURE / "expected.manifest.json",
        REFERENCE,
        IMAGE.name,
        sha256_of(IMAGE),
        TOOLS,
    )


def test_xdvdfs_is_green():
    """The full four-check gate passes on the synthetic XDVDFS fixture."""
    assert _checks() == []


def test_sniff():
    """Verify sniff detects XDVDFS images by the descriptor magic."""
    assert sniff(FileSource(IMAGE))
    assert not sniff(FileSource(ROOT / "fixtures" / "toy" / "toy.bin"))


def test_returns_filetree():
    """Verify normalize returns a FileTree with the expected format."""
    tree = normalize_xdvdfs(IMAGE)
    assert isinstance(tree, FileTree)
    assert tree.format == "xdvdfs"


def test_decoded_files_byte_equal_reference():
    """Verify files read through the FileTree equal the reference bytes."""
    tree = normalize_xdvdfs(IMAGE)
    entry = next(e for e in tree.entries if e.path == "BOOT/APP.BIN")
    assert tree.read(entry) == (REFERENCE / "BOOT/APP.BIN").read_bytes()


def test_composed_tree_matches_expected():
    """Verify the parsed tree structure matches the expected manifest."""
    tree = normalize_xdvdfs(IMAGE)
    expected = json.loads((FIXTURE / "expected.manifest.json").read_text("ascii"))
    got_paths = sorted(e.path for e in tree.entries)
    want_paths = sorted(e["path"] for e in expected["entries"])
    assert got_paths == want_paths


def test_fixture_exercises_valid_left_and_right_lcrs_branches():
    """The root node must make both pointer branches load-bearing on green."""
    with IMAGE.open("rb") as fh:
        fh.seek(0x22 * 0x800)
        table = fh.read(0x800)

    left_dwords, right_dwords = struct.unpack_from("<HH", table, 0)
    assert left_dwords != 0
    assert right_dwords != 0

    def name_at(dword_offset: int) -> str:
        offset = dword_offset * 4
        length = table[offset + 0x0D]
        return table[offset + 0x0E : offset + 0x0E + length].decode("ascii")

    assert name_at(0) == "DATA"
    assert name_at(left_dwords) == "BOOT"
    assert name_at(right_dwords) == "README.TXT"

    top_level = [
        entry.path
        for entry in normalize_xdvdfs(IMAGE).entries
        if "/" not in entry.path
    ]
    assert top_level == ["BOOT", "DATA", "README.TXT"]


def test_expected_manifest_validates_against_schema():
    schema = json.loads((ROOT / "schema" / "manifest.schema.json").read_text("utf-8"))
    doc = json.loads((FIXTURE / "expected.manifest.json").read_text("ascii"))
    jsonschema.Draft202012Validator(schema).validate(doc)
    assert doc["format"] == "xdvdfs"
    assert doc["source"]["name"] == "game.xiso"
    assert doc["source"]["size"] == IMAGE.stat().st_size


# --- structural reds ------------------------------------------------------


def test_corrupted_magic_is_structural_red(tmp_path):
    bad = tmp_path / "bad.xiso"
    data = bytearray(IMAGE.read_bytes())
    data[0x10000] ^= 0xFF
    bad.write_bytes(bytes(data))
    problems = _checks(normalize_xdvdfs, fixture=bad)
    assert problems and problems[0].startswith("structural:")


def test_corrupted_magic_tail_refused(tmp_path):
    bad = tmp_path / "bad-tail.xiso"
    data = bytearray(IMAGE.read_bytes())
    data[0x10000 + 0x7EC] ^= 0xFF
    bad.write_bytes(bytes(data))
    with pytest.raises(ValueError, match="tail"):
        normalize_xdvdfs(bad)


def test_bad_root_table_refused(tmp_path):
    bad = tmp_path / "bad-root.xiso"
    data = bytearray(IMAGE.read_bytes())
    data[0x10000 + 0x14 : 0x10000 + 0x18] = b"\x00" * 4
    bad.write_bytes(bytes(data))
    with pytest.raises(ValueError, match="size"):
        normalize_xdvdfs(bad)


def test_file_out_of_bounds_refused(tmp_path):
    bad = tmp_path / "bad-file.xiso"
    data = bytearray(IMAGE.read_bytes())
    table_offset = 0x22 * 0x800
    table = data[table_offset : table_offset + 0x800]
    for entry_offset in range(0, len(table) - 14, 0x10):
        if entry_offset + 0x0E > len(table):
            break
        name_len = table[entry_offset + 0x0D]
        name = table[entry_offset + 0x0E : entry_offset + 0x0E + name_len].decode("ascii", "ignore")
        if name == "README.TXT":
            struct.pack_into("<I", data, table_offset + entry_offset + 8, 0xFFFF_FFFF)
            break
    else:
        pytest.fail("README.TXT entry not found")
    bad.write_bytes(bytes(data))
    with pytest.raises(ValueError, match="exceeds source size"):
        normalize_xdvdfs(bad)


def test_truncated_refused(tmp_path):
    bad = tmp_path / "bad-truncated.xiso"
    data = IMAGE.read_bytes()[:-0x800]
    bad.write_bytes(data)
    with pytest.raises(ValueError, match="descriptor"):
        normalize_xdvdfs(bad)


def test_bad_l_offset_refused(tmp_path):
    bad = tmp_path / "bad-l-offset.xiso"
    data = bytearray(IMAGE.read_bytes())
    table_offset = 0x22 * 0x800
    table = data[table_offset : table_offset + 0x800]
    for entry_offset in range(0, len(table) - 14, 0x10):
        if entry_offset + 0x0E > len(table):
            break
        name_len = table[entry_offset + 0x0D]
        name = table[entry_offset + 0x0E : entry_offset + 0x0E + name_len].decode("ascii", "ignore")
        if name == "DATA":
            struct.pack_into("<H", data, table_offset + entry_offset, 0x1000)
            break
    else:
        pytest.fail("DATA entry not found")
    bad.write_bytes(bytes(data))
    with pytest.raises(ValueError, match="exceeds table size"):
        normalize_xdvdfs(bad)


def test_bad_filename_refused(tmp_path):
    bad = tmp_path / "bad-name.xiso"
    data = bytearray(IMAGE.read_bytes())
    table_offset = 0x22 * 0x800
    table = data[table_offset : table_offset + 0x800]
    for entry_offset in range(0, len(table) - 14, 0x10):
        if entry_offset + 0x0E > len(table):
            break
        name_len = table[entry_offset + 0x0D]
        name = table[entry_offset + 0x0E : entry_offset + 0x0E + name_len].decode("ascii", "ignore")
        if name == "README.TXT":
            invalid_name = b"bad/name!!"
            assert len(invalid_name) == len(name)
            data[table_offset + entry_offset + 0x0E : table_offset + entry_offset + 0x0E + len(name)] = invalid_name
            break
    else:
        pytest.fail("README.TXT entry not found")
    bad.write_bytes(bytes(data))
    with pytest.raises(ValueError, match="invalid"):
        normalize_xdvdfs(bad)


def test_nested_directory_cycle_refused(tmp_path):
    """A nested directory whose table points back at an ancestor's table is a
    cross-table cycle. Must raise a clean structural ValueError, not recurse
    until RecursionError (the gap surfaced in the 2026-07-25 verification).
    """
    bad = tmp_path / "bad-cycle.xiso"
    data = bytearray(IMAGE.read_bytes())
    # The DATA entry lives in the root table (sector 0x22). Repoint its
    # start_sector (u32 LE at entry+4) to the root table sector, so DATA's
    # nested table IS the root table -> infinite ancestor cycle.
    table_offset = 0x22 * 0x800
    table = data[table_offset : table_offset + 0x800]
    for entry_offset in range(0, len(table) - 14, 0x10):
        if entry_offset + 0x0E > len(table):
            break
        name_len = table[entry_offset + 0x0D]
        name = table[entry_offset + 0x0E : entry_offset + 0x0E + name_len].decode("ascii", "ignore")
        if name == "DATA":
            struct.pack_into("<I", data, table_offset + entry_offset + 4, 0x22)
            break
    else:
        pytest.fail("DATA entry not found")
    bad.write_bytes(bytes(data))
    with pytest.raises(ValueError, match="cycle"):
        normalize_xdvdfs(bad)


# --- red-team mutants ---------------------------------------------------


def test_wrong_endianness_dies():
    def normalize_mutant(source):
        src = source if isinstance(source, FileSource) else FileSource(source)
        src_size = src.size()
        desc = src.read_at(0x10000, 0x800)
        if desc[: len(b"MICROSOFT*XBOX*MEDIA")] != b"MICROSOFT*XBOX*MEDIA":
            raise ValueError("not an XDVDFS image")
        root_sector = struct.unpack_from(">I", desc, 0x14)[0]
        root_size = struct.unpack_from(">I", desc, 0x18)[0]
        if root_size == 0:
            raise ValueError("root size is zero")
        root_offset = root_sector * 0x800
        if root_offset + root_size > src_size:
            raise ValueError("root table exceeds image size")
        table = src.read_at(root_offset, root_size)
        entries: list[FileEntry] = []

        def _walk(table_bytes: bytes, entry_offset: int, prefix: str, visited: set[int]) -> None:
            if entry_offset in visited:
                raise ValueError("cycle")
            if entry_offset < 0 or entry_offset >= len(table_bytes):
                return
            if entry_offset + 2 > len(table_bytes):
                raise ValueError("entry truncated")
            l_offset = struct.unpack_from(">H", table_bytes, entry_offset)[0]
            if l_offset == 0xFFFF:
                return
            if l_offset != 0:
                child_offset = l_offset * 4
                if child_offset >= len(table_bytes):
                    raise ValueError("child offset exceeds table size")
                _walk(table_bytes, child_offset, prefix, visited)
            if entry_offset + 0x0E > len(table_bytes):
                raise ValueError("entry truncated")
            r_offset = struct.unpack_from(">H", table_bytes, entry_offset + 2)[0]
            start_sector = struct.unpack_from(">I", table_bytes, entry_offset + 4)[0]
            file_size = struct.unpack_from(">I", table_bytes, entry_offset + 8)[0]
            attrs = table_bytes[entry_offset + 0x0C]
            name_len = table_bytes[entry_offset + 0x0D]
            name = table_bytes[entry_offset + 0x0E : entry_offset + 0x0E + name_len].decode("ascii")
            path = f"{prefix}/{name}" if prefix else name
            visited.add(entry_offset)
            if attrs & 0x10:
                entries.append(FileEntry(path=path, kind="dir", offset=0, size=0))
            else:
                entries.append(FileEntry(path=path, kind="file", offset=start_sector * 0x800, size=file_size))
            if r_offset != 0:
                sibling_offset = r_offset * 4
                if sibling_offset >= len(table_bytes):
                    raise ValueError("right sibling offset exceeds table size")
                _walk(table_bytes, sibling_offset, prefix, visited)

        _walk(table, 0, "", set())
        return FileTree(source=src, format="xdvdfs", entries=tuple(entries))

    problems = _checks(normalize_mutant)
    assert problems
    assert any(p.startswith("structural:") or p.startswith("manifest:") or p.startswith("fidelity:") for p in problems)


def test_wrong_slice_slicer_dies():
    def normalize_mutant(source):
        tree = normalize_xdvdfs(source)
        mutated_entries = []
        for entry in tree.entries:
            if entry.kind == "file":
                mutated_entries.append(FileEntry(path=entry.path, kind=entry.kind, offset=entry.offset + 1, size=entry.size))
            else:
                mutated_entries.append(entry)
        return FileTree(source=tree.source, format=tree.format, entries=tuple(mutated_entries))

    problems = _checks(normalize_mutant)
    assert problems
    assert any(p.startswith("manifest:") or p.startswith("fidelity:") for p in problems)
