"""Gate tests for the 3DS RomFS normalizer (NORMALIZERS.md row `3ds-romfs`).

The synthetic fixture is hand-packed by seedtools/make_3ds_romfs_fixture.py
(real IVFC hash tree, real hash buckets, variable-length entries with
UTF-16LE names); its expected manifest is authored from the seedtool's own
layout (the xdvdfs pattern), so ctrtool carries the differential weight:
the synthetic-vs-ctrtool test compares the tree against ctrtool's own
extraction, and the retail test proves the unit on staged Cubic Ninja
media (540 files) through the full cci -> ncch -> romfs composition.
Tooling note: ctrtool v1.3.0's extractor fails on 0-byte members
(VirtualFileSystem openFile error), so the committed reference bytes for
EMPTY.BIN are staged empty while the rest come from a no-empty variant
extraction — normalize itself handles 0-byte members.
"""

from __future__ import annotations

import hashlib
import json
import struct
import subprocess
from pathlib import Path

import jsonschema
import pytest

from substratum.contract import FileEntry, FileSource, FileTree
from substratum.formats.three_ds_romfs import normalize_3ds_romfs, sniff
from substratum.verify import run_checks
from tests.assertions import assert_structural_failure

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "fixtures" / "3ds_romfs" / "synthetic"
REGION = FIXTURE / "game.romfs"
LEVEL3 = FIXTURE / "reference"

RETAIL_CCI = ROOT / "fixtures" / "_local" / "Cubic Ninja (Japan).3ds"
CTRTOOL = ROOT / "tools" / "ctrtool" / "ctrtool.exe"
CTRTOOL_TIMEOUT_SECONDS = 120

TOOLS = {
    "generator": "make_3ds_romfs_fixture v1",
    "differential": "ctrtool v1.3.0",
    "self-consistency": "structural-proof",
}

# seedtool layout facts (committed fixture is deterministic): the level-3
# data starts at 0x1000, its dir table at +0x38 (root@0, DATA@0x18,
# SUB@0x38) and file table at +0xB0 (README@0, A.BIN@0x34).
_DT = 0x1000 + 0x38
_FT = 0x1000 + 0xB0


def _blob(tag: bytes, size: int) -> bytes:
    out = bytearray()
    h = tag
    while len(out) < size:
        h = hashlib.sha256(h).digest()
        out += h
    return bytes(out[:size])


def _checks(normalize_fn=normalize_3ds_romfs, fixture=REGION):
    return run_checks(
        normalize_fn,
        fixture,
        FIXTURE / "expected.manifest.json",
        LEVEL3,
        REGION.name,
        hashlib.sha256(REGION.read_bytes()).hexdigest(),
        TOOLS,
    )


def test_3ds_romfs_is_green():
    """The full four-check gate passes on the synthetic fixture."""
    assert _checks() == []


def test_sniff():
    from substratum.contract import SliceSource
    assert sniff(FileSource(REGION))
    assert not sniff(FileSource(ROOT / "fixtures" / "toy" / "toy.bin"))
    assert not sniff(SliceSource(FileSource(REGION), 0, 0x40))


def test_returns_filetree():
    tree = normalize_3ds_romfs(REGION)
    assert isinstance(tree, FileTree)
    assert tree.format == "3ds-romfs"
    assert tree.source.size() == REGION.stat().st_size


def test_composed_tree_matches_expected():
    tree = normalize_3ds_romfs(REGION)
    expected = json.loads((FIXTURE / "expected.manifest.json").read_text("ascii"))
    got = sorted((e.path, e.kind, e.offset, e.size) for e in tree.entries)
    want = sorted((e["path"], e["kind"], e["offset"], e["size"]) for e in expected["entries"])
    assert got == want


def test_expected_manifest_validates_against_schema():
    schema = json.loads((ROOT / "schema" / "manifest.schema.json").read_text("utf-8"))
    doc = json.loads((FIXTURE / "expected.manifest.json").read_text("ascii"))
    jsonschema.Draft202012Validator(schema).validate(doc)
    assert doc["format"] == "3ds-romfs"
    assert doc["source"]["name"] == "game.romfs"


def test_zero_byte_member_walks_and_reads():
    tree = normalize_3ds_romfs(REGION)
    entry = next(e for e in tree.files() if e.path == "DATA/EMPTY.BIN")
    assert entry.size == 0
    assert tree.read(entry) == b""


def test_synthetic_tree_matches_ctrtool_extraction(tmp_path):
    """Two-party proof on the synthetic fixture itself: the tree equals
    ctrtool's own extraction of the level-3 slice."""
    if not CTRTOOL.exists():
        pytest.skip("vendored ctrtool absent")
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "make_3ds_romfs_fixture", ROOT / "seedtools" / "make_3ds_romfs_fixture.py"
    )
    mk = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mk)
    # ctrtool v1.3.0's extractor cannot materialize 0-byte members —
    # extract from a no-empty rebuild of the same fixture.
    mk.FILES = [f for f in mk.FILES if f[0] != "DATA/EMPTY.BIN"]
    _, level3, _ = mk.build_region()
    source = tmp_path / "level3.bin"
    source.write_bytes(level3)

    out = tmp_path / "x"
    out.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [str(CTRTOOL), "-t", "romfs", f"--romfsdir={out}", str(source)],
        check=True, capture_output=True, timeout=CTRTOOL_TIMEOUT_SECONDS,
    )
    oracle = {
        p.relative_to(out).as_posix(): p.stat().st_size
        for p in out.rglob("*") if p.is_file()
    }
    tree = normalize_3ds_romfs(REGION)
    mine = {e.path: e.size for e in tree.files()}
    assert mine.pop("DATA/EMPTY.BIN") == 0  # not extractable by ctrtool
    assert mine == oracle
    for rel in ("README.TXT", "DATA/A.BIN", "DATA/SUB/C.DAT"):
        entry = next(e for e in tree.files() if e.path == rel)
        assert tree.read(entry) == (out / rel).read_bytes()


@pytest.mark.skipif(not RETAIL_CCI.exists(), reason="retail Cubic Ninja drop not staged")
def test_retail_cubic_ninja_matches_ctrtool(tmp_path):
    """Full composition proof on real media: cci -> ncch -> romfs region,
    compared against ctrtool's listing/extraction (540 files)."""
    from substratum import normalize as dispatch
    from substratum.contract import SliceSource

    cci = dispatch(RETAIL_CCI)
    p0 = next(e for e in cci.files() if e.path == "partition0.cxi")
    ncch = dispatch(cci.open(p0))
    region_entry = next(e for e in ncch.files() if "romfs" in e.path)
    region = SliceSource(ncch.source, region_entry.offset, region_entry.size)

    tree = normalize_3ds_romfs(region)
    mine = {e.path: e.size for e in tree.files()}

    # exact level-3 slice for ctrtool: data at 0x1000, length = descriptor 3's size
    s_data = struct.unpack_from("<QQ", region.read_at(0, 0x5C), 0x3C)[1]
    level3 = tmp_path / "level3.bin"
    with level3.open("wb") as fh:
        pos = 0x1000
        while pos < 0x1000 + s_data:
            fh.write(region.read_at(pos, min(1 << 20, 0x1000 + s_data - pos)))
            pos += 1 << 20
    out = tmp_path / "x"
    out.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [str(CTRTOOL), "-t", "romfs", f"--romfsdir={out}", str(level3)],
        check=True, capture_output=True, timeout=CTRTOOL_TIMEOUT_SECONDS,
    )
    oracle = {
        p.relative_to(out).as_posix(): p.stat().st_size
        for p in out.rglob("*") if p.is_file()
    }
    assert mine == oracle
    for rel in ("Data/sysres/banner/homeicon.bnr", "shaders/shader.shbin"):
        entry = next(e for e in tree.files() if e.path == rel)
        assert tree.read(entry) == (out / rel).read_bytes()


# --- structural reds ------------------------------------------------------

def _rehash(data: bytearray) -> bytearray:
    """Recompute the IVFC hash tree over mutated level-3 bytes so a
    structural corruption survives the eager verification (an attacker
    fixing the hashes is the realistic threat model)."""
    head = bytes(data[:0x5C])
    _, s0, _, _ = struct.unpack_from("<QQII", head, 0x0C)
    _, s1, _, _ = struct.unpack_from("<QQII", head, 0x24)
    _, s_data, _, _ = struct.unpack_from("<QQII", head, 0x3C)
    block = 0x1000
    l0_off = (0x1000 + s_data + block - 1) & ~(block - 1)
    l1_off = (l0_off + s0 + block - 1) & ~(block - 1)

    def hash_blocks(blob: bytes) -> list[bytes]:
        if not blob:
            return [hashlib.sha256(b"\x00" * block).digest()]
        return [
            hashlib.sha256(blob[i : i + block] + b"\x00" * (block - len(blob[i : i + block]))).digest()
            for i in range(0, len(blob), block)
        ]

    l1 = b"".join(hash_blocks(bytes(data[0x1000 : 0x1000 + s_data])))
    l0 = b"".join(hash_blocks(l1))
    mht = b"".join(hash_blocks(l0))
    assert len(l1) == s1 and len(l0) == s0
    assert len(mht) == struct.unpack_from("<I", head, 8)[0]
    data[0x60 : 0x60 + len(mht)] = mht
    data[l0_off : l0_off + s0] = l0
    data[l1_off : l1_off + s1] = l1
    return data


def test_corrupted_ivfc_magic_is_structural_red(tmp_path):
    bad = tmp_path / "bad-magic.romfs"
    data = bytearray(REGION.read_bytes())
    data[0] ^= 0xFF
    bad.write_bytes(bytes(data))
    problems = _checks(fixture=bad)
    assert_structural_failure(problems, "magic")


def test_flipped_payload_byte_dies_at_hash_tree(tmp_path):
    """The gate that bites: enumeration stays perfect, one payload byte
    flips, and the eager level-1 hash verification refuses."""
    bad = tmp_path / "bad-payload.romfs"
    data = bytearray(REGION.read_bytes())
    payload = _blob(b"substratum-3dsromfs-a", 4096)
    at = bytes(data).find(payload)
    assert at > 0
    data[at + 100] ^= 0xFF
    bad.write_bytes(bytes(data))
    with pytest.raises(ValueError, match="level-1 hash mismatch"):
        normalize_3ds_romfs(bad)


def test_corrupted_level0_table_dies_at_master_hash(tmp_path):
    bad = tmp_path / "bad-l0.romfs"
    data = bytearray(REGION.read_bytes())
    head = REGION.read_bytes()[:0x5C]
    _, s0, _, _ = struct.unpack_from("<QQII", head, 0x0C)
    _, s1, _, _ = struct.unpack_from("<QQII", head, 0x24)
    _, s_data, _, _ = struct.unpack_from("<QQII", head, 0x3C)
    l0_off = (0x1000 + s_data + 0xFFF) & ~0xFFF
    data[l0_off + s0 - 1] ^= 0xFF  # last byte of the level-0 table
    bad.write_bytes(bytes(data))
    with pytest.raises(ValueError, match="master hash mismatch"):
        normalize_3ds_romfs(bad)


def test_truncated_refused(tmp_path):
    bad = tmp_path / "bad-trunc.romfs"
    bad.write_bytes(REGION.read_bytes()[:-0x200])
    with pytest.raises(ValueError, match="region end"):
        normalize_3ds_romfs(bad)


def test_wrong_header_size_field_refused(tmp_path):
    bad = tmp_path / "bad-hdr.romfs"
    data = bytearray(REGION.read_bytes())
    struct.pack_into("<I", data, 0x54, 0x50)
    bad.write_bytes(bytes(data))
    with pytest.raises(ValueError, match="header size"):
        normalize_3ds_romfs(bad)


def test_directory_sibling_cycle_refused(tmp_path):
    bad = tmp_path / "bad-dircycle.romfs"
    data = bytearray(REGION.read_bytes())
    # SUB's sibling field (dir table +0x38, field +4) -> SUB itself
    struct.pack_into("<I", data, _DT + 0x38 + 4, 0x38)
    bad.write_bytes(_rehash(data))
    with pytest.raises(ValueError, match="cyclic directory"):
        normalize_3ds_romfs(bad)


def test_file_sibling_cycle_refused(tmp_path):
    bad = tmp_path / "bad-filecycle.romfs"
    data = bytearray(REGION.read_bytes())
    # README.TXT's sibling field (file table +0, field +4) -> itself
    struct.pack_into("<I", data, _FT + 4, 0)
    bad.write_bytes(_rehash(data))
    with pytest.raises(ValueError, match="cyclic file"):
        normalize_3ds_romfs(bad)


def test_dotdot_name_refused(tmp_path):
    bad = tmp_path / "bad-name.romfs"
    data = bytearray(REGION.read_bytes())
    # A.BIN's file entry (file table +0x34): name length -> 4, name -> ".."
    struct.pack_into("<I", data, _FT + 0x34 + 0x1C, 4)
    data[_FT + 0x34 + 0x20 : _FT + 0x34 + 0x24] = b"\x2e\x00\x2e\x00"
    bad.write_bytes(_rehash(data))
    with pytest.raises(ValueError, match="path component"):
        normalize_3ds_romfs(bad)


# --- red-team mutants ---------------------------------------------------


def test_wrong_slice_slicer_dies():
    def normalize_mutant(source):
        tree = normalize_3ds_romfs(source)
        mutated = [
            FileEntry(path=e.path, kind=e.kind, offset=e.offset + 1, size=e.size)
            if e.kind == "file" and e.size > 0 else e
            for e in tree.entries
        ]
        return FileTree(source=tree.source, format=tree.format, entries=tuple(mutated))

    problems = _checks(normalize_mutant)
    assert problems
    assert any(p.startswith(("structural:", "manifest:", "fidelity:")) for p in problems)


def test_data_offset_mutant_dies():
    def normalize_mutant(source):
        tree = normalize_3ds_romfs(source)
        mutated = [
            FileEntry(path=e.path, kind=e.kind, offset=e.offset + 16, size=e.size)
            if e.kind == "file" and e.size > 0 else e
            for e in tree.entries
        ]
        return FileTree(source=tree.source, format=tree.format, entries=tuple(mutated))

    problems = _checks(normalize_mutant)
    assert problems
    assert any(p.startswith(("manifest:", "fidelity:")) for p in problems)
