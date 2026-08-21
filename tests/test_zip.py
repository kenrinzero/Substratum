"""Gate tests for the ZIP archive normalizer (NORMALIZERS.md row `zip`).

The fixture is authored by seedtools/make_zip_fixture.py (hand-packed:
stored + deflate members, a data-descriptor member, a ZIP64 member, and
a ZIP64 EOCD chain). The expected manifest is authored by
seedtools/author_zip_manifest.py from 7-Zip's independent listing, and
the reference bytes are 7-Zip's own extraction — never tree.read output
(DESIGN §3 two-party rule). Per the house convention for spooled
containers, source.size/sha256 describe the decompression spool; the
expected sha below is computed from the 7-Zip reference bytes
concatenated in the documented spool order (ascending path).
"""

from __future__ import annotations

import hashlib
import json
import struct
import zlib
from pathlib import Path

import jsonschema
import pytest

from substratum.contract import FileEntry, FileSource, FileTree
from substratum.formats.zip import normalize_zip, sniff
from substratum.verify import run_checks
from tests.assertions import assert_structural_failure

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "fixtures" / "zip" / "synthetic"
ARCHIVE = FIXTURE / "game.zip"
REFERENCE = FIXTURE / "reference"

TOOLS = {
    "differential": "7-Zip 26.02 (x64) 2026-06-25",
    "generator": "make_zip_fixture v1",
    "self-consistency": "structural-proof",
}


def _spool_sha256() -> str:
    """sha256 of the 7-Zip reference bytes concatenated in spool order."""
    digest = hashlib.sha256()
    files = sorted(
        (f for f in REFERENCE.rglob("*") if f.is_file()),
        key=lambda f: f.relative_to(REFERENCE).as_posix(),
    )
    for extracted in files:
        with extracted.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                digest.update(chunk)
    return digest.hexdigest()


def _checks(normalize_fn=normalize_zip, fixture=ARCHIVE):
    return run_checks(
        normalize_fn,
        fixture,
        FIXTURE / "expected.manifest.json",
        REFERENCE,
        ARCHIVE.name,
        _spool_sha256(),
        TOOLS,
    )


def test_zip_is_green():
    """The full four-check gate passes on the synthetic ZIP fixture."""
    assert _checks() == []


def test_sniff():
    """ZIP detection via the EOCD chain; negatives stay negative."""
    assert sniff(FileSource(ARCHIVE))
    assert not sniff(FileSource(ROOT / "fixtures" / "toy" / "toy.bin"))
    assert not sniff(FileSource(
        ROOT / "fixtures" / "iso9660" / "supertux" / "supertux.iso"
    ))


def test_returns_filetree():
    tree = normalize_zip(ARCHIVE)
    try:
        assert isinstance(tree, FileTree)
        assert tree.format == "zip"
    finally:
        tree.source.close()


def test_spool_layout_is_path_sorted_not_cd_order():
    """The spool offsets follow ascending path order, NOT central-directory
    order — the load-bearing layout rule the manifest is authored against
    (the fixture's CD order is README first, BIG/Z64.BIN last)."""
    tree = normalize_zip(ARCHIVE)
    try:
        by_path = {e.path: e for e in tree.entries}
        assert by_path["BIG/Z64.BIN"].offset == 0
        assert by_path["README.TXT"].offset == 7936
        assert by_path["BOOT/APP.BIN"].offset == 1024
        # CD order: DATA/, README.TXT, BOOT/APP.BIN, ..., BIG/Z64.BIN
        assert [e.path for e in tree.entries][0] == "DATA"
        assert [e.path for e in tree.entries][1] == "README.TXT"
        assert [e.path for e in tree.entries][-1] == "BIG/Z64.BIN"
        assert tree.source.size() == 8013
    finally:
        tree.source.close()


def test_descriptor_and_zip64_members_decode_byte_equal_reference():
    """The streaming (data-descriptor) and ZIP64 members are exactly the
    7-Zip-extracted bytes."""
    tree = normalize_zip(ARCHIVE)
    try:
        for rel in ("DATA/SUB/C.DAT", "BIG/Z64.BIN", "BOOT/APP.BIN",
                    "DATA/EMPTY.BIN", "README.TXT"):
            entry = next(e for e in tree.files() if e.path == rel)
            want = (REFERENCE / rel).read_bytes()
            assert tree.read(entry) == want
    finally:
        tree.source.close()


def test_spool_lifecycle():
    """The tree owns its spool: explicit close unlinks it, idempotently."""
    tree = normalize_zip(ARCHIVE)
    inner = tree.source._inner.path
    assert inner.exists()
    tree.source.close()
    assert not inner.exists()
    tree.source.close()  # idempotent
    tree2 = normalize_zip(ARCHIVE)
    with tree2.source as source:
        assert source.size() == 8013


def test_expected_manifest_validates_against_schema():
    schema = json.loads((ROOT / "schema" / "manifest.schema.json").read_text("utf-8"))
    doc = json.loads((FIXTURE / "expected.manifest.json").read_text("ascii"))
    jsonschema.Draft202012Validator(schema).validate(doc)
    assert doc["format"] == "zip"
    assert doc["source"]["name"] == "game.zip"
    # source.size describes the spool (the tree's underlying source),
    # not the archive — assert it against the 7-Zip reference bytes.
    spool_total = sum(
        f.stat().st_size for f in REFERENCE.rglob("*") if f.is_file()
    )
    assert doc["source"]["size"] == spool_total


def test_composed_tree_matches_expected():
    tree = normalize_zip(ARCHIVE)
    try:
        expected = json.loads((FIXTURE / "expected.manifest.json").read_text("ascii"))
        got_paths = sorted(e.path for e in tree.entries)
        want_paths = sorted(e["path"] for e in expected["entries"])
        assert got_paths == want_paths
    finally:
        tree.source.close()


# --- structural reds ------------------------------------------------------


def test_corrupted_local_magic_is_structural_red(tmp_path):
    bad = tmp_path / "bad-local.zip"
    data = bytearray(ARCHIVE.read_bytes())
    data[0] ^= 0xFF  # first local header signature
    bad.write_bytes(bytes(data))
    problems = _checks(normalize_zip, fixture=bad)
    assert_structural_failure(problems, "local")


def test_corrupted_central_magic_is_structural_red(tmp_path):
    bad = tmp_path / "bad-cd.zip"
    data = bytearray(ARCHIVE.read_bytes())
    cd_at = bytes(data).find(b"PK\x01\x02")
    assert cd_at > 0
    data[cd_at] ^= 0xFF
    bad.write_bytes(bytes(data))
    problems = _checks(normalize_zip, fixture=bad)
    assert_structural_failure(problems, "central directory")


def test_payload_bitflip_is_structural_red(tmp_path):
    """A flipped payload byte in the STORED member must die at CRC."""
    bad = tmp_path / "bad-crc.zip"
    data = bytearray(ARCHIVE.read_bytes())
    payload_at = bytes(data).find(b"\x00\x01\x02\x03" * 512)
    assert payload_at > 0
    data[payload_at + 1000] ^= 0xFF
    bad.write_bytes(bytes(data))
    problems = _checks(normalize_zip, fixture=bad)
    assert_structural_failure(problems, "checksum")


def test_truncated_refused(tmp_path):
    bad = tmp_path / "bad-trunc.zip"
    bad.write_bytes(ARCHIVE.read_bytes()[:-0x40])  # cuts the EOCD chain
    with pytest.raises(ValueError, match="end of central directory"):
        normalize_zip(bad)


def _tiny_zip(entries, *, eocd_count=None):
    """Hand-pack a minimal archive: entries are (name_bytes, payload,
    flags, method) tuples; local + central + EOCD only."""
    out = bytearray()
    offsets = []
    names = []
    for name, payload, flags, method in entries:
        names.append(name)
        offsets.append(len(out))
        out += struct.pack(
            "<IHHHHHIIIHH", 0x04034B50, 20, flags, method, 0, 0,
            zlib_crc(payload), len(payload), len(payload), len(name), 0,
        )
        out += name + payload
    cd_start = len(out)
    for (name, payload, flags, method), local in zip(entries, offsets):
        out += struct.pack(
            "<IHHHHHHIIIHHHHHII", 0x02014B50, 20, 20, flags, method, 0, 0,
            zlib_crc(payload), len(payload), len(payload), len(name), 0, 0,
            0, 0, 0x20, local,
        )
        out += name
    cd_size = len(out) - cd_start
    count = len(entries) if eocd_count is None else eocd_count
    out += struct.pack(
        "<IHHHHIIH", 0x06054B50, 0, 0, count, count, cd_size, cd_start, 0
    )
    return bytes(out)


def zlib_crc(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF


def test_traversal_name_refused(tmp_path):
    bad = tmp_path / "evil.zip"
    bad.write_bytes(_tiny_zip([(b"../EVIL.TXT", b"x", 0, 0)]))
    with pytest.raises(ValueError, match="path"):
        normalize_zip(bad)


def test_backslash_name_refused(tmp_path):
    bad = tmp_path / "bs.zip"
    bad.write_bytes(_tiny_zip([(b"DIR\\FILE.TXT", b"x", 0, 0)]))
    with pytest.raises(ValueError, match="path"):
        normalize_zip(bad)


def test_duplicate_names_refused(tmp_path):
    bad = tmp_path / "dup.zip"
    bad.write_bytes(_tiny_zip([(b"A.TXT", b"x", 0, 0), (b"A.TXT", b"y", 0, 0)]))
    with pytest.raises(ValueError, match="duplicate"):
        normalize_zip(bad)


def test_encrypted_member_refused(tmp_path):
    bad = tmp_path / "enc.zip"
    bad.write_bytes(_tiny_zip([(b"A.TXT", b"x", 0x0001, 0)]))
    with pytest.raises(ValueError, match="encrypted"):
        normalize_zip(bad)


def test_unsupported_method_refused(tmp_path):
    bad = tmp_path / "bz2.zip"
    bad.write_bytes(_tiny_zip([(b"A.TXT", b"x", 0, 12)]))
    with pytest.raises(ValueError, match="compression method"):
        normalize_zip(bad)


def test_empty_archive_refused(tmp_path):
    bad = tmp_path / "empty.zip"
    bad.write_bytes(_tiny_zip([]))
    with pytest.raises(ValueError, match="empty archive"):
        normalize_zip(bad)


def test_eocd_count_mismatch_refused(tmp_path):
    bad = tmp_path / "count.zip"
    bad.write_bytes(_tiny_zip([(b"A.TXT", b"x", 0, 0)], eocd_count=2))
    with pytest.raises(ValueError, match="declares"):
        normalize_zip(bad)


# --- red-team mutants ---------------------------------------------------


def test_cd_order_offset_mutant_dies():
    """A normalizer that confuses central-directory order with the spool
    layout is fully self-consistent but disagrees with the manifest."""
    def normalize_mutant(source):
        tree = normalize_zip(source)
        cursor = 0
        rebuilt = []
        for entry in tree.entries:
            if entry.kind == "file":
                rebuilt.append(FileEntry(path=entry.path, kind=entry.kind,
                                         offset=cursor, size=entry.size))
                cursor += entry.size
            else:
                rebuilt.append(entry)
        return FileTree(source=tree.source, format=tree.format,
                        entries=tuple(rebuilt))

    problems = _checks(normalize_mutant)
    assert problems
    # The spool has no slack: the shifted last file exceeds the spool and
    # dies at the structural check (a layout with slack would die at
    # manifest/fidelity instead).
    assert any(
        p.startswith(("structural:", "manifest:", "fidelity:")) for p in problems
    )


def test_wrong_slice_slicer_dies():
    def normalize_mutant(source):
        tree = normalize_zip(source)
        mutated_entries = []
        for entry in tree.entries:
            if entry.kind == "file" and entry.size > 0:
                mutated_entries.append(FileEntry(path=entry.path, kind=entry.kind,
                                                 offset=entry.offset + 1, size=entry.size))
            else:
                mutated_entries.append(entry)
        return FileTree(source=tree.source, format=tree.format,
                        entries=tuple(mutated_entries))

    problems = _checks(normalize_mutant)
    assert problems
    assert any(
        p.startswith(("structural:", "manifest:", "fidelity:")) for p in problems
    )
