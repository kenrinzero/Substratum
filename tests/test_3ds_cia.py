"""Gate tests for the one-layer 3DS CIA container normalizer.

The runtime exposes each CIA section (header, certs, ticket, TMD, per-index
content blobs, footer) as opaque slices. It deliberately does not decrypt the
ticket, parse the NCCH content, or validate TMD signatures: those are later
caller-visible layers (decrypt via ``3ds-ncch-enc``, then walk via
``3ds-ncch``).

Two pillars (NORMALIZERS.md row ``cia``):

1. **Synthetic (committed):** a two-content CIA built by
   ``make_3ds_cia_fixture.py`` with a TMD whose content-chunk records carry
   each content's SHA-256 — the independent correctness anchor. The four-check
   gate runs over it (manifest match + byte-stability + fidelity vs the
   committed reference bytes).

2. **Retail anchor (gitignored, skip-if-absent):** Biohazard — The
   Mercenaries 3D; the content blob's on-media hash equals the TMD-declared
   hash, and a wrong-slice mutant dies at manifest or fidelity (the load-
   bearing red case).
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from substratum import normalize
from substratum.contract import FileEntry, FileSource, FileTree, sha256_of
from substratum.formats.three_ds_cia import normalize_3ds_cia, sniff
from substratum.verify import run_checks

ROOT = Path(__file__).resolve().parent.parent
SYNTHETIC_FIXTURE = ROOT / "fixtures" / "3ds_cia" / "synthetic"
SYNTHETIC_CIA = SYNTHETIC_FIXTURE / "game.cia"
SYNTHETIC_REFERENCE = SYNTHETIC_FIXTURE / "reference"
SYNTHETIC_TOOLS = {"generator": "make_3ds_cia_fixture v1"}

RETAIL_FIXTURE = ROOT / "fixtures" / "3ds_cia" / "biohazard"
RETAIL_CIA = ROOT / "fixtures" / "_local" / "Biohazard - The Mercenaries 3D (Japan).cia"
RETAIL_REFERENCE = RETAIL_FIXTURE / "reference"

skip_if_no_retail_anchor = pytest.mark.skipif(
    not RETAIL_CIA.is_file() or not RETAIL_REFERENCE.is_dir(),
    reason="Biohazard CIA or gitignored content reference absent",
)

_CIA_ALIGN = 0x40
_TMD_SIG_TYPE = 0x10004
_TMD_SIG_SIZE = 0x140


def _align(value: int) -> int:
    return (value + _CIA_ALIGN - 1) & ~(_CIA_ALIGN - 1)


def _build_synthetic_cia(
    contents: tuple[tuple[int, bytes], ...] = (
        (0x0000, b"CYAN-" * 128),
        (0x0001, b"MAGENTA-" * 64),
    ),
    *,
    header_size: int = 0x2020,
    footer_size: int = 0x40,
) -> bytes:
    """Build a minimal CIA whose TMD content records match the blobs.

    Mirrors make_3ds_cia_fixture's layout. ``contents`` is a tuple of
    (index, plaintext) pairs.
    """
    cert = b"\x00" * 0x80
    ticket = b"\x00" * 0x40

    # TMD: sig region + fixed header + content-chunk records.
    tmd = bytearray(_TMD_SIG_SIZE + 0xC4)
    struct.pack_into(">I", tmd, 0x0, _TMD_SIG_TYPE)
    struct.pack_into(">H", tmd, _TMD_SIG_SIZE + 0x9E, len(contents))
    records_base = 0x9C4 + _TMD_SIG_SIZE
    tmd += b"\x00" * (records_base - len(tmd))
    for index, data in sorted(contents, key=lambda item: item[0]):
        rec = bytearray(0x30)
        struct.pack_into(">H", rec, 0x04, index)
        struct.pack_into(">Q", rec, 0x08, len(data))
        import hashlib

        rec[0x10:0x30] = hashlib.sha256(data).digest()
        tmd += rec

    content_section = bytearray()
    for _index, data in sorted(contents, key=lambda item: item[0]):
        content_section += data
        pad = _align(len(content_section)) - len(content_section)
        content_section += b"\xFF" * pad

    header = bytearray(header_size)
    struct.pack_into("<I", header, 0x00, header_size)
    struct.pack_into("<H", header, 0x04, 0x0000)
    struct.pack_into("<H", header, 0x06, 0x0000)
    struct.pack_into("<I", header, 0x08, len(cert))
    struct.pack_into("<I", header, 0x0C, len(ticket))
    struct.pack_into("<I", header, 0x10, len(tmd))
    struct.pack_into("<I", header, 0x14, footer_size)
    struct.pack_into("<I", header, 0x18, len(content_section))

    out = bytearray()
    out += header
    out += b"\x00" * (_align(len(out)) - len(out))
    out += cert
    out += b"\x00" * (_align(len(out)) - len(out))
    out += ticket
    out += b"\x00" * (_align(len(out)) - len(out))
    out += tmd
    out += b"\x00" * (_align(len(out)) - len(out))
    out += content_section
    out += b"\x00" * (_align(len(out)) - len(out))
    out += b"\x00" * footer_size
    return bytes(out)


def _write(tmp_path: Path, data: bytes) -> Path:
    path = tmp_path / "game.cia"
    path.write_bytes(data)
    return path


# ---------------------------------------------------------------------------
# Synthetic acceptance + dispatch
# ---------------------------------------------------------------------------

def test_synthetic_cia_returns_opaque_sections(tmp_path):
    cia = _write(tmp_path, _build_synthetic_cia())
    tree = normalize_3ds_cia(cia)
    assert isinstance(tree, FileTree)
    assert tree.format == "cia"
    paths = [e.path for e in tree.entries]
    assert paths == [
        "header.bin",
        "cert.bin",
        "ticket.bin",
        "tmd.bin",
        "content.0000.ncch",
        "content.0001.ncch",
        "footer.bin",
    ]
    # content blobs are opaque slices whose bytes survive a round-trip read
    c0 = next(e for e in tree.entries if e.path == "content.0000.ncch")
    assert tree.read(c0) == b"CYAN-" * 128


def test_sniff_and_public_dispatch(tmp_path):
    cia = _write(tmp_path, _build_synthetic_cia())
    assert sniff(FileSource(cia))
    assert not sniff(FileSource(ROOT / "fixtures" / "toy" / "toy.bin"))
    auto = normalize(cia)
    pinned = normalize(FileSource(cia), format="cia")
    assert isinstance(auto, FileTree) and auto.format == "cia"
    assert pinned.entries == auto.entries


def test_synthetic_gate_is_green():
    assert run_checks(
        normalize_3ds_cia,
        SYNTHETIC_CIA,
        SYNTHETIC_FIXTURE / "expected.manifest.json",
        SYNTHETIC_REFERENCE,
        SYNTHETIC_CIA.name,
        sha256_of(SYNTHETIC_CIA),
        SYNTHETIC_TOOLS,
    ) == []


# ---------------------------------------------------------------------------
# Structural-red cases
# ---------------------------------------------------------------------------

def test_bad_header_size_is_structural_red(tmp_path):
    data = bytearray(_build_synthetic_cia())
    struct.pack_into("<I", data, 0x00, 0x1000)  # wrong header size
    with pytest.raises(ValueError, match="unexpected CiaHeader size"):
        normalize_3ds_cia(_write(tmp_path, data))


def test_wrong_archive_type_is_structural_red(tmp_path):
    data = bytearray(_build_synthetic_cia())
    struct.pack_into("<H", data, 0x04, 0x0001)  # not Normal
    with pytest.raises(ValueError):
        normalize_3ds_cia(_write(tmp_path, data))


def test_zero_content_size_is_structural_red(tmp_path):
    data = bytearray(_build_synthetic_cia())
    struct.pack_into("<I", data, 0x18, 0)  # zero content
    with pytest.raises(ValueError, match="content section size is zero"):
        normalize_3ds_cia(_write(tmp_path, data))


def test_sections_not_tiling_file_is_structural_red(tmp_path):
    # Truncate the footer so the sections no longer tile the file.
    data = bytearray(_build_synthetic_cia())[:-1]
    with pytest.raises(ValueError, match="do not tile the file"):
        normalize_3ds_cia(_write(tmp_path, data))


def test_content_hash_mismatch_is_structural_red(tmp_path):
    # Flip a byte inside the first content blob after the TMD was authored.
    data = bytearray(_build_synthetic_cia())
    # Locate the first content blob (after the 64-aligned TMD end) and corrupt it.
    # Header(0x2020) aligned + cert(0x80) aligned + ticket(0x40) aligned + tmd.
    cursor = _align(0x2020)
    cursor = _align(cursor + 0x80)
    cursor = _align(cursor + 0x40)
    tmd_len = _TMD_SIG_SIZE + 0xC4 + (0x9C4 + _TMD_SIG_SIZE - (_TMD_SIG_SIZE + 0xC4)) + 2 * 0x30
    content_off = _align(cursor + tmd_len)
    data[content_off] ^= 0xFF
    with pytest.raises(ValueError, match="hash mismatch"):
        normalize_3ds_cia(_write(tmp_path, bytes(data)))


def test_tmd_content_count_zero_is_structural_red(tmp_path):
    data = bytearray(_build_synthetic_cia())
    struct.pack_into(">H", data, _TMD_SIG_SIZE + 0x9E + 0, 0)  # within the tmd
    # The TMD sits after header+cert+ticket (each 64-aligned); patch the count
    # field relative to the TMD start.
    cursor = _align(0x2020)
    cursor = _align(cursor + 0x80)
    cursor = _align(cursor + 0x40)
    tmd_off = cursor
    struct.pack_into(">H", data, tmd_off + _TMD_SIG_SIZE + 0x9E, 0)
    with pytest.raises(ValueError, match="zero content chunks"):
        normalize_3ds_cia(_write(tmp_path, bytes(data)))


def test_duplicate_content_index_is_structural_red(tmp_path):
    data = bytearray(_build_synthetic_cia())
    cursor = _align(0x2020)
    cursor = _align(cursor + 0x80)
    cursor = _align(cursor + 0x40)
    tmd_off = cursor
    records_base = tmd_off + 0x9C4 + _TMD_SIG_SIZE
    struct.pack_into(">H", data, records_base + 0x30 + 0x04, 0x0000)  # 2nd idx = 0
    with pytest.raises(ValueError, match="duplicate TMD content index"):
        normalize_3ds_cia(_write(tmp_path, bytes(data)))


# ---------------------------------------------------------------------------
# Retail anchor (the gate that bites)
# ---------------------------------------------------------------------------

@skip_if_no_retail_anchor
def test_retail_manifest_records_pinned_oracle():
    import json

    doc = json.loads((RETAIL_FIXTURE / "expected.manifest.json").read_text("ascii"))
    assert doc["identity"]["title_id"] == "0004000000043e00"
    assert doc["tool_versions"]["ctrtool"] == "CTRTool v1.3.0 (C) jakcron"
    section_paths = {s["path"] for s in doc["sections"]}
    assert "content.0000.ncch" in section_paths


@skip_if_no_retail_anchor
def test_retail_content_blob_matches_two_party_reference():
    """The on-media content blob equals ctrtool's recognized content and its
    streamed hash equals the TMD-declared value (the independent anchor)."""
    tree = normalize_3ds_cia(RETAIL_CIA)
    content = next(e for e in tree.entries if e.path == "content.0000.ncch")
    ref = RETAIL_REFERENCE / "content.0000.ncch"
    assert ref.is_file() and ref.stat().st_size == content.size
    # streamed compare (memory-gate compliant)
    from substratum.verify import _first_diff

    first = _first_diff(tree.open(content), ref, content.size, content.size)
    assert first is None, f"content blob differs from reference at byte {first}"


@skip_if_no_retail_anchor
def test_wrong_slice_mutant_dies_at_manifest_or_fidelity():
    def normalize_mutant(source):
        tree = normalize_3ds_cia(source)
        entries = list(tree.entries)
        content = next(e for e in entries if e.path == "content.0000.ncch")
        idx = entries.index(content)
        entries[idx] = FileEntry(
            content.path, content.kind, content.offset + 1, content.size
        )
        return FileTree(tree.source, tree.format, tuple(entries))

    import json

    doc = json.loads((RETAIL_FIXTURE / "expected.manifest.json").read_text("ascii"))
    problems = run_checks(
        normalize_mutant,
        RETAIL_CIA,
        RETAIL_FIXTURE / "expected.manifest.json",
        RETAIL_REFERENCE,
        RETAIL_CIA.name,
        doc["source"]["sha256"],
        doc["tool_versions"],
    )
    assert any(
        problem.startswith(("manifest:", "fidelity:", "structural:"))
        for problem in problems
    )
