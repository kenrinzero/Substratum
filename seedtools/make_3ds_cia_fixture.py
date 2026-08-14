#!/usr/bin/env python3
"""Author the committed synthetic 3DS CIA fixture.

Usage:
    uv run python seedtools/make_3ds_cia_fixture.py

Builds a minimal multi-content CIA with a valid CiaHeader + TMD whose
content-chunk records (index/size/hash) match the synthetic content blobs.
No crypto: the ticket's title key is a zero stub, TMD RSA signatures are
zero, and the content blobs are deterministic plaintext. This exercises the
normalizer's section-table parsing, 64-byte alignment, multi-content
splitting, and the TMD content-hash anchor — without any retail bytes or
keys.

The expected manifest is derivable from this seedtool's documented section
layout (DESIGN section 3 one-party rule), not from running the normalizer.
Runtime is stdlib-only.
"""

from __future__ import annotations

import hashlib
import shutil
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "fixtures" / "3ds_cia" / "synthetic"

sys.path.insert(0, str(ROOT))
from substratum.contract import (  # noqa: E402
    FileEntry,
    FileSource,
    FileTree,
    canonical_manifest,
)

_CIA_ALIGN = 0x40
_HEADER_SIZE = 0x2020
_FOOTER_SIZE = 0x40  # small synthetic footer (real CIAs vary)
_CERT_SIZE = 0x80
_TICKET_SIZE = 0x40
_TMD_SIG_SIZE = 0x140  # RSA-2048-SHA256 sig region
_TMD_HEADER_FIXED = 0xC4
_TMD_CONTENT_RECORD_SIZE = 0x30


def _align64(value: int) -> int:
    return (value + _CIA_ALIGN - 1) & ~(_CIA_ALIGN - 1)


def _build_tmd(content_records: list[tuple[int, bytes]]) -> bytes:
    """Build a minimal TMD whose content-chunk records match the contents.

    ``content_records`` is a list of (index, plaintext_bytes). The signature
    region is a zero-filled RSA-2048-SHA256 stub; the content-chunk records
    carry each content's index, size, and SHA-256.
    """
    tmd = bytearray(_TMD_SIG_SIZE + _TMD_HEADER_FIXED)
    struct.pack_into(">I", tmd, 0x0, 0x10004)  # RSA-2048-SHA256 sig type
    tmd[_TMD_SIG_SIZE : _TMD_SIG_SIZE + 0x40] = b"Root-CA00000003-CP0000000b".ljust(
        0x40, b"\x00"
    )
    content_count = len(content_records)
    struct.pack_into(
        ">H", tmd, _TMD_SIG_SIZE + 0x9E, content_count
    )
    records_base = 0x9C4 + _TMD_SIG_SIZE
    # (the gap between header end and records_base is the 64-slot ContentInfo
    # hash-chain summary, zero-filled here — not parsed by the normalizer)
    tmd += b"\x00" * (records_base - len(tmd))
    for index, data in sorted(content_records, key=lambda item: item[0]):
        digest = hashlib.sha256(data).digest()
        rec = bytearray(_TMD_CONTENT_RECORD_SIZE)
        struct.pack_into(">I", rec, 0x00, 0x00000000)  # content id (unused)
        struct.pack_into(">H", rec, 0x04, index)
        struct.pack_into(">H", rec, 0x06, 0x0000)  # type
        struct.pack_into(">Q", rec, 0x08, len(data))
        rec[0x10:0x30] = digest
        tmd += rec
    return bytes(tmd)


def _build_cia() -> tuple[bytes, list[tuple[str, int, int]]]:
    """Build a two-content CIA; return (bytes, section entries).

    Section entries are ``(path, offset, size)`` derived from the layout this
    function assembles — independent of the runtime normalizer's parser. The
    normalizer must reproduce these exact offsets/sizes.
    """
    # Two deterministic content blobs (different sizes -> exercises alignment).
    content_a = (b"CYAN-SYNTHETIC-CIA-CONTENT-A-" * 64)[:0x400]
    content_b = (b"MAGENTA-SYNTHETIC-CIA-CONTENT-B-" * 64)[:0x200]
    content_records = [(0x0000, content_a), (0x0001, content_b)]

    tmd = _build_tmd(content_records)
    cert = b"CERT-STUB" + b"\x00" * (_CERT_SIZE - 9)
    ticket = b"TIK-STUB" + b"\x00" * (_TICKET_SIZE - 8)
    footer = b"FOOTER-STUB" + b"\x00" * (_FOOTER_SIZE - 11)

    content_chunks: list[tuple[int, int, int]] = []  # (index, offset, size)
    content_section = bytearray()
    for index, data in sorted(content_records, key=lambda item: item[0]):
        content_chunks.append((index, len(content_section), len(data)))
        content_section += data
        pad = _align64(len(content_section)) - len(content_section)
        content_section += b"\xFF" * pad
    content_size = len(content_section)

    # CiaHeader
    header = bytearray(_HEADER_SIZE)
    struct.pack_into("<I", header, 0x00, _HEADER_SIZE)
    struct.pack_into("<H", header, 0x04, 0x0000)  # type Normal
    struct.pack_into("<H", header, 0x06, 0x0000)  # format version Cia
    struct.pack_into("<I", header, 0x08, _CERT_SIZE)
    struct.pack_into("<I", header, 0x0C, _TICKET_SIZE)
    struct.pack_into("<I", header, 0x10, len(tmd))
    struct.pack_into("<I", header, 0x14, _FOOTER_SIZE)
    struct.pack_into("<I", header, 0x18, content_size)

    # Assemble with 64-byte alignment between sections, tracking offsets.
    out = bytearray()
    section_entries: list[tuple[str, int, int]] = []
    section_entries.append(("header.bin", len(out), _HEADER_SIZE))
    out += header
    out += b"\x00" * (_align64(len(out)) - len(out))
    section_entries.append(("cert.bin", len(out), _CERT_SIZE))
    out += cert
    out += b"\x00" * (_align64(len(out)) - len(out))
    section_entries.append(("ticket.bin", len(out), _TICKET_SIZE))
    out += ticket
    out += b"\x00" * (_align64(len(out)) - len(out))
    section_entries.append(("tmd.bin", len(out), len(tmd)))
    out += tmd
    out += b"\x00" * (_align64(len(out)) - len(out))
    content_base = len(out)
    for index, rel_off, size in content_chunks:
        section_entries.append(
            (f"content.{index:04x}.ncch", content_base + rel_off, size)
        )
    out += content_section
    out += b"\x00" * (_align64(len(out)) - len(out))
    section_entries.append(("footer.bin", len(out), _FOOTER_SIZE))
    out += footer
    return bytes(out), section_entries


def main() -> None:
    if len(sys.argv) > 1:
        raise SystemExit(__doc__)
    OUTPUT.mkdir(parents=True, exist_ok=True)
    cia, section_entries = _build_cia()
    cia_path = OUTPUT / "game.cia"
    cia_path.write_bytes(cia)

    # Author the expected manifest from this seedtool's own layout (independent
    # of the runtime normalizer's parser — DESIGN section 3 one-party rule).
    tree = FileTree(
        FileSource(cia_path), "cia", tuple(
            FileEntry(path, "file", offset, size)
            for path, offset, size in section_entries
        )
    )
    tools = {"generator": "make_3ds_cia_fixture v1"}
    manifest = canonical_manifest(tree, cia_path.name, hashlib.sha256(cia).hexdigest(), tools)
    manifest_path = OUTPUT / "expected.manifest.json"
    manifest_path.write_bytes(manifest)

    # Reference bytes for the four-check fidelity gate. These are generated
    # (not retail), so they commit alongside the fixture; the gate compares
    # every section slice read through the normalizer against them.
    reference = OUTPUT / "reference"
    if reference.exists():
        shutil.rmtree(reference)
    reference.mkdir()
    for path, offset, size in section_entries:
        (reference / path).write_bytes(cia[offset : offset + size])

    digest = hashlib.sha256(cia).hexdigest()
    print(f"wrote {cia_path} ({len(cia)} bytes, sha256 {digest})")
    print(f"manifest -> {manifest_path}")
    print(f"reference bytes -> {reference}")
    print(
        "two content blobs (index 0x0000, 0x0001); TMD content-chunk records "
        "carry their SHA-256 — the independent anchor"
    )


if __name__ == "__main__":
    main()
