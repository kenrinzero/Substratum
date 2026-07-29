"""Nintendo 3DS CIA outer-container normalizer.

A CIA (CTR Importable Archive) is the eShop/install container: a fixed
CiaHeader followed by a certificate chain, a ticket, a TMD (title metadata),
one or more content blobs, and a footer. This unit reads only the header's
section-size table and the TMD's content-chunk records, and returns every
section as an opaque slice into the original image. It does NOT decrypt the
ticket's title key, parse the NCCH content, or validate TMD/RSA signatures —
those are later caller-visible layers (DESIGN.md section 1):

  normalize("game.cia")                          -> FileTree of sections
  normalize(tree, format="3ds-ncch-enc")         -> decrypt the content blob
  normalize(view.source, format="3ds-ncch")      -> walk NCCH regions

Section layout (header-driven; each section is 64-byte aligned, the content
section lands at align64(header+cert+ticket+tmd)):
  [CiaHeader 0x2020][CertChain][Ticket][TMD][Content(s)][Footer]

The independent correctness anchor is the TMD: each content-chunk record
declares the content's SHA-256, and this normalizer stream-hashes each
exposed content slice against it (a wrong slice fails structurally).

Runtime is stdlib-only. CIA section sizes are plain bytes; the header fields
and the TMD are big-endian (per 3DBrew).
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass

from substratum.contract import ByteSource, FileEntry, FileSource, FileTree

__all__ = ["sniff", "normalize_3ds_cia"]

_CIA_ALIGN = 0x40
_HEADER_READ = 0x40  # the fixed-size portion of the CiaHeader we parse

# CiaHeader field offsets (big-endian u32 unless noted).
_HEADER_SIZE_OFFSET = 0x00
_ARCHIVE_TYPE_OFFSET = 0x04  # u16
_FORMAT_VERSION_OFFSET = 0x06  # u16
_CERT_SIZE_OFFSET = 0x08
_TICKET_SIZE_OFFSET = 0x0C
_TMD_SIZE_OFFSET = 0x10
_FOOTER_SIZE_OFFSET = 0x14
_CONTENT_SIZE_OFFSET = 0x18

_HEADER_SIZE_FIXED = 0x2020
_ARCHIVE_TYPE_NORMAL = 0x0000
_FORMAT_VERSION_CIA = 0x0000

# TMD signature types (3DBrew) -> signature-region size Y.
_TMD_SIG_RSA4096_SHA256 = 0x10003  # Y = 0x200
_TMD_SIG_RSA2048_SHA256 = 0x10004  # Y = 0x140
_TMD_SIG_RSA2048_SHA1 = 0x10005  # Y = 0x140
_TMD_SIG_SIZE = {
    _TMD_SIG_RSA4096_SHA256: 0x200,
    _TMD_SIG_RSA2048_SHA256: 0x140,
    _TMD_SIG_RSA2048_SHA1: 0x140,
}
# TMD header (after the signature region) field offsets.
_TMD_HEADER_FIXED_SIZE = 0xC4
_TMD_CONTENT_COUNT_OFFSET = 0x9E  # u16 BE, within the post-sig header
_TMD_CONTENT_RECORDS_BASE = 0x9C4  # content chunk records start here (after sig)
_TMD_CONTENT_RECORD_SIZE = 0x30
_TMD_CONTENT_INDEX_OFFSET = 0x04  # u16 BE, within a record
_TMD_CONTENT_TYPE_OFFSET = 0x06  # u16 BE
_TMD_CONTENT_SIZE_OFFSET = 0x08  # u64 BE
_TMD_CONTENT_HASH_OFFSET = 0x10  # 0x20 bytes


def _align64(value: int) -> int:
    return (value + _CIA_ALIGN - 1) & ~(_CIA_ALIGN - 1)


@dataclass(frozen=True, slots=True)
class _ContentRecord:
    index: int
    size: int
    hash: bytes


def sniff(source: ByteSource) -> bool:
    """A CIA has no magic bytes; sniff the fixed CiaHeader structure."""
    if source.size() < _HEADER_READ:
        return False
    header = source.read_at(0, _HEADER_READ)
    if struct.unpack_from("<I", header, _HEADER_SIZE_OFFSET)[0] != _HEADER_SIZE_FIXED:
        return False
    archive_type = struct.unpack_from("<H", header, _ARCHIVE_TYPE_OFFSET)[0]
    format_version = struct.unpack_from("<H", header, _FORMAT_VERSION_OFFSET)[0]
    if archive_type != _ARCHIVE_TYPE_NORMAL or format_version != _FORMAT_VERSION_CIA:
        return False
    content_size = struct.unpack_from("<I", header, _CONTENT_SIZE_OFFSET)[0]
    return content_size > 0


def _parse_header(source_size: int, header: bytes) -> dict[str, int]:
    """Validate the CiaHeader and return the six section sizes."""
    archive_type = struct.unpack_from("<H", header, _ARCHIVE_TYPE_OFFSET)[0]
    format_version = struct.unpack_from("<H", header, _FORMAT_VERSION_OFFSET)[0]
    if archive_type != _ARCHIVE_TYPE_NORMAL:
        raise ValueError(
            f"unsupported CIA archive type {archive_type:#x}; "
            f"expected Normal ({_ARCHIVE_TYPE_NORMAL:#x})"
        )
    if format_version != _FORMAT_VERSION_CIA:
        raise ValueError(
            f"unsupported CIA format version {format_version:#x}; "
            f"expected Cia ({_FORMAT_VERSION_CIA:#x})"
        )
    sizes = {
        "header": struct.unpack_from("<I", header, _HEADER_SIZE_OFFSET)[0],
        "cert": struct.unpack_from("<I", header, _CERT_SIZE_OFFSET)[0],
        "ticket": struct.unpack_from("<I", header, _TICKET_SIZE_OFFSET)[0],
        "tmd": struct.unpack_from("<I", header, _TMD_SIZE_OFFSET)[0],
        "content": struct.unpack_from("<I", header, _CONTENT_SIZE_OFFSET)[0],
        "footer": struct.unpack_from("<I", header, _FOOTER_SIZE_OFFSET)[0],
    }
    if sizes["header"] != _HEADER_SIZE_FIXED:
        raise ValueError(
            f"unexpected CiaHeader size {sizes['header']:#x}; "
            f"expected {_HEADER_SIZE_FIXED:#x}"
        )
    for name in ("cert", "ticket", "tmd"):
        if sizes[name] == 0:
            raise ValueError(f"CIA {name} section size is zero")
    # content may legitimately be the only zero in odd cases, but a real CIA
    # carries content; require it.
    if sizes["content"] == 0:
        raise ValueError("CIA content section size is zero")
    return sizes


def _section_offsets(sizes: dict[str, int]) -> dict[str, int]:
    """Compute each section's start offset via 64-byte cumulative alignment.

    Sections are laid out header -> cert -> ticket -> tmd -> content(s) ->
    footer, each beginning at align64(prev_end).
    """
    offsets: dict[str, int] = {"header": 0}
    cursor = _align64(sizes["header"])
    offsets["cert"] = cursor
    cursor = _align64(cursor + sizes["cert"])
    offsets["ticket"] = cursor
    cursor = _align64(cursor + sizes["ticket"])
    offsets["tmd"] = cursor
    cursor = _align64(cursor + sizes["tmd"])
    offsets["content"] = cursor
    cursor = _align64(cursor + sizes["content"])
    offsets["footer"] = cursor
    return offsets


def _parse_tmd(tmd: bytes) -> list[_ContentRecord]:
    """Parse the TMD's content-chunk records (big-endian, 3DBrew layout)."""
    if len(tmd) < 4:
        raise ValueError("TMD too small to contain a signature type")
    sig_type = struct.unpack_from(">I", tmd, 0)[0]
    sig_size = _TMD_SIG_SIZE.get(sig_type)
    if sig_size is None:
        raise ValueError(f"unsupported TMD signature type {sig_type:#x}")
    header_base = sig_size
    if len(tmd) < header_base + _TMD_HEADER_FIXED_SIZE:
        raise ValueError("TMD too small to contain its fixed header")

    content_count = struct.unpack_from(
        ">H", tmd, header_base + _TMD_CONTENT_COUNT_OFFSET
    )[0]
    if content_count == 0:
        raise ValueError("TMD declares zero content chunks")
    records_base = _TMD_CONTENT_RECORDS_BASE + sig_size
    records_end = records_base + content_count * _TMD_CONTENT_RECORD_SIZE
    if records_end > len(tmd):
        raise ValueError(
            f"TMD content-chunk records [{records_base:#x}, {records_end:#x}) "
            f"exceed TMD size {len(tmd):#x}"
        )

    records: list[_ContentRecord] = []
    seen_indices: set[int] = set()
    for i in range(content_count):
        rec = tmd[
            records_base + i * _TMD_CONTENT_RECORD_SIZE : records_base
            + (i + 1) * _TMD_CONTENT_RECORD_SIZE
        ]
        index = struct.unpack_from(">H", rec, _TMD_CONTENT_INDEX_OFFSET)[0]
        if index in seen_indices:
            raise ValueError(f"duplicate TMD content index {index}")
        seen_indices.add(index)
        size = struct.unpack_from(">Q", rec, _TMD_CONTENT_SIZE_OFFSET)[0]
        digest = rec[_TMD_CONTENT_HASH_OFFSET : _TMD_CONTENT_HASH_OFFSET + 0x20]
        records.append(_ContentRecord(index=index, size=size, hash=digest))
    # Content records appear in ascending index order.
    ordered = sorted(records, key=lambda r: r.index)
    if [r.index for r in ordered] != [r.index for r in records]:
        raise ValueError("TMD content indices are not in ascending order")
    return ordered


def _stream_hash(src: ByteSource, offset: int, size: int) -> bytes:
    """Stream a byte range through SHA-256 without materializing it."""
    digest = hashlib.sha256()
    consumed = 0
    while consumed < size:
        chunk = src.read_at(offset + consumed, min(1 << 20, size - consumed))
        if not chunk:
            raise ValueError("short read while hashing a CIA content chunk")
        digest.update(chunk)
        consumed += len(chunk)
    return digest.digest()


def normalize_3ds_cia(source) -> FileTree:
    """Expose one CIA layer as opaque section slices."""
    src = source if isinstance(source, ByteSource) else FileSource(source)
    source_size = src.size()
    if source_size < _HEADER_READ:
        raise ValueError("source too small to contain a CIA header")
    header = src.read_at(0, _HEADER_READ)
    sizes = _parse_header(source_size, header)
    offsets = _section_offsets(sizes)

    # The footer trails the content section; the file must end exactly at
    # footer_start + footer_size (plus any final 64-byte alignment is not
    # part of the CIA — the footer is the last section).
    footer_end = offsets["footer"] + sizes["footer"]
    if footer_end != source_size:
        raise ValueError(
            f"CIA sections do not tile the file: footer ends at "
            f"{footer_end:#x} but file size is {source_size:#x}"
        )

    tmd_bytes = src.read_at(offsets["tmd"], sizes["tmd"])
    records = _parse_tmd(tmd_bytes)

    # Split the content section into per-chunk slices, each followed by
    # 64-byte alignment padding before the next chunk. The cursor walk must
    # land exactly at content_end: this validates that the TMD-declared chunk
    # sizes tile the content section (sum of sizes + inter-chunk padding).
    content_cursor = offsets["content"]
    content_end = content_cursor + sizes["content"]
    entries: list[FileEntry] = []
    chunk_specs: list[tuple[str, int, int, bytes]] = []  # (path, off, size, hash)
    for rec in records:
        if content_cursor + rec.size > content_end:
            raise ValueError(
                f"content chunk index {rec.index} range "
                f"[{content_cursor:#x}, {content_cursor + rec.size:#x}) "
                f"exceeds content section"
            )
        path = f"content.{rec.index:04x}.ncch"
        chunk_specs.append((path, content_cursor, rec.size, rec.hash))
        content_cursor = _align64(content_cursor + rec.size)
    if content_cursor != content_end:
        raise ValueError(
            f"TMD content chunks do not tile the content section: cursor "
            f"ends at {content_cursor:#x}, content section ends at {content_end:#x}"
        )

    # Build the section entries in on-media order: header/cert/ticket/tmd, then
    # content chunks, then the trailing footer. Content chunks are verified
    # against their TMD-declared hash; the rest are opaque.
    for name in ("header", "cert", "ticket", "tmd"):
        entries.append(
            FileEntry(
                path=f"{name}.bin",
                kind="file",
                offset=offsets[name],
                size=sizes[name],
            )
        )
    for path, offset, size, expected_hash in chunk_specs:
        actual = _stream_hash(src, offset, size)
        if actual != expected_hash:
            raise ValueError(
                f"content chunk {path} hash mismatch — wrong slice or corrupt"
            )
        entries.append(FileEntry(path=path, kind="file", offset=offset, size=size))
    entries.append(
        FileEntry(
            path="footer.bin",
            kind="file",
            offset=offsets["footer"],
            size=sizes["footer"],
        )
    )

    # Structural ordering check: sections must not overlap.
    by_offset = sorted(entries, key=lambda e: e.offset)
    for left, right in zip(by_offset, by_offset[1:]):
        if left.offset + left.size > right.offset:
            raise ValueError(
                f"section {right.path} overlaps section {left.path}"
            )

    return FileTree(source=src, format="cia", entries=tuple(entries))
