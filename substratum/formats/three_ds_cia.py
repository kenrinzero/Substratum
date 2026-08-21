"""Nintendo 3DS CIA outer-container normalizer.

A CIA (CTR Importable Archive) is the eShop/install container: a fixed
CiaHeader followed by a certificate chain, a ticket, a TMD (title metadata),
one or more content blobs, and a footer. This unit reads the header's
section-size table and the TMD's content-chunk records, and returns every
section as an opaque slice into the original image. CDN-encrypted chunks
(TMD type bit 0) have their TMD SHA-256 verified after titlekey decrypt;
the FileTree still exposes the on-media ciphertext. It does not parse NCCH
content or validate TMD/RSA signatures — those are later caller-visible
layers (DESIGN.md section 1):

  normalize("game.cia")                          -> FileTree of sections
  normalize(tree, format="3ds-ncch-enc")         -> decrypt the content blob
  normalize(view.source, format="3ds-ncch")      -> walk NCCH regions

Section layout (header-driven; each section is 64-byte aligned, the content
section lands at align64(header+cert+ticket+tmd)):
  [CiaHeader 0x2020][CertChain][Ticket][TMD][Content(s)][Footer]

The independent correctness anchor is the TMD: each content-chunk record
declares the content's SHA-256. For unencrypted chunks that hash is of the
on-media bytes; for chunks with the TMD encrypted flag (bit 0) it is of the
**titlekey-decrypted** blob (AES-128-CBC, IV = content index as BE u16 at
the start of a zeroed 16-byte block — ctrtool CiaProcess). The FileTree
still exposes on-media slices; only the structural hash check decrypts.
eShop CIAs therefore need the operator keyset (``SUBSTRATUM_3DS_KEYSET_FILE``,
``slot0x3DKeyX`` + ``commonN`` as keyY; the AES common key is the hardware
key-generator normal key). Cartridge-dump CIAs with the encrypted flag clear
stay keyless.

Runtime is stdlib-only. CIA section sizes are plain bytes; the header fields
and the TMD/ticket bodies are big-endian (per 3DBrew).
"""

from __future__ import annotations

import hashlib
import os
import struct
from dataclasses import dataclass
from pathlib import Path

from substratum._aes import cbc_decrypt_blocks, expand_key, normalkey_from_keyxy
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
_CONTENT_TYPE_ENCRYPTED = 0x0001

# Ticket body (after the signature region) field offsets. For RSA-2048-SHA256
# (sig region 0x140) these land at the classic 0x1BF / 0x1DC / 0x1F1 file
# offsets; deriving them from the sig region keeps ECDSA tickets consistent.
_TICKET_TITLEKEY_OFFSET = 0x7F  # 16 bytes, AES-CBC encrypted
_TICKET_TITLE_ID_OFFSET = 0x9C  # u64 BE
_TICKET_KEY_ID_OFFSET = 0xB1  # u8, selects common0..common5 as slot 0x3D keyY
_AES_BLOCK = 16
_KEYSET_ENV = "SUBSTRATUM_3DS_KEYSET_FILE"
_COMMON_KEYX_NAME = "slot0x3DKeyX"


def _align64(value: int) -> int:
    return (value + _CIA_ALIGN - 1) & ~(_CIA_ALIGN - 1)


@dataclass(frozen=True, slots=True)
class _ContentRecord:
    index: int
    size: int
    hash: bytes
    encrypted: bool


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
        ctype = struct.unpack_from(">H", rec, _TMD_CONTENT_TYPE_OFFSET)[0]
        records.append(
            _ContentRecord(
                index=index,
                size=size,
                hash=digest,
                encrypted=bool(ctype & _CONTENT_TYPE_ENCRYPTED),
            )
        )
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


def _content_iv(index: int) -> bytes:
    """AES-CBC IV for one CIA content blob: BE u16 index at byte 0, rest zero."""
    iv = bytearray(_AES_BLOCK)
    struct.pack_into(">H", iv, 0, index)
    return bytes(iv)


def _load_keyset_value(slot_name: str) -> bytes:
    """Load one 16-byte key from the operator keyset. Presence-only; never logs keys."""
    raw = os.environ.get(_KEYSET_ENV)
    if not raw:
        raise ValueError(
            f"{_KEYSET_ENV} is not set; CDN-encrypted CIA content needs "
            "the 3DS keyset (see docs/3DS-KEYED-WORK.md)"
        )
    path = Path(raw)
    if not path.is_file():
        raise ValueError(
            f"{_KEYSET_ENV} points to a missing file "
            "(see docs/3DS-KEYED-WORK.md)"
        )
    needle = f"{slot_name}="
    with path.open("r", encoding="ascii", errors="replace") as fh:
        for line in fh:
            stripped = line.strip()
            if stripped.startswith(needle):
                hexval = stripped[len(needle) :].strip()
                try:
                    key = bytes.fromhex(hexval)
                except ValueError as exc:
                    raise ValueError(
                        f"{slot_name} in the keyset is not valid hex "
                        "(see docs/3DS-KEYED-WORK.md)"
                    ) from exc
                if len(key) != _AES_BLOCK:
                    raise ValueError(
                        f"{slot_name} in the keyset is not 16 bytes "
                        "(see docs/3DS-KEYED-WORK.md)"
                    )
                return key
    raise ValueError(
        f"{slot_name} not found in the keyset "
        "(see docs/3DS-KEYED-WORK.md)"
    )


def _common_normal_key(key_id: int) -> bytes:
    """AES key for ticket titlekey decrypt: slot0x3D keyX + commonN keyY."""
    if key_id < 0 or key_id > 5:
        raise ValueError(f"unsupported CIA ticket common-key index {key_id}")
    keyx = _load_keyset_value(_COMMON_KEYX_NAME)
    keyy = _load_keyset_value(f"common{key_id}")
    return normalkey_from_keyxy(keyx, keyy)


def _title_key_from_ticket(ticket: bytes) -> bytes:
    """Decrypt the ticket titlekey. The result stays in memory; never logged."""
    if len(ticket) < 4:
        raise ValueError("ticket too small to contain a signature type")
    sig_type = struct.unpack_from(">I", ticket, 0)[0]
    sig_size = _TMD_SIG_SIZE.get(sig_type)
    if sig_size is None:
        raise ValueError(f"unsupported ticket signature type {sig_type:#x}")
    body = sig_size
    needed = body + _TICKET_KEY_ID_OFFSET + 1
    if len(ticket) < needed:
        raise ValueError("ticket too small to contain a titlekey")
    enc_titlekey = ticket[body + _TICKET_TITLEKEY_OFFSET : body + _TICKET_TITLEKEY_OFFSET + _AES_BLOCK]
    title_id = struct.unpack_from(">Q", ticket, body + _TICKET_TITLE_ID_OFFSET)[0]
    key_id = ticket[body + _TICKET_KEY_ID_OFFSET]
    common_key = _common_normal_key(key_id)
    iv = bytearray(_AES_BLOCK)
    struct.pack_into(">Q", iv, 0, title_id)
    return cbc_decrypt_blocks(expand_key(common_key), bytes(iv), enc_titlekey)


def _stream_hash_cbc(
    src: ByteSource, offset: int, size: int, title_key: bytes, iv: bytes
) -> bytes:
    """SHA-256 of AES-128-CBC decrypted content, streamed in 1 MiB chunks."""
    if size % _AES_BLOCK != 0:
        raise ValueError(
            "CDN-encrypted CIA content size is not a multiple of the AES block"
        )
    digest = hashlib.sha256()
    round_keys = expand_key(title_key)
    prev_iv = iv
    consumed = 0
    while consumed < size:
        n = min(1 << 20, size - consumed)
        chunk = src.read_at(offset + consumed, n)
        if len(chunk) != n:
            raise ValueError("short read while hashing a CIA content chunk")
        digest.update(cbc_decrypt_blocks(round_keys, prev_iv, chunk))
        prev_iv = chunk[-_AES_BLOCK:]
        consumed += n
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
    chunk_specs: list[tuple[str, int, int, int, bytes, bool]] = []
    for rec in records:
        if content_cursor + rec.size > content_end:
            raise ValueError(
                f"content chunk index {rec.index} range "
                f"[{content_cursor:#x}, {content_cursor + rec.size:#x}) "
                f"exceeds content section"
            )
        path = f"content.{rec.index:04x}.ncch"
        chunk_specs.append(
            (path, rec.index, content_cursor, rec.size, rec.hash, rec.encrypted)
        )
        content_cursor = _align64(content_cursor + rec.size)
    if content_cursor != content_end:
        raise ValueError(
            f"TMD content chunks do not tile the content section: cursor "
            f"ends at {content_cursor:#x}, content section ends at {content_end:#x}"
        )

    title_key: bytes | None = None
    if any(encrypted for _p, _i, _o, _s, _h, encrypted in chunk_specs):
        ticket = src.read_at(offsets["ticket"], sizes["ticket"])
        title_key = _title_key_from_ticket(ticket)

    # Build the section entries in on-media order: header/cert/ticket/tmd, then
    # content chunks, then the trailing footer. Content chunks are verified
    # against their TMD-declared hash (decrypt-then-hash when the encrypted
    # flag is set); the rest are opaque.
    for name in ("header", "cert", "ticket", "tmd"):
        entries.append(
            FileEntry(
                path=f"{name}.bin",
                kind="file",
                offset=offsets[name],
                size=sizes[name],
            )
        )
    for path, index, offset, size, expected_hash, encrypted in chunk_specs:
        if encrypted:
            if title_key is None:
                raise ValueError("CDN-encrypted CIA content is missing a titlekey")
            actual = _stream_hash_cbc(
                src, offset, size, title_key, _content_iv(index)
            )
        else:
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
