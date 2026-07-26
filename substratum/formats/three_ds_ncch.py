"""Nintendo 3DS NCCH section-table normalizer (decrypted images only).

The returned FileTree contains only opaque regions from one NCCH layer:
extended header, plain region, logo, ExeFS, and RomFS.  It never traverses
ExeFS or RomFS.  Encrypted and seed-encrypted NCCHs are deliberately refused;
those require a separate key-provider/decoder boundary.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass

from substratum.contract import ByteSource, FileEntry, FileSource, FileTree

__all__ = ["sniff", "normalize_3ds_ncch"]

_HEADER_SIZE = 0x200
_MAGIC_OFFSET = 0x100
_ACCESS_DESCRIPTOR_SIZE = 0x400
_NO_ENCRYPTION = 1 << 2
_SEEDED_AES_KEY_Y = 1 << 5


@dataclass(frozen=True, slots=True)
class _Region:
    label: str
    path: str
    offset: int
    size: int
    hashed_size: int = 0
    expected_hash: bytes = b""


def sniff(source: ByteSource) -> bool:
    """Return true when ``source`` carries the NCCH magic at 0x100."""
    return (
        source.size() >= _MAGIC_OFFSET + 4
        and source.read_at(_MAGIC_OFFSET, 4) == b"NCCH"
    )


def _table_region(
    header: bytes,
    *,
    label: str,
    path: str,
    field_offset: int,
    block_size: int,
    protected: bool = False,
    expected_hash: bytes = b"",
) -> _Region | None:
    offset_units, size_units = struct.unpack_from("<II", header, field_offset)
    protected_units = (
        struct.unpack_from("<I", header, field_offset + 8)[0]
        if protected
        else 0
    )
    if offset_units == 0 and size_units == 0:
        if protected_units:
            raise ValueError(f"absent {label} has protected blocks")
        return None
    if offset_units == 0 or size_units == 0:
        raise ValueError(
            f"half-empty {label} region: "
            f"offset={offset_units}, size={size_units}"
        )

    size = size_units * block_size
    hashed_size = protected_units * block_size
    if hashed_size > size:
        raise ValueError(
            f"{label} protected hash span {hashed_size} exceeds "
            f"region size {size}"
        )
    return _Region(
        label=label,
        path=path,
        offset=offset_units * block_size,
        size=size,
        hashed_size=hashed_size,
        expected_hash=expected_hash,
    )


def _verify_hash(src: ByteSource, region: _Region, reason: str) -> None:
    if region.hashed_size == 0:
        return
    digest = hashlib.sha256()
    consumed = 0
    while consumed < region.hashed_size:
        chunk_size = min(1 << 20, region.hashed_size - consumed)
        digest.update(src.read_at(region.offset + consumed, chunk_size))
        consumed += chunk_size
    if digest.digest() != region.expected_hash:
        raise ValueError(reason)


def normalize_3ds_ncch(source) -> FileTree:
    """Expose one decrypted NCCH layer as opaque section slices."""
    src = source if isinstance(source, ByteSource) else FileSource(source)
    source_size = src.size()
    if source_size < _HEADER_SIZE:
        raise ValueError("source too small to contain a 3DS NCCH header")

    header = src.read_at(0, _HEADER_SIZE)
    if header[_MAGIC_OFFSET : _MAGIC_OFFSET + 4] != b"NCCH":
        raise ValueError("not a 3DS NCCH image (missing NCCH magic)")

    format_version = struct.unpack_from("<H", header, 0x112)[0]
    if format_version == 1:
        raise ValueError("NCCH prototype format version 1 is outside scope")
    if format_version not in {0, 2}:
        raise ValueError(f"unsupported NCCH format version {format_version}")

    block_size_log = header[0x18E]
    if block_size_log > 31:
        raise ValueError(f"invalid NCCH block-size log {block_size_log}")
    block_size = 1 << (block_size_log + 9)
    content_units = struct.unpack_from("<I", header, 0x104)[0]
    declared_size = content_units * block_size
    if declared_size != source_size:
        raise ValueError(
            f"declared NCCH content size {declared_size} does not match "
            f"source size {source_size}"
        )

    other_flags = header[0x18F]
    if other_flags & _SEEDED_AES_KEY_Y:
        raise ValueError("seed-encrypted NCCH is outside decrypted-only scope")
    if not other_flags & _NO_ENCRYPTION:
        raise ValueError("encrypted NCCH is outside decrypted-only scope")

    exheader_size = struct.unpack_from("<I", header, 0x180)[0]
    if exheader_size not in {0, 0x400}:
        raise ValueError(
            f"invalid extended-header size {exheader_size:#x} "
            f"for NCCH format version {format_version}"
        )

    regions: list[_Region] = []
    if exheader_size:
        regions.append(
            _Region(
                label="extended-header",
                path="extendedheader.bin",
                offset=_HEADER_SIZE,
                size=exheader_size + _ACCESS_DESCRIPTOR_SIZE,
                hashed_size=exheader_size,
                expected_hash=header[0x160:0x180],
            )
        )

    plain = _table_region(
        header,
        label="plain",
        path="plain.bin",
        field_offset=0x190,
        block_size=block_size,
    )
    logo = _table_region(
        header,
        label="logo",
        path="logo.bin",
        field_offset=0x198,
        block_size=block_size,
        expected_hash=header[0x130:0x150],
    )
    exefs = _table_region(
        header,
        label="ExeFS",
        path="exefs.bin",
        field_offset=0x1A0,
        block_size=block_size,
        protected=True,
        expected_hash=header[0x1C0:0x1E0],
    )
    romfs = _table_region(
        header,
        label="RomFS",
        path="romfs.bin",
        field_offset=0x1B0,
        block_size=block_size,
        protected=True,
        expected_hash=header[0x1E0:0x200],
    )
    for region in (plain, logo, exefs, romfs):
        if region is not None:
            regions.append(region)

    for region in regions:
        end = region.offset + region.size
        if region.offset < _HEADER_SIZE:
            raise ValueError(f"{region.label} region overlaps the NCCH header")
        if end > source_size:
            raise ValueError(
                f"{region.label} range [{region.offset:#x}, {end:#x}) "
                f"exceeds NCCH size {source_size:#x}"
            )

    by_offset = sorted(regions, key=lambda region: region.offset)
    for left, right in zip(by_offset, by_offset[1:]):
        if left.offset + left.size > right.offset:
            raise ValueError(
                f"{right.label} region overlaps {left.label} region"
            )

    if exheader_size:
        _verify_hash(src, regions[0], "extended-header hash mismatch")
    if logo is not None:
        logo_with_hash = _Region(
            logo.label,
            logo.path,
            logo.offset,
            logo.size,
            logo.size,
            logo.expected_hash,
        )
        _verify_hash(src, logo_with_hash, "logo hash mismatch")
    if exefs is not None:
        _verify_hash(src, exefs, "ExeFS protected hash mismatch")
    if romfs is not None:
        _verify_hash(src, romfs, "RomFS protected hash mismatch")

    entries = tuple(
        FileEntry(region.path, "file", region.offset, region.size)
        for region in regions
    )
    return FileTree(source=src, format="3ds-ncch", entries=entries)
