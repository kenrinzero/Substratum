"""CSO / CISO container normalizer (NORMALIZERS.md row `cso`).

Decodes a CISO v1 compressed disc image to a ByteView of the inner
2048-byte-sector ISO stream. Returns exactly ONE layer (DESIGN.md §1):
the caller re-normalizes the ByteView with `iso9660` — never recurse.

CISO v1 on disk:
  header (24 B): magic 'CISO', header_size u32, total_bytes u64,
    block_size u32, ver u8, align u8 (index_shift), unused[2].
  index: (nblocks+1) u32, nblocks = ceil(total_bytes / block_size).
    For block i: bit31 = stored uncompressed; the low 31 bits are the
    block's ABSOLUTE file offset >> align. Block data spans
    [off_i, off_{i+1}); compressed blocks are raw DEFLATE (no zlib
    header). The final decoded stream is trimmed to total_bytes.

Scope (bounded, mirrors iso9660/ps1-bincue): CISO v1 only. ZSO (lz4),
CSO v2, DAX, JISO are refused by magic/version — they are separate rows.
Decompression is stdlib zlib; the container parsing is the substance.

Runtime is stdlib-only per DESIGN.md § 4.
"""

from __future__ import annotations

import struct
import zlib

from substratum.contract import ByteSource, ByteView, FileSource

__all__ = ["sniff", "normalize_cso"]

_MAGIC = b"CISO"
_HEADER = struct.Struct("<4sIQIBBBB")  # magic, header_size, total, block, ver, align, u, u
_HEADER_SIZE = 24
_PLAIN_BIT = 0x8000_0000
_OFFSET_MASK = 0x7FFF_FFFF
_SUPPORTED_BLOCK = 2048


class _CisoSource:
    """A ByteSource over the decoded inner ISO stream.

    Nothing is materialized (DESIGN.md §1): `read_at` maps output offsets
    to CISO blocks and decodes each on demand, with a one-block cache so
    sequential reads within a block do not re-inflate.
    """

    def __init__(
        self, base: ByteSource, total: int, block_size: int, align: int, index: list[int]
    ) -> None:
        self._base = base
        self._total = total
        self._bs = block_size
        self._align = align
        self._index = index  # raw u32 entries, len == nblocks + 1
        self._cache_i = -1
        self._cache_block = b""

    def size(self) -> int:
        return self._total

    def _block(self, i: int) -> bytes:
        if i == self._cache_i:
            return self._cache_block
        entry = self._index[i]
        start = (entry & _OFFSET_MASK) << self._align
        end = (self._index[i + 1] & _OFFSET_MASK) << self._align
        if end < start or end > self._base.size():
            raise ValueError(f"cso: block {i} range [{start}, {end}) out of file bounds")
        chunk = self._base.read_at(start, end - start)
        if entry & _PLAIN_BIT:
            block = chunk[: self._bs]
        else:
            block = zlib.decompress(chunk, -15)  # raw DEFLATE
        if len(block) != self._bs:
            raise ValueError(
                f"cso: block {i} decoded to {len(block)} bytes, expected {self._bs}"
            )
        self._cache_i = i
        self._cache_block = block
        return block

    def read_at(self, offset: int, size: int) -> bytes:
        if offset < 0 or size < 0 or offset + size > self._total:
            raise ValueError(
                f"read [{offset}, {offset + size}) out of bounds (size {self._total})"
            )
        out = bytearray()
        pos, stop = offset, offset + size
        while pos < stop:
            block = self._block(pos // self._bs)
            within = pos % self._bs
            take = min(self._bs - within, stop - pos)
            out += block[within : within + take]
            pos += take
        return bytes(out)


def sniff(source: ByteSource) -> bool:
    """True when the source starts with the CISO magic. ZSO/DAX are false."""
    if source.size() < 4:
        return False
    return source.read_at(0, 4) == _MAGIC


def normalize_cso(source) -> ByteView:
    """Decode a CISO v1 image to a ByteView of the inner ISO.

    Accepts a path (str/Path) or a ByteSource. Parses + validates the
    header and index eagerly (structural reds fire here, at check 1);
    block decoding is lazy through `_CisoSource`.
    """
    src = source if isinstance(source, ByteSource) else FileSource(source)
    if src.size() < _HEADER_SIZE:
        raise ValueError("cso: file smaller than CISO header")

    magic, header_size, total, block_size, ver, align, _u0, _u1 = _HEADER.unpack(
        src.read_at(0, _HEADER_SIZE)
    )
    if magic != _MAGIC:
        raise ValueError(f"cso: bad magic {magic!r} (ZSO/DAX/CSO v2 are separate rows)")
    if ver != 1:
        raise ValueError(f"cso: unsupported version {ver} (CSO v1 only)")
    if block_size != _SUPPORTED_BLOCK:
        raise ValueError(f"cso: unsupported block size {block_size} (2048 only)")

    nblocks = (total + block_size - 1) // block_size
    idx_off = header_size if header_size else _HEADER_SIZE
    index = list(struct.unpack(f"<{nblocks + 1}I", src.read_at(idx_off, 4 * (nblocks + 1))))

    # Eager index validation — the block offsets (top bit stripped) must be
    # monotonic non-decreasing and within the file. These reds fire
    # deterministically at check 1, independent of which blocks a read touches.
    fsize = src.size()
    prev = -1
    for i, entry in enumerate(index):
        off = (entry & _OFFSET_MASK) << align
        if off > fsize:
            raise ValueError(f"cso: index[{i}] offset {off} past EOF {fsize}")
        if off < prev:
            raise ValueError(f"cso: index[{i}] offset {off} < previous {prev}")
        prev = off

    return ByteView(source=_CisoSource(src, total, block_size, align, index), format="cso")
