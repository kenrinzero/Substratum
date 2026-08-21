"""CISO compact-ISO container normalizer (NORMALIZERS.md row `ciso`).

wit's CISO — the compact-ISO container wit 3.05a reads and writes for
GameCube/Wii images. The only other writer observed in the wild is
NKit 2, whose output is the same container plus an appended recovery
trailer. Decodes to a ByteView of the disc address space; exactly ONE
layer (DESIGN.md §1): the caller re-normalizes with gc-fst — never
recurse.

Layout (characterized empirically 2026-08-21 against wit 3.05a's own
reader AND writer — the staged Luigi's Mansion anchor plus a wit-written
Hulk round-trip):

  0x0000  magic 'CISO'
  0x0004  u32 LE block size — wit and NKit both write 0x200000 (2 MiB);
          any other value is out of scope and refused
  0x0008  block map: ONE byte per block, 1 = present, 0 = absent
          (zero-filled on decode). The map covers the fixed single-layer
          Wii-size address space (ceil(4_699_979_776 / 0x200000) = 2242
          entries) and lives inside the fixed 0x8000-byte header area.
  0x8000  PRESENT blocks' payloads as fixed block-size slots stored RAW
          (no compression), packed in ascending block order: slot j
          holds present-block j — NOT block index j. GC content occupies
          a block prefix of the address space; the tail blocks are
          absent.
  EOF     past the last slot: nothing, or an NKit v2 recovery trailer
          (starts b'NKIT'; the observed one is 0x240 bytes carrying the
          original disc size as BE u32). wit ignores it; so does this
          normalizer.

The container declares no total size anywhere. wit's reader always
reconstructs the fixed single-layer Wii size (verified: `wit COPY` of a
GC-content CISO emits a 4,699,979,776-byte ISO), so the ByteView reports
that size. Dual-layer Wii CISOs are untested and out of scope; a file
whose slots exceed the 2242-block map fails the trailing-data check.

Load-bearing wit behavior (recorded): `wit copy` SCRUBS GC junk — it
drops all-junk blocks from the map and zeroes junk spans inside stored
blocks. wit-authored CISOs therefore contain zeroed junk; NKit-authored
ones preserve original junk bytes. Differentials against `wit copy`
output must expect one-directional nonzero->zero differences confined to
junk regions (blocks 1 and 604 on the Luigi anchor) — never inside game
files (proven per-file by the retail gate).

Sniffer disambiguation (the reason this unit exists): the PSP `cso` unit
shares the 'CISO' magic. PSP CISO v1 carries LE u32 0x18 (header size)
at 0x04; this format carries LE u32 0x200000 (block size). ciso is
registered BEFORE cso and both sniffers key on their 0x04 word, so the
two families can never cross-dispatch.

Runtime is stdlib-only per DESIGN.md § 4 — the format is a pure block
remap over raw slots; there is nothing to decompress.
"""

from __future__ import annotations

import struct

from substratum.contract import ByteSource, ByteView, FileSource

__all__ = ["sniff", "normalize_ciso"]

_MAGIC = b"CISO"
_HEADER_AREA = 0x8000
_MAP_OFF = 0x08
_BLOCK_SIZE = 0x200000
_TOTAL = 4_699_979_776  # fixed single-layer Wii-size address space
_NBLOCKS = (_TOTAL + _BLOCK_SIZE - 1) // _BLOCK_SIZE  # 2242
_MAP_END = _MAP_OFF + _NBLOCKS
_TRAILER_MAGIC = b"NKIT"
_MAX_TRAILER = _BLOCK_SIZE


class _CisoSource:
    """A ByteSource over the decoded disc address space.

    Nothing is materialized (DESIGN.md §1): `read_at` maps output blocks
    to their slots and reads the raw bytes on demand; absent blocks read
    as zeros. Slots are contiguous raw file ranges, so no cache is needed.
    """

    def __init__(self, base: ByteSource, rank: list[int]) -> None:
        self._base = base
        self._rank = rank  # per block: slot index, or -1 when absent
        self._total = _TOTAL

    def size(self) -> int:
        return self._total

    def read_at(self, offset: int, size: int) -> bytes:
        if offset < 0 or size < 0 or offset + size > self._total:
            raise ValueError(
                f"read [{offset}, {offset + size}) out of bounds (size {self._total})"
            )
        out = bytearray()
        pos, stop = offset, offset + size
        while pos < stop:
            block = pos // _BLOCK_SIZE
            within = pos % _BLOCK_SIZE
            take = min(_BLOCK_SIZE - within, stop - pos)
            slot = self._rank[block]
            if slot < 0:
                out += bytes(take)
            else:
                out += self._base.read_at(
                    _HEADER_AREA + slot * _BLOCK_SIZE + within, take
                )
            pos += take
        return bytes(out)


def sniff(source: ByteSource) -> bool:
    """True for the wit/NKit CISO shape: 'CISO' + LE 2 MiB block size at
    0x04 + at least one present map entry. PSP CISO v1 (the `cso` unit)
    carries LE 0x18 there and must not dispatch here — or vice versa."""
    if source.size() < _HEADER_AREA:
        return False
    head = source.read_at(0, _MAP_END)
    if head[:4] != _MAGIC:
        return False
    (block_size,) = struct.unpack_from("<I", head, 4)
    if block_size != _BLOCK_SIZE:
        return False
    return 1 in head[_MAP_OFF:_MAP_END]


def normalize_ciso(source) -> ByteView:
    """Decode a CISO image to a ByteView of the disc address space.

    Accepts a path (str/Path) or a ByteSource. The header, map, and slot
    arithmetic are validated eagerly (structural reds fire here, at
    check 1); block reads are lazy through `_CisoSource`.
    """
    src = source if isinstance(source, ByteSource) else FileSource(source)
    if src.size() < _HEADER_AREA + _BLOCK_SIZE:
        raise ValueError(
            f"ciso: file {src.size()} smaller than header area + one slot"
        )

    head = src.read_at(0, _HEADER_AREA)
    magic = head[:4]
    if magic != _MAGIC:
        raise ValueError(f"ciso: bad magic {magic!r}")
    (block_size,) = struct.unpack_from("<I", head, 4)
    if block_size != _BLOCK_SIZE:
        raise ValueError(
            f"ciso: unsupported block size {block_size:#x} "
            f"(wit/NKit write {_BLOCK_SIZE:#x}; PSP CISO v1 is the cso unit)"
        )

    present: list[int] = []
    for i in range(_NBLOCKS):
        value = head[_MAP_OFF + i]
        if value == 1:
            present.append(i)
        elif value != 0:
            raise ValueError(
                f"ciso: unknown map value {value:#x} at block {i} (0/1 only)"
            )
    if not present:
        raise ValueError("ciso: block map marks no blocks present")
    residue = head[_MAP_END:]
    if any(residue):
        raise ValueError(
            "ciso: nonzero bytes in the header area past the 2242-entry map"
        )

    rank = [-1] * _NBLOCKS
    for slot, block in enumerate(present):
        rank[block] = slot

    needed = sum(
        min(_BLOCK_SIZE, _TOTAL - block * _BLOCK_SIZE) for block in present
    )
    extra = src.size() - _HEADER_AREA - needed
    if extra < 0:
        raise ValueError(
            f"ciso: file ends {-extra} bytes inside slot "
            f"{len(present) - 1} (block {present[-1]})"
        )
    if extra:
        lead = src.read_at(_HEADER_AREA + needed, min(len(_TRAILER_MAGIC), extra))
        if lead != _TRAILER_MAGIC[: len(lead)] or extra > _MAX_TRAILER:
            raise ValueError(
                "ciso: trailing data after the last slot is neither EOF nor "
                "an NKit recovery trailer"
            )

    return ByteView(source=_CisoSource(src, rank), format="ciso")
