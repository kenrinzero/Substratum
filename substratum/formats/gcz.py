"""GCZ container normalizer (NORMALIZERS.md row `gcz`).

Returns exactly ONE layer — a ByteView of the decompressed disc image.
Never recurses into inner filesystems (caller composes, DESIGN.md §1).

Decompression delegates to DolphinTool (`dolphin-tool convert`), the
reference codec for Dolphin's legacy CompressedBlob container (magic
0xB10BC001; sub_type 0 = GameCube, 1 = Wii).  The on-disk layout — a
32-byte little-endian header, a u64 block-offset array whose bit 63 marks
stored-raw blocks, a u32 hash array, then zlib block data — is
characterized and differentially proven by the spec-derived decoder in
tests/test_gcz.py (wit cannot read GCZ).  Tool plumbing is shared with
the `rvz` unit in `substratum/formats/_dolphin.py`.

Runtime is stdlib-only per DESIGN.md § 4.
"""

from __future__ import annotations

import struct

from substratum.contract import ByteSource, ByteView
from substratum.formats._dolphin import convert_disc_to_iso

__all__ = ["sniff", "normalize_gcz"]

_GCZ_MAGIC = 0xB10BC001


def sniff(source: ByteSource) -> bool:
    """True when the source starts with the GCZ magic 0xB10BC001 (LE)."""
    if source.size() < 4:
        return False
    return struct.unpack("<I", source.read_at(0, 4))[0] == _GCZ_MAGIC


def normalize_gcz(source) -> ByteView:
    """Decompress a GCZ to a ByteView of the raw disc image."""
    return convert_disc_to_iso(source, format_tag="gcz")
