"""RVZ container normalizer (NORMALIZERS.md row `rvz`).

Returns exactly ONE layer — a ByteView of the decompressed disc image.
Never recurses into inner filesystems (caller composes, DESIGN.md §1).

Decompression delegates to DolphinTool (`dolphin-tool convert`), the
reference RVZ codec from the Dolphin emulator project; the tool plumbing
is shared with the `gcz` unit in `substratum/formats/_dolphin.py`.

Runtime is stdlib-only per DESIGN.md § 4.
"""

from __future__ import annotations

import shutil  # noqa: F401  (tests monkeypatch rvz_module.shutil.which)

from substratum.contract import ByteSource, ByteView
from substratum.formats._dolphin import (
    TempFileSource as _TempFileSource,  # noqa: F401  (test surface)
    convert_disc_to_iso,
    dolphin_tool_exe as _dolphin_tool_exe,  # noqa: F401  (test surface)
)

__all__ = ["sniff", "normalize_rvz"]


_RVZ_MAGIC = b"RVZ\x01"


def sniff(source: ByteSource) -> bool:
    """True when the source starts with the RVZ magic b'RVZ\\x01'.

    All four bytes are checked. The version byte is part of the magic
    (verified on the GT Cube and Ghost Squad anchors, both `52 56 5a 01`);
    matching only `RVZ` left a 3-byte signature with no corroboration,
    against the house rule recorded in `nkit.py`.
    """
    if source.size() < len(_RVZ_MAGIC):
        return False
    return source.read_at(0, len(_RVZ_MAGIC)) == _RVZ_MAGIC


def normalize_rvz(source) -> ByteView:
    """Decompress an RVZ to a ByteView of the raw disc image."""
    return convert_disc_to_iso(source, format_tag="rvz")
