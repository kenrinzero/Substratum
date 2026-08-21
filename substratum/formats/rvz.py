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


def sniff(source: ByteSource) -> bool:
    """True when the source starts with the RVZ magic 'RVZ'."""
    if source.size() < 4:
        return False
    return source.read_at(0, 3) == b"RVZ"


def normalize_rvz(source) -> ByteView:
    """Decompress an RVZ to a ByteView of the raw disc image."""
    return convert_disc_to_iso(source, format_tag="rvz")
