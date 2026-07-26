"""Public one-layer normalization dispatcher (DESIGN.md §1)."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from substratum.contract import ByteSource, ByteView, FileSource, FileTree
from substratum.formats.chd import normalize_chd, sniff as sniff_chd
from substratum.formats.cso import normalize_cso, sniff as sniff_cso
from substratum.formats.gc_fst import normalize_gc_fst, sniff as sniff_gc_fst
from substratum.formats.iso9660 import normalize_iso9660, sniff as sniff_iso9660
from substratum.formats.ps1_bincue import (
    normalize_ps1_bincue,
    sniff as sniff_ps1_bincue,
)
from substratum.formats.saturn_dc_raw import (
    normalize_saturn_dc_raw,
    sniff as sniff_saturn_dc_raw,
)
from substratum.formats.three_ds_cci import (
    normalize_3ds_cci,
    sniff as sniff_3ds_cci,
)
from substratum.formats.wii_u8_arc import (
    normalize_wii_u8_arc,
    sniff as sniff_wii_u8_arc,
)
from substratum.formats.xdvdfs import normalize_xdvdfs, sniff as sniff_xdvdfs

NormalizeResult = ByteView | FileTree
Normalizer = Callable[[object], NormalizeResult]
Sniffer = Callable[[ByteSource], bool]


@dataclass(frozen=True, slots=True)
class _Format:
    name: str
    sniff: Sniffer
    normalize: Normalizer


# Specific raw-sector formats precede ISO9660. Saturn's mode-byte check must
# precede PS1's path-bound BIN/CUE check because both use the CD sync pattern.
_FORMATS = (
    _Format("3ds-cci", sniff_3ds_cci, normalize_3ds_cci),
    _Format("chd", sniff_chd, normalize_chd),
    _Format("cso", sniff_cso, normalize_cso),
    _Format("gc-fst", sniff_gc_fst, normalize_gc_fst),
    _Format("wii-u8-arc", sniff_wii_u8_arc, normalize_wii_u8_arc),
    _Format("xdvdfs", sniff_xdvdfs, normalize_xdvdfs),
    _Format("saturn-dc-raw", sniff_saturn_dc_raw, normalize_saturn_dc_raw),
    _Format("ps1-bincue", sniff_ps1_bincue, normalize_ps1_bincue),
    _Format("iso9660", sniff_iso9660, normalize_iso9660),
)
_BY_NAME = {entry.name: entry for entry in _FORMATS}


def normalize(source, *, format: str | None = None) -> NormalizeResult:
    """Normalize exactly one recognized layer to a ByteView or FileTree.

    ``format`` pins a registered normalizer and bypasses sniffing. With no
    pin, the source is sniffed in registry order. ByteViews remain caller-
    composed: pass ``view.source`` to a later call when another layer exists.
    """
    if format is not None:
        try:
            entry = _BY_NAME[format]
        except KeyError:
            supported = ", ".join(_BY_NAME)
            raise ValueError(
                f"unknown format {format!r}; supported formats: {supported}"
            ) from None
        return entry.normalize(source)

    probe = source if isinstance(source, ByteSource) else FileSource(source)
    for entry in _FORMATS:
        if entry.sniff(probe):
            return entry.normalize(source)

    raise ValueError("unrecognized format; pass format= to select a normalizer")
