"""Public one-layer normalization dispatcher (DESIGN.md §1)."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from substratum.contract import ByteSource, ByteView, FileSource, FileTree
from substratum.formats.chd import normalize_chd, sniff as sniff_chd
from substratum.formats.ciso import normalize_ciso, sniff as sniff_ciso
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
from substratum.formats.three_ds_cia import (
    normalize_3ds_cia,
    sniff as sniff_3ds_cia,
)
from substratum.formats.three_ds_ncch import (
    normalize_3ds_ncch,
    sniff as sniff_3ds_ncch,
)
from substratum.formats.three_ds_romfs import (
    normalize_3ds_romfs,
    sniff as sniff_3ds_romfs,
)
from substratum.formats.three_ds_ncch_enc import (
    normalize_3ds_ncch_enc,
    sniff as sniff_3ds_ncch_enc,
)
from substratum.formats.three_ds_ncch_enc_96 import (
    normalize_3ds_ncch_enc_96,
    sniff as sniff_3ds_ncch_enc_96,
)
from substratum.formats.three_ds_ncch_enc_seed import (
    normalize_3ds_ncch_enc_seed,
    sniff as sniff_3ds_ncch_enc_seed,
)
from substratum.formats.wii_disc import (
    normalize_wii_disc,
    sniff as sniff_wii_disc,
)
from substratum.formats.wii_partition import (
    normalize_wii_partition,
    sniff as sniff_wii_partition,
)
from substratum.formats.wii_fst import (
    normalize_wii_fst,
    sniff as sniff_wii_fst,
)
from substratum.formats.wii_u8_arc import (
    normalize_wii_u8_arc,
    sniff as sniff_wii_u8_arc,
)
from substratum.formats.rvz import normalize_rvz, sniff as sniff_rvz
from substratum.formats.gcz import normalize_gcz, sniff as sniff_gcz
from substratum.formats.wbfs import normalize_wbfs, sniff as sniff_wbfs
from substratum.formats.nkit import normalize_nkit, sniff as sniff_nkit
from substratum.formats.xdvdfs import normalize_xdvdfs, sniff as sniff_xdvdfs
from substratum.formats.zip import normalize_zip, sniff as sniff_zip

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
    _Format("cia", sniff_3ds_cia, normalize_3ds_cia),
    _Format("3ds-ncch-enc-seed", sniff_3ds_ncch_enc_seed, normalize_3ds_ncch_enc_seed),
    # New3DS 9.6/9.3 must precede both the standard encrypted and the decrypted
    # NCCH sniffers: its header is plaintext (so 3ds-ncch would also claim it),
    # and it carries ncchflag[3] in {0x0A, 0x0B} — outside the {0x00,0x01} set
    # 3ds-ncch-enc accepts. Registered first so 0x0A/0x0B dispatch to pure-Python
    # CTR decryption (vendored ctrtool cannot decrypt keyslot 0x1B/0x18).
    _Format(
        "3ds-ncch-enc-96",
        sniff_3ds_ncch_enc_96,
        normalize_3ds_ncch_enc_96,
    ),
    # Encrypted NCCH must precede its decrypted sibling: an encrypted content's
    # NCCH magic is plaintext, so both sniffers see it; this one accepts only
    # the encrypted (standard-crypto) form and routes it to decryption.
    _Format("3ds-ncch-enc", sniff_3ds_ncch_enc, normalize_3ds_ncch_enc),
    _Format("3ds-ncch", sniff_3ds_ncch, normalize_3ds_ncch),
    _Format("3ds-romfs", sniff_3ds_romfs, normalize_3ds_romfs),
    _Format("wii-disc", sniff_wii_disc, normalize_wii_disc),
    _Format("wii-partition", sniff_wii_partition, normalize_wii_partition),
    _Format("wii-fst", sniff_wii_fst, normalize_wii_fst),
    _Format("chd", sniff_chd, normalize_chd),
    # ciso (wit's GC/Wii compact ISO) shares the 'CISO' magic with the PSP
    # cso unit; both sniffers disambiguate on the LE u32 at 0x04 (2 MiB
    # block size vs PSP header size 0x18), and ciso is registered first so
    # a GC/Wii compact ISO can never dispatch to the PSP parser.
    _Format("ciso", sniff_ciso, normalize_ciso),
    _Format("cso", sniff_cso, normalize_cso),
    _Format("zip", sniff_zip, normalize_zip),
    _Format("rvz", sniff_rvz, normalize_rvz),
    # GCZ's magic (0xB10BC001 at 0) cannot collide with a disc header, but it
    # stays beside rvz and ahead of gc-fst so both Dolphin containers sit
    # before any raw-image sniffer that might see a decoded/odd cousin.
    _Format("gcz", sniff_gcz, normalize_gcz),
    # WBFS magic ("WBFS" at 0) is distinct from every disc-header format, but
    # it stays in the Dolphin-container block ahead of the raw-image sniffers.
    _Format("wbfs", sniff_wbfs, normalize_wbfs),
    # A GC .nkit.iso begins with a real GC disc header, so this sniffer MUST
    # precede gc-fst or NKit files would dispatch to the compacted walk.
    _Format("nkit", sniff_nkit, normalize_nkit),
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
