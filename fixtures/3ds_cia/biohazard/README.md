# Biohazard — The Mercenaries 3D (Japan) CIA retail anchor

The source is the operator-provided `.cia` in the gitignored `fixtures/_local/`
directory (DESIGN section 5). Its original download location was not recorded,
so this fixture makes no public preservation-source claim.

Validated CIA identity (via pinned ctrtool v1.3.0):

- File: 698,837,440 bytes; CiaHeader 0x2020, type Normal, format version Cia.
- Title ID `0004000000043E00`; product code `CTR-P-ABMJ`.
- Section sizes: Cert 0xA00 · Ticket 0x350 · TMD 0xB34 · Content 0x29A6F600 ·
  Footer 0x3AC0. Content section lands at `align64(header+cert+ticket+tmd)`
  = 0x3900 (64-byte per-section alignment).
- Single content (TMD ContentInfo index 0x0000); the content blob is an
  encrypted NCCH (standard crypto, keyslot 0x2C).

## Independent correctness anchor

`uv run python seedtools/stage_3ds_cia_retail_anchor.py` requires the
SHA-256-pinned ctrtool v1.3.0 and 3dstool v1.2.6. The TMD's content-chunk
record declares the content SHA-256, and the on-media content blob (streamed
directly from the CIA at the computed offset) hashes to that exact value
(`bb6a9bfd…`). The runtime normalizer recomputes and compares this hash
independently of the seedtool's value.

Only this provenance and `anchor.json` enter Git. The on-media
content blob (encrypted retail bytes) stays local and ignored. The content is
opaque to this layer — a caller composes `3ds-ncch-enc` to decrypt it.
