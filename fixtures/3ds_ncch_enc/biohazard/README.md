# Biohazard — The Mercenaries 3D (Japan) encrypted-NCCH retail anchor

The source is the operator-provided `.cia` in the gitignored `fixtures/_local/`
directory (DESIGN §5). Its original download location was not recorded, so this
fixture makes no public preservation-source claim.

Validated encrypted NCCH identity (via pinned ctrtool v1.3.0 on the content slice):

- Container: CIA, 698,837,440 bytes; content slice at file offset 0x3900,
  698,807,808 bytes (`0x29A6F600`).
- Title ID: `0004000000043E00`; product code: `CTR-P-ABMJ`.
- Crypto: **standard** (`Secure (0)`, `ncchflag[3] == 0x00`, keyslot `0x2C`);
  **not** seed-encrypted (`Title seed check 00000000`).
- NCCH regions (encrypted on-media): Exheader @0x400; ExeFS @0xC00/0x50FA00;
  RomFS @0x510600/0x2955F000; Plain @0xA00/0x200.

## Two-party differential (the genuine oracle)

`uv run python seedtools/stage_3ds_ncch_enc_retail_anchor.py` requires the
SHA-256-pinned ctrtool v1.3.0 and 3dstool v1.2.6 executables. Both tools
independently **decrypt** the encrypted NCCH content slice (ctrtool default mode,
3dstool auto-retail) and must produce byte-identical exheader/plain/exefs/romfs
regions. This is the load-bearing two-party check: ctrtool's `-p` (no-decrypt)
path is a tautology (`-p` returns encrypted bytes), so ctrtool-decrypt vs
3dstool-decrypt is the honest independent oracle.

The NCCH header's declared SHA-256 protected hashes provide the independent
**correctness** anchor: the decrypted image is fed back through `three_ds_ncch`,
which validates those hashes — a wrong decryption fails them.

Only this provenance and `anchor.json` enter Git. The independently
decrypted region references stay local and ignored. No key bytes or decrypted
retail payloads are committed.
