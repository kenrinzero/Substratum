# Synthetic decrypted-NCCH fixture for the encrypted-NCCH normalizer

Authored by `seedtools/make_3ds_ncch_enc_fixture.py`. This is a small **NoCrypto
(decrypted)** NCCH with known region payloads, exercising every region type
(extended header, plain, ExeFS, RomFS).

## Why decrypted, not encrypted

A committed encrypted NCCH that the production ctrtool (retail AES keys compiled
in) can decrypt is **not authorable without retail key material**: encrypting
an NCCH under the standard key requires the retail AES key, which this repo
never handles (DESIGN §5). 3dstool's `--fixed-key` uses a debug key that ctrtool
cannot decrypt, and the ExeFS sub-layer's separate crypto diverges between the
two tools even under dev keys. Recorded finding, 2026-07-29.

The committed fixture therefore exercises the layers testable without retail
bytes: the NCCH header shape, the region table, and the downstream `three_ds_ncch`
composition. The structural-red tests mutate this fixture's header to declare
encryption / non-standard crypto / seed, asserting the normalizer refuses them
**before** any ctrtool call. The actual decrypt path + genuine two-party
differential is carried by the retail Biohazard anchor (skip-if-absent).

## Shape

- `decrypted.ncch` — 5,120 bytes, NoCrypto, format version 2, block size 0x200.
- Regions: `extendedheader.bin` @0x200/0x800 · `plain.bin` @0xA00/0x200 ·
  `exefs.bin` @0xC00/0x400 · `romfs.bin` @0x1000/0x400.

Re-generate with `uv run python seedtools/make_3ds_ncch_enc_fixture.py`.
