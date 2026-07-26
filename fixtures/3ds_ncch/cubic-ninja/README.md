# Cubic Ninja (Japan) decrypted NCCH metadata anchor

The source is partition 0 extracted independently by the committed 3DS CCI
stager from the local operator-provided `Cubic Ninja (Japan).3ds`. Its original
download location was not recorded, so this fixture makes no public
preservation-source claim.

Validated NCCH identity:

- Path: `fixtures/3ds_cci/cubic-ninja/reference/partition0.cxi`
- Size: 86,430,720 bytes
- SHA-256:
  `b805cdfdf2965e8a6f90990982bf7386ba755811bea52c5d0902bbb799a6af80`
- Title ID: `0004000000034300`
- Product code: `CTR-P-AQNJ`
- Format version: 2
- Crypto key: none (`NoCrypto`)

The NCCH header RSA signature is invalid because this image was modified to
remove encryption. That expected signature failure is not used as content
proof. ctrtool v1.3.0 instead reports GOOD extended-header, ExeFS, and RomFS
protected hashes, and GOOD internal ExeFS section and RomFS IVFC checks.

`uv run python seedtools/stage_3ds_ncch_retail_anchor.py` requires the
SHA-256-pinned ctrtool v1.3.0 and 3dstool v1.2.6 executables. ctrtool supplies
the independent decrypted NCCH identity, region table, and protected-hash
checks. 3dstool extracts each opaque region, after which the stager verifies
its complete hash against the corresponding direct source range:

- `extendedheader.bin`: offset 512; size 2,048; SHA-256
  `f6d8a5193e7bed1fc1c7e3aa0733e2f3e8c4eca6d534f9e07de0c1af0350cc3d`
- `plain.bin`: offset 2,560; size 512; SHA-256
  `b46a299ba59fe45420f113a65957867199b6125595141f944e12fc7d0ee4b556`
- `exefs.bin`: offset 3,072; size 1,452,032; SHA-256
  `8ab4d508067648723505888a15fa203d0867da714de9a7e7409c816b8911b155`
- `romfs.bin`: offset 1,455,104; size 84,975,616; SHA-256
  `09ed1f54e53a3bec3711b33eb3e4ee3993e004fe5786bb79357af5db66566de5`

Only this provenance and `expected.manifest.json` enter Git. The independently
extracted region references remain local and ignored. The normalizer exposes
these regions as opaque slices and does not traverse ExeFS or RomFS.
