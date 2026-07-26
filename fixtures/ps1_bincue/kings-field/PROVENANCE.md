# King's Field (Japan) retail PS1 anchor

- **Title:** King's Field
- **Region:** Japan
- **Platform:** Sony PlayStation
- **Track layout:** one `MODE2/2352` data track, index `00:00:00`
- **Operator drop:** `King's Field (Japan).bin` + matching CUE under
  gitignored `fixtures/_local/`
- **Source evidence:** the operator-supplied Vimm's Lair verification note
  identifies its PlayStation media as Redump-verified (2025-05-29).

## Verified carrier hashes

| File | Algorithm | Digest |
|---|---|---|
| BIN | CRC32 | `54c8f64a` |
| BIN | MD5 | `c2b8b1652407c6c8107b0c93e20624a6` |
| BIN | SHA-1 | `00bfd94ce99bf214b03bdaa07de99b9ca1466550` |
| BIN | SHA-256 | `ae74beba377d686bfaa292ea40df8ade4454ec3139c2b5152364e02aac90b3d9` |
| CUE | SHA-256 | `955b14c0a14254dd2866c0ee0ab15e02906f8020120295f6a681a62aeeb90ab7` |

The Redump CRC32, MD5, and SHA-1 values match the supplied verification
note exactly; SHA-256 was computed locally.

## Published proof

`expected.manifest.json` contains metadata only. It is independently
authored by `seedtools/stage_ps1_retail_anchor.py` from a temporary
2048-byte view, with pycdlib and 7-Zip agreeing on all 470 ISO9660
entries. chdman 0.288 accepts and verifies the original BIN/CUE as
`MODE2_RAW`. Reference payloads extracted by 7-Zip remain gitignored.

The raw image has 12,916 clean Mode-2 sectors. Exactly sectors 12-15 are
Form 2; all 2324 payload bytes in each are zero. They lie in ISO9660's
pre-PVD system area. Every later sector is Form 1. This anchor therefore
proves only the bounded zero-padding exception, not general XA Form-2
video or ADPCM support.
