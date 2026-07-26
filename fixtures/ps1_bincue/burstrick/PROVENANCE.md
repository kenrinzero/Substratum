# BursTrick - Wake Boarding!! (USA) retail PS1 mixed-XA anchor

- **Title:** BursTrick - Wake Boarding!!
- **Region:** USA
- **Platform:** Sony PlayStation
- **Disc identity:** `SLUS_013.17`
- **Track layout:** one `MODE2/2352` data track, index `00:00:00`
- **Operator drop:** `BursTrick - Wake Boarding!! (USA).bin` + matching
  CUE under gitignored `fixtures/_local/bin-chd-playstation/`
- **Archive source:** Internet Archive item
  [`burs-trick-wake-boarding-eu-jp-us-2000-sports-racing-bin-chd-playstation`](https://archive.org/details/burs-trick-wake-boarding-eu-jp-us-2000-sports-racing-bin-chd-playstation)
- **Archive member:** `BursTrick - Wake Boarding!! (US) (2000) (Sports,
  Racing) (BIN) (Playstation).zip`

## Source-chain verification

The Archive member is 144,353,033 bytes with published CRC32 `d1ceab78`,
MD5 `719a4e355452b4a4d5d69726b2569b7d`, and SHA-1
`9b2eb284a92e5a14fe67c7d258031f8f8b380404`. A fresh download matched the
published size, MD5, and SHA-1.

Inside that ZIP, the BIN member is 369,842,592 bytes with CRC32
`969e9f78`; the CUE member is 99 bytes with CRC32 `a1fcce1a`. Both values
and sizes match the operator drop exactly. The archive names the CUE
`(US)` while its contents reference the `(USA).bin`; the local CUE was
renamed to `(USA).cue` without changing its 99 bytes.

## Verified local carrier hashes

| File | Algorithm | Digest |
|---|---|---|
| BIN | CRC32 | `969e9f78` |
| BIN | MD5 | `6f55001cffb01ec619ff2d726a134fff` |
| BIN | SHA-1 | `c6e9d6c0685b67614891166b515ba666ef05892d` |
| BIN | SHA-256 | `21f02044173b2298199fb3d0adf1673520a3b044fd61e7f0b7b1f30a0b90ce40` |
| CUE | CRC32 | `a1fcce1a` |
| CUE | SHA-256 | `c37e5918d9eaaf7ceedb456210d60e98c3d515bf23b2dc909c83bf7b82b9a445` |

## Published proof

`expected.manifest.json` contains metadata only. It is independently
authored by `seedtools/stage_ps1_form2_retail_anchor.py` from a temporary
fixed-width 2048-byte view, with pycdlib and 7-Zip agreeing on all 9
ISO9660 entries. chdman 0.288 accepts and verifies the original BIN/CUE
as `MODE2_RAW`. Reference payloads extracted by 7-Zip remain gitignored.

The raw image has 157,246 clean Mode-2 sectors, including 60,666 Form-2
sectors distributed through real STR/XA extents. The public sector API
preserves their complete 2324-byte payloads and XA metadata. The
committed manifest describes the normalizer's deliberately fixed-width
2048-byte cooked stream (322,039,808 bytes, SHA-256
`293af0bc2523225c31940b6af3b62109c1063213a2fd891b3fd927e2281db7bd`);
it does not claim that the trailing 276 Form-2 payload bytes are part of
the ISO9660 file-tree view.
