# Ape Escape (EU) retail PSP CSO anchor

- **Title:** Ape Escape
- **Region:** Europe
- **Platform:** Sony PlayStation Portable
- **Internal identity:** `UCES00045` / `UCES-00045`, version 1.00
- **Container:** CISO v1, 2048-byte blocks
- **Operator drop:** `Ape Escape (EU).cso` under gitignored
  `fixtures/_local/cso/`
- **Internet Archive item:** [`psp-cso-eu`](https://archive.org/details/psp-cso-eu)
- **Archive member:** `Ape Escape (EU).cso`, source `original`, timestamp
  `2022-06-23T13:09:36Z`
- **Metadata checked:** 2026-07-26 through
  `https://archive.org/metadata/psp-cso-eu`

## Verified carrier hashes

| Algorithm | Digest |
|---|---|
| CRC32 | `72dd6463` |
| MD5 | `b9e4a4df9c7490340dba9635e49189b1` |
| SHA-1 | `4c9fd7d991069a161311945b8e60f3fb0a40dfbd` |
| SHA-256 | `2298624db25dc7615b1fc69605824f635a59202827107de74988255b56d505f1` |

The carrier size is 396,382,256 bytes. Its size, CRC32, MD5, and SHA-1
match the Internet Archive member metadata exactly; SHA-256 was computed
locally.

## Published proof

`expected.manifest.json` contains metadata only. It is independently
authored by `seedtools/stage_cso_retail_anchor.py`: pinned maxcso
decompresses the exact carrier into a temporary ISO, pycdlib and 7-Zip
must agree on its complete ISO9660 listing, and 7-Zip supplies the
gitignored reference payloads. Internal `PARAM.SFO` and `UMD_DATA.BIN`
must identify Ape Escape as `UCES00045` / `UCES-00045`.

The retail CSO, decoded ISO, and extracted reference payloads never enter
Git. The manifest records the decoded stream's size and SHA-256 so the
local optional gate can prove Substratum's complete decoded stream
against maxcso, not only sampled files.
