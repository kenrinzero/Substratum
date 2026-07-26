# Gallop Racer 2001 (USA) retail PS2 ISO anchor

- **Title:** Gallop Racer 2001
- **Region:** USA / NTSC
- **Platform:** Sony PlayStation 2
- **Internal identity:** `SLUS_202.55` / `SLUS-20255`, version 1.00
- **Media view:** plain 2048-byte-sector ISO9660 image
- **Operator drop:** `Gallop Racer 2001 (USA).iso` under gitignored
  `fixtures/_local/Gallop Racer 2001 (USA)/`
- **Original download source:** not retained with the operator's corpus
- **Public fixity evidence:** [ScreenScraper record][screenscraper]
- **Independent identity evidence:** [PSX Data Center][psxdatacenter] and
  [GameFAQs release data][gamefaqs]
- **Metadata checked:** 2026-07-26

[screenscraper]: https://screenscraper.fr/rominfos.php?romid=300995
[psxdatacenter]: https://psxdatacenter.com/psx2/games2/SLUS-20255.html
[gamefaqs]: https://gamefaqs.gamespot.com/ps2/520006-gallop-racer-2001/data

## Verified carrier hashes

| Algorithm | Digest |
|---|---|
| CRC32 | `77f06762` |
| MD5 | `79d3630668c55f2cabebf326f1a631d8` |
| SHA-1 | `8ac72dc8cfeb8879e44bf22706a109d064d9c5cf` |
| SHA-256 | `d0b02a886a77491f5636c5bce4f163d6c7922ff23b8ce57e208f6a56a18d2a64` |

The image is 790,986,752 bytes. Its CRC32, MD5, and SHA-1 match the
public preservation metadata exactly; SHA-256 was computed locally.
`SYSTEM.CNF` names `SLUS_202.55`, version 1.00, NTSC, matching the public
USA release identity.

## Published proof

`expected.manifest.json` contains metadata only. It is independently
authored by `seedtools/stage_iso9660_retail_anchor.py`: pycdlib and pinned
7-Zip must agree on the complete ISO9660 listing, and 7-Zip supplies the
gitignored reference payloads. The stager also requires the exact
carrier hashes and `SYSTEM.CNF` identity before producing the manifest.

The retail ISO and extracted reference payloads never enter Git.
