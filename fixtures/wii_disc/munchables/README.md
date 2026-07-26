# The Munchables (USA) Wii disc metadata anchor

The local operator-provided retail image is
`fixtures/_local/The Munchables (USA).iso`. Its original download location
was not recorded, so this fixture makes no public preservation-source claim.

Validated carrier identity:

- Disc ID: `RQCEAF`
- Region: NTSC/USA
- Revision: 0
- Size: 4,699,979,776 bytes
- CRC32: `ab7f4478`
- MD5: `2e2592f013d1d7cad7a9e54ab1521495`
- SHA-1: `2b7706b9f3cd251922c72fddfdcf35231b77012c`
- SHA-256:
  `64c012f35d0c8b97e34c13e47060550b36d89fc36bed2691661cfdf108671cbb`

This is a scrubbed encrypted image, not a pristine whole-disc preservation
hash anchor. The unused scrubbed clusters do not affect this unit's purpose:
pinned wit v3.05a r8638 reports both partitions as well signed and verifies
both as `+OK`. Earlier qualification with Dolphin 2606 agreed with wit on the
disc identity and all 61 extracted source/system files totaling
1,690,942,404 bytes.

`uv run python seedtools/stage_wii_disc_retail_anchor.py` requires the
SHA-256-pinned wit executable. It parses wit's independent partition report,
requires successful verification of both partitions, and copies the complete
opaque encrypted ranges directly from wit-authored offsets:

- `partition-update.bin`: offset 327,680; size 187,334,656; SHA-256
  `61338bbb4ea345521b103c04908101ef78fb03159d7f24026c701a7b66b7fdec`
- `partition-data.bin`: offset 260,046,848; size 4,424,728,576; SHA-256
  `0c1af607b6c22d41eaa661fbb3ffd18bf9bf95acf473769fc43712d032d1a3e0`

Only this provenance and `expected.manifest.json` enter Git. The retail image
and complete partition references remain local and ignored. No key bytes,
decrypted clusters, or inner filesystem payloads are part of this fixture.
