# Substratum — backlog (Kenrin-paced; one normalizer per session)

Substratum is the normalization foundation for the Spolia program. Its
contract is frozen: each unit adds exactly one container/filesystem layer and
proves it with the four-check gate, including independent differential
byte-range fidelity where available.

## Current boundary

Version **0.0.18** is clean (post New3DS 9.6). **17 normalizers** are GREEN:
the keyless/decrypted floor, the complete Wii chain, the CIA container, and the
full 3DS encrypted-NCCH family — standard + plain-7.x crypto (`3ds-ncch-enc`,
no-seed `{0x00, 0x01}`), 7.x-seed (`3ds-ncch-enc-seed`), and New3DS 9.6
(`3ds-ncch-enc-96`, pure-Python AES-CTR, `0x0B`/`0x1B`). The 9.6 unit bypasses
vendored ctrtool entirely and implements the **two-key NCCH model**
(exheader/ExeFS-superblock/ExeFS-tail = Key0/`0x2C`; `.code`+RomFS =
Key1/`0x1B`). **Next: New3DS 9.3 (`0x0A`/`0x18`) is opportunistic only** —
tooling falls out of the 9.6 path, but a genuine `0x0A` anchor is effectively
lost media. See
[`docs/3DS-KEYED-WORK.md`](docs/3DS-KEYED-WORK.md) § "CORRECTION (2026-07-30)"
and the two-key finding in
[`docs/3DS-PURE-PYTHON-AES-CTR-PLAN.md`](docs/3DS-PURE-PYTHON-AES-CTR-PLAN.md).

## Done

- [x] **Foundation contract and gate:** frozen `ByteSource` / `ByteView` /
      `FileTree` interface, manifests, fixture policy, and four-check
      verification gate (`DESIGN.md`, `schema/`, `substratum/verify.py`).

- [x] **Keyless/decrypted normalizer floor:** 11 GREEN units — `iso9660`,
      `gc-fst`, `chd`, `ps1-bincue`, `saturn/dc-raw`, `cso`, `wii-u8-arc`,
      `xdvdfs`, `3ds-cci`, `3ds-ncch`, and `wii-disc`.

- [x] **Wii partition decode (`wii-partition`):** pure-Python AES-128-CBC
      (NIST SP 800-38A anchored) decrypts the title key and cluster payloads
      into a lazy `ByteView`; synthetic generated-key fixture + wit-extracted
      retail proof against The Munchables. Standard common key supplied
      locally and never committed.

- [x] **Wii decrypted FST (`wii-fst`):** walks the decrypted DATA-partition
      `ByteView` into a `FileTree`. Completes the Wii chain:
      `wii-disc` → `wii-partition` → `wii-fst`.

- [x] **Encrypted 3DS NCCH (`3ds-ncch-enc`):** ctrtool-at-runtime decrypts
      standard-encrypted NCCH content into a decrypted `ByteView` the caller
      composes through `three_ds_ncch` (the `chd`→`iso9660` pattern applied to
      3DS). Genuine two-party differential: ctrtool-decrypt vs 3dstool-decrypt
      on the Biohazard Mercenaries 3D anchor (byte-identical regions); NCCH
      protected hashes are the independent correctness anchor. Standard crypto
      only; 7.x/9.3/seed refused.

- [x] **CIA install container (`cia`):** parses the header-driven section table
      and exposes each section (header/certs/ticket/tmd/content blobs/footer)
      as an opaque slice. Full multi-content support; the TMD content-chunk
      records' declared SHA-256 is the correctness anchor. Completes the 3DS
      stack from outer container to decrypted NCCH regions.

- [x] **7.x-seed encrypted NCCH (`3ds-ncch-enc-seed`):** decrypts
      `Secure (1) (KeyY seeded)` NCCH content inside a CIA via vendored ctrtool
      (7.x keyslot `0x25` compiled in) + the operator-supplied seeddb. Consumes
      a whole CIA (the variant encrypts the NCCH header itself, so a raw slice
      can't be decrypted). Two retail anchors: BoxBoxBoy + Mini Sports.

- [x] **Plain-7.x encrypted NCCH (`3ds-ncch-enc` widening):** widened the
      no-seed scope of `3ds-ncch-enc` to accept `ncchflag[3]` in `{0x00, 0x01}`
      — standard crypto (`0x2C`) plus plain-7.x (`Secure (1)` no-seed, keyslot
      `0x25`). Plaintext header (unlike 7.x-seed), so slice-decryptable from a
      CCI via `3ds-cci`. Retail anchor: Kobayashi (CCI). Load-bearing finding:
      ctrtool and 3dstool agree on `.code`/`icon`/`plain`/`logo`/`exheader`/
      `romfs` content; 3dstool strips a ~207-byte banner signature region that
      ctrtool preserves (documented tooling difference, not a decrypt
      disagreement).

- [x] **9.3 anchor hunt (investigation, 2026-07-30):** confirmed genuine
      `0x0A`-crypto titles are effectively lost media. Three database-"9.3"
      eShop candidates (Adventure Bar Story, Shin Hyu Stone, 3D Gunstar
      Heroes) all qualified as `ncchflag[3]==0x01` (one plain-7.x, two
      7.x-seed) — i.e. already-covered variants. **Load-bearing lesson: a
      title's firmware requirement is unrelated to its NCCH crypto method.**
      "9.3" in title databases usually means the *required FW*, not the
      keyslot; a late-shipping title can require FW 9.3+ yet still ship 7.x
      (`0x01`) crypto. Read ctrtool `-v`'s `Flags:` 4th byte (`00`/`01`/`0A`/
      `0B`), never the firmware version.

- [x] **Proof and hardening pass:** independent-tool differential checks,
      retail/homebrew anchors, path and header rejection, streaming and
      memory-discipline protections, and pinned tool versions are recorded in
      `NORMALIZERS.md` and the archived project log.

- [x] **New3DS 9.6 encrypted NCCH (`3ds-ncch-enc-96`):** pure-Python AES-128-CTR
      (NIST SP 800-38A F.5.1 anchored) + the 3DS hardware key-generator decrypt
      no-seed `0x0B` NCCH content, bypassing vendored ctrtool v1.3.0 (which
      cannot decrypt keyslot `0x1B`). Retail anchor: Fire Emblem Warriors (USA)
      `.3ds`. **Load-bearing finding — the two-key NCCH model:** a 9.6 NCCH uses
      TWO normal keys derived from the same keyY but different keyX slots —
      Key0 (`0x2C`) encrypts the extended header, the ExeFS superblock, and the
      ExeFS tail; Key1 (`0x1B`) encrypts the first ExeFS file (`.code`) and the
      entire RomFS. The ExeFS is one continuous CTR stream whose key switches
      mid-stream. The protected-hash gate caught the naive "one key per region"
      assumption before commit. The committed synthetic (generated test keys)
      exercises the real decrypt path + the ExeFS key split — a stronger
      synthetic than standard-crypto's (which could only author a decrypted
      image). No-seed 9.6 only this unit; seeded-9.6 and 9.3 are the same code
      path once an anchor exists.

## Next (in dispatch order)

- [x] **Wii partition read performance — decrypt-once / caching source
      (consumer request from Stratum, 2026-08-14; DONE same day):** the
      decrypted Wii-partition `ByteView` re-decrypts on every `read_at`, and
      pure-Python AES runs ~0.5 MiB/s, so a census that reads one header per
      file over Mario Kart Wii's data partition (2007 files) took **133 s**
      (re-measured 139.4 s), and any detector that walks structure with
      multi-read access (e.g. a Yaz0 chunk walk) would take hours. **Root
      cause found during the fix: every `read_at` decrypted a whole 0x7C00
      cluster (1,984 AES blocks ≈ 70 ms) even for a 4-byte header read.**
      Fix (key-schedule memoization + block-granular CBC): CBC *decryption*
      chains through ciphertext, so a read decrypts exactly its own 16-byte
      blocks (the preceding ciphertext block serves as the XOR IV; the
      cluster-header IV seeds only block 0), and the AES key schedule is
      expanded once per source (`_aes.expand_key` +
      `cbc_decrypt_blocks` are the new public primitives, NIST-anchored).
      Plus the explicit **`materialize()` decrypt-once spool** (temp-file
      `ByteView`, context-managed, idempotent close, `weakref.finalize`
      fallback) for bulk consumers. The old 4-cluster LRU was removed —
      block-granular reads make it strictly dominated (a repeated read
      costs only its own blocks). **Benchmark: the 2007-file MKWii census
      dropped 139.4 s → 0.61 s (228×)**; scattered small reads now read
      ≤ their own blocks from the parent (test-enforced). Sequential bulk
      throughput is data-bound and unchanged (~0.5 MiB/s: a 3.4 MB
      `.szs` reads in ~7 s; the one-time `materialize()` spool of a 4.4 GB
      partition costs the same ~2.4 h single-threaded and serves plain
      reads after). Context: Stratum BACKLOG, Unit 3 "Separate track
      (Substratum, not Stratum)".

- [ ] **iso9660 both-endian extent-location mismatch (RE4 PAL, consumer
      report from Stratum, 2026-08-14):** the staged
      `SLES_537.02.Resident Evil 4.iso` fails `normalize(format="iso9660")`
      with "both-endian extent location mismatch" — a mastering-era quirk
      where the PVD/directory-record little- and big-endian extent fields
      disagree. This blocks a staged retail fixture for Stratum's census
      (RE4 is one of its four `cri.adx` positive candidates, and the only
      non-Sega one). The unit: reproduce from the staged image, characterize
      the exact divergence (which fields, which records), then decide the
      tolerant parse with the four-check discipline — a fallback rule
      (e.g. trust one byte order when the other is zero or out of bounds,
      restricted to what the differential oracle accepts), never a blanket
      skip of the dual-endian check.

- [x] **saturn-dc-raw rejects the Dreamcast GD-ROM high-density area (consumer
      request from Stratum, 2026-08-14; DONE same day):** the staged Sonic
      Adventure 2 GDI set's data track (`track03.bin`, 504,200 raw sectors,
      data track at LBA 45000 per the `.gdi`) failed
      `normalize(format="saturn-dc-raw")` at **sector 404850** with
      "invalid BCD minute 0xa0". **Empirical characterization (probe over
      the whole track): addresses run contiguously from absolute MSF
      10:02:00 (= LBA 45,000 + the 150-frame pregap); BCD holds to the last
      representable 99:59:74 at sector 404,849, then minute 100 continues
      the BCD pattern with hexadecimal tens digits — 0xA0 = 100 … 0xC2 =
      122 at the track end.** Fix: the minute's high nibble may now be
      0xA–0xF (seconds/frames stay strict BCD; the low nibble stays ≤ 9);
      per-sector MSF contiguity remains the structural gate, and genuine
      Saturn media tops out at 99:59:74 so the relaxation cannot fire
      there. TDD: minute-100 continuation accepted (user stream
      byte-identical), hex-minute at a wrong position still refused
      (contiguity), invalid low nibble still refused; the pre-existing
      0xFA red test is unchanged. Verified on the real track: the eager
      pass now validates all 504,150 sectors. **Follow-up gap found while
      proving the composition (→ new ask below): `iso9660` cannot walk
      SA2's inner filesystem yet.**

- [ ] **iso9660 cannot walk the SA2 GD-ROM filesystem (consumer request
      from Stratum, 2026-08-14, found while proving the DC-gap fix):** the
      track now remaps cleanly, and the PVD at inner sector 16 parses
      (CD001, volume space 504,150 LE==BE), but the PVD's root directory
      record claims extent **45,020** — where the bytes are high-entropy
      file content — while actual ISO9660 directory records (`1ST_READ.BIN`,
      ADX filenames) sit at inner sectors **~20–36**, and clean structure is
      everywhere (IP.BIN `SEGA SEGAKATANA` at sector 0, ADX `(c)CRI`
      headers from sector 8,359, MPEG/SFD pack headers at sector 100,000).
      Investigate before coding: re-parse the PVD root record byte-exactly
      (offset 156), check for a second/descriptor-set variant or mastered
      poison values, and decide whether this is a Substratum parse gap or a
      disc-mastering anti-rip quirk needing a documented tolerant rule.
      Blocks Stratum's `cri.adx` 2nd positive (the last hop) and Quarry's
      spare-ADX enumeration.

- [ ] **`F:\game` corpus formats — RVZ / WBFS (+ GCZ / NKit as follow-ons;
      Stratum Unit 4 prerequisite, operator-gated samples):** Stratum's
      eventual operator-run corpus sweep (its BACKLOG Unit 4) targets
      `F:\game`, which is **decrypted emulator-optimized formats — not raw
      disc images** (RVZ/WBFS for Wii, GCZ/NKit for GC/Wii). None of these
      normalize today, so a sweep over the real corpus would skip most of
      it. Each format is its own normalizer unit with its own differential
      oracle (RVZ is Dolphin's own container → the Dolphin CLI; WBFS and
      GCZ → wit where applicable; NKit → the NKit tool), following the
      retail-anchor pattern: small operator-supplied samples staged into
      the gitignored drop zone, provenance + manifest committed, agents
      never reading `F:\game` autonomously. Decide and record up front
      (a) whether to normalize each container directly or define an
      operator pre-conversion path, and (b) the minimum set that makes the
      first 50-title sweep meaningful — RVZ + NKit likely cover the bulk.
      This family is **not dispatchable until the operator stages
      samples**; it is recorded here so the dependency is durable.

- [ ] **New3DS 9.3 variant (opportunistic — media-scarce):** `ncchflag[3] ==
      0x0A`, keyslot `0x18`, no seeddb. Tooling-wise this falls out of the 9.6
      pure-Python path for free (`0x18` keyX is in the parked keyset, same
      module), **but it still needs a genuine `0x0A` retail anchor**, which
      Kenrin's hunt confirms is effectively lost media (2026-07-30: three
      database-"9.3" titles all turned out `0x01` — see the finding above).
      **Read the crypto method, not the firmware version:** a title can require
      FW 9.3+ and still ship 7.x (`0x01`) crypto. This unit only lands if a real
      `0x0A` surfaces.

- [x] **Promote the Spolia program (2026-08-05):** Stratum at
      `C:\Users\kenrin\Project\Stratum` (`37c9f74`) and Quarry at
      `C:\Users\kenrin\Project\Quarry` (`352e05a`) now consume the frozen
      public contract; Kura and Interlinear remain downstream of Quarry.

## How to orient quickly

1. Read this file for the current boundary and next unlock.
2. Read `NORMALIZERS.md` for unit status, fixtures, pinned tools, and proof
   obligations.
3. Read `DESIGN.md` before changing the contract or starting a unit.
4. Read `docs/WII-KEYED-WORK.md` when the common-key artifact is available.
5. Run `uv run pytest` for the full four-check gate after implementation;
   structural-only or self-consistency-only results are not GREEN.
