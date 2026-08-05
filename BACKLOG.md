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
