# Substratum — backlog (Kenrin-paced; one normalizer per session)

Substratum is the normalization foundation for the Spolia program. Its
contract is frozen: each unit adds exactly one container/filesystem layer and
proves it with the four-check gate, including independent differential
byte-range fidelity where available.

## Current boundary

Version **0.0.17** is clean (post plain-7.x widening). **16 normalizers**
are GREEN: the keyless/decrypted floor, the complete Wii chain, the CIA
container, and the 3DS encrypted-NCCH variants — standard + plain-7.x crypto
(`3ds-ncch-enc`, no-seed `{0x00, 0x01}`) and 7.x-seed (`3ds-ncch-enc-seed`).
The remaining deferred work is the New3DS variants: 9.3 (`0x0A`/`0x18`,
tooling untested) and 9.6 (`0x0B`/`0x1B`, **blocked** — vendored ctrtool
v1.3.0 cannot decrypt the parked FE Warriors anchor; keyslot `0x1B`'s keyX
appears unavailable). See [`docs/3DS-KEYED-WORK.md`](docs/3DS-KEYED-WORK.md)
§ "CORRECTION (2026-07-30)".

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

- [x] **Proof and hardening pass:** independent-tool differential checks,
      retail/homebrew anchors, path and header rejection, streaming and
      memory-discipline protections, and pinned tool versions are recorded in
      `NORMALIZERS.md` and the archived project log.

## Next (in dispatch order)

- [ ] **New3DS 9.3 variant:** `ncchflag[3] == 0x0A`, keyslot `0x18`,
      New3DS-only, no seeddb (the `0x20` keyY generator postdates 9.3).
      Architecturally the simplest remaining variant (plaintext header,
      slice-decryptable — closest to plain-7.x). **Tooling caveat (2026-07-30):**
      whether keyslot `0x18`'s keyX is available to vendored ctrtool v1.3.0 is
      **untested** — the 9.6 keyslot `0x1B` proved unavailable on the same
      build, so a 9.3 anchor must be confirmed to decrypt *before* this unit is
      dispatched. Needs an encrypted retail anchor; no extra artifact.

- [ ] **New3DS 9.6 variant:** `ncchflag[3] == 0x0B`, keyslot `0x1B`. **BLOCKED
      on tooling (2026-07-30 correction):** the parked **Fire Emblem Warriors**
      `.3ds` is the right format anchor (`0x0B`), but vendored ctrtool v1.3.0
      **cannot decrypt it** (0 files under all tested conditions; "NcchHeader
      corrupted") — keyslot `0x1B`'s keyX appears unavailable to this build,
      while keyslot `0x25` (7.x-seed, BoxBoxBoy) works. The seeddb stays parked
      and is required for seeded-9.6 titles only (never 9.3). Unblocks on a
      ctrtool build with working `0x1B`, or a pure-Python AES-CTR path. **The
      pure-Python path is now PLANNED** — see
      [`docs/3DS-PURE-PYTHON-AES-CTR-PLAN.md`](docs/3DS-PURE-PYTHON-AES-CTR-PLAN.md)
      (full algorithm + two-session build plan; the `0x1B` keyX is already in
      the parked keysets, so no new media is needed for 9.6). It also unblocks
      9.3 tooling-side. See [`docs/3DS-KEYED-WORK.md`](docs/3DS-KEYED-WORK.md)
      § "CORRECTION" for the failed-decrypt verification.

- [ ] **Promote the Spolia program:** downstream segments (Stratum, Quarry,
      Kura, and Interlinear) consume only the frozen contract types and
      manifests; promotion remains deferred until explicitly selected.

## How to orient quickly

1. Read this file for the current boundary and next unlock.
2. Read `NORMALIZERS.md` for unit status, fixtures, pinned tools, and proof
   obligations.
3. Read `DESIGN.md` before changing the contract or starting a unit.
4. Read `docs/WII-KEYED-WORK.md` when the common-key artifact is available.
5. Run `uv run pytest` for the full four-check gate after implementation;
   structural-only or self-consistency-only results are not GREEN.
