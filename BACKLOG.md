# Substratum — backlog (Kenrin-paced; one normalizer per session)

Substratum is the normalization foundation for the Spolia program. Its
contract is frozen: each unit adds exactly one container/filesystem layer and
proves it with the four-check gate, including independent differential
byte-range fidelity where available.

## Current boundary

Version **0.0.16** is clean (post-`3ds-ncch-enc-seed`). **16 normalizers**
are GREEN: the keyless/decrypted floor, the complete Wii chain, the CIA
container, and both 3DS encrypted-NCCH variants — standard crypto
(`3ds-ncch-enc`) and 7.x-seed (`3ds-ncch-enc-seed`). The remaining deferred
work is the rarer 3DS crypto variants: plain 7.x (no seed), 9.3, and 9.6.

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

- [x] **Proof and hardening pass:** independent-tool differential checks,
      retail/homebrew anchors, path and header rejection, streaming and
      memory-discipline protections, and pinned tool versions are recorded in
      `NORMALIZERS.md` and the archived project log.

## Next (in dispatch order)

- [ ] **Plain-7.x encrypted NCCH (next unit, fixture fulfilled):** the
      remaining 7.x sub-variant — `Crypto Key Secure (1)` with **no** seed
      (`ncchflag[3] == 0x01`, seed bit clear, keyslot `0x25`). Retail anchor
      parked at gitignored `fixtures/_local/3DS1333 - Kobayashi ga Kawai
      Sugite Tsurai!! … (Japan).3ds` (title ID `0004000000168700`, verified
      `Secure (1)` no-seed). Architecturally close to `3ds-ncch-enc` (NOT
      `3ds-ncch-enc-seed`): plain 7.x has a *plaintext* NCCH header, so it is
      slice-decryptable and consumes a raw NCCH slice (via `3ds-cci`), not a
      whole CIA. Likely a sniff/scope widening of `3ds-ncch-enc` to accept
      `ncchflag[3]` in `{0x00, 0x01}` (no-seed). See
      [`docs/3DS-KEYED-WORK.md`](docs/3DS-KEYED-WORK.md) § Resume checklist.

- [ ] **New3DS 9.3 / 9.6-seed variants:** `ncchflag[3]` `0x0A` / `0x1B`. Each
      needs an encrypted retail anchor; the seeddb is already parked for 9.6.
      Rarer variants (later New3DS titles); the architecture generalizes.

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
