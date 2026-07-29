# Substratum — backlog (Kenrin-paced; one normalizer per session)

Substratum is the normalization foundation for the Spolia program. Its
contract is frozen: each unit adds exactly one container/filesystem layer and
proves it with the four-check gate, including independent differential
byte-range fidelity where available.

## Current boundary

Version **0.0.12** is clean at `34cb474` (implementation pending commit). The
keyless/decrypted floor plus keyed Wii partition decode is complete: **12
normalizers are GREEN**. `wii-fst` is the next READY unit — it walks the
decrypted DATA-partition `ByteView` that `wii-partition` now produces.

## Done

- [x] **Foundation contract and gate:** frozen `ByteSource` / `ByteView` /
      `FileTree` interface, manifests, fixture policy, and four-check
      verification gate (`DESIGN.md`, `schema/`, `substratum/verify.py`).

- [x] **Keyless/decrypted normalizer floor:** 11 GREEN units — `iso9660`,
      `gc-fst`, `chd`, `ps1-bincue`, `saturn/dc-raw`, `cso`, `wii-u8-arc`,
      `xdvdfs`, `3ds-cci`, `3ds-ncch`, and `wii-disc`.

- [x] **Proof and hardening pass:** independent-tool differential checks,
      retail/homebrew anchors, path and header rejection, streaming and
      memory-discipline protections, and pinned tool versions are recorded in
      `NORMALIZERS.md` and the archived project log.

- [x] **Wii outer layer:** `wii-disc` exposes opaque encrypted partition
      slices without crossing the one-layer composition boundary.

- [x] **Keyed-work handoff:** `docs/WII-KEYED-WORK.md` records the exact key
      artifact, safe gitignored storage, environment boundary, and resume
      checklist without storing key material or its digest.

- [x] **Wii partition decode (`wii-partition`):** pure-Python AES-128-CBC
      (NIST SP 800-38A anchored) decrypts the title key and cluster payloads
      into a lazy `ByteView`; synthetic generated-key fixture + wit-extracted
      retail proof against The Munchables. Standard common key supplied
      locally and never committed.

## Next (in dispatch order)

- [ ] **`wii-fst` — decrypted filesystem:** walk the `wii-partition` decoded
      DATA-partition `ByteView` as a separate `FileTree` normalizer. wit's
      53-entry user tree and 61-file extraction corpus for The Munchables are
      already independently qualified; the decrypted stream is now available.

- [ ] **Revisit deferred formats:** encrypted or seeded 3DS formats remain
      explicitly deferred until their fixture and key-provider plan is
      selected.

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
