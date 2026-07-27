# Substratum — backlog (Kenrin-paced; one normalizer per session)

Substratum is the normalization foundation for the Spolia program. Its
contract is frozen: each unit adds exactly one container/filesystem layer and
proves it with the four-check gate, including independent differential
byte-range fidelity where available.

## Current boundary

Version **0.0.11** is clean at `94925c6`. The keyless/decrypted floor is
complete: **11 normalizers are GREEN**. No new normalizer is currently
dispatchable. The next unlock is a locally supplied raw 16-byte standard Wii
common key; keyed Wii work then proceeds in two separate sessions.

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

## Next (in dispatch order)

- [ ] **Supply the Wii common key:** place the owner-supplied raw standard Wii
      common key at `fixtures/_local/wii-common-key.bin`; it must be exactly
      16 bytes. Never commit, print, hash, or log it.

- [ ] **`wii-partition` — AES-CBC decode:** author the generated-key synthetic
      fixture and NIST-vector anchor, then prove the lazy decrypted
      `ByteView` against the pinned `wit` / Dolphin qualification evidence.

- [ ] **`wii-fst` — decrypted filesystem:** after `wii-partition` is GREEN,
      walk its decoded DATA-partition view as a separate `FileTree` normalizer.

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
