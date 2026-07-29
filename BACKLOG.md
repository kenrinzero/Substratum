# Substratum — backlog (Kenrin-paced; one normalizer per session)

Substratum is the normalization foundation for the Spolia program. Its
contract is frozen: each unit adds exactly one container/filesystem layer and
proves it with the four-check gate, including independent differential
byte-range fidelity where available.

## Current boundary

Version **0.0.13** is clean at `bd03e24`. The
complete Wii chain is end-to-end GREEN: **13 normalizers** cover outer
partition tables (`wii-disc`), AES-CBC cluster decode (`wii-partition`), and
the decrypted FST filesystem (`wii-fst`). The encrypted-3DS track is
**READY** (architecture settled, fixture fulfilled) — `3ds-encrypted-ncch`
is the next dispatchable unit.

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
      `ByteView` into a `FileTree` of 53 entries (50 files + 3 dirs). The
      load-bearing Wii-format finding: FST file offsets are word offsets
      (`<< 2`), unlike GameCube's byte offsets. Synthetic nested fixture +
      wit-listing retail proof against The Munchables. Completes the Wii
      chain: `wii-disc` → `wii-partition` → `wii-fst`.

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

- [ ] **`3ds-encrypted-ncch` (next unit):** architecture settled
      (ctrtool-at-runtime; retail keys compiled into vendored ctrtool
      v1.3.0; consistent with `chd`→chdman per DESIGN § 4) **and fixture
      fulfilled** — Biohazard — The Mercenaries 3D (Japan) `.cia` dropped in
      gitignored `fixtures/_local/` (standard crypto `Secure (0)`, not
      seed-encrypted). Cubic Ninja (NoCrypto) stays the decrypted-path
      anchor. See [`docs/3DS-KEYED-WORK.md`](docs/3DS-KEYED-WORK.md) for the
      full resume checklist. CIA is a separate later unit.

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
