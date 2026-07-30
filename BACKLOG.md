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
**Next step: New3DS 9.6 (`0x0B`/`0x1B`) via the planned pure-Python AES-CTR
path** ([`docs/3DS-PURE-PYTHON-AES-CTR-PLAN.md`](docs/3DS-PURE-PYTHON-AES-CTR-PLAN.md))
— no new media needed (FE Warriors + the `0x1B` keyX are parked). 9.3
(`0x0A`/`0x18`) is opportunistic: tooling-free once 9.6 lands, but a genuine
`0x0A` anchor is effectively lost media. See
[`docs/3DS-KEYED-WORK.md`](docs/3DS-KEYED-WORK.md) § "CORRECTION (2026-07-30)".

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

## Next (in dispatch order)

- [ ] **New3DS 9.6 variant (the lead next step):** `ncchflag[3] == 0x0B`,
      keyslot `0x1B`. **Actionable now via the planned pure-Python AES-CTR
      path** — see
      [`docs/3DS-PURE-PYTHON-AES-CTR-PLAN.md`](docs/3DS-PURE-PYTHON-AES-CTR-PLAN.md).
      No new media needed: the parked **Fire Emblem Warriors** `.3ds` is the
      `0x0B` anchor and the `0x1B` keyX is already in the parked keysets
      (vendored ctrtool v1.3.0 cannot decrypt it — "NcchHeader corrupted",
      keyslot `0x1B` unavailable — which is *why* the pure-Python path exists).
      Two-session build: (A) extend `_aes.py` with AES-CTR + the key-generator
      formula; (B) the `three_ds_ncch_enc_96` normalizer + FE Warriors retail
      proof. The seeddb stays parked for the seeded sub-variant.

- [ ] **New3DS 9.3 variant (opportunistic — media-scarce):** `ncchflag[3] ==
      0x0A`, keyslot `0x18`, no seeddb. Tooling-wise this falls out of the 9.6
      pure-Python path for free (`0x18` keyX is in the parked keyset), **but it
      still needs a genuine `0x0A` retail anchor**, which Kenrin's hunt
      confirms is effectively lost media (2026-07-30: three database-"9.3"
      titles all turned out `0x01` — see the finding below). **Read the crypto
      method, not the firmware version:** a title can require FW 9.3+ and still
      ship 7.x (`0x01`) crypto. This unit only lands if a real `0x0A` surfaces.

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
