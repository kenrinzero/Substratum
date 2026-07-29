# Deferred 3DS keyed normalization

## Current boundary

Substratum 0.0.13 already normalizes the **decrypted** 3DS layers:

- `3ds-cci` returns opaque NCCH partition slices from the CCI/NCSD outer
  container (game-card dump).
- `3ds-ncch` exposes one **decrypted** NCCH's regions (extended header,
  plain, logo, ExeFS, RomFS) as opaque slices.

Both refuse encrypted and seed-encrypted NCCH (`three_ds_ncch.py:131,133`).
The current retail anchor — **Cubic Ninja (Japan).3ds** — is NoCrypto
(`CryptoType: Secure0 (0)`, `> Crypto Key None`), so it cannot exercise the
decryption path. Encrypted NCCH and CIA parsing remain deferred.

This document records the architecture decision for resuming that work and
the exact fixture it is blocked on.

## The 3DS crypto hierarchy (unlike Wii, this is layered)

Wii needed one 16-byte common key to unblock everything. 3DS splits into two
distinct decryption systems, and the term "title key" means different things
in each:

### Path A — NCCH content (inside both `.3ds` and `.cia`)

NCCH content is not decrypted with a title key directly. It uses the 3DS AES
engine's **hardware keyslots** combined with a **keyY derived from the NCCH
signature** (first 0x10 bytes at offset 0x0). The NCCH header Flags field at
offset `0x188` selects the variant:

| `ncchflag[3]` | Variant | Content keyslot | Era |
|---|---|---|---|
| `0x00` | Standard crypto | `0x2C` | original firmware |
| `0x01` | 7.x "secured" crypto | `0x25` | firmware 7.0+ |
| `0x0A` | New3DS 9.3 crypto | `0x18` | New3DS 9.3+ |
| `0x0B` | New3DS 9.6 crypto | `0x1B` | New3DS 9.6+ |

Flags byte `0x188+7` bitmasks: bit 0 (`0x1`) = FixedCryptoKey (debug keys),
bit 2 (`0x4`) = NoCrypto (unencrypted — this is Cubic Ninja), bit 5 (`0x20`)
= seed crypto (9.6+, needs a per-title **seed**).

### Path B — CIA ticket (eShop / digital)

This is the Wii-like layer: a **common key** (keyslot `0x3D` keyY) decrypts
the per-title **titlekey** stored at ticket offset `0x1BF` (AES-CBC, IV =
reversed title ID + zero pad). The decrypted titlekey then decrypts the NCCH
content. The titlekey is **per title** (one per game), not a single artifact.

## Architecture decision (settled 2026-07-29)

**ctrtool-at-runtime** for standard encrypted NCCH, mirroring the `chd` →
chdman precedent. The vendored ctrtool **v1.3.0** (built 2026-01-18) carries
retail AES keys **compiled in** and decrypts standard encrypted NCCH with no
external key material. This is consistent with DESIGN § 4: "runtime
stdlib-only" means *no pip/runtime dependencies*, not *no subprocess* — the
`chd` normalizer already shells out to chdman (`substratum/formats/chd.py`)
while its docstring states "Runtime is stdlib-only per DESIGN.md § 4." No
contract amendment is required.

### Keyfile parked (load-bearing finding)

A complete, correctly-formatted `aes_keys.txt` (the canonical ctrtool/3dstool
keyset, source: `retrobios` on GitHub) was supplied and placed at
gitignored `fixtures/_local/aes_keys.txt`. **It is NOT consumed by vendored
ctrtool v1.3.0** — the `-k`/`--keyset` flag is deprecated ("Generic AES/RSA
keys are initialised internally"). The keyset is correct and complete (six
common keys `common0`–`common5`, all NCCH content keyslot keyX values
including `0x2C`/`0x25`/`0x18`/`0x1B`, RSA/ECC material); it is parked for a
future path that loads it:

- a **pure-Python AES-CTR** normalizer extending `substratum/_aes.py` (the
  Wii AES-CBC implementation) with an env-var key boundary, honoring DESIGN §
  4 the way `wii-partition` did; or
- an **older ctrtool build** that honors `-k`, if one is ever vendored.

The keyfile stays gitignored; its bytes are never hashed, logged, echoed, or
committed. Code reports only whether the file exists and is well-formed.

## Fixture required to resume

The encrypted-NCCH normalizer cannot be built or proven against Cubic Ninja
(NoCrypto). It needs **one encrypted retail 3DS title** as a `FIXTURE
REQUEST` anchor.

### FIXTURE REQUEST: encrypted retail 3DS title

- **One** game-card dump (`.3ds` / `.cci`) **or** eShop package (`.cia`),
  any small title, sourced from a 3DS you own.
- Must be **encrypted** — i.e. not NoCrypto. Verify before sourcing by
  running, against any candidate file:

  ```powershell
  tools\ctrtool\ctrtool.exe -i "candidate.3ds"
  ```

  An encrypted title's NCCH section shows `> Crypto Key` as something other
  than `None`, and NCCH `Flags` byte index 3 (at header offset `0x18B`) is
  nonzero. Cubic Ninja shows `> Crypto Key None` and is the contrast case.

- **Preferred: standard crypto (`ncchflag[3] == 0x00`)** for the first unit —
  ctrtool decrypts it with no external key or seed. Avoid New3DS 9.6 seed
  titles for the first unit (they additionally need `--seed=`/`--seeddb=`).
- Drop the file into gitignored `fixtures/_local/`. Only provenance + a
  metadata manifest commit; the title bytes never enter git or leave the
  machine (DESIGN § 5, same posture as the Wii/Cubic Ninja anchors).

## Resume checklist

When an encrypted title exists in `fixtures/_local/`:

1. Confirm its crypto variant with `ctrtool -i` (expect standard crypto for
   the first unit; record the `ncchflag` values).
2. Take **encrypted-NCCH** as one normalizer session (`three_ds_ncch_enc.py`
   or an extension of `three_ds_ncch.py`). One unit = one session.
3. Shell out to vendored ctrtool v1.3.0 for decryption; resolve the
   executable via `SUBSTRATUM_CTRTOOL` → `PATH` → repo-local
   `tools/ctrtool/ctrtool.exe` (same resolution order as `chd`/chdman).
4. Author a synthetic encrypted-NCCH fixture (generated keys) for the
   structural + round-trip checks, so the committed suite is not gated on
   the retail drop.
5. Conditional retail proof: ctrtool `-p` (plain, no decrypt) vs default
   (decrypt) extraction at fixed offsets — the differential gate, ctrtool as
   its own independent oracle across its two modes.
6. Commit no decrypted retail payloads or key bytes.
7. **CIA** (the eShop container: TMD + ticket + content) is a *separate
   later* unit, not part of encrypted-NCCH — it parses a different container
   and its content is the same encrypted NCCH this unit handles.

Until then, encrypted/seeded NCCH and CIA remain deferred and Substratum is
cleanly usable through the thirteen GREEN normalizers (the two 3DS units
covering the decrypted layers).
