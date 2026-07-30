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

> **Second keyset parked (2026-07-29).** A second `aes_keys.txt` (9,912 B,
> larger than the retrobios one's 4,965 B — a superset) was supplied via the
> Internet Archive item
> [`Nintendo-3DS-BIOS-DSP-Aes-Keys-SeedDB-Font`](https://archive.org/details/Nintendo-3DS-BIOS-DSP-Aes-Keys-SeedDB-Font)
> and parked at gitignored `fixtures/_local/aes_keys_ia.txt` (distinct name so
> it does not clobber the retrobios file). Same key-discipline applies: never
> hashed/logged/committed; structure-only. Neither is consumed by ctrtool
> v1.3.0; both are parked for the future pure-Python path.

### SeedDB parked (for New3DS 9.6 seed crypto)

Seed-encrypted NCCH (New3DS 9.6, `ncchflag[3] == 0x0B`, keyslot `0x1B`)
needs a per-title **seed** resolved from a **seeddb**. The 9.6 unit is
therefore the one variant that requires a second keyed artifact beyond a
retail title. A `seeddb.bin` (59,568 bytes; 1,861 seed records) was supplied
from the same Internet Archive item and parked at gitignored
`fixtures/_local/seeddb.bin`. ctrtool v1.3.0 accepts it via
`--seeddb=<path>` (verified — it loads cleanly), so the 9.6 normalizer will
pass the path through to ctrtool rather than reading the seeddb itself.

**Key-discipline boundary for the 9.6 unit** (mirrors the Wii common key and
the parked keysets): the seeddb lives only at `fixtures/_local/seeddb.bin`,
named by an operator env var (e.g. `SUBSTRATUM_CTRTOOL_SEEDDB`); code reports
only whether the file exists, never its contents; its bytes are never hashed,
logged, echoed, or committed. The 7.x (`0x25`) and New3DS 9.3 (`0x18`)
variants need **no** extra artifact — ctrtool decrypts them with compiled-in
keys via the same command used for standard crypto.

## Fixture required to resume

The encrypted-NCCH normalizer cannot be built or proven against Cubic Ninja
(NoCrypto). It needs **one encrypted retail 3DS title** as a `FIXTURE
REQUEST` anchor.

### FIXTURE REQUEST: encrypted retail 3DS title — **FULFILLED 2026-07-29**

Kenrin dropped **Biohazard — The Mercenaries 3D (Japan)** as a `.cia` into
gitignored `fixtures/_local/`. Qualified via `ctrtool -i` (vendored v1.3.0,
keys compiled in):

- **File:** `fixtures/_local/Biohazard - The Mercenaries 3D (Japan).cia`
  (698,837,440 bytes / 0x29A6F600 content)
- **Title ID:** `0004000000043E00` (CTR, eShop/digital; product `CTR-P-BREJ`)
- **Container:** CIA — `HeaderSize 0x2020`, `CertSize 0xA00`,
  `TicketSize 0x350`, `TMDSize 0xB34`, `FooterSize 0x3AC0`, single content
- **NCCH crypto:** `Flags 0000000001030000`, **`> Crypto Key Secure (0)`**
  → standard crypto (`ncchflag[3] == 0x00`, keyslot `0x2C`) — exactly the
  preferred first-unit variant. **Not** seed-encrypted
  (`Title seed check 00000000`, no 9.6 flag).
- **NCCH regions (encrypted on-media):** Exheader `0x400`;
  ExeFS offset `0xC00` size `0x50FA00`; RomFS offset `0x510600` size
  `0x2955F000`. ctrtool prints the NCCH-declared protected hashes
  (Exheader/ExeFS/RomFS) for the differential gate.
- **Content-flag note:** ctrtool reports the TMD `ContentInfo` as
  `Encrypted: NO`, while the NCCH header itself is `Secure (0)`. This is the
  known CIA/TMD-vs-NCCH-flag distinction (the TMD content-encryption flag
  and the NCCH crypto-method are separate fields); the NCCH header is the
  authoritative source and it is standard-encrypted. The normalizer must
  treat the content as encrypted NCCH and decrypt via ctrtool.

**How a future candidate is verified** (kept for any later anchor swap):

```powershell
tools\ctrtool\ctrtool.exe -i "candidate.3ds"
```

An encrypted title's NCCH section shows `> Crypto Key` as something other
than `None` (this anchor shows `Secure (0)`); Cubic Ninja shows
`> Crypto Key None` and is the contrast case. Standard crypto
(`Secure (0)` / `ncchflag[3] == 0x00`) is preferred; New3DS 9.6 seed titles
additionally need `--seed=`/`--seeddb=` and are deferred past this unit.

The title bytes are gitignored and never enter git or leave the machine
(DESIGN § 5, same posture as the Wii/Cubic Ninja anchors). **The decrypted
titlekey value is not recorded here** — ctrtool prints it, but it stays out
of docs/logs/manifests per key-discipline.

## Resume checklist

The standard-encrypted NCCH unit shipped 2026-07-29 (`3ds-ncch-enc`, GREEN),
CIA container parsing shipped 2026-07-29 (`cia`, GREEN), and the **7.x-seed**
variant shipped 2026-07-29 (`3ds-ncch-enc-seed`, GREEN). The open deferred
work is the rarer 3DS crypto variants:

1. Standard-encrypted NCCH (`ncchflag[3] == 0x00`, keyslot `0x2C`) — DONE.
2. **7.x-seed** (`ncchflag[3] == 0x01` + seed bit, keyslot `0x25`,
   `Crypto Key Secure (1) (KeyY seeded)`) — DONE.
   `substratum/formats/three_ds_ncch_enc_seed.py` decrypts via vendored
   ctrtool + the operator-supplied seeddb. Anchors: BoxBoxBoy + Mini Sports.
3. **Plain 7.x** (`ncchflag[3] == 0x01`, no seed bit, `Crypto Key Secure (1)`
   with no "(KeyY seeded)" suffix) — DONE (2026-07-30, `53ed3de`). The
   `3ds-ncch-enc` normalizer was widened to accept `ncchflag[3]` in `{0x00,
   0x01}`; Kobayashi is the retail anchor. Plain-7.x two-party refinement
   (ctrtool/3dstool agree on content; 3dstool strips a banner signature region)
   recorded above.
4. **New3DS 9.3** (`ncchflag[3] == 0x0A`, keyslot `0x18`) — **tooling
   untested, media scarce.** Whether ctrtool v1.3.0 has a working `0x18` is
   unknown; per the 9.6 correction below, assume it does NOT until proven. The
   pure-Python AES-CTR path (item 5's plan) covers 9.3 with no extra work once
   built — `slot0x18KeyX` is in the parked keyset — but a 9.3 retail anchor
   title is still needed and Kenrin reports the late-library titles are
   effectively lost media.
5. **New3DS 9.6** (`ncchflag[3] == 0x0B`, keyslot `0x1B`) — **BLOCKED on
   tooling, PLANNED via pure-Python AES-CTR.** Vendored ctrtool v1.3.0 cannot
   decrypt the parked FE Warriors anchor (keyslot `0x1B` unavailable; see
   "CORRECTION (2026-07-30)" above). The `0x1B` keyX IS in the parked keysets,
   so the fix is a pure-Python AES-CTR normalizer that reads it directly — see
   [`3DS-PURE-PYTHON-AES-CTR-PLAN.md`](3DS-PURE-PYTHON-AES-CTR-PLAN.md) for the
   full algorithm (normalkey key-gen formula, seed-keyY derivation, CTR
   counter) and the two-session build plan. FE Warriors is the anchor; the
   seeddb is parked for the seeded sub-variant.

### Load-bearing empirical findings

From the standard-crypto unit: the NCCH header at 0x100 is plaintext for
**standard** crypto; ctrtool's `-p` flag is NOT a differential (it returns
encrypted bytes) — the genuine two-party oracle is ctrtool-decrypt vs
3dstool-decrypt; and no committed encrypted synthetic is authorable without
retail key material, so the committed fixture is a decrypted NoCrypto NCCH.

From the 7.x-seed unit (the load-bearing new finding): **the 7.x-seed variant
encrypts the NCCH header itself** — the magic at 0x100 is ciphertext, not
plaintext. Two consequences: (1) ctrtool cannot decrypt a raw 7.x-seed NCCH
slice in isolation (it needs the CIA's ticket to decrypt the header first), so
the normalizer consumes a **whole CIA**, not a slice; (2) ctrtool exposes the
decrypted regions but not the decrypted header, so the normalizer reconstructs
the 0x200 header from ctrtool's parsed report. 3dstool cannot serve as a
second-party decryptor for 7.x-seed (it handles neither the CIA nor a raw
7.x-seed slice), so the NCCH-declared protected SHA-256 hashes — validated by
composing through `three_ds_ncch` — carry the correctness proof on their own.

### Plain-7.x two-party finding (2026-07-30)

Unlike 7.x-seed, **plain 7.x (`ncchflag[3] == 0x01`, no seed bit) IS
slice-decryptable by both ctrtool and 3dstool** — the NCCH header is plaintext
(just like standard crypto), so the normalizer consumes a raw NCCH slice cut
from the CCI via `3ds-cci`, exactly like the standard-crypto path. The
two-party differential therefore carries the correctness proof, same as
standard crypto, with one documented refinement:

**ctrtool and 3dstool agree on essentially all content; the only divergence is
where 3dstool strips banner signature bytes.** On the Kobayashi anchor,
`.code`, `icon`, `plain`, `extendedheader`, and `romfs` decrypt
byte-identically between both tools. The ExeFS *header* (the 0x200 protected
hash region) is also identical. The only differing bytes (207 of them) lie
inside the ExeFS `banner` file at `banner+0x130` (len 206) and `banner+0x1ff`
(len 1) — and there **3dstool writes zeros where ctrtool preserves real
data**, consistent with 3dstool stripping a banner signature/hash region it
does not render. This is a documented tooling difference, not a decrypt
disagreement: the NCCH-protected-hash correctness anchor validates the ExeFS
header (not each file's full content), and the normalizer's region slice
exposes the raw ExeFS bytes ctrtool emits. The retail proof therefore (a)
asserts byte-identity on `.code`, `icon`, `plain`, `extendedheader`, and
`romfs` — the genuine two-party content oracle — and (b) carries the banner's
correctness via the NCCH protected-hash validation through the composed
`three_ds_ncch` gate (ctrtool is the banner oracle; 3dstool's stripped banner
is expected).

### New3DS 9.6 + FE Warriors anchor — CORRECTION (2026-07-30)

Kenrin sourced **Fire Emblem Warriors (USA) (v0.0)** `.3ds` (CCI, 2 GiB, title
ID `000400000f70cd00`) and parked it at gitignored
`fixtures/_local/Fire Emblem Warriors (USA) (v0.0).3ds`. Qualified via vendored
ctrtool v1.3.0 + raw-byte read of the NCCH flags: **`ncchflag[3] == 0x0B` →
New3DS 9.6 crypto, keyslot `0x1B`**, NoCrypto clear, plaintext NCCH header.
This is the New3DS 9.6 variant (checklist item 5).

> **CORRECTION (2026-07-30, session #227).** An earlier draft of this section
> (and the `53ed3de` commit message, the project log, and the brief) claimed
> FE Warriors "decrypts seeddb-free" and anchors a "no-seed 9.6 path." That
> finding was **false** — a test-hygiene artifact (a `romfs/` dir left over
> from a *different* title's extraction was misread as FE Warriors output, so
> both the "146 files extracted" and the "byte-identical with/without seeddb"
> observations were reading stale bytes, not a live decrypt). It is retracted
> here and superseded by the verified facts below.

**Verified facts (re-checked cleanly, fresh dirs each run):**

1. **FE Warriors does NOT decrypt with vendored ctrtool v1.3.0** (built
   2026-01-18) under any tested condition: with/without `--seeddb`, with/without
   `-k aes_keys.txt` (both the retrobios and IA keysets, though ctrtool reports
   `-k` deprecated and keys "initialised internally"), from the repo root or an
   isolated cwd, `--romfs` or `--romfsdir`, with/without `-y`. Every run prints
   `[ctrtool::NcchProcess ERROR] NcchHeader is corrupted (Bad struct magic).`
   and extracts **0 files**. `ctrtool -v` *analyzes* the title fine (reports
   `Secure (11)`, derives keys, `Title seed check: 00000000`) — only the
   decrypt-extract path fails.
2. **The ctrtool build and seeddb are not the blocker in general**: the same
   build + same seeddb **does decrypt BoxBoxBoy (7.x-seed, keyslot `0x25`) to
   532 files.** So keyslot `0x25` works; what fails is specifically the 9.6
   keyslot `0x1B`. The inference: **keyslot `0x1B`'s keyX is not effectively
   available to this ctrtool v1.3.0 decrypt path** (the keyslot's keyX is
   New3DS-`arm9loader`-derived and may not be compiled in the way `0x2C`/`0x25`
   are).
3. FE Warriors **is present in the parked seeddb** (title ID `000400000f70cd00`
   confirmed by presence-only membership check; no seed bytes read/printed).

**Consequence:** the New3DS 9.6 unit is **NOT ready** as of this correction.
FE Warriors is the right *format* anchor (`0x0B`), but the decrypt oracle
itself is blocked on tooling — either a ctrtool build with working keyslot
`0x1B`, or a pure-Python AES-CTR path using the `0x1B` keyX from the parked
keysets (the deferred path this doc already records). 9.6 stays deferred until
that resolves. The seeddb remains parked and is genuinely required for any
seeded 9.6 title (the `0x20` keyY-generator bit, per the corrected flag model
below) — but FE Warriors cannot currently prove either 9.6 sub-variant.

**The two-byte flag model (corrected — authoritatively per 3DBrew NCCH).** The
earlier part of this doc conflated the crypto method with the seed flag. They
are **two independent bytes**:

- `ncchflag[3]` — the crypto *method* → AES keyslot: `0x00`/`0x2C`,
  `0x01`/`0x25`, `0x0A`/`0x18` (9.3, New3DS-only), `0x0B`/`0x1B` (9.6,
  New3DS-only).
- `ncchflag[7]` — keyY *generator*: bit `0x20` set → seed crypto (the title is
  looked up in the seeddb; the seed modifies keyY). The `0x20` generator
  "starts with FIRM 9.6.0-X," so **9.3 (`0x0A`) does NOT use seed crypto**;
  only 9.6 titles *can*, and only those with the bit set.

So the seeddb is relevant to **seeded 9.6** titles only — never to 9.3, and
not to every 9.6 title. This also means **9.3 is architecturally the simplest
remaining variant** (New3DS-only, keyslot `0x18`, no seeddb, plaintext header,
slice-decryptable — closest to plain-7.x), *if* a ctrtool build has working
keyslot `0x1B`/`0x18` support; that tooling question is currently open for
both New3DS keyslots.
