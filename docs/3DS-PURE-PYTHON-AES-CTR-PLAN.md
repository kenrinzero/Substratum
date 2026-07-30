# Plan — pure-Python AES-CTR for New3DS 9.6 (and 9.3) NCCH

> **Status: BUILT (2026-07-30, sessions #256).** 9.6 (`0x0B`) is GREEN. The
> prep was scoped 2026-07-30 (session #230); Sessions A + B both landed in
> session #256. This record now also documents the **two-key NCCH decryption
> model** — the load-bearing finding that emerged during Session B and that the
> protected-hash gate caught before any commit. 9.3 (`0x0A`/`0x18`) remains
> opportunistic (tooling-ready, no anchor).
> See `docs/3DS-KEYED-WORK.md` § "CORRECTION (2026-07-30)" for why the
> pure-Python path was needed: vendored ctrtool v1.3.0 cannot decrypt keyslot
> `0x1B` (FE Warriors) despite the `0x1B` keyX being present in the parked
> keysets.

## Why pure-Python, not a different ctrtool build

- **The keys are already on disk.** `slot0x1BKeyX` and `slot0x18KeyX` are both
  present in `fixtures/_local/aes_keys.txt` (retrobios) and the larger
  `aes_keys_ia.txt`. The blocker is purely that ctrtool v1.3.0 ignores `-k`
  ("keys initialised internally") and its internal set lacks working `0x1B`.
- **It dissolves the whole class of problem.** Sourcing an older ctrtool that
  honors `-k` would work for 9.6 but leaves every future keyslot at the mercy
  of "does this build have it?" A pure-Python path reads the keyX from the
  operator-supplied keyset, so any keyslot whose keyX is present just works.
- **Consistency.** `wii-partition` already chose pure-Python AES-128-CBC
  (`substratum/_aes.py`) over a subprocess for DESIGN §4's stdlib-only runtime,
  anchored by NIST SP 800-38A vectors. AES-CTR is a natural sibling that reuses
  the *same* FIPS-197 block primitive.

## The decrypt algorithm (ground-truthed from primary sources)

Sources: 3DBrew [NCCH](https://www.3dbrew.org/wiki/NCCH),
[AES_Registers](https://www.3dbrew.org/wiki/AES_Registers); nocash
[GBATEK 3DS crypto](http://problemkaputt.de/gbatek-3ds-crypto-aes-keyslots.htm);
reference `ctrKeyGen.py` (Relys/3DS_Multi_Decryptor) for the seed path.

### Step 1 — normal key from keyX ⊕ keyY (hardware key generator)

```
NormalKey = ROL87( (ROL2(KeyX) XOR KeyY) + C1 )     # 3DBrew writes ROR 41
```

- 128-bit big-endian unsigned wraparound arithmetic (3DBrew AES_Registers,
  "Hardware key generator").
- `ROL 2` = rotate the 128-bit value left by 2 bits; `+ C1` = 128-bit modular
  addition; the final rotate is **`ROL 87`** in 3dstool/RomForge source
  (3DBrew expresses the same operation as `ROR 41`, since `41 + 87 = 128`).
  Implement as `ROL 87` to match the differential tool byte-for-byte.
- **`C1` = `1FF9E9AAC5FE0408024591DC5D52768A`** — pinned 2026-07-30 from
  `dnasdw/3dstool` `src/ncch.cpp:556-557` (the vendored differential decryptor),
  cross-confirmed in `sinjunyoung/RomForge` and `TASEmulators/BizHawk`. See
  "Open items" §1 for the full provenance. (DSi uses a separate `C2` — out of
  scope.)
- `keyX` comes from the parked keyset (`slot0x1BKeyX` / `slot0x18KeyX`).
- `keyY` = the NCCH signature's first 0x10 bytes (offset `0x000`–`0x00F` of the
  NCCH), **unless** the seed bit modifies it (step 2).

### Step 2 — seed modification of keyY (seeded 9.6 only)

Active when `ncchflag[7] & 0x20` (the keyY-generator / seed bit). Then:

1. **Verify the seed** against the on-header seedcheck: `seedcheck` is the u32
   at NCCH offset `0x114`; it must equal the first 4 bytes of
   `SHA256(seed + programID)`. `programID` is the u64 at NCCH `0x118` (same as
   title ID for retail titles). `seed` is the 16-byte value looked up in the
   seeddb by programID.
2. **Derive the new keyY** = first 16 bytes of `SHA256(keyY + seed)` (original
   signature-derived keyY concatenated with the seed). This new keyY feeds
   step 1.

(ctrKeyGen.py: `keystr = sha256(keyY + seed).hexdigest()[:32]`; the
verification is `sha256(seed + titleID)[:4] == seedcheck`.) Plain 9.6, 9.3,
standard, and plain-7.x skip this step entirely.

### Step 3 — AES-128-CTR decrypt of the encrypted regions

- The normal key from step 1 is the AES-128 key.
- **Counter (version 2, the production format):** a 16-byte counter built from
  the 8-byte **partition ID** (NCCH offset `0x108`) in **big-endian byte
  order**, followed by a 1-byte **region magic** `M` (1 = extended header,
  2 = ExeFS, 3 = RomFS), then 7 zero bytes. The counter then increments by
  `region_offset / 16` (big-endian, per 16-byte block) to reach the region,
  and continues incrementing per block across the region.
- **Version 1** (prototype — already refused by `three_ds_ncch`) uses a
  different counter layout (little-endian partition ID + a big-endian region
  offset in the low bytes). Out of scope; refuse it as today.
- CTR uses the **forward** AES block cipher (`_aes._encrypt_block`), not the
  decrypt path: keystream block `i` = `AES_encrypt(counter + i)`, plaintext =
  `ciphertext XOR keystream`.

### Encrypted vs plaintext regions

- **Never encrypted:** the 0x200 NCCH header, the plain region, the logo
  region, the access descriptor.
- **Encrypted (AES-CTR):** extended header (incl. access descriptor's encrypted
  half), ExeFS, RomFS — unless `ncchflag[7] & 0x04` (NoCrypto) is set.

This matches the existing `three_ds_ncch_enc` region assembly: decrypt the
encrypted regions, leave plaintext regions as-is, flip NoCrypto, emit a
ByteView the caller composes through `three_ds_ncch`.

## Build plan (two sessions)

### Session A — extend `substratum/_aes.py` with AES-CTR + the key generator

New code in `_aes.py` (pure additions; **do not change the CBC path** the Wii
units depend on):

1. `aes128_ctr_xor(key, counter, data) -> bytes` — SP 800-38A §6.5 CTR mode.
   Reuses `_expand_key` + `_encrypt_block`. Counter is a 16-byte initial value;
   big-endian increment per block. `data` need not be block-aligned (final
   block keystream is truncated). Anchor: **NIST SP 800-38A Appendix F.5.1
   AES-128-CTR vectors** — the independent correctness anchor, same posture as
   the Wii CBC anchor.
2. `_rol128(value, n)` / `_ror128(value, n)` — 128-bit big-endian rotation on
   Python `int` (arbitrary precision; mask to 128 bits).
3. `normalkey_from_keyxy(keyx: bytes, keyy: bytes) -> bytes` — implements the
   hardware key-generator formula. `C1` pinned from primary source (cited).
   Anchor: a known `keyX/keyY → normalkey` test vector from a reference
   decryptor or 3DBrew, if one is findable; otherwise self-consistency via
   round-trip against the seeded retail anchor (ctrtool-independent — the NCCH
   protected-hash gate is the oracle).

Tests (`tests/test_aes_ctr.py`): NIST CTR vectors (green); rotation
identities (`rol(ror(x,41),41)==x`); a synthetic keyX/keyY → normalkey →
CTR-encrypt-known-plaintext → decrypt round-trip.

### Session B — the 9.6 normalizer + retail proof (DONE 2026-07-30, #256)

> **Status: SHIPPED.** `substratum/formats/three_ds_ncch_enc_96.py` + tests +
> seedtool landed. The load-bearing finding that emerged during implementation
> — the **two-key NCCH decryption model** — is recorded below because it
> contradicted the plan's "one key per region" assumption and was the single
> thing the protected-hash gate caught before commit.

New module `substratum/formats/three_ds_ncch_enc_96.py` (parallel to
`three_ds_ncch_enc_seed.py`, not a widening — 9.6 is a meaningfully different
dispatch shape):

- **Keyset boundary** (mirrors `wii-partition`'s
  `SUBSTRATUM_WII_COMMON_KEY_FILE`): `SUBSTRATUM_3DS_KEYSET_FILE` names the
  operator-supplied `aes_keys.txt`; the loader reads only the needed
  `slot0x2CKeyX` + `slot0x1BKeyX` (or `0x18`) lines, reports presence-only,
  never hashes/logs/echoes a key byte. Fails closed when absent.
- **No-seed scope only this unit:** FE Warriors is `ncchflag[3]==0x0B` with the
  seed bit **clear** (`seedcheck=0`), so no seeddb is needed. The seeded-9.6
  sub-variant (seed bit set) is deferred to a future widening.
- **Decrypt path:** read NCCH header → load both keyX values → derive the two
  normal keys (both from keyY = signature[:16]) → lazy CTR-decrypt the encrypted
  sub-spans on demand → present a NoCrypto NCCH ByteView → caller composes
  `three_ds_ncch`. Bounded LRU cache of decrypted 4 KiB block windows (mirror
  `_DecryptedPartitionSource`), since pure-Python AES is ~0.5 MiB/s and the FE
  Warriors romfs is ~1.9 GB.
- **Sniffer:** registered **before** `3ds-ncch-enc` and `3ds-ncch`; accepts
  `ncchflag[3] in {0x0A, 0x0B}` with NoCrypto clear and the seed bit clear.
- **Retail proof (FE Warriors):** the NCCH-declared protected hashes are the
  independent correctness anchor — decrypt → compose `three_ds_ncch` → its
  protected-hash validation passes on real retail bytes (verified). 3dstool
  cannot second-party 9.6 (no `--seeddb`, lacks a working `0x1B` decrypt path
  here), so the protected-hash gate carries the proof, as it does for 7.x-seed.
- **Synthetic fixture (SHIPPED, stronger than standard-crypto's):** because the
  9.6 path is pure-Python, the seedtool encrypts a known-plaintext NCCH with
  **generated test** keyX/keyY pairs and the normalizer decrypts it back — a
  committed fixture that exercises the *real* decrypt path AND the two-key ExeFS
  split. The standard-crypto unit could only author a decrypted image.

#### LOAD-BEARING FINDING: the two-key NCCH decryption model

The plan assumed each encrypted region decrypts with one key (the `0x1B`
normalkey). That is **wrong**, and the protected-hash gate caught it before any
commit. A New3DS-9.6 NCCH has **two** AES normal keys, both derived from the
same keyY (signature[:16]) but different keyX slots (ground-truthed from
`dnasdw/3dstool src/ncch.cpp` extract, lines 151-224; verified against FE
Warriors retail bytes 2026-07-30):

- **Key0** (`slot0x2C`, the original content keyslot): encrypts the **extended
  header**, the **ExeFS superblock** (the 0x200 header), and the **ExeFS bytes
  after the first file**.
- **Key1** (`slot0x1B` for 9.6 / `slot0x18` for 9.3, the "new" keyslot):
  encrypts the **first ExeFS file's content (`.code`)** and the **entire
  RomFS**.

The ExeFS region is decrypted as ONE continuous CTR stream whose key switches
mid-stream: Key0 over `[0, 0x200)`, Key1 over `[0x200, 0x200+code_size)`, Key0
over the remainder. The counter never resets between these sub-spans (the byte
offset advances the keystream; the region magic is set once per region). This is
why ctrtool `-v` prints both `NCCH AES Key0` and `NCCH AES Key1` for a 9.6
title. The normalizer builds a sorted list of `(offset, size, key_index, magic)`
sub-spans and decrypts each with its key; ExeFS sub-spans share one
`region_base` (the exefs offset) so their counter block indices stay
continuous. The committed synthetic fixture exercises all three ExeFS sub-spans.

This two-key split also applies to standard/7.x crypto (the same `Old`/`New`
key indices), but the ctrtool-subprocess modules never had to model it —
ctrtool does it internally. Only the pure-Python 9.6 path had to encode it.

### After Session B

- 9.6 (`0x0B`) is GREEN; FE Warriors is the anchor.
- **9.3 (`0x0A`) becomes trivially dispatchable** — same module, keyslot
  `0x18`, no seed path. It still needs one retail anchor title, but the
  *tooling* barrier is gone: if the title's `slot0x18KeyX` is in the keyset, it
  decrypts. (This does not solve the media-availability problem Kenrin flagged;
  it only removes the tooling dependency.)

## Open items for the implementer

1. **`C1` PINNED (2026-07-30, session #256).** `C1 =
   1FF9E9AAC5FE0408024591DC5D52768A`, confirmed identically in three
   independent codebases: `dnasdw/3dstool` `src/ncch.cpp:556-557` (the
   reference decryptor Substratum already vendors — authoritative), the
   independent C# `sinjunyoung/RomForge` `3DS.Core/Crypto/KeySlot.cs:5,28`,
   and the TAS-emulator `TASEmulators/BizHawk`
   `src/BizHawk.Emulation.Common/N3DSHasher.cs:27`. **Plan correction: the
   final rotation is `ROL 87`, not `ROR 41`.** 3dstool writes `.Crol(87,
   128)`; RomForge writes `Lrot128(step3, 87)`. 3DBrew's "ROR 41" is the
   same operation since `41 + 87 = 128` on a 128-bit value — but implement
   as **ROL 87** to match the differential tool's source byte-for-byte and
   dodge the off-by-arithmetic risk. So `normalkey = ROL87( (ROL2(keyX) ^
   keyY) + C1 )`.
   - **3DBrew AES_Registers does not define C1** — it names it only (page
     rev 22989, 2024-12-22). The constant lives in the reference tools.
   - `ctrKeyGen.py` (Relys/3DS_Multi_Decryptor) does NOT contain C1 and does
     NOT compute the normal-key at all: it emits `ncchinfo.bin` entries
     (counter + keyY) for an on-console xorpad generator. It is the wrong
     place to look for C1; it is the right place for the counter (item 2).
2. **Counter CONFIRMED (2026-07-30, session #256)** from
   `ctrKeyGen.py:130-147` (`getNcchAesCounter`, "based on code from
   ctrtool's source"). Format version 2/0:
   `counter[0:8] = header.titleId[::-1]` (the 8 raw bytes at NCCH 0x108,
   reversed to big-endian), `counter[8] = region_magic` (1=exheader,
   2=exefs, 3=romfs), `counter[9:16] = 0`. No per-block increment is
   applied by ctrKeyGen — the counter is the *initial* 16-byte value;
   increment is big-endian per 16-byte block during the CTR stream. Version
   1 (prototype) counter stays out of scope / refused as today.
3. **Seeddb record layout** is `[seed(16)][titleID(8)][reserved(8)]`,
   records from byte 0, no header (verified 2026-07-30 against the parked
   file; FE Warriors title ID `000400000f70cd00` is present). The seed
   check + keyY derivation are confirmed verbatim in `ctrKeyGen.py:194-198`:
   `seedcheck = big-endian u32 at 0x114`, verify
   `sha256(seed + titleId)[:4] == seedcheck`, then
   `newkeyY = sha256(keyY + seed)[:16]`.
4. The pure-Python AES throughput (~0.5 MiB/s) means **full** romfs decrypt is
   impractical — the normalizer must be lazy + windowed from the start, and
   the retail test must sample, not whole-read (same constraint as wii-fst).

## Discipline (unchanged from the program rules)

- No key bytes or decrypted retail payloads enter git; only the manifest +
  provenance commit. References stay gitignored.
- Frozen contract (`contract.py`, schema, `verify.py`) untouched — this is one
  new format module + one `_aes.py` addition.
- The four-check gate (`uv run pytest`) is the dispatch gate; the protected-hash
  validation through `three_ds_ncch` is the byte-correctness anchor.
