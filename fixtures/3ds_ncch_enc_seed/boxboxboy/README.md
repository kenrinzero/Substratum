# BoxBoxBoy! (USA) — 7.x-seed encrypted-NCCH retail anchor

The source is the operator-provided `.cia` in the gitignored `fixtures/_local/`
directory (DESIGN section 5). Its original download location was not recorded,
so this fixture makes no public preservation-source claim.

Validated encrypted NCCH identity (via pinned ctrtool v1.3.0 + the parked seeddb):

- File: `BoxBoxBoy! (USA) (eShop).cia`; title ID `000400000018ee00`;
  product code `CTR-N-KCAE`.
- Crypto: **7.x-seed** — `> Crypto Key Secure (1) (KeyY seeded)`,
  `ncchflag[3] == 0x01` (keyslot `0x25`) + seed bit.

## Load-bearing difference from standard crypto

Unlike standard crypto (where the NCCH header at 0x100 is **plaintext**), the
7.x-seed variant encrypts the header itself — so the magic at the content
offset is ciphertext. ctrtool therefore cannot decrypt a raw 7.x-seed NCCH
slice ("NcchHeader is corrupted"); it needs the CIA's ticket to decrypt the
header first. The runtime normalizer consumes the **whole CIA** and hands it
to ctrtool with `--seeddb`.

## Correctness anchor

`uv run python seedtools/stage_3ds_ncch_enc_seed_retail_anchor.py` requires
the SHA-256-pinned ctrtool v1.3.0 and the seeddb at gitignored
`fixtures/_local/seeddb.bin`. ctrtool `-y` verifies the NCCH-declared
Exheader/ExeFS/RomFS protected SHA-256 hashes (all GOOD); the runtime
normalizer re-validates them by composing the decrypted ByteView through
`three_ds_ncch`. 3dstool cannot serve as a second-party decryptor here (it
handles neither the CIA nor a raw 7.x-seed slice), so the protected-hash
anchor carries the correctness proof on its own.

Only this provenance and `expected.manifest.json` enter Git. The decrypted
region references stay local and ignored. No seeddb bytes or decrypted retail
payloads enter git.
