# NORMALIZERS.md — registry + unit manifest

One row per normalizer. A unit is dispatchable only when its `deps` are
already vendored/pinned and its fixture plan is satisfiable without
`F:\game` access (DESIGN.md § 5). One unit = one format:
`substratum/formats/<format>.py` + fixtures + expected manifests +
`tests/test_<format>.py` calling `substratum.verify.run_checks`. Every
routine unit carries a differential tool OR the self-consistency proof —
structural-only green does not exist here.

**Fixture tiers (DESIGN.md § 5):** `synthetic` (committed) ·
`homebrew` (web-fetched, committed if license-clean, else `fixtures/_local/`) ·
`FIXTURE REQUEST` (Kenrin drops one retail file into `fixtures/_local/`
at his convenience; never committed, metadata only in outputs).

| format | kind | tier | status | fixture plan | differential (pinned at unit) | deps | notes |
|---|---|---|---|---|---|---|---|
| toyfs | synthetic container | — | HARNESS-ONLY (committed at seed) | `fixtures/toy/` | generator-authored reference bytes | none | exists to prove the gate bites; never extend it |
| iso9660 | disc filesystem | T2 | **GREEN** (2026-07-17, `substratum/formats/iso9660.py`) | synthetic via pycdlib (`fixtures/iso9660/synthetic/`, seedtool-authored) + homebrew SuperTux PS2 CD (`fixtures/iso9660/supertux/`, 779 files, GPL-2.0, provenance in dir); optional `FIXTURE REQUEST: PS2, any small retail title` for a pressing anchor still open | 7-Zip **26.02 (x64) 2026-06-25** (`7z l -slt -tiso` / `7z x -tiso`) + pycdlib **1.16.0** as second reader; fidelity sample seed **1** | none new | PVD-only by scope (no Joliet/RR; mode2/2352 is ps1-bincue's substance); refuses multi-extent/interleave/XAR/BE-mismatch structurally; `stage_homebrew_iso.py` re-runs the two-reader acceptance check on any future ISO |
| gc-fst | disc filesystem | T2 | **GREEN** (2026-07-22, `substratum/formats/gc_fst.py`) | `FIXTURE REQUEST` retail drop "The Hulk" (`GHKE7D`, NTSC/USA, 1,459,978,240 bytes) in gitignored `fixtures/_local/game.iso`; flat FST (11 files, no nested dirs); test skips cleanly when ISO absent — only the metadata manifest commits. **+ nested-fixture proof-strengthening** (2026-07-22): hand-authored 4-file/2-dir nested FST exercising the recursive traversal (`fixtures/gc_fst/nested/`, built on demand by `seedtools/make_gc_fst_nested_fixture.py` from the Hulk's sys region; genuine wit two-party differential on nested bytes — upgrades the flat fixture's self-consistency proof; only the manifest commits) | wit **v3.05a r8638 cygwin64** (vendored 2026-07-17 → `tools/wit/`; `wit files-ll` for listing, `wit extract` for reference bytes); sole differential tool + DESIGN §3 structural self-consistency proof (no second GC-FST reader exists); fidelity sample seed **1** (all files, ≤16) | none left (wit vendored) | FST-only scope (user-data files; `sys/` virtual header regions not synthesized); refuses Wii/TGC/malformed structurally; FST nodes are **0x0C not 0x20** (load-bearing yagcd §13.4 finding); directory nesting supported by parser AND exercised by the nested fixture (recursive close/resume + sibling-after-subtree proven on real bytes) |
| chd | container (decode) | T2 | **GREEN** (2026-07-18, `substratum/formats/chd.py`) | self-staged from the iso9660 unit's SuperTux PS2 ISO via `chdman createcd` → `fixtures/chd/supertux/supertux.chd` (8,492,240 bytes, sha256 8aff4f64); expected manifest derived from pre-compression iso manifest (independently authored at S1); reference bytes = iso reference (decompressed disc byte-identical) | chdman **0.288 (mame0288)** (vendored 2026-07-17 → `tools/chdman/`) + inner walk vs the pre-compression iso manifest | none left (chdman vendored) | returns ByteView; call chdman extractcd → .bin (original ISO); caller re-normalizes (DESIGN § 1 composition rule) |
| ps1-bincue | disc image (mode2) | T2 | **GREEN** (2026-07-23, `substratum/formats/ps1_bincue.py`) | synthetic via pycdlib XA ISO (`fixtures/ps1_bincue/synthetic/`, seedtool-authored) — pycdlib authors a PS1-shaped XA ISO (interchange_level=1, xa=True, SYSTEM.CNF-style boot stub + DATA + DATA/SUB + APP.ELF + 0-byte file + sha256-chain blobs); seedtool wraps each 2048-byte block into a 2352-byte Mode 2 Form 1 raw sector (sync + BCD address + XA subheader + user data + CRC-32 EDC + zero-fill ECC) and writes `game.bin` + `game.cue` (single data track MODE2/2352, INDEX 01 00:00:00); chdman `createcd -i game.cue` accepts the wrapped structure as **MODE2_RAW** (structural anchor) | chdman **0.288 (mame0288)** (vendored 2026-07-17 → `tools/chdman/`; structural anchor via `createcd` info: `TYPE:MODE2_RAW FRAMES:83`) + pycdlib **1.16.0** byte-differential (the inner ISO is pycdlib-authored, the normalizer must recover it byte-exact from the raw sectors); 7-Zip **26.02 (x64) 2026-06-25** for the post-remap ISO reference extraction; fidelity sample seed **1** | none left (chdman vendored, pycdlib dev-only) | ECMA-130 / Yellow Book Mode 2 Form 1: 12 sync + 4 header + 8 XA subheader + 2048 user + 4 EDC + 276 ECC = 2352 (sector size corrected from spec's earlier 280 typo on 2026-07-23 after the chdman probe re-confirmed the layout); EDC is real CRC-32 over [0, 2072), ECC zero-filled (chdman only checks structure; pycdlib is the byte oracle); stdlib Mode-2 remapper returns a `ByteView`, caller composes with `iso9660` (DESIGN §1, same one-layer shape as `chd`); eager structural pass validates sync + mode on every data sector at normalize time so corrupted sectors fire at check 1; lazy `_Mode2RemapSource` (one-sector cache) materializes nothing; refuses multi-track, audio, non-MODE2/2352, bad INDEX 01, .bin not a multiple of 2352, missing .cue sibling, sync mismatch, mode != 2 structurally; Mode 1 / Form 2 (2324-byte) / CD-DA are out of scope by design |
| saturn/dc-raw | disc image | T2 | queued | homebrew (DC homebrew scene is rich) | `7z` (ISO9660 inner) | none | |
| cso | container (decode) | T2 | **GREEN** (2026-07-23, `substratum/formats/cso.py`) | synthetic: maxcso compresses the iso9660 synthetic disc to `game.cso` (its incompressible sha256-chain blobs force stored-raw blocks alongside compressed ones); reference = the iso9660 synthetic fixture's `reference/` (inner disc byte-identical); only `game.cso` + manifest commit | maxcso **v1.13.0** (vendored 2026-07-23 → `tools/maxcso/`; `--decompress` round-trip = structural anchor) + pycdlib **1.16.0** inner-ISO byte-differential; **stdlib zlib decode**; fidelity sample seed **1** | maxcso (vendored) | CISO **v1 only** (magic `CISO`, u32 index, 2048B blocks, top-bit stored-raw, `align`/index_shift honored, ABSOLUTE file offsets); ZSO/CSO-v2/DAX refused by magic/version; returns ByteView, caller re-normalizes with iso9660 (DESIGN §1). Resolves the old `umd/psp-iso` row: a plain UMD/PSP `.iso` is 2048B ISO9660 already walked by `iso9660` — no separate unit; the compressed CISO container is the substance |
| wii-u8-arc | archive-as-FS | T2 | queued | homebrew | `wit`/`dolphin-tool` | shared with gc-fst | |
| xdvdfs (Xbox) | disc filesystem | T2 | queued (deferred tier) | `FIXTURE REQUEST: XBOX` likely | `extract-xiso` (vendor + pin) | extract-xiso | open-docs but tooling-dependent |
| wii partitions / 3ds ncch-cia | keyed platforms | T2/T3 | DEFERRED (plan Tier 3) | — | — | keys + tooling | sequenced after open platforms |

Prep rows (explicitly-scoped, not normalizer units) — **both DONE
2026-07-17** via `seedtools/vendor_tools.py` (binaries live in gitignored
`tools/`; the committed script re-fetches and verifies against its pinned
sha256s, so the repo carries the provenance, not the bytes):

- `vendor-chdman` — chdman **0.288** (banner `manager 0.288 (mame0288)`),
  extracted with 7-Zip from the official MAME 0.288 Windows SFX
  (`mame0288b_x64.exe`, sha256 `e4ae20a2…` matching upstream SHA256SUMS;
  SFX never executed) → `tools/chdman/chdman.exe`. GPL-2.0+ as a linked
  whole (chdman.cpp itself BSD-3) — vendored locally, never committed.
- `vendor-dolphin-tool-or-wit` — **wit v3.05a r8638** chosen over
  dolphin-tool: listing carries sizes+offsets (`wit files-ll`),
  self-contained cygwin64 zip, real `wit version`; dolphin-tool lists
  bare names, has no version flag, and needs the VC++ redistributable.
  Zip sha256 `04967055…` (TOFU, upstream publishes no sums) →
  `tools/wit/` (wit.exe + cygwin DLLs). GPL-2.0.
- `vendor-maxcso` — maxcso **v1.13.0** (own code ISC; bundled libs
  MIT/BSD/zlib/Apache-2.0, 7-zip deflate LGPL), the 64-bit Windows release
  `maxcso_v1.13.0_windows.7z` (7z sha256 `51362619…`, TOFU — upstream
  publishes no sums), flat-extracted with 7-Zip → `tools/maxcso/maxcso.exe`.
  Run-only, never linked or committed (same posture as chdman);
  `maxcso --version` → `maxcso v1.13.0`. Authors the `cso` fixture and is
  its `--decompress` structural anchor.
