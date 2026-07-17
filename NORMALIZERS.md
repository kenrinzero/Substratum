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
| iso9660 | disc filesystem | T2 | **S1 — READY** | synthetic via pycdlib (dev dep) + homebrew PS2 ISO (web fetch); optional `FIXTURE REQUEST: PS2, any small retail title` for a pressing anchor | `7z l` + `7z e` (scoop 7-Zip; record `7z i` banner) + pycdlib as second reader | none new | the proof unit — no vendored tooling needed |
| gc-fst | disc filesystem | T2 | S2 — needs fixture staging | homebrew GameCube .iso/.gcm (web fetch); else `FIXTURE REQUEST: GameCube, any small title` | wit v3.05a r8638 (vendored 2026-07-17 → `tools/wit/`; `wit files-ll` lists sizes+offsets, `wit extract`) | none left (wit vendored) | documented, deterministic layout |
| chd | container (decode) | T2 | **S3 — READY** (chdman vendored; fixture self-staged from the iso9660 unit's) | create `.chd` FROM the iso9660 fixture via chdman (`createcd`) — self-staged, no new content | chdman 0.288 (mame0288) (vendored 2026-07-17 → `tools/chdman/`) + inner walk vs the pre-compression iso manifest | none left (chdman vendored) | returns ByteView; caller re-normalizes (DESIGN § 1 composition rule) |
| ps1-bincue | disc image (mode2) | T2 | queued | homebrew PS1 (PSX SDK demos) or `FIXTURE REQUEST: PS1` | `7z`/`isoinfo` after mode2→2048 mapping | none | sector-format handling is the unit's substance |
| saturn/dc-raw | disc image | T2 | queued | homebrew (DC homebrew scene is rich) | `7z` (ISO9660 inner) | none | |
| umd/psp-iso | disc filesystem | T2 | queued | homebrew PSP | `7z` | none | |
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
