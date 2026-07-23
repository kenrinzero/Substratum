# Saturn / Dreamcast raw disc image Normalizer — Design Spec

> **Status:** Proposed (2026-07-23). New floor normalizer row `saturn-dc-raw`
> (NORMALIZERS.md, currently `queued`). Follows the composition pattern of
> `ps1-bincue` and `chd`: a raw-sector decoder that returns one `ByteView`
> of the inner 2048-byte ISO9660 stream; the caller re-normalizes it with
> `iso9660` (DESIGN § 1 — one normalizer, one layer, no recursion). This is
> the natural next unit per the atelier brief (coding/substratum), which
> flagged it as best-sequenced now that `ps1-bincue` shipped the shared
> raw-sector machinery. One open scoping decision is flagged for Kenrin in
> § 11.

## 0. What `saturn/dc-raw` actually is (the T1 finding)

The backlog row `saturn/dc-raw` (kind "disc image", differential `7z`,
deps none) conflates two representations. Probed against the committed
corpus of normalizers (2026-07-23); it resolves into two, only one of
which is a normalizer:

1. **A 2048-byte-sector "raw" image is already an ISO9660** — the existing
   `iso9660` normalizer walks it with zero new code. This is the exact
   situation the `cso` spec's § 0.1 finding documented for plain UMD/PSP
   `.iso`: building a separate normalizer for it duplicates a shipped unit.
   **Conclusion:** 2048-raw is **redundant** with `iso9660` and is *out of
   scope* as a distinct unit (recorded in § 9), same as the cso plain-iso
   half.

2. **The 2352-byte-sector raw CD-ROM Mode 1 image is the real substance.**
   Saturn discs (CD) and Dreamcast discs (GD-ROM data track) both store
   2048-byte user data inside 2352-byte raw sectors: `12 sync + 4 header +
   2048 user + 4 EDC + 276 ECC`. `iso9660` *cannot* read these — it expects
   bare 2048-byte sectors. A `saturn-dc-raw` normalizer strips the 16-byte
   (sync+header) prefix and the 288-byte (EDC+ECC) trailer per sector to
   recover the 2048-byte ISO9660 stream, then composes with `iso9660`. This
   is `ps1-bincue`-shaped (raw-sector remap → `ByteView`), but **distinct**:
   Mode 1 (no XA subheader; user at `[16:2064]`) vs Mode 2 Form 1 (`[24:2072]`
   + 8-byte XA subheader), and **single data track, no `.cue`** (the whole
   file is the disc / one contiguous data track — the registry lists no
   cue dependency and Differential is `7z` on the inner ISO).

**Recommendation:** scope `saturn-dc-raw` to **2352-byte-sector CD-ROM
Mode 1 raw, single data track, no cue**. The 2048-raw case is `iso9660`'s
domain. The NORMALIZERS.md edit is proposed in § 10; landing it rides with
implementation.

The unit is **platform-agnostic at the container layer** — Saturn and DC
both use Mode 1 2352 raw; the inner ISO's platform is the composed
`iso9660` layer's concern (PVD-only as today). Naming the unit for the
container shape (`saturn-dc-raw`), not a platform, matches `chd`/`cso` and
DESIGN's "normalize access, nothing else."

## 1. Motivation

Saturn and Dreamcast dumps in the wild frequently arrive as 2352-byte raw
images (e.g. DC rips, Saturn single-track `.bin`). Substratum currently has
no normalizer that can ingest them; `iso9660` chokes on the 2352 layout.
The substance of this unit is **CD-ROM Mode 1 sector-format understanding**
— the same raw-sector → lazy-`ByteView` → compose discipline `ps1-bincue`
proved — so the Spolia downstream (Stratum/Quarry/Kura/Interlinear) gains a
second major CD-era platform without re-implementing offsets.

## 2. Scope

**In scope:**
- `substratum/formats/saturn_dc_raw.py` — the normalizer (stdlib, returns `ByteView`).
- `seedtools/make_saturn_dc_raw_fixture.py` — authors the synthetic fixture.
- `fixtures/saturn_dc_raw/synthetic/` — committed `game_2352.bin` (the raw
  image), `synthetic.iso` (the pycdlib inner truth), `expected.manifest.json`,
  `reference/` (7-Zip extraction of `synthetic.iso`, per file).
- `tests/test_saturn_dc_raw.py` — the four-check gate + structural reds.
- **2352-byte-sector CD-ROM Mode 1 only.** Whole file = one contiguous
  data track.

**Out of scope (frozen / refused):**
- `substratum/contract.py`, `schema/manifest.schema.json`, `verify.py` — frozen.
- **No new runtime deps.** The remap is stdlib byte-slicing; pycdlib stays
  dev-only (fixture authoring / second reader); 7-Zip is already on PATH
  (DESIGN § 0). Deps: **none new** → row stays `deps: none`.
- **2048-raw images** — redundant with `iso9660` (§ 0.1); refused structurally
  (a 2048-raw file has no CD sync at `[0:12]`, so `sniff` returns False and it
  falls through to `iso9660` anyway — no separate unit needed).
- **Multi-track / audio discs** (e.g. a `.gdi` + multiple track `.bin`, or a
  raw image with an audio pregap track) — refused structurally (see § 5
  refusals). A GD-ROM with a separated audio track is a *different* row.
- The inner ISO's Joliet/RR, multisession — the composed `iso9660` layer's
  concern (PVD-only as today).
- EDC/ECC **validation** — zero-filled in the fixture and not checked (mirrors
  `ps1-bincue`; 7z only reads structure, and the normalizer's job is the
  byte-slice, not CD error-correction). Sync + mode are validated eagerly.

## 3. Feasibility findings (load-bearing)

Established by reading the two sibling decode-layers (no throwaway probe
needed — the pattern is already proven):

1. **`iso9660` already walks a 2048 ISO** (S1, 48 tests green) — so the inner
   half is a solved problem; `saturn-dc-raw` only needs to *produce* that
   2048 stream. The `ps1-bincue` wrapper `_normalize_ps1_to_tree` is the exact
   template: `view = normalize(src); tree = normalize_iso9660(view.source);
   return FileTree(source=tree.source, format="saturn-dc-raw", entries=tree.entries)`.
2. **The remap is pure stdlib slicing.** Mode 1 sector = `sync[0:12] +
   header[12:16] + user[16:2064] + EDC[2064:2068] + ECC[2068:2352]`; keep
   `[16:2064]` (2048 bytes). No external decoder, no vendoring — same posture
   `ps1-bincue` took (it deliberately rejected shell-out-to-chdman; we reject
   shell-out-to-7z for the decode, keeping the normalizer the system under
   test).
3. **`7z` is the natural differential + structural anchor** (the registry's
   chosen tool and the `iso9660` row's own oracle): `7z l -slt -tiso
   inner.iso` confirms the remapped file is a valid ISO (structural anchor,
   parallel to `ps1-bincue`'s chdman acceptance), and `7z x -tiso inner.iso`
   extracts `reference/` bytes for check 4 fidelity. pycdlib authors the inner
   ISO (independent creator + second reader for the expected manifest),
   exactly like S1.
4. **Independence is three-party:** pycdlib *authors* the inner ISO, `7z`
   *independently extracts* reference bytes, our remapper *independently
   slices* the 2352 raw. The remap's only job is recovering the 2048 stream;
   a wrong slicer yields wrong bytes and dies at check 4 (and, as § 7.1 notes,
   at check 1 once it corrupts the PVD).

## 4. Approach

**Stdlib Mode-1 raw-sector remap layer (chosen), returning one `ByteView`.**
The normalizer validates the 2352 layout eagerly (sync + mode on every
sector), exposes the reconstructed 2048-byte ISO stream as a lazy
`ByteSource`, and returns `ByteView(source=_Mode1RemapSource(...),
format="saturn-dc-raw")`. The caller re-normalizes that view with
`iso9660` (DESIGN § 1 — one layer, same shape as `chd`/`ps1-bincue`).

A shell-out-to-`7z`-for-decode variant is rejected (same reasoning as
`ps1-bincue` rejecting shell-out-to-chdman): it would delegate the unit's
substance (CD mode-1 sector understanding) to the very tool used as the
differential, collapsing the proof toward a one-party round-trip.

### 4.1 Independence model

- **Reference truth** = the pycdlib-authored inner-ISO content. pycdlib is
  the established second reader for the `iso9660` layer and is *never* the
  code under test. The normalizer must recover those bytes byte-exact by
  stripping the 2352 overhead; then `iso9660` walks them and check 4 diffs
  sampled files against `7z`'s extraction of the *same* pycdlib ISO.
- The differential reader (`7z`) and the author (pycdlib) are independent of
  each other and of the normalizer. Genuine two/three-party: pycdlib authored
  it; 7z independently extracts it; we independently remap it.

### 4.2 Composition check (closes the loop)

After remap, the normalizer's `ByteView` is re-normalized through `iso9660`
and the resulting `FileTree` is cross-checked against `7z`'s extraction —
the same two-reader gate S1 proved, exercised end-to-end:
`2352 raw → 2048-byte ISO → ISO9660 tree → diff vs 7z`. In tests this is the
`_normalize_saturn_to_tree` wrapper feeding `run_checks` (mirrors
`test_ps1_bincue.py`'s `_normalize_ps1_to_tree`).

### 4.3 Code-reuse posture (decision D3)

`ps1-bincue` already proved the lazy sector-remap + compose pattern. Two
options for `saturn-dc-raw`:

| | **A. Self-contained module (RECOMMENDED)** | **B. Shared `_sector.py` helper** |
|---|---|---|
| Form | `saturn_dc_raw.py` carries its own `_Mode1RemapSource` (≈50 lines, mirrors `_Mode2RemapSource` but offset `[16:2064]`, no XA subheader, no cue) | extract a shared `_RawSectorSource` base into `substratum/formats/_sector.py`, imported by both |
| Regression risk | **Zero** — `ps1_bincue.py` is untouched (a green unit stays green) | modifies a shipped unit; must re-run the full 60-test suite to confirm no regression |
| Duplication | ~50 lines of lazy-source boilerplate | none |

**Recommendation: A.** The brief's "shared sector machinery" refers to the
*proven approach* (ps1 shipped it first), not literal code-sharing. Self-
contained keeps the unit atomic and avoids regressing the just-shipped
ps1-bincue. B is available later as a cleanup if Kenrin wants DRY and is
willing to re-verify ps1.

## 5. The normalizer

`substratum/formats/saturn_dc_raw.py` (stdlib-only):

- **`sniff(source) -> bool`** — True when `size() >= SECTOR` and
  `read_at(0,12) == SYNC` **and** `read_at(15,1) == b"\x01"` (Mode 1). False
  for plain ISO (no sync at 0; mode byte absent) and for ps1-bincue's Mode-2
  raw (mode byte == 2). Bounded — refuse look-alikes, don't guess.
- **`normalize_saturn_dc_raw(source) -> ByteView`** — accept a path (str/Path)
  or a `ByteSource` (like `chd`/`iso9660`). Steps:
  1. Resolve a `ByteSource` (path → `FileSource`). Refuse if `size() == 0`.
  2. **Refuse** if `size() % SECTOR != 0` (structural red — not a raw disc).
  3. **Eager structural pass:** for every sector `i`, read `raw[i*2352 :
     i*2352+16]` and check `raw[0:12] == SYNC` and `raw[15] == 0x01`
     (Mode 1). Any mismatch → structural red (this is red-team case (a) — a
     corrupted/mis-scoped sector dies at check 1, deterministically, before
     any byte is materialized). The user stream is **not** materialized
     (these 16-byte reads are discarded immediately).
  4. Return `ByteView(source=_Mode1RemapSource(src), format="saturn-dc-raw")`.
- **`_Mode1RemapSource`** (mirrors `_Mode2RemapSource`): `size() →
  n_sectors*2048`; `read_at(off,n)` maps output offsets to
  `(sector, within)`, reads the 2352 raw sector on demand, returns
  `raw[16:2064]` for that sector's 2048 bytes; a **one-sector cache** keeps
  sequential reads within a sector from re-reading. Nothing materialized
  (DESIGN § 1).
- **Refusals (structural reds):** size not a multiple of 2352; sector-0 (or
  any) sync mismatch; mode byte != 1; a 2048-raw file (no sync → sniff False,
  falls through to `iso9660`); multi-track/audio-shaped inputs are out of
  scope by the single-data-track rule (a tool that needs a `.cue`/track table
  is a different row — see § 9).

Memory-bounded regardless of image size: only one 2352-byte sector is held
at a time — the lazy-source discipline `SliceSource`/`chd`/`ps1-bincue` set.

## 6. Fixture & differential

### 6.1 Fixture (synthetic, committed)

`seedtools/make_saturn_dc_raw_fixture.py` authors it deterministically:

1. **pycdlib** authors a small ISO (`interchange_level=1`): a `SYSTEM.CNF`/
   boot-stub + a few files + a nested dir + an incompressible blob (variety
   so the ISO is non-trivial) — the Saturn/DC-mastering shape and the
   **user-data truth** (2048-byte-sector ISO9660). Written to
   `synthetic.iso`; its per-file content is the `reference/` truth.
2. Wrap each 2048 sector into a 2352 MODE1 raw sector: prepend `SYNC`(12) +
   header(4: BCD address + mode=1) and append `EDC`(4, real CRC-32 over
   `[0,2064)` — matches Mode 1) + `ECC`(276, **zero-filled**, validation is
   out of scope per § 2) → write `game_2352.bin`.
3. Run `7z x -slt -tiso synthetic.iso -oreference` to extract `reference/`.
4. Commit `game_2352.bin`, `synthetic.iso`, `expected.manifest.json`
   (authored from **pycdlib's** records — independent of the normalizer),
   and `reference/`.

### 6.2 Differential (independence-critical)

- **Byte differential:** `7z`'s extraction of `synthetic.iso` — check 4 diffs
  each sampled file read *through* the composed tree against
  `reference/<path>`. The normalizer recovers the pycdlib ISO byte-exact by
  stripping overhead; `iso9660` walks it.
- **Structural anchor:** `7z l -slt -tiso` on the **remapped** inner stream
  lists the expected entries (third-party confirmation the remap produced a
  real ISO, parallel to `ps1-bincue`'s chdman acceptance + the iso9660 row's
  own `stage_homebrew_iso.py` acceptance check).
- **Composition check:** § 4.2 — the remapped `ByteView` re-normalized through
  `iso9660` matches pycdlib's directory records.

### 6.3 Tool pins

- pycdlib **1.16.0** (dev-only; pinned as at S1).
- 7-Zip **26.02 (x64) 2026-06-25** (on PATH; recorded in manifest
  `tool_versions`, the registry's differential).
- stdlib `zlib`/`struct` (runtime; Python 3.13 pin recorded by the env).
- Generator: `make_saturn_dc_raw_fixture v1`.

## 7. Tests

`tests/test_saturn_dc_raw.py` (additive; suite **60 → ~70**, +10). Wrapper
`_normalize_saturn_to_tree` composes `raw → ByteView → iso9660 → FileTree`
and overrides `format="saturn-dc-raw"` (mirrors `test_ps1_bincue.py`):

- **`test_saturn_dc_raw_is_green`** — `run_checks` on the synthetic fixture
  passes all four. Expected manifest authored by the seedtool from pycdlib's
  records; reference bytes = `7z` extraction of `synthetic.iso`.
- **`test_sniff`** — `SYNC`+mode1 true on `game_2352.bin`; plain ISO false;
  ps1 `game.bin` false (mode 2).
- **`test_returns_byteview`** — returns `ByteView(format="saturn-dc-raw")`;
  `view.source.size() == synthetic.iso` size and `% 2048 == 0`.
- **`test_decoded_stream_byte_equal_inner_iso`** — `read_at(0, size)` of the
  view == `synthetic.iso` bytes; a known file reads correctly through the
  lazy source (spot-check like `test_ps1_bincue.py`).
- **`test_composed_iso9660_tree_matches_expected`** — composed tree's entry
  paths match the expected manifest; every file reads byte-equal to
  `reference/`.
- **`test_expected_manifest_validates_against_schema`** — schema-valid,
  `format == "saturn-dc-raw"`, `kinds == {"file","dir"}`; `source.name ==
  "game_2352.bin"`, `source.sha256 == sha256(synthetic.iso)`,
  `source.size == synthetic.iso` size (the ps1/ chd manifest convention).
- **Structural reds:**
  - `test_corrupted_sync_is_structural_red` — flip a sync byte in sector 0.
  - `test_mode2_refused` — set a sector's mode byte to 2 (Mode 2 is ps1's
    domain; saturn-dc-raw is Mode 1 only).
  - `test_truncated_refused` — size not a multiple of 2352.
  - `test_not_a_raw_disc_refused` — a 2048 ISO sniffed False (falls through).
- **`test_wrong_offset_slicer_dies`** — inline mutant reads the wrong in-
  sector offset (e.g. `[24:2072]` Mode-2-style, or `[12:2060]` including
  header). Enumeration is unchanged but bytes are wrong; like `ps1_bincue`,
  a wrong offset corrupts the PVD signature at LBA 16, so it is **caught at
  check 1** (iso9660 refuses `CD001`), an even stronger guarantee than check
  4 — the DESIGN § 3(b) green-but-wrong case, dead.

### 7.1 Red-team positioning

The load-bearing mutant is a **wrong in-sector offset slicer** (returns
`raw[24:2072]` or `raw[12:2060]` instead of `raw[16:2064]`). It emits a
plausible 2048-stream and enumerates correctly through `iso9660`, but the
bytes are shifted; the PVD at LBA 16 no longer begins with `01 CD001 …`, so
the composed `iso9660` walker refuses structurally (check 1) — exactly the
outcome `ps1_bincue`'s spec documented. If a future variant slips past the
PVD (e.g. by chance the shifted bytes still parse), check 4 (fidelity vs the
7z reference) kills it regardless. Either way the green-but-wrong case is
dead.

## 8. Risks & mitigations

| Risk | Mitigation |
|---|---|
| Eager per-sector sync+mode scan is slow on huge homebrew images | Reads only 16 bytes/sector (≈0.7% of payload); bounded. Acceptable for the synthetic fixture; note if a retail DC anchor is later added (§ 9). |
| Mis-scoped input (2048 vs 2352) | `size % 2352 != 0` → structural red; sniff requires sync+mode1 so 2048-raw falls through to `iso9660`. |
| Wrong in-sector offset (the mutant) | § 7.1 + the PVD structural guard in composed `iso9660`. |
| 7z not on PATH in some env | DESIGN § 0 records 7-Zip on PATH via scoop; the differential step in the test uses a path check + skips visibly if absent (palimpsest optional-MediaInfo pattern), keeping the synthetic gate green without 7z. |
| ECC zero-filled in fixture reads as "valid ECC" inadvertently | ECC is never validated (§ 2); normalizer only slices user bytes. No correctness claim about ECC. |

## 9. Out of scope / deferred

- **2048-byte raw images** — already `iso9660`'s domain (§ 0.1). Optional:
  add a license-clean homebrew 2048 Saturn/DC `.iso` *fixture* to the
  `iso9660` row to prove generalization — not a new unit.
- **Multi-track / audio discs** (`.gdi` + track `.bin`, GD-ROM with audio
  pregap) — a different row (track-table parsing + data-track offset); not
  this unit. A `dreamcast-gdi` row can be spun later if felt need arises.
- **Mode 2 Form 1/2, CD-DA, mixed-mode** — ps1's domain / out of scope here.
- **Real retail Saturn/DC anchor** — a homebrew fixture (web-fetchable,
  license-clean per DESIGN § 5 tier 2) is the proof-strengthening path; a
  retail `FIXTURE REQUEST` drop is optional and metadata-only. The synthetic
  fixture is sufficient for the gate.

## 10. Proposed NORMALIZERS.md edit (lands with implementation)

Update the `saturn/dc-raw` row from `queued` to `GREEN` on completion, with:

```
| saturn/dc-raw | disc image (raw 2352) | T2 | GREEN (2026-07-23,
`substratum/formats/saturn_dc_raw.py`) | synthetic via pycdlib (Mode 1 2352
wrap, seedtool-authored) `fixtures/saturn_dc_raw/synthetic/`; homebrew
DC/Saturn disc (tier 2) proof-strengthening optional | 7-Zip 26.02 (x64)
2026-06-25 (`7z l -slt -tiso` / `7z x -tiso` on the remapped inner ISO) +
pycdlib 1.16.0 as second reader; fidelity sample seed 1 | none new | 2352
CD-ROM Mode-1 raw, single data track, no cue; refuses multi-track/audio/
2048-raw structurally; returns ByteView, caller composes with iso9660 (DESIGN
§1). 2048-raw is iso9660's domain (no separate unit) |
```

## 11. Open decisions for Kenrin

The normalizer, gate, and tests are identical regardless of these calls;
they are scoping/ergonomics, flagged rather than self-served (standing
"GitHub remote = Kenrin's call" discipline):

- **D1 — Scope to 2352 MODE1 only (recommended).** Confirm 2048-raw is
  treated as `iso9660`'s domain (not a unit). If you'd rather also ingest
  bare 2048 images through this row, say so — but it's redundant code.
- **D2 — No `.cue`, single data track (recommended).** Confirmed by the
  registry's `deps: none` / `7z`-only differential. Multi-track DC (`.gdi`)
  is explicitly deferred to its own row.
- **D3 — Self-contained module (recommended).** Don't refactor `ps1_bincue`
  to share a helper (zero regression risk). Flip to option B only if you
  want DRY and accept re-running the 60-test suite.
- **D4 — Eager full-sector scan (recommended).** Catches red-team case (a)
  anywhere deterministically. Acceptable cost; relax to sector-0-only + lazy
  per-read validation only if a large retail anchor later makes it slow.
- **D5 — Homebrew vs retail fixture for proof-strengthening.** Synthetic is
  sufficient for GREEN. A homebrew DC/Saturn disc (tier 2, web-fetched,
  committed if license-clean) is the natural follow-up anchor — Kenrin can
  green-light the fetch, or supply a retail `FIXTURE REQUEST` drop.

## 12. Implementation checklist (for the implementing session)

Carry this unit in one session, one git commit at the end (the atelier
"one unit = one format" rule). The design is frozen; execution is
mechanical. Commands assume the repo root
(`C:\Users\kenrin\Project\Substratum`) with `uv` on PATH.

**Pre-flight (30s):** confirm D1–D5 = the recommended defaults in § 11
(none require code changes — they only bind scope). If Kenrin overrode any,
re-read the relevant §. Assume defaults otherwise.

- [ ] **Step 1 — Fixture generator.**
  `seedtools/make_saturn_dc_raw_fixture.py` (new, dev-only pycdlib + 7z).
  Mirrors `make_ps1_bincue_fixture.py` structure. Implement § 6.1:
  (1) pycdlib authors a level-1 ISO →
  `fixtures/saturn_dc_raw/synthetic/synthetic.iso`;
  (2) wrap each 2048 sector into a 2352 MODE1 raw
  (`SYNC`+header[mode=1]+user+EDC[real CRC-32 over `[0,2064)`]+ECC[zero-
  filled]) → `game_2352.bin`;
  (3) `7z x -slt -tiso synthetic.iso -oreference` → `reference/`;
  (4) write `expected.manifest.json` from **pycdlib's** records (format
  `saturn-dc-raw`, source name `game_2352.bin`, sha256+size = synthetic.iso's).
  Generate deterministically (fixed timestamps / sorted entries) so the
  manifest is stable.

- [ ] **Step 2 — The normalizer.**
  `substratum/formats/saturn_dc_raw.py` (new, stdlib-only). Implement § 5:
  `sniff` (sync[0:12] **and** byte[15]==0x01), `normalize_saturn_dc_raw`
  (size%2352!=0 → refuse; eager per-sector sync+mode==1 scan; return
  `ByteView(_Mode1RemapSource, "saturn-dc-raw")`), `_Mode1RemapSource`
  (lazy, `raw[16:2064]` per sector, one-sector cache). Refusals per § 5.

- [ ] **Step 3 — The gate tests.**
  `tests/test_saturn_dc_raw.py` (new). Implement § 7: the
  `_normalize_saturn_to_tree` wrapper (raw→ByteView→iso9660→FileTree,
  format override), `run_checks` green test, sniff / byteview /
  decoded-stream / composed-tree / manifest-schema tests, the structural
  reds, and the wrong-offset red-team mutant (§ 7.1). Suite grows
  60 → ~70.

- [ ] **Step 4 — Prove GREEN & land.**
  1. `uv run pytest -q` → **all green, 60 → ~70** (full suite, not just the
     new file — confirms no regression in the shipped units).
  2. Flip the NORMALIZERS.md `saturn/dc-raw` row `queued` → `GREEN` using the
     text in § 10.
  3. `git add` the new/changed files (synthetic fixture + `reference/`, the
     three source/test files, NORMALIZERS.md, this spec — note
     `fixtures/saturn_dc_raw/synthetic/reference/` is **NOT** gitignored
     here, unlike gc_fst, so it commits; verify `.gitignore` doesn't
     exclude it).
  4. One commit; then update the atelier brief `Next steps` (mark
     saturn/dc-raw shipped) and append a `## 2026-… — Hunyuan` block to
     `projects/coding/substratum/log.md` + a week-log line. Clock out per
     `.atelier/CHARTER.md`.

**Definition of done:** `uv run pytest` fully green; manifest byte-equals
the generator's independent records; fidelity check 4 passes on the 7z
extraction; red-team mutant dies; NORMALIZERS row GREEN; atelier logged.
