# PS1 BIN/CUE Normalizer — Design Spec

> **Status:** Proposed (2026-07-22). A new floor normalizer (NORMALIZERS.md row
> `ps1-bincue`). The fourth normalizer unit. Follows the composition pattern
> of `chd` (returns a `ByteView`; the caller re-normalizes with `iso9660`).

## 1. Motivation

PS1 (and many PS2-CD) dumps are CD-ROM XA discs stored as a raw `.bin` of
2352-byte sectors + a `.cue` sheet. Each Mode 2 Form 1 sector carries 2048
bytes of user data wrapped in a 16-byte sync/header + an 8-byte XA subheader
+ EDC/ECC. A normalizer must remap the raw sector stream into the 2048-byte
user-data stream that `iso9660` then walks.

The substance of the unit — per NORMALIZERS.md — is "sector-format handling":
the normalizer genuinely understands CD-ROM XA Mode 2 sectors rather than
delegating to an external decoder. This is why it ships as its own layer
instead of leaning on `chdman` (which the `chd` unit already does for a
different purpose).

## 2. Scope

**In scope:**
- `substratum/formats/ps1_bincue.py` — the normalizer (stdlib, returns `ByteView`).
- `seedtools/make_ps1_bincue_fixture.py` — authors the synthetic fixture.
- `fixtures/ps1_bincue/synthetic/` — committed `.bin`, `.cue`, expected manifest,
  reference bytes (the pycdlib-authored 2048-byte stream).
- `tests/test_ps1_bincue.py` — the four-check gate + structural reds.

**Out of scope (frozen / refused):**
- `substratum/contract.py`, `schema/manifest.schema.json`, `verify.py` — frozen.
- No new vendored deps. pycdlib is dev-only (fixture authoring); chdman is
  already vendored (structural cross-check). No runtime deps beyond stdlib.
- Mode 1 sectors, Mode 2 Form 2 (2324-byte), audio tracks, multi-track discs,
  CD-TEXT, subchannel data — refused structurally (bounded discipline, mirrors
  iso9660). Form 2 / multi-track can be a future proof-strengthening row.

## 3. Feasibility findings (load-bearing)

Probed 2026-07-22 before this spec:

1. **7z 26.02 has no Mode-2-raw codec.** `7z i` lists only Iso and Udf codecs,
   both of which read 2048-byte-sector images. 7z cannot read a 2352-byte raw
   `.bin` directly. → 7z is not a standalone differential for the *raw* input;
   it is only usable *after* the normalizer remaps to the 2048 stream.
2. **pycdlib authors XA ISOs.** `PyCdlib.new(interchange_level=1, xa=True)`
   writes a 2048-byte-sector ISO9660 with the CD-ROM XA flag set — the
   user-data stream a PS1 disc carries. Proven: a tiny XA ISO authored and
   re-opened with `xa == True`.
3. **The seedtool wraps 2048 → 2352 raw sectors.** Each pycdlib block becomes
   a Mode 2 Form 1 sector: 12-byte sync (`00 FF*10 00`) + 4-byte header
   (BCD minute/second/frame + mode=2) + 8-byte XA subheader (repeated) +
   2048-byte user data + EDC (4) + ECC (280). Proven: 26 sectors wrapped,
   written as `.bin` + `.cue`.
4. **chdman `createcd` accepts the wrapped `.bin`/`.cue`.** A third-party tool
   reads the hand-authored raw structure and compresses it to a CHD tagged
   `MODE2_RAW` (26 frames). → structural validity confirmed by an independent
   tool. (chdman's `extractcd` re-emits raw sectors, not the 2048 stream, so
   it is a *structural* anchor, not the byte-level differential.)

## 4. Approach

**Stdlib Mode-2 Form-1 remapper (chosen over shell-out).** The normalizer
parses the `.cue` for the data track and sector size, walks each 2352-byte
raw sector, validates the sync pattern + mode, extracts the 2048-byte Form-1
user data, and returns it as a contiguous `ByteView`. The caller re-normalizes
that view with `iso9660` (DESIGN §1 composition — one normalizer, one layer,
same shape as `chd`).

A shell-out-to-chdman variant was rejected: it would delegate the unit's
substance (sector-format understanding) to the same tool that is the
differential, collapsing the proof toward a one-party round-trip. The stdlib
remapper makes the normalizer the system under test and pycdlib the
independent oracle.

## 5. The normalizer

`substratum/formats/ps1_bincue.py`:

- **`sniff(source) -> bool`** — True when the source is a `.bin` paired with a
  `.cue` (or a `.bin` whose first sector shows the Mode 2 sync pattern at the
  expected offset). Lightweight; does not fully parse.
- **`normalize_ps1_bincue(source) -> ByteView`** — accept a path or ByteSource.
  Steps:
  1. Resolve the `.bin` + `.cue` pair (a `.bin` path implies `.cue` sibling).
  2. Parse the `.cue`: locate the single data `TRACK ... MODE2/2352` and its
     `INDEX 01` start. Refuse multi-track, audio tracks, or non-MODE2 formats.
  3. Walk each 2352-byte sector from the INDEX 01 offset. For each:
     - Validate the 12-byte sync (`00 FF*10 00`); refuse on mismatch (structural).
     - Read mode byte (offset 15); must be 2.
     - Extract bytes [24:2072] — the 2048-byte Form-1 user data.
  4. Concatenate into a contiguous in-memory byte stream (or a lazy
     sector-remapping source; see §5.1).
  5. Return `ByteView(source=<remapped>, format="ps1-bincue")`.

**5.1 Lazy vs materialized.** A `ByteView` wraps a `ByteSource`. The cleanest
design is a `_Mode2RemapSource` that implements `read_at`/`size` by translating
byte offsets → (sector index, sector offset) and reading the underlying raw
`.bin` on demand — nothing materialized, mirroring `SliceSource`'s laziness.
The 2048-byte user stream is `nsectors * 2048` bytes. This keeps the
normalizer memory-bounded regardless of disc size.

### 5.2 Refusals (structural reds)

- Sync-pattern mismatch in any sector.
- Mode byte ≠ 2 (Mode 1 discs are a different row; refuse, don't guess).
- A `.cue` with multiple tracks, an audio track, or a non-MODE2/2352 data track.
- A `.bin` whose length is not a whole multiple of 2352.
- Missing `.cue` sibling.

## 6. Fixture & differential

### 6.1 Fixture (synthetic, committed)

`seedtools/make_ps1_bincue_fixture.py` authors the fixture in one deterministic
run:

1. pycdlib authors a small XA ISO (`interchange_level=1, xa=True`): a few files
   (a SYSTEM.CNF-style boot stub, a data file, an empty file, a nested dir) —
   the PS1-mastering shape. This 2048-byte-sector ISO is the **user-data truth**.
2. The seedtool wraps each 2048-byte block into a 2352-byte Mode 2 Form 1 raw
   sector (sync + BCD address from sector index + 2-second lead-in + XA
   subheader + user data + computed EDC/ECC). Writes `game.bin`.
3. Writes `game.cue`: single `TRACK 01 MODE2/2352`, `INDEX 01 00:00:00`.
4. Computes EDC/ECC for real (EDC is CRC-32 over bytes [0,2064); ECC is the
   CD-ROM ECC over the data columns) so the sectors are fully valid, not just
   structurally suggestive. **chdman's acceptance is the structural proof.**

The committed artifacts: `game.bin`, `game.cue`, `expected.manifest.json`, and
`reference/` (the pycdlib-authored 2048-byte stream as a plain `.iso`, which
verify.py's check 4 compares the normalizer's ByteView against).

### 6.2 Differential (independence-critical)

- **Reference truth:** the pycdlib-authored 2048-byte user-data stream. The
  normalizer must recover it byte-exact from the raw sectors. pycdlib is the
  independent reader (established at S1 as the ISO9660 second reader; never the
  normalizer under test). This is a genuine two-party proof: the normalizer
  independently decodes the raw sectors, pycdlib independently authored the
  user data.
- **chdman structural anchor:** `createcd` must accept the wrapped `.bin`/`.cue`
  without error — a third-party confirmation the raw structure is valid, not a
  fixture that only the normalizer happens to parse. (chdman does not produce
  the 2048 stream, so it is the *structural* anchor; pycdlib is the *byte*
  differential.)
- **Composition check:** after remapping, the normalizer's `ByteView` is
  re-normalized with `iso9660` and the resulting FileTree is cross-checked
  against pycdlib's own directory records (the same two-reader gate S1 proved).
  This closes the loop: raw sectors → 2048 stream → ISO9660 tree, all
  independently verified.

### 6.3 Tool pins

- pycdlib **1.16.0** (dev-only; pinned like S1).
- chdman **0.288 (mame0288)** (vendored; structural anchor).
- 7-Zip **26.02** — recorded for the composition check's post-remap ISO read,
  though it is not the primary differential here.
- Generator: `make_ps1_bincue_fixture v1`.

## 7. Tests

`tests/test_ps1_bincue.py` (additive; suite 36 → 45, +9):

- **`test_green_full_gate`** — `run_checks` on the synthetic fixture passes all
  four. The expected manifest is authored by the seedtool from pycdlib's
  records (independent of the normalizer); reference bytes are the pycdlib
  2048-byte stream.
- **`test_sniff`** — a `.bin`+`.cue` sniffs true; a plain ISO sniffs false.
- **`test_composed_iso9660_tree_matches_pycdlib`** — the normalizer's ByteView
  re-normalized through iso9660 yields a FileTree matching pycdlib's directory
  records (the composition-correctness gate).
- **Structural reds:**
  - `test_corrupted_sync_is_structural_red` — flip a sync byte in sector 0.
  - `test_mode1_refused` — a Mode 1 disc (mode byte = 1) is refused.
  - `test_audio_track_refused` — a `.cue` with an audio track is refused.
  - `test_truncated_bin_refused` — a `.bin` not a multiple of 2352 is refused.
  - `test_missing_cue_refused` — a `.bin` with no `.cue` sibling is refused.
- **`test_expected_manifest_validates_against_schema`**.

### 7.1 Red-team positioning

The load-bearing mutant is a **wrong-offset slicer**: extract the wrong byte
range from each sector (e.g. [16:2064] instead of [24:2072], reading the XA
subheader as user data). It produces a self-consistent, walkable, enumeration-
correct-looking stream — but the bytes are wrong, so check 4 (fidelity vs the
pycdlib reference stream) catches it. The sync-corruption and mode-byte reds
are the structural traps.

## 8. Risks & mitigations

| Risk | Mitigation |
|---|---|
| EDC/ECC computation is fiddly to get right | The seedtool computes them for sector validity; a wrong EDC/ECC still parses (chdman accepted zeroed ones) but computing real ones makes the fixture honest. Unit-test the EDC/ECC against a known vector. |
| BCD address encoding errors break chdman acceptance | The structural anchor (chdman createcd) catches a malformed address before the fixture commits. |
| Lazy remap source is more complex than materializing | The whole user stream of the synthetic fixture is tiny (<100 KB); materializing is acceptable. Decide at implementation: prefer lazy for fidelity to the contract's "nothing materialized" principle, fall back to materialized if lazy adds risk. |
| Mode 2 Form 2 sectors (video/ADPCM) are refused | Out of scope by design; Form 2 carries 2324 bytes and would need a separate handling row. The fixture uses only Form 1. |

## 9. Out of scope / deferred

- Mode 2 Form 2 (2324-byte) sectors — separate row if needed.
- Real PS1 retail anchor (FIXTURE REQUEST) — the synthetic fixture is
  sufficient for the gate; a retail drop is proof-strengthening only.
- Multi-track / CD-DA discs — refused structurally.
- Subchannel / CD-TEXT — out of scope.
- `.bin` without a `.cue` (raw sector inference) — sniff-only; refuse in
  normalize unless the cue is present (bounded discipline).
