# CSO (PSP/PS2 CISO) Normalizer — Design Spec

> **Status:** Proposed (2026-07-23). Resolves the `umd/psp-iso` backlog row
> (NORMALIZERS.md) — see §0. The delivered unit is a new floor normalizer row
> `cso`, the **fifth** normalizer unit. Follows the composition pattern of
> `chd` (returns a `ByteView`; the caller re-normalizes with `iso9660`).
> One open decision is flagged for Kenrin in §4.3 (fixture-author vendoring).

## 0. What `umd/psp-iso` actually is (the T1 finding)

The backlog row `umd/psp-iso` (kind "disc filesystem", differential `7z`,
deps none) conflates two different things. Probed 2026-07-23; the row
**resolves into two, only one of which is a normalizer:**

1. **A plain UMD `.iso` is a 2048-byte-sector ISO9660** — which the existing
   `iso9660` normalizer already walks. **Proven** (`probe_cso.py` [A]): a
   pycdlib-authored PSP-shaped image (29 × 2048B sectors, `PSP_GAME/` +
   files) was enumerated by `normalize_iso9660` with **zero new code**. So a
   plain UMD/PSP/PS2-CD `.iso` is **redundant** with `iso9660`; building a
   separate normalizer for it would duplicate a shipped unit. At most it
   justifies adding a license-clean homebrew PSP `.iso` *fixture* to the
   `iso9660` row to prove generalization — not a new unit, and low value.

2. **The CSO / CISO compressed container is the real substance.** `.cso` is
   the format the PSP/PS2 scene actually stores images in that `iso9660`
   *cannot* read — it is a compressed wrapper around the 2048-byte ISO. It is
   `chd`-shaped: decode the container to a `ByteView` of the inner ISO, then
   the caller composes with `iso9660`. This is a genuine new floor unit.

**Recommendation:** retire the vague `umd/psp-iso` row; replace it with a
`cso` decode-layer row (this spec). The plain-`.iso` half needs no unit. The
NORMALIZERS.md edit is proposed in §10; landing it rides with implementation.

`cso` is **platform-agnostic at the container layer** — CSO wraps both PSP
and PS2 ISOs, and Substratum normalizes access only (the inner ISO's platform
is nobody's concern here). Naming the unit for the container (`cso`), not the
platform (`umd`), matches `chd` and the DESIGN's "normalize access, nothing
else."

## 1. Motivation

CSO ("compressed ISO", a.k.a. CISO) is the dominant space-saving format for
PSP and PS2 optical dumps. Format: a 24-byte header, a per-block offset index,
and deflate-compressed 2048-byte blocks. A normalizer must parse the CISO
container and reconstruct the 2048-byte ISO9660 stream that `iso9660` then
walks. The substance of the unit is **CISO container handling** — header +
index-table + per-block compressed/stored decisions + alignment — not the
deflate primitive (stdlib), so it ships as its own layer rather than leaning
on an external decoder.

## 2. Scope

**In scope:**
- `substratum/formats/cso.py` — the normalizer (stdlib, returns `ByteView`).
- `seedtools/make_cso_fixture.py` — authors the synthetic fixture.
- `fixtures/cso/synthetic/` — committed `game.cso`, `expected.manifest.json`,
  `reference/` (the pycdlib-authored 2048-byte ISO content, per file).
- `tests/test_cso.py` — the four-check gate + structural reds.
- **CSO v1 only:** magic `CISO`, 24-byte header, `uint32` index table,
  `block_size == 2048`, top-bit "stored uncompressed" flag, `align`
  (index_shift) honored, blocks = **raw deflate** (stdlib `zlib`, wbits −15).

**Out of scope (frozen / refused):**
- `substratum/contract.py`, `schema/manifest.schema.json`, `verify.py` — frozen.
- **No new runtime deps.** Decompression is stdlib `zlib`. pycdlib stays
  dev-only (fixture authoring / second reader). The only *tooling* question is
  the fixture author (§4.3).
- **ZSO** (`ZISO` magic, lz4), **CSO v2**, **DAX**, **JISO** — refused
  structurally by magic/version (bounded discipline, mirrors `iso9660`'s
  PVD-only and `ps1-bincue`'s Mode-2-Form-1-only scope). Each can be a future
  row (lz4 is not stdlib, so ZSO would carry a runtime-dep decision).
- The inner ISO's Joliet/RR, multi-track, audio — not this layer's concern
  (the composed `iso9660` layer owns filesystem scope, PVD-only as today).

## 3. Feasibility findings (load-bearing)

Probed 2026-07-23 (a one-off probe script, run in the repo uv env) before
this spec:

1. **Plain `.iso` is already handled** (§0.1). pycdlib authored a PSP-shaped
   ISO; the *existing* `normalize_iso9660` walked it (3 entries). → no plain-
   `.iso` normalizer needed.
2. **CISO v1 round-trips byte-exact with stdlib `zlib`.** The probe authored
   an ISO, wrote a CISO v1 `.cso` (header + index + raw-deflate blocks,
   **forcing one stored-uncompressed block** to exercise the top-bit), then a
   minimal reader decoded it: **`decode == original iso` → True**, 59,392 B
   recovered exactly; the `.cso` was 6.0% of the ISO with 1 stored-raw block.
   → the normalizer needs no vendored decoder; stdlib `zlib` suffices.
3. **maxcso is the natural third-party author/anchor** (web-confirmed): CLI
   `maxcso in.iso -o out.cso` and `maxcso --decompress in.cso -o out.iso`,
   emits standard deflate (stdlib `zlib` inflates it regardless of whether
   maxcso used zlib/7-zip-deflate/zopfli), supports CSO v1. This is the
   `chd`↔`chdman` relationship for `cso`.
4. **Red-team subtlety surfaced by the probe.** A throwaway "ignore the
   top-bit" mutant reader *accidentally passed* on the forced-raw fixture,
   because a stored-raw block survives a naive `try zlib.decompress except
   copy` fallback. → the load-bearing mutant for check 4 must be a
   **wrong-block-boundary / wrong-`align` slicer** (produces wrong bytes for
   *compressed* blocks), not a top-bit-ignore. Recorded so the implementer
   picks the mutant that actually bites (§7.1).

## 4. Approach

**Stdlib CISO decode layer (chosen), returning one `ByteView`.** The
normalizer parses the CISO header + index, exposes the reconstructed 2048-byte
ISO stream as a lazy `ByteSource`, and returns `ByteView(source, "cso")`. The
caller re-normalizes that view with `iso9660` (DESIGN §1 — one normalizer, one
layer, same shape as `chd`).

A shell-out-to-maxcso *decoder* variant is rejected for the normalizer body
(same reasoning as `ps1-bincue` rejecting shell-out-to-chdman): it would
delegate the unit's substance (CISO container understanding) to the very tool
used as the anchor, collapsing the proof toward a one-party round-trip. The
stdlib reader makes the normalizer the system under test.

### 4.1 Independence model

- **Reference truth** = the pycdlib-authored inner-ISO content. pycdlib is the
  established second reader for the `iso9660` layer (S1) and is *never* the
  code under test. The normalizer must recover those bytes byte-exact by
  decoding the CISO, after which `iso9660` walks them and check 4 diffs
  sampled files against pycdlib's records. Genuine two-party: pycdlib authored
  the content; the normalizer independently decodes container + deflate.
- The deflate primitive is shared (stdlib `zlib` on both sides) but is **not
  the substance** — a standard codec, like `struct` in `iso9660`. A mutant
  that mis-parses the index, drops the `align` shift, or misorders blocks
  yields wrong bytes and dies at fidelity regardless of `zlib`.

### 4.2 Composition check (closes the loop)

After decode, the normalizer's `ByteView` is re-normalized through `iso9660`
and the resulting `FileTree` is cross-checked against pycdlib's own directory
records — the same two-reader gate S1 proved, exercised end-to-end:
`.cso` → 2048-byte ISO → ISO9660 tree, each step independently verified. In
tests this is the `_normalize_cso_to_tree` wrapper feeding `run_checks`
(mirrors `test_chd.py`'s `_normalize_chd_to_tree`).

### 4.3 OPEN DECISION for Kenrin — fixture author

Who authors the committed `.cso`? Two viable paths; the normalizer, gate, and
tests are **identical** either way (probe [2] proved the dep-free path works,
so this is a strength-vs-vendoring call, not a feasibility one):

| | **A. maxcso (RECOMMENDED)** | **B. stdlib-zlib seedtool (dep-free)** |
|---|---|---|
| Fixture author | vendored maxcso (`maxcso in.iso -o game.cso`) | `make_cso_fixture.py` writes CISO v1 with `zlib` |
| Independence | **third-party** author; the normalizer inverts a real-world CISO | compress+decompress are the same stdlib codec (weaker) |
| Structural anchor | `maxcso --decompress` reproduces the ISO byte-exact (a third-party "this is a valid CISO", parallel to `chd`'s `chdman createcd`) | none beyond self-consistency |
| Real-world shapes | maxcso picks mixed compressed/raw blocks + `align` — exercises shapes a toy writer won't | only the shapes our writer emits |
| Cost | one vendor-prep row (binary in gitignored `tools/`, TOFU sha256 + **license check** like `wit`); deps: none → `maxcso` | zero new vendoring; row stays deps: none |

**Recommendation: A (vendor maxcso).** It reproduces the established `chd`
pattern (a decode-layer unit whose format warrants a third-party tool), gives
a genuine third-party author + a `--decompress` round-trip anchor, and stresses
the reader with real CISO shapes. B is the clean fallback if Kenrin prefers
zero new vendoring — the gate still bites (a wrong-slicer mutant fails check 4
on compressed blocks). Flagging rather than self-serving the vendoring call,
same as the standing "GitHub remote = Kenrin's call".

*(Hybrid available: ship B's seedtool as the always-green committed path AND
add maxcso as an optional `--decompress` cross-check that skips visibly when
the binary is absent — the palimpsest optional-MediaInfo pattern. Noted; not
the primary recommendation, to avoid a half-measure.)*

## 5. The normalizer

`substratum/formats/cso.py` (stdlib-only, runtime `zlib`):

- **`sniff(source) -> bool`** — True when the first 4 bytes are `CISO`. False
  for `ZISO`/`DAX`/plain ISO (bounded — refuse look-alikes, don't guess).
- **`normalize_cso(source) -> ByteView`** — accept a path or `ByteSource`
  (like `chd`/`iso9660`). Steps:
  1. Read the 24-byte header: `magic[4]="CISO"`, `header_size(u32)`,
     `total_bytes(u64)`, `block_size(u32)`, `ver(u8)`, `align(u8)`, `unused[2]`.
     Refuse: magic≠`CISO`; `ver≠1`; `block_size≠2048` (structural reds).
  2. Read the `(nblocks+1)` `uint32` index (`nblocks = ceil(total/block_size)`),
     starting at `header_size` (fall back to 24 when the field is 0, as some
     writers leave it). For block *i*: `plain = index[i] & 0x8000_0000`;
     `start = (index[i] & 0x7fff_ffff) << align`;
     `end = (index[i+1] & 0x7fff_ffff) << align`. **Validate the index eagerly**
     at parse time (cheap — the table only, not the blocks): refuse a truncated
     index, a non-monotonic offset, or any `[start,end)` outside the file
     (structural reds that fire deterministically at check 1).
  3. Return `ByteView(source=_CisoSource(raw, header, index), format="cso")` —
     **do not materialize** (DESIGN §1). `_CisoSource` implements the contract:
     - `size()` → `total_bytes`.
     - `read_at(off, n)` → map `[off, off+n)` to block indices; for each block,
       fetch-and-cache its 2048 bytes: `plain` → copy `raw[body0+start:...][:2048]`;
       else `zlib.decompress(raw[body0+start:end], -15)`; assert the decoded
       block length == `block_size` (else structural red — a wrong/oversized
       block). This block-content check is inherently **lazy** (fires when a
       read touches the bad block); the eager index validation in step 2 is
       what makes structural reds deterministic, and the malformed-block test
       (§7) corrupts a sector the `iso9660` enumeration reads so the guard
       surfaces at check 1. A **1-block LRU** keeps sequential reads from
       re-inflating.
- **Refusals (structural reds):** bad magic; `ver≠1`; unsupported `block_size`;
  `ZISO`/`DAX` magic; truncated header/index/body; an index range out of file
  bounds; a compressed block that inflates to ≠ `block_size`.

Memory-bounded regardless of image size: only one (optionally a few) 2048-byte
block is held at a time — the lazy-source discipline `SliceSource`/`chd` set.

## 6. Fixture & differential

### 6.1 Fixture (synthetic, committed)

`seedtools/make_cso_fixture.py` authors it deterministically:

1. pycdlib authors a small ISO (`interchange_level=1`): a `PSP_GAME/` dir, a
   compressible file, an **incompressible** file (forces ≥1 stored-raw block),
   an empty file, a nested dir — the PSP-mastering shape and the **user-data
   truth** (2048-byte-sector ISO9660). This is the `reference/` content.
2. Compress the ISO to `game.cso` — **maxcso** (path A) or a stdlib-`zlib`
   CISO v1 writer (path B), per §4.3.
3. Commit `game.cso`, `expected.manifest.json` (authored from **pycdlib's**
   records — independent of the normalizer), and `reference/` (the pycdlib
   2048-byte content that check 4 diffs the decoded ByteView against).

### 6.2 Differential (independence-critical)

- **Byte differential:** the pycdlib inner-ISO content — the normalizer
  recovers it byte-exact through decode; pycdlib is the independent reader
  (never the code under test).
- **Structural anchor (path A):** `maxcso --decompress game.cso -o rt.iso`
  reproduces the pycdlib ISO byte-exact — third-party confirmation the `.cso`
  is a valid CISO, not a fixture only this normalizer parses. (Path B has no
  third-party anchor; the two-reader composition check + red-team carry it.)
- **Composition check:** §4.2 — the decoded ByteView re-normalized through
  `iso9660` matches pycdlib's directory records.

### 6.3 Tool pins

- pycdlib **1.16.0** (dev-only; pinned as at S1).
- maxcso **<pin at vendor-prep>** (path A only; TOFU sha256 + license check,
  binary gitignored in `tools/`, script is the provenance — `wit` discipline).
- stdlib `zlib` (runtime; Python 3.13 pin recorded by the environment).
- Generator: `make_cso_fixture v1`.

## 7. Tests

`tests/test_cso.py` (additive; suite **36 → 46**, +10). Wrapper
`_normalize_cso_to_tree` composes `cso → ByteView → iso9660 → FileTree` and
overrides `format="cso"` (mirrors `test_chd.py`):

- **`test_cso_is_green`** — `run_checks` on the synthetic fixture passes all
  four. Expected manifest authored by the seedtool from pycdlib's records;
  reference bytes = the pycdlib 2048-byte content.
- **`test_sniff`** — `CISO` true; plain ISO false; a `ZISO`-magic blob false.
- **`test_normalize_cso_returns_byteview`** — returns `ByteView(format="cso")`;
  `view.source.size() == total_bytes`.
- **`test_decompressed_matches_iso`** — spot-check: `read_at(16*2048, 2048)`
  (the PVD sector) byte-identical to the pycdlib ISO (as `test_chd.py` does).
- **Structural reds:**
  - `test_bad_magic_is_structural_red` — flip a magic byte.
  - `test_zso_refused` — a `ZISO`-magic input is refused (not silently parsed).
  - `test_unsupported_blocksize_refused` — `block_size≠2048`.
  - `test_truncated_index_refused` — index shorter than `nblocks+1`.
  - `test_block_wrong_length_refused` — a block that inflates to ≠2048.
- **`test_expected_manifest_validates_against_schema`** — schema-valid,
  `format == "cso"`, `kinds == {"file","dir"}`.

### 7.1 Red-team positioning

The load-bearing mutant is a **wrong-block-boundary / dropped-`align` slicer**:
compute `start/end` without the `<< align` shift, or read block *i* with block
*i−1*'s offset. It enumerates a plausible-looking stream but decodes wrong
bytes for every *compressed* block, so check 4 (fidelity vs the pycdlib
reference) kills it — the DESIGN §3(b) green-but-wrong case. **Not** the
top-bit-ignore mutant: probe finding [4] showed a stored-raw block survives a
naive fallback, so that mutant is a false comfort. The magic/version/block-size
cases are the structural traps.

## 8. Risks & mitigations

| Risk | Mitigation |
|---|---|
| `align`/index_shift handled wrong on larger images | Fixture is small (`align=0`), but honor `align` generally in `read_at`; a maxcso-authored fixture (path A) may pick `align>0`, exercising the shift. Add a targeted unit if a real image needs it. |
| Shared stdlib `zlib` on both sides reads as a one-party round-trip | §4.1: the *substance* is CISO container parsing, not deflate; path A removes the doubt entirely (third-party author + `--decompress` anchor). |
| maxcso license/redistribution | Same as `wit`/`chdman`: binary stays in gitignored `tools/`, the vendor script + pinned sha256 is the committed provenance; verify license at the vendor-prep step; the tool is only *run*, never linked or committed. |
| Wrong red-team mutant chosen (top-bit-ignore) | §7.1 pins the correct wrong-slicer mutant; probe [4] documents why. |
| A block inflates to ≠2048 (malformed/hostile) | Explicit length assertion in `read_at` → structural red (`test_block_wrong_length_refused`). |

## 9. Out of scope / deferred

- **ZSO** (lz4) and **CSO v2** — separate rows; lz4 is not stdlib, so ZSO
  carries a runtime-dep decision (defer until felt need).
- **DAX / JISO** — legacy PSP formats; refused by magic, future rows if needed.
- Plain UMD/PSP `.iso` — already `iso9660`'s domain (§0.1); optional homebrew
  fixture add to that row, not a unit here.
- Real retail PSP CSO anchor — a `FIXTURE REQUEST: PSP .cso` is proof-
  strengthening only; the synthetic fixture is sufficient for the gate.
- Form-2 / mixed-mode inner discs — the inner layer's concern, unchanged.

## 10. Proposed NORMALIZERS.md edit (lands with implementation)

Replace the `umd/psp-iso` row with:

```
| cso | container (decode) | T2 | queued | synthetic: pycdlib authors an ISO
(2048B sectors, incompressible file forces a stored-raw block), compressed to
game.cso by maxcso [path A] or a stdlib-zlib seedtool [path B]; reference =
pycdlib inner-ISO content | pycdlib 1.16.0 byte-differential + (path A) maxcso
--decompress structural anchor; stdlib zlib decode | none new [B] / maxcso [A]
| CISO v1 only (magic CISO, u32 index, 2048B blocks, top-bit stored-raw, align
honored); ZSO/CSO-v2/DAX refused by magic; returns ByteView, caller re-normalizes
with iso9660 (DESIGN §1) |
```

The plain-`.iso` half of the old row needs no unit (§0.1). If path A is chosen,
add a `vendor-maxcso` prep row alongside `vendor-chdman` / `vendor-wit`.
