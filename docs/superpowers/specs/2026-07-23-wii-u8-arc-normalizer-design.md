# Wii U8 archive normalizer — Design Spec

> **Status:** Proposed (2026-07-23). New floor normalizer row `wii-u8-arc`
> (NORMALIZERS.md, currently `queued`). Follows the same shape as `gc-fst`
> (archive-as-FS → `FileTree`); `deps: shared with gc-fst` in the registry
> means the **node-table walk algorithm** is shared, not a code import
> (see D2). One open scoping decision on the differential tool is flagged
> for Kenrin in § 11 — the registry's assumed `wit`/`dolphin-tool`
> differential does **not** apply (proven below, § 0 / § 3).

## 0. What `wii-u8-arc` actually is (the T1 finding)

The backlog row `wii-u8-arc` (kind "archive-as-FS", differential
`wit`/`dolphin-tool`, deps "shared with gc-fst") is sensible at a glance
but, probed against the format and the vendored toolchain
(2026-07-23), resolves into one load-bearing correction:

1. **`wit` cannot read a standalone U8.** `wit` (v3.05a r8638, the only
   vendored tool of the two) is a GameCube/Wii *disc-image* tool. A quick
   feasibility probe — authored a minimal valid U8 (root dir + one file
   `a.txt` = `hello`, 69 bytes) and ran `wit FILETYPE` / `wit DUMP` — both
   failed: `FILETYPE` reports `NO-FILE`, `DUMP` errors `CAN'T OPEN FILE`
   (#76). `dolphin-tool` is **not vendored** at all (confirmed: `tools/`
   holds only `chdman/`, `maxcso/`, `wit/`). So the registry's
   `wit`/`dolphin-tool` differential does not exist for this row. The
   spec records this and proposes a real alternative (§ 3 / § 6 / D1).
2. **A U8 is trivially authorable → the fixture is SYNTHETIC (tier-1),
   not a homebrew/retail drop.** The NORMALIZERS row guessed "homebrew";
   but U8 is a fully-specified directory-tree serialization (WiiBrew,
   below) with no compression or crypto, so a deterministic seedtool can
   author it directly — exactly like the iso9660 / ps1-bincue / cso
   fixtures. No retail/homebrew anchor is needed for GREEN. (This mirrors
   the saturn-dc-raw § 0 finding that a format can be authorable without
   a retail drop.)
3. **The substance is the node-table walk — shared with `gc-fst`.**
   U8 nodes are **`0x0C` (12) bytes**, same size as GameCube FST nodes,
   with the same `(type, name_offset, offset/size)` layout and the same
   contiguous-child recursion. The two differ only in indexing: U8 is
   **1-based** (root is node "1"; a directory's `size` = the *node number*
   of its last child) and files carry an **absolute** `data_offset`; GC
   FST is 0-based with an FST-relative file offset. So `wii-u8-arc` is a
   natural next unit — it reuses `gc-fst`'s proven traversal discipline.

**Recommendation:** implement `wii-u8-arc` as a self-contained
`archive-as-FS` normalizer returning a `FileTree` (like `gc-fst`/`iso9660`,
NOT a `ByteView` — U8 *is* a filesystem, it has no inner image to compose
with `iso9660`). Scoped to **uncompressed U8**; YAZ0/SZS-compressed U8 is
out of scope as a separate row (§ 9). NORMALIZERS.md edit lands with
implementation (§ 10).

## 1. Motivation

U8 archives (`.arc`, `.carc`, `.szs`) are the Wii/GameCube "attach files in
a directory structure" format — `opening.bnr`, Wii Shop content, many
system files. Substratum currently has no normalizer for a plain archive
format that resolves to a `FileTree` directly (gc-fst is disc-FST; the
rest are `ByteView` decoders composed with iso9660). A `wii-u8-arc` unit
extends the archive-as-FS class and gives the Spolia downstream
(Stratum/Quarry/Kura/Interlinear) a second archive platform. It is the
natural sequel to `gc-fst` — same walk, different container.

## 2. Scope

**In scope:**
- `substratum/formats/wii_u8_arc.py` — the normalizer (stdlib, returns `FileTree`).
- `seedtools/make_wii_u8_arc_fixture.py` — authors the synthetic fixture.
- `fixtures/wii_u8_arc/synthetic/` — committed `archive.arc` (the U8),
  `expected.manifest.json`, `reference/` (extracted file contents).
- `tests/test_wii_u8_arc.py` — the four-check gate + structural reds + the
  wrong-slice red-team mutant.
- **Uncompressed U8 only.** Root is one archive (the whole file).

**Out of scope (frozen / refused):**
- `substratum/contract.py`, `schema/manifest.schema.json`, `verify.py` — frozen.
- **No new runtime deps.** The walk is stdlib byte-slicing; nothing vendored
  unless Kenrin picks the vendored-CLI differential in D1 (in which case the
  tool is gitignored in `tools/`, pinned like `chdman`/`maxcso`).
- **YAZ0 / SZS-compressed U8** — `.szs`/`.carc` are usually YAZ0-wrapped
  U8; that is a separate decode layer (a `cso`-shaped `ByteView` unit), NOT
  this row. Refused structurally (the tag would be the YAZ0 magic, not U8).
- Multi-archive / concatenated U8, encryption, non-node-table variants.
- Names outside the byte-string table, cycle/self-parent dirs, out-of-bounds
  offsets — refused structurally (see § 5 refusals).

## 3. Feasibility findings (load-bearing)

Established by reading `gc_fst.py` + `gc_fst`'s yagcd §13 reference, the
WiiBrew U8 page, and a hands-on `wit` probe (no throwaway was wasted — it
disproved the registry's assumed differential):

1. **U8 header** (32 bytes, big-endian): `tag` (`0x55AA382D` — rendered
   "U.8-", bytes `55 AA 38 2D`), `rootnode_offset` (always `0x20`),
   `header_size` (root_node..end of string table), `data_offset`
   (rootnode_offset + header_size, **aligned to `0x40`**), then `zeroes[16]`.
   The node array begins at `0x20`; the string table begins at
   `0x20 + n_nodes*12`. `n_nodes` is the root node's `size` field (§ 0.3).
2. **Node** (`0x0C` = 12 bytes, identical size to GC FST): byte 0 = `type`
   (`0x00` file, `0x01` dir); bytes 1–3 = `name_offset` (24-bit, big-endian,
   into the string table); bytes 4–7 = `data_offset` (for a file: **absolute**
   byte offset from the U8 header start; for a dir: parent node number);
   bytes 8–11 = `size` (for a file: byte length; for a dir: **1-based node
   number of the last child included**). Root is node 1: `type=1`,
   `name=""` (name_offset 0), and the `data_offset`/`size` locate its scope.
3. **Recursion = GC FST's contiguous-child walk, 1-based.** A directory's
   direct children are the nodes immediately after it, up to (exclusive) its
   `size` node-number. `wii_u8_arc` reuses `gc_fst._walk`'s algorithm with
   the two indexing adjustments (1-based scope; absolute file offset). The
   parser, like `gc_fst`, supports nesting generically (a nested-dir
   fixture is proof-strengthening, not a gate).
4. **`wit` cannot read standalone U8** — probe above (`NO-FILE` / open
   error). So the differential is NOT `wit`/`dolphin-tool`. Concrete
   alternatives (D1): (a) **vendor a pinned U8 extractor CLI**
   (`parse-u8.c`, bushing — the canonical ~120-line reference; compile and
   sha256-pin like `chdman`/`maxcso`; TOFU since upstream publishes no
   checksums) and use it for reference-byte extraction (check 4) + a
   structural `parse-u8` listing anchor; or (b) **structural self-consistency
   proof (DESIGN § 3)** — the U8 node-table walk is fully determined by the
   bytes, so a wrong parser fails check 1 (bounds) / check 2 (manifest) /
   check 3 (stability), exactly like `gc-fst`'s fallback; or (c) pin a
   second Python U8 reader. Recommended: (a) if a CLI can be compiled in the
   env; else (b). Either way the **manifest is authored by the generator from
   its known in-memory tree T** (independent of the parser under test), and
   **reference bytes come from a different extraction path than the
   normalizer** (no one-party round-trip).
5. **Independence is three-party:** the seedtool *authors* T and the bytes;
   the normalizer *independently parses* the bytes; the differential
   (vendored CLI or self-consistency proof) *independently re-derives* the
   contents. A normalizer that mis-slices or mis-recurses yields wrong
   entries/offsets and dies at check 1/2/4.

## 4. Approach

**Stdlib U8 node-table walker (chosen), returning one `FileTree`.** The
normalizer validates the header + tag eagerly (tag, sizes, alignment sanity),
walks the node table into `FileEntry`s (directories get `offset=0,size=0`;
files get `offset=data_offset, size=size`, both absolute into the source),
and returns `FileTree(source=src, format="wii-u8-arc", entries=...)`. No
inner ISO, no `iso9660` composition — U8 *is* the filesystem.

### 4.1 Independence model

- **Expected manifest** = derived by the seedtool from its known in-memory
  tree T (the generator is the authoritative author, like `pycdlib` is for
  iso9660). `canonical_manifest(tree_T, source_name, sha256(archive),
  tool_versions)` — byte-exact, never from the parser.
- **Reference bytes** (check 4) = the differential's extraction of the
  archive's files into `reference/`. The normalizer's `FileTree` is read
  through `verify.py`'s sampling and diffed against `reference/`.
- **The differential** is independent of both (D1). Genuine two/three-party.

### 4.2 Composition check

None needed — `wii-u8-arc` returns a `FileTree` directly (it does not
compose with `iso9660`). The gate closes the loop as
`archive → FileTree → diff vs reference/`, same as `gc-fst` / `iso9660`.

### 4.3 Code-reuse posture (decision D2)

`gc_fst._walk` already proved the walker. Two options for `wii_u8_arc`:

| | **A. Self-contained module (RECOMMENDED)** | **B. Shared `_node_archive.py` helper** |
|---|---|---|
| Form | `wii_u8_arc.py` carries its own `_Walk` (≈60 lines, mirrors `gc_fst._walk` with 1-based + absolute-offset adjustments) | extract a shared `_NodeArchiveWalker` into a helper imported by both |
| Regression risk | **Zero** — `gc_fst.py` is untouched (a green unit stays green) | modifies a shipped unit; must re-run the full suite to confirm no regression |
| Duplication | ~60 lines of walker boilerplate | none |

**Recommendation: A.** The brief's "shared with gc-fst" refers to the
*proven algorithm* (gc-fst shipped it first), not a literal code import.
Self-contained keeps the unit atomic and avoids regressing the just-shipped
`gc_fst` (and, transitively, the saturn unit that has its own pattern). B
is available later as a cleanup if Kenrin wants DRY and accepts re-verifying
`gc-fst`.

## 5. The normalizer

`substratum/formats/wii_u8_arc.py` (stdlib-only):

- **Constants:** `_TAG = 0x55AA382D` (`b"\x55\xAA\x38\x2D"`), `_HEADER = 32`,
  `_NODE_SIZE = 0x0C`, `_STR_BASE = 0x20` (node array start), dir/file types
  `1`/`0``.
- **`sniff(source) -> bool`** — True when `size() >= 32` and
  `read_at(0,4) == b"\x55\xAA\x38\x2D"`. Bounded — refuse look-alikes.
- **`normalize_wii_u8_arc(source) -> FileTree`** — accepts a path or
  `ByteSource`. Steps:
  1. Resolve a `ByteSource` (path → `FileSource`). Refuse if `size() == 0`.
  2. **Eager header pass:** read `tag` (must equal `_TAG`, else structural
     red — also rules out YAZ0/SZS/other magics); read `rootnode_offset`
     (must be `0x20`); `n_nodes = root_node.size` (the root is node 1, its
     `size` = total node count). Refuse if `root` `type != 1`, or
     `0x20 + n_nodes*12 > size()` (table past EOF), or the root `data_offset`
     (parent) is not `0`/`1` (self).
  3. **Walk** (`_walk`): recurse from the root with array scope
     `[1, n_nodes)`; for each dir node, children = `[self+1, size)`; for each
     file node, `offset = data_offset`, `size = size`, and **bounds-check**
     `offset + size <= src_size` (structural red otherwise). Decode names
     from the string table (`strtab_base = 0x20 + n_nodes*12`,
     `name_offset` 24-bit, null-terminated; refuse non-ASCII / unterminated /
     out-of-table names). Skip the root's own (empty) name; prefix children.
  4. Return `FileTree(source=src, format="wii-u8-arc", entries=tuple(entries))`.
- **Refusals (structural reds):** bad tag (also YAZ0/SZS/other); root not a
  dir; `n_nodes` makes the table exceed the file; a dir whose `size` (next)
  is `<= self` or `> n_nodes` (cycle/truncation); a file whose
  `data_offset + size > src_size`; a name offset outside the string table or
  with no null terminator; non-ASCII names; unknown node type. A too-small
  file (< 32) is refused at `sniff`/header.

Memory-bounded regardless of archive size: the node table + string table are
read once into a `bytes` buffer (small, metadata-only — file payloads stay
lazy via `SliceSource`/`FileTree.open`); only manifest entry offsets/sizes
are materialized, never the file contents.

## 6. Fixture & differential

### 6.1 Fixture (synthetic, committed — tier-1)

`seedtools/make_wii_u8_arc_fixture.py` authors it deterministically:

1. Define an in-memory tree T: e.g. `README.TXT`, `BOOT/APP.BIN`,
   `DATA/A.BIN`, `DATA/B.BIN` (incompressible `bytes(range(256))` + repeated
   pattern), `DATA/EMPTY.BIN` (0 bytes), `DATA/SUB/C.DAT` — a small,
   non-trivial tree that exercises nesting + an empty file + an
   incompressible blob.
2. Serialize T to a **valid U8 byte image**: root dir node (node 1) +
   one node per file/dir (depth-first, children contiguous — matching the
   walk's expectation); a 24-bit `name_offset` string table (root name =
   empty at offset 0); `data_offset` for each file = the file's absolute
   offset (string-table end, then each payload placed contiguously,
   **data region aligned to `0x40`** per the header contract); `size` for
   dirs = 1-based last-child node number. Write `archive.arc`.
3. **Derive `expected.manifest.json` from T** (the generator knows T — the
   independent author). `source.name = "archive.arc"`,
   `source.sha256 = sha256(archive)`, `source.size = len(archive)`; entries =
   T's files/dirs. `tool_versions` record the differential's pinned version
   (or `"structural-proof"` if D1=b).
4. **Reference bytes** (`reference/`): the differential (D1-a vendored CLI,
   or D1-b a second extraction) writes each file's content to
   `reference/<path>`. These are the check-4 fidelity substrate.

### 6.2 Differential (independence-critical)

- **Byte differential (check 4):** read each sampled file *through* the
  normalizer's `FileTree` (`tree.read(entry)`), diff against
  `reference/<path>`. A wrong offset / wrong recursion yields wrong bytes
  and dies at check 4 (and, as § 7.1 notes, at check 2 if the entry
  metadata is also wrong).
- **Structural anchor (D1-a only):** the vendored `parse-u8` CLI (or
  equivalent) *lists* the archive's files — a third-party confirmation the
  normalizer's `FileTree` matches an independent reader; parallel to
  `gc-fst`'s `wit files-ll`. Run-only, gitignored, sha256-pinned.
- **Composition check:** none (returns `FileTree` directly).

### 6.3 Tool pins

- Differential (D1-a): e.g. `parse-u8` compiled, version string from the
  binary/`--help`; recorded in `tool_versions` and the manifest. **stdlib
  `struct`** (runtime; Python 3.13).
- Generator: `make_wii_u8_arc_fixture v1`.
- If D1-b (structural self-consistency): no tool pin; `tool_versions` notes
  `"self-consistency"` + generator.

## 7. Tests

`tests/test_wii_u8_arc.py` (additive; suite `~71 → ~81`, +10). Mirrors
`test_gc_fst.py` / `test_saturn_dc_raw.py`; the `run_checks` wrapper is just
`normalize_wii_u8_arc` (it already returns a `FileTree`):

- **`test_wii_u8_arc_is_green`** — `run_checks` on the synthetic fixture
  passes all four. Expected manifest authored by the seedtool from T;
  reference bytes from the differential.
- **`test_sniff`** — `archive.arc` sniffs True; a plain zero file / a YAZ0
  (`Yaz0`) magic / an ISO sniffs False.
- **`test_returns_filetree`** — returns `FileTree(format="wii-u8-arc")`; its
  entries' union of file ranges lies within `source.size()`; file count /
  dir count match T.
- **`test_decoded_files_byte_equal_reference`** — each sampled file read
  through the tree equals `reference/<path>`; spot-check `BOOT/APP.BIN`
  length and a known payload.
- **`test_composed_tree_matches_expected`** — tree entry paths/offsets/sizes
  match the expected manifest exactly; every file reads byte-equal to
  `reference/`.
- **`test_expected_manifest_validates_against_schema`** — schema-valid,
  `format == "wii-u8-arc"`, `kinds == {"file","dir"}`,
  `source.name == "archive.arc"`,
  `source.sha256 == sha256(archive)`, `source.size == len(archive)`.
- **Structural reds:**
  - `test_corrupted_tag_is_structural_red` — flip a tag byte.
  - `test_yaz0_refused` — prepend/overwrite with the YAZ0 magic (`Yaz0`) →
    sniff False (falls through to "not a U8"); assert not green.
  - `test_bad_node_type_refused` — root node `type != 1`.
  - `test_file_out_of_bounds_refused` — a file `data_offset + size > size()`.
  - `test_truncated_refused` — file smaller than the declared table.
  - `test_cycle_refused` — a dir `size` pointing at/before itself.
- **`test_wrong_slice_slicer_dies`** — inline mutant: a parser that reads a
  file's bytes from a shifted offset (or mis-recurses a dir boundary). Like
  `gc_fst`/`ps1`/`saturn`, enumeration may be correct but bytes/offsets are
  wrong → caught at check 2 (manifest) and/or check 4 (fidelity). DESIGN § 3
  green-but-wrong case, dead.

### 7.1 Red-team positioning

The load-bearing mutant is a **wrong file offset or a wrong dir-boundary
recursion**: it emits a plausible `FileTree` but the bytes/offsets are off.
- A wrong absolute `data_offset` shift corrupts file contents → caught at
  check 4 (fidelity vs `reference/`).
- A wrong dir `size` (next) mis-scopes children → wrong entry set / offsets →
  caught at check 2 (manifest byte-unequal, since the generator's T is
  authoritative) and/or check 4.
Either way the green-but-wrong case is dead.

## 8. Risks & mitigations

| Risk | Mitigation |
|---|---|
| The registry's `wit`/`dolphin-tool` differential is wrong (proven) | D1 picks a real differential: vendored pinned `parse-u8` CLI, or structural self-consistency (DESIGN §3). No silent one-party round-trip. |
| `parse-u8` won't compile in the env (no mingw/MSVC) | D1-b fallback: structural self-consistency proof (gc-fst's accepted fallback) — the walk is fully determined by the bytes. |
| 1-based vs 0-based indexing slip (U8 next is 1-based) | The walk treats `size` as the 1-based last-child number; array scope is `[self+1, size)`; cross-checked against the seedtool's T. |
| data_offset alignment (`0x40`) assumptions vary by tool | Lenient on alignment for parsing (bounds only); the seedtool writes `0x40`-aligned data so the differential's extraction is stable. |
| Non-ASCII / unterminated names | Refused structurally (mirrors `gc-fst`'s ASCII-only discipline). |

## 9. Out of scope / deferred

- **YAZ0 / SZS-compressed U8** — `.szs`/`.carc` are usually YAZ0-wrapped U8.
  That is a separate decode layer (returns a `ByteView` of the uncompressed
  U8; caller re-normalizes with `wii-u8-arc` — a `cso`-shaped unit). A plain
  U8 with a YAZ0 magic is refused structurally here. (Open row, not gated.)
- **Multi-archive / concatenated U8**, encryption, non-node-table variants.
- **Real retail/homebrew U8 anchor** — a synthetic fixture is sufficient for
  GREEN (§ 0.2). A retail Wii `opening.bnr` etc. is optional
  proof-strengthening (tier 2, license-clean) — Kenrin can green-light a
  fetch; only metadata would commit (bytes stay out of git).
- **Deeply nested / huge archives** — the parser supports arbitrary nesting;
  a nested-dir *fixture* is proof-strengthening (like `gc-fst`'s nested
  item), not a gate.

## 10. Proposed NORMALIZERS.md edit (lands with implementation)

Update the `wii-u8-arc` row from `queued` to `GREEN` on completion, with:

```
| wii-u8-arc | archive-as-FS | T2 | GREEN (2026-07-23,
`substratum/formats/wii_u8_arc.py`) | synthetic (tier-1, seedtool-authored)
`fixtures/wii_u8_arc/synthetic/`; retail/homebrew anchor optional
(tier 2) | <differential per D1: vendored `parse-u8` CLI, pinned>
OR structural self-consistency (DESIGN §3); fidelity sample seed 1 |
none new (stdlib `struct`) | U8 node archive -> FileTree; 12-byte nodes,
1-based child scopes, absolute file offsets; refuses YAZ0/SZS/other magics,
bad tag, out-of-bounds files, cycle/self-parent dirs, non-ASCII names
structurally; returns FileTree (not a ByteView) |
```

## 11. Open decisions for Kenrin

The normalizer, gate, and tests are identical regardless of these calls;
they are scoping/ergonomics, flagged rather than self-served (standing
"GitHub remote = Kenrin's call" discipline):

- **D1 — Which differential to pin (recommended: vendored `parse-u8` CLI,
  else structural self-consistency).** Probe-proven: `wit`/`dolphin-tool`
  cannot read a standalone U8. (a) Vendor + sha256-pin `parse-u8.c`
  (bushing) or an equivalent maintained U8 extractor; use it for `reference/`
  extraction (check 4) + a structural listing anchor. (b) Fall back to a
  DESIGN §3 structural self-consistency proof (gc-fst's accepted pattern) —
  the walk is fully determined by the bytes, so a wrong parser fails
  check 1/2/3. Acceptable because the format has no compression/crypto.
- **D2 — Self-contained module (recommended).** Don't refactor shipped
  `gc_fst` to share a helper (zero regression risk; option B only if Kenrin
  wants DRY and accepts re-running the ~81-test suite). The registry's
  "shared with gc-fst" = shared *algorithm*, not a code import.
- **D3 — Synthetic fixture (recommended).** U8 is fully authorable, so the
  tier-1 synthetic fixture (like iso9660/ps1/cso) suffices for GREEN; no
  retail/homebrew drop needed. Override only if Kenrin wants a retail anchor
  committed (bytes stay out of git regardless).
- **D4 — Refuse YAZ0/SZS here (recommended).** Plain U8 only; compressed U8
  is a separate decode-layer row. Keep this unit's scope clean.

## 12. Implementation checklist (for the implementing session)

Carry this unit in one session, one git commit at the end (the atelier
"one unit = one format" rule). The design is frozen; execution is
mechanical. Commands assume the repo root
(`C:\Users\kenrin\Project\Substratum`) with `uv` on PATH.

**Pre-flight (30s):** confirm D1–D4 = the recommended defaults in § 11
(none require code changes — they only bind scope). If Kenrin overrode any,
re-read the relevant §. Assume defaults otherwise. If D1 = (a), first
`vendor` the chosen U8 extractor and pin its sha256 in `seedtools/vendor_tools.py`
(+ gitignored `tools/`).

- [ ] **Step 1 — Fixture generator.**
  `seedtools/make_wii_u8_arc_fixture.py` (new, dev-only). Implements § 6.1:
  (1) define tree T; (2) serialize to a valid U8 (`archive.arc`, nodes +
  string table + `0x40`-aligned data region); (3) write `expected.manifest.json`
  from T (format `wii-u8-arc`, source name `archive.arc`, sha256+size = the
  archive); (4) extract `reference/` via the D1 differential. Deterministic
  (fixed names / sorted entries / stable payloads) so the manifest is stable.

- [ ] **Step 2 — The normalizer.**
  `substratum/formats/wii_u8_arc.py` (new, stdlib-only). Implement § 5:
  `sniff` (tag `b"\x55\xAA\x38\x2D"`), `normalize_wii_u8_arc` (eager header
  pass → `_walk` → `FileTree`), the 1-based contiguous-child recursion with
  absolute file offsets, name decoding from the string table, structural
  reds per § 5.

- [ ] **Step 3 — The gate tests.**
  `tests/test_wii_u8_arc.py` (new). Implement § 7: the `run_checks` wrapper
  (just `normalize_wii_u8_arc`), green test, sniff / filetree /
  decoded-files / composed-tree / manifest-schema tests, the structural
  reds, and the wrong-offset/recursion red-team mutant. Suite grows
  ~71 → ~81.

- [ ] **Step 4 — Prove GREEN & land.**
  1. `uv run pytest -q` → **all green, ~71 → ~81** (full suite, not just the
     new file — confirms no regression in the shipped units, including the
     self-contained `gc_fst`).
  2. Flip the NORMALIZERS.md `wii-u8-arc` row `queued` → `GREEN` using the
     text in § 10.
  3. `git add` the new/changed files (synthetic fixture + `reference/`, the
     three source/test files, NORMALIZERS.md, this spec — verify
     `fixtures/wii_u8_arc/synthetic/reference/` is committed, not gitignored).
     If D1 = (a), the vendored CLI lives in gitignored `tools/`; the pinned
     script goes in.
  4. One commit; then update the atelier brief `Next steps` (mark wii-u8-arc
     shipped) and append a `## 2026-… — Hunyuan` block to
     `projects/coding/substratum/log.md` + a week-log line. Clock out per
     `.atelier/CHARTER.md`.

**Definition of done:** `uv run pytest` fully green; manifest byte-equals
the generator's independent tree T; fidelity check 4 passes on the
differential's extraction; red-team mutant dies; NORMALIZERS row GREEN;
atelier logged.
