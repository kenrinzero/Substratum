# Xbox XDVDFS normalizer — Design Spec

> **Status:** Proposed (2026-07-24). New floor normalizer row `xdvdfs`
> (NORMALIZERS.md, currently `queued`). The last **open-platform** row in
> the backlog — after this, only the keyed platforms (wii partitions /
> 3ds ncch-cia, DEFERRED per plan Tier 3) remain. Two scoping decisions
> (D1 the differential, D2 the fixture tier) are flagged for Kenrin in
> § 11; the rest take the recommended defaults.

## 0. What `xdvdfs` actually is (the T1 finding)

The backlog row `xdvdfs (Xbox)` (kind "disc filesystem", differential
`extract-xiso`, deps `extract-xiso`, "open-docs but tooling-dependent")
is accurate at a glance. Grounded against primary sources — the
`extract-xiso.c` source (XboxDev/extract-xiso, read line-by-line),
xboxdevwiki.net/XDVDFS, and the independent `antangelo/xdvdfs` Rust
reader — it resolves into one load-bearing structural fact and two
tooling realities:

1. **XDVDFS directories are a binary tree (left-child / right-sibling),
   NOT a flat or contiguous-children layout.** This is the
   differentiating structural fact of the format and it is genuinely
   *new* to Substratum: `iso9660` walks flat directory extents linearly;
   `gc_fst` and `wii_u8_arc` walk a flat node table where a directory
   owns a contiguous `[self+1, next)` span. XDVDFS instead gives each
   directory its *own* table, and within that table entries are nodes of
   a binary tree navigated by explicit `l_offset` / `r_offset` dword
   pointers (0 = no child). So `xdvdfs.py` carries a **new traversal
   primitive** — a recursive LCRS walk with sector-boundary padding —
   not a reuse of the gc-fst/u8 `_recurse`. There is no "shared
   algorithm" claim here, unlike the gc-fst ↔ wii-u8-arc pairing.

2. **XDVDFS is all-little-endian.** Every multi-byte field (`l_offset`,
   `r_offset`, `start_sector`, `file_size`, the volume-descriptor
   fields) is little-endian — confirmed by `extract-xiso.c`'s
   `little16()` / `little32()` byte-swap macros. This is the *opposite*
   convention from the big-endian Nintendo formats (`gc_fst`, `wii_u8_arc`
   both use `struct.unpack(">I", …)`) and unlike ISO9660's both-endian
   u32 pairs. A parser that copies gc-fst's `">I"` unpacks will silently
   mis-read every offset — exactly the kind of green-but-wrong mutant the
   gate exists to kill.

3. **`extract-xiso` is C source with no prebuilt Windows binary shipped
   upstream, and the host has no C compiler** (probed 2026-07-24: no
   `gcc` / `cc` / `cl` / `mingw32-gcc`). So the registry's assumed
   `extract-xiso` differential is not buildable in-env from source. Two
   real alternatives exist (D1, § 3 / § 6): (a) vendor a prebuilt
   Windows `extract-xiso.exe` (available via the SourceForge release
   lineage / third-party GUI wrappers) and sha256-pin it like
   `chdman`/`maxcso`/`wit`; or (b) vendor the `antangelo/xdvdfs` Rust
   CLI (MIT, *independent* implementation, with a per-file `copy-out`
   and an offset-bearing `info` command — strictly stronger than
   `extract-xiso -l`, which lists only `name (size)` with no offsets).
   **7-Zip has NO XDVDFS codec** (confirmed — `7z i` lists no XISO
   codec; the iso9660/cso/saturn 7z differential path is not available
   here).

**Recommendation:** implement `xdvdfs` as a self-contained disc-FS
normalizer returning a `FileTree` (like `gc-fst`/`iso9660`/`wii-u8-arc`,
NOT a `ByteView` — XDVDFS *is* the filesystem). Scoped to **single
XDVDFS partition, plain `.xiso`/trimmed images** (volume descriptor at
`0x10000`); the retail XGD1/XGD2/XGD3 embedding offsets and the
`$SystemUpdate` second partition are out of scope (§ 9). NORMALIZERS.md
edit lands with implementation (§ 10).

## 1. Motivation

XDVDFS is the filesystem on every Xbox and Xbox 360 disc. A `xdvdfs`
unit closes Substratum's open-platform coverage: with it, every
non-keyed disc/filesystem format in the backlog is walked (iso9660,
gc-fst, wii-u8-arc, xdvdfs), leaving only the crypto-keyed platforms
(wii partitions, 3ds ncch-cia) deferred per the plan. It also exercises
a traversal shape Substratum doesn't yet have (binary-tree directories),
strengthening the contract's generality for downstream (Stratum's census,
Quarry's extraction).

## 2. Scope

**In scope:**
- `substratum/formats/xdvdfs.py` — the normalizer (stdlib, returns `FileTree`).
- `seedtools/make_xdvdfs_fixture.py` — authors the synthetic fixture.
- `fixtures/xdvdfs/synthetic/` — committed `game.xiso` (the XDVDFS image),
  `expected.manifest.json`, `reference/` (extracted file contents).
- `tests/test_xdvdfs.py` — the four-check gate + structural reds + the
  wrong-slice / wrong-endian red-team mutants.
- **Single XDVDFS partition, plain image** (descriptor at `0x10000`).

**Out of scope (frozen / refused):**
- `substratum/contract.py`, `schema/manifest.schema.json`, `verify.py` — frozen.
- **No new runtime deps.** The walk is stdlib byte-slicing; nothing
  vendored unless Kenrin picks a vendored-CLI differential in D1 (in
  which case the tool is gitignored in `tools/`, pinned like
  `chdman`/`maxcso`).
- **Retail XGD1/XGD2/XGD3 embedded images** — the XDVDFS partition lives
  at `0x10000 + LSEEK_OFFSET` (GLOBAL `0x0FD90000`, XGD3 `0x02080000`,
  XGD1 `0x18300000`) inside a full retail dump. A plain `.xiso` (trimmed
  to the partition) has the descriptor at exactly `0x10000`; this unit
  handles that. The LSEEK_OFFSET variants are a separate concern (a
  future "xgd-wrapper" row or a sniff that tries the known offsets) —
  refused structurally here (sniff requires the magic at `0x10000`).
- **`$SystemUpdate` second partition** (Xbox 360) — out of scope;
  `extract-xiso` skips it with `-s`, we refuse/handle-only-the-first.
- **The `XISO_MEDIA_ENABLE` anti-piracy XBE patch** (`-m`) — a runtime
  XBE concern, not a filesystem-structure concern; irrelevant to a
  tree-walking normalizer.
- Crypto/signing: **none in the XDVDFS partition itself** (confirmed);
  keyed-platform concerns belong to the deferred wii/3ds rows.

## 3. Feasibility findings (load-bearing)

Established by reading `extract-xiso.c` (XboxDev/extract-xiso,
`#define`s and the `verify_xiso` / `traverse_xiso` / `write_directory`
code paths), xboxdevwiki.net/XDVDFS, and `antangelo/xdvdfs` (the
independent Rust reader):

1. **Volume descriptor** — lives at the start of **sector #32** =
   absolute byte offset **`0x10000`** (sector size 2048). A redundant
   copy sits at sector #33 (`0x10800`). Layout (all little-endian;
   offsets within the descriptor sector):
   - `0x00` (20 bytes): **magic** = `MICROSOFT*XBOX*MEDIA`
     (hex `4D 49 43 52 4F 53 4F 46 54 2A 58 42 4F 58 2A 4D 45 44 49 41`;
     note the two `*`, no NUL).
   - `0x14` (u32 LE): **root directory table sector** → byte offset =
     `* 0x800`.
   - `0x18` (u32 LE): **root directory table size** (bytes; a multiple
     of `0x800`).
   - `0x1C` (u64 LE): timestamp (Windows FILETIME; not validated).
   - `0x7EC` (20 bytes): **magic tail** (same string; integrity check —
     `verify_xiso` re-reads it after skipping the filetime+unused gap).
   Sector #33 optionally carries an authoring-tool tag string
   (`XBOX_DVD_LAYOUT_TOOL_SIG`); not needed for parsing.

2. **Directory entry (inode)** — **variable length**, little-endian,
   laid out as:
   - `0x00` (u16 LE): **`l_offset`** — left-subtree pointer, in
     **dwords (4-byte units) relative to this directory table's start**;
     `0` = no left child.
   - `0x02` (u16 LE): **`r_offset`** — right-sibling pointer, same units;
     `0` = no right sibling.
   - `0x04` (u32 LE): **`start_sector`** — for a file, the sector where
     file data begins (byte offset `* 0x800`); for a directory, the
     sector where that subdirectory's *own* table begins.
   - `0x08` (u32 LE): **`file_size`** — for a file, byte length; for a
     directory, the byte size of that nested directory table.
   - `0x0C` (u8): **attributes** — bit `0x10` = DIRECTORY; `0x01` RO,
     `0x02` HIDDEN, `0x04` SYSTEM, `0x20` ARCHIVE, `0x80` NORMAL.
   - `0x0D` (u8): **filename length** (1..255; `XISO_FILENAME_MAX_CHARS`).
   - `0x0E` (`filename_length` bytes): **filename**, raw bytes,
     **no NUL terminator** on disc.
   Minimum entry size = 14 bytes (`0x0E`) + name.

3. **Binary-tree directory layout (LCRS) — confirmed.** Each directory's
   entries form a binary tree built as an AVL tree at author time
   (`avl_traverse_depth_first` in `extract-xiso.c`), serialized to the
   LCRS pointers. On read, walk it as: read node → if `l_offset != 0`,
   recurse into the left child (seek to `dir_start + l_offset*4`) →
   process self → if `r_offset != 0`, move to the right sibling (seek to
   `dir_start + r_offset*4`). A value of **`0xFFFF`**
   (`XISO_PAD_SHORT`) in the `l_offset` field signals **end of this
   sector** / an empty-directory sentinel; entries do not cross sector
   boundaries, padding bytes (`0xFF`, `XISO_PAD_BYTE`) fill to the next
   2048 boundary, and the reader skips forward. For a **directory**
   entry, recurse with `dir_start = start_sector * 0x800` (a fresh
   nested table with its own LCRS tree). **No documented subdirectory
   depth limit** — recursion is bounded only by the directory table
   sizes (treat as unbounded-by-spec; the seedtool's fixture stays
   shallow).

4. **Authoring is fully feasible from scratch** — XDVDFS is a pure,
   deterministic, spec-driven binary layout with **no encryption, no
   signing, no keys, no crypto** in the partition itself. `extract-xiso`
   itself has a `-c` create mode that synthesizes an XISO from an
   arbitrary directory tree, proving the format is constructible from
   inputs alone. A Python seedtool can author a synthetic fixture
   (volume descriptor + serialized LCRS directory tables + file data)
   with only stdlib `struct` — directly analogous to ISO9660-via-pycdlib
   and U8-by-hand. **No retail Xbox disc is required for GREEN** (D2).

5. **`extract-xiso`'s `-l` listing does NOT include offsets** — it
   prints exactly `"%s%s%s (%u bytes)"` (path + name + " (size bytes)"),
   no sector/byte offset. This is **weaker than wit's `files-ll`** (which
   carries offset+size for gc-fst). So for an *offset-bearing* structural
   anchor, `extract-xiso -l` alone is insufficient; the seedtool's known
   tree T provides the authoritative offsets, and either `extract-xiso -x`
   (full extract → reference bytes) or `antangelo/xdvdfs info` (per-entry
   offset+size) fills the gap.

6. **A genuine second independent reader exists: `antangelo/xdvdfs`**
   (Rust, MIT, not a fork of extract-xiso). It offers `unpack` (whole
   image), `copy-out` (**single file or directory** — fills
   extract-xiso's no-single-file gap), `info` (per-entry metadata
   *including offsets/size*), `ls`/`tree`, and `md5`/`checksum`. This is
   the real two-party differential option — analogous to pycdlib being
   the second reader for iso9660.

7. **Independence is three-party:** the seedtool *authors* T and the
   bytes; the normalizer *independently parses* the bytes; the
   differential (vendored `extract-xiso` or `antangelo/xdvdfs`)
   *independently re-derives* the contents. A normalizer that mis-slices,
   mis-recurses, or mis-reads endianness yields wrong entries/offsets and
   dies at check 1 (bounds) / check 2 (manifest) / check 4 (fidelity).

## 4. Approach

**Stdlib XDVDFS LCRS-tree walker (chosen), returning one `FileTree`.**
The normalizer validates the volume descriptor eagerly (magic at
`0x10000` AND magic tail at `0x107EC`, root-dir sector/size sanity),
walks the root directory table into `FileEntry`s (recursing into
subdirectory tables), and returns `FileTree(source=src, format="xdvdfs",
entries=…)`. No inner image, no composition — XDVDFS *is* the filesystem.

### 4.1 Independence model

- **Expected manifest** = derived by the seedtool from its known
  in-memory tree T (the generator is the authoritative author, like
  `pycdlib` is for iso9660, like the U8 seedtool for wii-u8-arc).
  `canonical_manifest(tree_T, source_name, sha256(game.xiso),
  tool_versions)` — byte-exact, never from the parser.
- **Reference bytes** (check 4) = the differential's extraction of the
  image's files into `reference/`. The normalizer's `FileTree` is read
  through `verify.py`'s sampling and diffed against `reference/`.
- **The differential** is independent of both (D1). Genuine two/three-party.

### 4.2 Composition check

None needed — `xdvdfs` returns a `FileTree` directly (it does not
compose with `iso9660`). The gate closes the loop as
`game.xiso → FileTree → diff vs reference/`, same as `gc-fst` /
`iso9660` / `wii-u8-arc`.

### 4.3 Code-reuse posture

No reuse of `gc_fst._walk` / `wii_u8_arc._walk` — those implement a
*contiguous-children* span walk, which is the wrong algorithm here.
`xdvdfs.py` carries its own LCRS-tree `_walk` (≈70 lines: read node →
recurse left → emit self → advance right, with `0xFFFF` sector-end and
`0xFF`-pad handling). Self-contained, zero regression risk to the
shipped units (mirrors the self-contained-module discipline of saturn,
ps1, wii-u8-arc).

## 5. The normalizer

`substratum/formats/xdvdfs.py` (stdlib-only):

- **Constants:**
  `_MAGIC = b"MICROSOFT*XBOX*MEDIA"` (20 bytes),
  `_SECTOR = 0x800` (2048), `_DESC_SECTOR = 0x20` (32 → offset `0x10000`),
  `_DESC_OFFSET = 0x10000`, `_MAGIC_TAIL_OFFSET = 0x7EC` (within the
  descriptor sector → absolute `0x107EC`),
  `_DIR_ATTR = 0x10`, `_PAD_SHORT = 0xFFFF`, `_PAD_BYTE = 0xFF`,
  `_NAME_MAX = 255`.
- **`sniff(source) -> bool`** — True when `size() >= 0x10000 + 0x800`
  and `read_at(0x10000, 20) == _MAGIC`. Bounded — refuse look-alikes
  (and refuses retail XGD images whose magic is at a LSEEK_OFFSET, by
  design — § 2 / § 9).
- **`normalize_xdvdfs(source) -> FileTree`** — accepts a path or
  `ByteSource`. Steps:
  1. Resolve a `ByteSource` (path → `FileSource`). Refuse if
     `size() < _DESC_OFFSET + _SECTOR`.
  2. **Eager descriptor pass:** read the descriptor sector
     (`read_at(0x10000, 0x800)`). Refuse if `desc[0:20] != _MAGIC`
     (also rules out ISO9660/U8/other magics). Refuse if
     `desc[0x7EC:0x7EC+20] != _MAGIC` (tail/integrity check — catches a
     corrupt or partial descriptor). Read `root_sector` (u32 LE at
     `0x14`), `root_size` (u32 LE at `0x18`). Refuse if
     `root_sector * _SECTOR + root_size > size()` (root table past EOF),
     or `root_size == 0`, or `root_size % _SECTOR != 0`.
  3. **Walk** (`_walk`): read the root directory table
     (`read_at(root_sector * _SECTOR, root_size)`), then recurse the
     LCRS tree from the first entry (dword offset 0). For each node:
     - If `l_offset == _PAD_SHORT` → end of this directory's sector-span
       (empty dir or sector boundary); stop.
     - If `l_offset != 0` → recurse into the left child at
       `dir_start + l_offset * 4` *before* emitting self (depth-first
       in-order, matching `extract-xiso`'s `traverse_xiso`).
     - Emit self: decode `attributes`, `filename_length`, `filename`
       (raw bytes → ASCII; refuse non-ASCII / `/` / `\` / `.` / `..` per
       extract-xiso's security discipline). If `attributes & _DIR_ATTR`:
       it's a directory → `FileEntry(path, "dir", 0, 0)` AND recurse
       into its own table at `start_sector * _SECTOR` (size
       `file_size`). Else: file → `FileEntry(path, "file",
       start_sector * _SECTOR, file_size)`, **bounds-check**
       `offset + size <= src_size` (structural red otherwise).
     - If `r_offset != 0` → advance to right sibling at
       `dir_start + r_offset * 4` and continue (iterative tail, not
       recursion, to keep the right-spine O(1) stack); else stop.
  4. Return `FileTree(source=src, format="xdvdfs", entries=tuple(entries))`.
- **Refusals (structural reds):** bad magic (head or tail); root table
  out of bounds / zero / unaligned; an `l_offset`/`r_offset` dword
  pointer that lands outside `[0, dir_size)` (cycle/oob); a file whose
  `start_sector * _SECTOR + file_size > src_size`; a dir whose nested
  table is out of bounds; a filename that is non-ASCII, empty, contains
  `/`/`\`, or is `.`/`..`; `filename_length == 0` or `> _NAME_MAX`; an
  unknown-critical attribute combination. A too-small file (< `0x10800`)
  is refused at `sniff`/descriptor.

Memory-bounded regardless of image size: each directory table is read
once into a `bytes` buffer (metadata-only — file payloads stay lazy via
`SliceSource`/`FileTree.open`); only manifest entry offsets/sizes are
materialized, never file contents.

## 6. Fixture & differential

### 6.1 Fixture (synthetic, committed — tier-1)

`seedtools/make_xdvdfs_fixture.py` authors it deterministically:

1. Define an in-memory tree T: e.g. `README.TXT`, `BOOT/APP.BIN`,
   `DATA/A.BIN`, `DATA/B.BIN` (incompressible `bytes(range(256))` +
   repeated pattern), `DATA/EMPTY.BIN` (0 bytes),
   `DATA/SUB/C.DAT` — a small, non-trivial tree that exercises nesting
   + an empty file + an incompressible blob + **at least 3 siblings in
   one directory to force a non-trivial LCRS tree** (left child + right
   sibling both non-zero — the structural case a 1-or-2-child fixture
   cannot test).
2. Serialize T to a **valid XDVDFS byte image**:
   - Volume descriptor at `0x10000`: magic + root sector + root size +
     a fixed FILETIME (deterministic) + magic tail at `0x7EC`; pad the
     rest of the descriptor sector with `0xFF`.
   - Each directory's table: serialize its entries as an AVL-balanced
     LCRS tree (for a small deterministic fixture, a hand-assigned
     balanced shape suffices — the *reader* must handle any valid tree,
     but the *writer* may pick a simple valid one), entries padded to
     dword alignment, the table padded to a multiple of `0x800` with
     `0xFF`, and an `0xFFFF` sentinel where `extract-xiso` expects one.
   - File payloads placed at `0x800`-aligned sectors, contents from T.
   Write `game.xiso`.
3. **Derive `expected.manifest.json` from T** (the generator knows T —
   the independent author). `source.name = "game.xiso"`,
   `source.sha256 = sha256(game.xiso)`, `source.size = len(game.xiso)`;
   entries = T's files/dirs (offsets = the sectors the writer assigned,
   sizes from T). `tool_versions` records the differential's pinned
   version (D1) + the generator.
4. **Reference bytes** (`reference/`): the differential (D1) extracts
   each file's content to `reference/<path>`. These are the check-4
   fidelity substrate. (For D1-b self-consistency, the seedtool writes
   `reference/` directly from T — same independence posture as
   wii-u8-arc.)

### 6.2 Differential (independence-critical)

- **Byte differential (check 4):** read each sampled file *through* the
  normalizer's `FileTree` (`tree.read(entry)`), diff against
  `reference/<path>`. A wrong offset / wrong endianness / wrong
  recursion yields wrong bytes and dies at check 4 (and, as § 7.1
  notes, at check 2 if the entry metadata is also wrong).
- **Structural anchor (D1-a/c only):** the vendored CLI
  (`extract-xiso -l` or `antangelo/xdvdfs info`) *lists* the image's
  files — a third-party confirmation the normalizer's `FileTree`
  matches an independent reader; parallel to `gc-fst`'s `wit files-ll`
  (note: `extract-xiso -l` carries no offsets, so the offset check is
  the seedtool's T vs the normalizer; `antangelo/xdvdfs info` carries
  offsets and is the stronger anchor). Run-only, gitignored,
  sha256-pinned.
- **Composition check:** none (returns `FileTree` directly).

### 6.3 Tool pins

- Differential (D1): the chosen tool's version string, recorded in
  `tool_versions` and the manifest. **stdlib `struct`** (runtime;
  Python 3.13).
- Generator: `make_xdvdfs_fixture v1`.
- If D1-b (structural self-consistency): no tool pin; `tool_versions`
  notes `"self-consistency"` + generator (the wii-u8-arc precedent).

## 7. Tests

`tests/test_xdvdfs.py` (additive; suite `~84 → ~96`, +~12). Mirrors
`test_gc_fst.py` / `test_wii_u8_arc.py`; the `run_checks` wrapper is
just `normalize_xdvdfs` (it already returns a `FileTree`):

- **`test_xdvdfs_is_green`** — `run_checks` on the synthetic fixture
  passes all four. Expected manifest authored by the seedtool from T;
  reference bytes from the differential.
- **`test_sniff`** — `game.xiso` sniffs True; a plain ISO / a U8 / a
  zero file sniffs False.
- **`test_returns_filetree`** — returns `FileTree(format="xdvdfs")`; its
  entries' union of file ranges lies within `source.size()`; file/dir
  counts match T.
- **`test_decoded_files_byte_equal_reference`** — each sampled file read
  through the tree equals `reference/<path>`; spot-check `BOOT/APP.BIN`
  length and a known payload.
- **`test_composed_tree_matches_expected`** — tree entry
  paths/offsets/sizes match the expected manifest exactly; every file
  reads byte-equal to `reference/`.
- **`test_expected_manifest_validates_against_schema`** — schema-valid,
  `format == "xdvdfs"`, `kinds == {"file","dir"}`,
  `source.name == "game.xiso"`,
  `source.sha256 == sha256(game.xiso)`, `source.size == len(game.xiso)`.
- **Structural reds:**
  - `test_corrupted_magic_is_structural_red` — flip a magic byte.
  - `test_corrupted_magic_tail_refused` — flip a magic-tail byte (the
    integrity check `extract-xiso` itself performs).
  - `test_bad_root_table_refused` — root size zero / unaligned / past EOF.
  - `test_file_out_of_bounds_refused` — a file whose
    `start_sector * 0x800 + file_size > size()`.
  - `test_truncated_refused` — image smaller than the declared tables.
  - `test_bad_l_offset_refused` — an `l_offset` dword pointer outside
    `[0, dir_size)` (cycle/oob).
  - `test_bad_filename_refused` — a name with `/` or non-ASCII or `..`.
- **Red-team mutants (the load-bearing cases):**
  - `test_wrong_endianness_dies` — a mutant that unpacks offsets as
    big-endian (`">I"`) like gc-fst/u8 instead of little-endian. With
    real (small) offset values this produces huge out-of-bounds numbers
    → dies at check 1 (structural); if it happens to stay in bounds,
    dies at check 2/4. Either way the green-but-wrong case is dead.
  - `test_wrong_slice_slicer_dies` — a mutant that shifts file offsets
    (or mis-walks the LCRS tree — e.g. treats `r_offset` as a fourth
    child instead of a sibling). Enumeration may look plausible but
    bytes/offsets are wrong → caught at check 2 (manifest) and/or
    check 4 (fidelity). DESIGN § 3 green-but-wrong case, dead.

### 7.1 Red-team positioning

Two load-bearing mutants, specific to this format:

- **Wrong endianness** — the most likely implementation slip given every
  prior Substratum disc format is big-endian. A `">I"` unpack on little-
  endian XDVDFS fields yields wrong offsets; with small real values the
  byte-swapped number is typically enormous → structural red at check 1.
  This is stronger than the generic wrong-slice case and worth its own
  test.
- **Wrong LCRS walk** — treating the binary tree as a flat list, or
  confusing `l_offset` (recurse) with `r_offset` (iterate), mis-scopes
  the entry set → wrong entries/offsets → caught at check 2 (manifest
  byte-unequal, since the generator's T is authoritative) and/or
  check 4 (fidelity vs `reference/`).

Either way the green-but-wrong case is dead.

## 8. Risks & mitigations

| Risk | Mitigation |
|---|---|
| `extract-xiso` won't compile in-env (no C compiler — probed 2026-07-24) | D1 picks a real differential that doesn't need compiling: vendor a prebuilt Windows `extract-xiso.exe` (SourceForge release lineage), OR vendor `antangelo/xdvdfs` (Rust, prebuilt releases), OR fall back to DESIGN §3 structural self-consistency (the wii-u8-arc precedent). No silent one-party round-trip. |
| Little-endian slip (every prior disc format here is big-endian) | Dedicated `test_wrong_endianness_dies` red-team mutant; all unpacks via `struct.unpack("<I"…)`. |
| LCRS traversal is a new primitive (not the contiguous-children walk) | Self-contained `_walk` with the `0xFFFF`/`0xFF`-pad handling unit-tested; the fixture forces ≥3 siblings so both `l_offset` and `r_offset` exercise non-zero paths. |
| `extract-xiso -l` carries no offsets (weaker than wit's files-ll) | The seedtool's T is the authoritative offset source; offset parity is T-vs-normalizer at check 2. `antangelo/xdvdfs info` (D1-c) is the offset-bearing structural anchor if Kenrin wants it. |
| Retail XGD LSEEK_OFFSET images refused at sniff | By design — this unit handles plain `.xiso` (descriptor at `0x10000`); XGD embedding is a separate future row (§ 9). The sniff documents this bound. |
| Non-ASCII / path-traversal names | Refused structurally (mirrors extract-xiso's own security patch: reject `/`, `\`, `.`, `..`). |

## 9. Out of scope / deferred

- **Retail XGD1/XGD2/XGD3 embedded images** — the XDVDFS partition at
  `0x10000 + LSEEK_OFFSET`. A separate "xgd-wrapper" row (or a sniff
  that probes the known LSEEK offsets) is the clean home; this unit is
  plain-`.xiso` only.
- **`$SystemUpdate` second partition** (Xbox 360) — out of scope; only
  the first XDVDFS partition is walked.
- **Real retail Xbox anchor** — a synthetic fixture is sufficient for
  GREEN (§ 0.4). A retail `.xiso` is optional proof-strengthening
  (tier 2, license-clean) — Kenrin can green-light a fetch or drop one
  via FIXTURE REQUEST; only metadata would commit (bytes stay out of git).
- **The `XISO_MEDIA_ENABLE` XBE patch** — runtime anti-piracy, not a
  filesystem-structure concern.
- **Deeply nested / huge images** — the parser supports arbitrary
  nesting; a deep-nesting *fixture* is proof-strengthening (like
  gc-fst's nested item), not a gate.
- **Keyed platforms** (wii partitions, 3ds ncch-cia) — DEFERRED per plan
  Tier 3, sequenced after open platforms. With xdvdfs shipped, they are
  the only backlog rows left.

## 10. Proposed NORMALIZERS.md edit (lands with implementation)

Update the `xdvdfs (Xbox)` row from `queued` to `GREEN` on completion:

```
| xdvdfs (Xbox) | disc filesystem | T2 | GREEN (2026-07-2x,
`substratum/formats/xdvdfs.py`) | synthetic (tier-1, seedtool-authored)
`fixtures/xdvdfs/synthetic/`; retail `.xiso` anchor optional (tier 2)
| <differential per D1: vendored `extract-xiso` (prebuilt Win32,
 pinned) OR `antangelo/xdvdfs` (MIT Rust CLI) OR structural
 self-consistency (DESIGN §3)>; fidelity sample seed **1** | none new
 (stdlib `struct`) | XDVDFS → FileTree; LCRS binary-tree directories
 (l_offset/r_offset dword ptrs), all-little-endian, magic
 `MICROSOFT*XBOX*MEDIA` @ 0x10000 (+tail @ 0x107EC); refuses bad
 magic/tail, XGD-embedded images, oob files/tables, bad LCRS ptrs,
 non-ASCII/traversal names structurally; returns FileTree (not a
 ByteView) |
```

## 11. Open decisions for Kenrin

The normalizer, gate, and tests are identical regardless of these calls;
they are scoping/ergonomics, flagged rather than self-served.

- **D1 — Which differential to pin.** Probe-proven: no C compiler on
  host, so `extract-xiso` is not buildable from source here; 7-Zip has
  no XDVDFS codec. Three real options:
  - **(a) Vendor a prebuilt Windows `extract-xiso.exe`** (SourceForge
    release lineage / GUI-wrapper extract) and sha256-pin it in
    `seedtools/vendor_tools.py` (+ gitignored `tools/extract-xiso/`).
    Mirrors the chdman/maxcso posture. Caveat: `-l` lists no offsets, so
    it's a listing+extraction anchor, not an offset oracle.
  - **(b) Structural self-consistency (DESIGN §3)** — the wii-u8-arc
    precedent. The LCRS walk is fully determined by the bytes, so a
    wrong parser fails check 1/2/3; the seedtool authors `reference/`
    from T. Zero vendoring.
  - **(c) Vendor `antangelo/xdvdfs`** (Rust, MIT, prebuilt Windows
    releases) — the strongest option: an *independent* implementation
    with per-file `copy-out` AND offset-bearing `info`. Genuine
    two-party with offsets. Most rigor, most setup.
  - **Recommendation: (a) if a trustworthy prebuilt `extract-xiso.exe`
    is easily sourced; else (b).** (c) is the upgrade path if Kenrin
    wants maximum rigor and accepts vendoring a Rust binary. (b) alone
    is acceptable — XDVDFS has no compression/crypto, so
    self-consistency is load-bearing here, same as it was for wii-u8-arc.
- **D2 — Synthetic fixture (recommended).** XDVDFS is fully authorable
  with no crypto/keys, so the tier-1 synthetic fixture (like
  iso9660/ps1/cso/u8) suffices for GREEN; no retail drop needed.
  Override only if Kenrin wants a retail `.xiso` committed (metadata
  only; bytes stay out of git regardless).
- **D3 — Self-contained module (recommended).** New LCRS `_walk`
  primitive; no refactor of shipped units. Zero regression risk.
- **D4 — Plain-`.xiso` scope only (recommended).** Refuse XGD-embedded
  retail images at sniff (magic must be at `0x10000`); the LSEEK_OFFSET
  variants are a separate future row.

## 12. Implementation checklist (for the implementing session)

Carry this unit in one session, one git commit at the end (the atelier
"one unit = one format" rule). The design is frozen; execution is
mechanical. Commands assume the repo root
(`C:\Users\kenrin\Project\Substratum`) with `uv` on PATH.

**Pre-flight (30s):** confirm D1–D4 = the recommended defaults in § 11
(none require code changes — they only bind scope). If Kenrin overrode
any, re-read the relevant §. Assume defaults otherwise. If D1 = (a) or
(c), first `vendor` the chosen tool and pin its sha256 in
`seedtools/vendor_tools.py` (+ gitignored `tools/`).

- [ ] **Step 1 — Fixture generator.**
  `seedtools/make_xdvdfs_fixture.py` (new, dev-only). Implements § 6.1:
  (1) define tree T (with ≥3 siblings in one dir to exercise LCRS);
  (2) serialize to a valid XDVDFS (`game.xiso` — descriptor at `0x10000`
  with magic+tail, LCRS directory tables with `0xFFFF`/`0xFF` padding,
  `0x800`-aligned file payloads); (3) write `expected.manifest.json`
  from T (format `xdvdfs`, source name `game.xiso`, sha256+size = the
  image); (4) extract `reference/` via the D1 differential (or from T
  for D1-b). Deterministic (fixed names / balanced tree / stable
  payloads) so the manifest is stable.

- [ ] **Step 2 — The normalizer.**
  `substratum/formats/xdvdfs.py` (new, stdlib-only). Implement § 5:
  `sniff` (magic `MICROSOFT*XBOX*MEDIA` at `0x10000`),
  `normalize_xdvdfs` (eager descriptor pass with magic-tail check →
  `_walk` → `FileTree`), the **all-little-endian** LCRS-tree recursion
  (`l_offset` recurse / `r_offset` iterate / `0xFFFF` sector-end /
  `0xFF` pad), sector→byte offset math (`* 0x800`), name decoding +
  security refusals, structural reds per § 5.

- [ ] **Step 3 — The gate tests.**
  `tests/test_xdvdfs.py` (new). Implement § 7: the `run_checks` wrapper
  (just `normalize_xdvdfs`), green test, sniff / filetree /
  decoded-files / composed-tree / manifest-schema tests, the structural
  reds, and **both** red-team mutants (wrong-endianness + wrong-slice).
  Suite grows ~84 → ~96.

- [ ] **Step 4 — Prove GREEN & land.**
  1. `uv run pytest -q` → **all green, ~84 → ~96** (full suite, not just
     the new file — confirms no regression in the shipped units).
  2. Flip the NORMALIZERS.md `xdvdfs (Xbox)` row `queued` → `GREEN`
     using the text in § 10.
  3. `git add` the new/changed files (synthetic fixture + `reference/`,
     the three source/test files, NORMALIZERS.md, this spec — verify
     `fixtures/xdvdfs/synthetic/reference/` is committed, not
     gitignored). If D1 = (a)/(c), the vendored CLI lives in gitignored
     `tools/`; the pinned script goes in.
  4. One commit; then update the atelier brief `Next steps` (mark xdvdfs
     shipped) and append a `## 2026-… — <agent>` block to
     `projects/coding/substratum/log.md` + a week-log line. Clock out
     per `.atelier/CHARTER.md`.

**Definition of done:** `uv run pytest` fully green; manifest byte-equals
the generator's independent tree T; fidelity check 4 passes on the
differential's extraction (or self-consistency for D1-b); both red-team
mutants die; NORMALIZERS row GREEN; atelier logged.
