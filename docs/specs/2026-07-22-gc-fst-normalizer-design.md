# S2 gc-fst — GameCube FST normalizer (design)

- **Unit:** `gc-fst` (NORMALIZERS.md row `gc-fst`)
- **Tier:** T2 (floor)
- **Date:** 2026-07-22
- **Agent:** ZCode (GLM-5.2)
- **Approach:** A — FST-only scope, wit-as-differential + structural self-consistency proof (DESIGN §3 fallback for one-tool formats)
- **Fixture tier:** `FIXTURE REQUEST` (retail drop, gitignored, metadata-only publication)

## Context

The third floor normalizer. `iso9660` (S1) and `chd` (S3) are GREEN. This unit
adds the GameCube disc filesystem. It binds to the frozen contract
(`contract.py`, `verify.py`, schema) exactly as the prior units did — no
contract changes.

## Fixture

- **Source:** `fixtures/_local/game.iso` — retail GameCube disc "The Hulk"
  (`GHKE7D`, NTSC/USA), 1,459,978,240 bytes (~1.36 GiB, full GC capacity).
  Dropped by Kenrin via the `FIXTURE REQUEST` tier.
- **Git posture:** retail bytes never enter git. `fixtures/_local/` is
  gitignored (verified: `git check-ignore` matches). Published artifacts are
  metadata only: the expected manifest (paths, offsets, sizes, sha256s of
  sampled ranges) and the FST structural record. No file payloads committed.
- **Why this title is fine despite being flat:** The Hulk's FST is a flat
  root (11 files, no nested directories). The parser handles nesting
  generically, but a nested-dir fixture is a *future proof-strengthening*
  item, not an S2 gate. Recorded as an open item below.

## Format findings (the substance of this unit)

Reverse-engineered against the disc bytes and confirmed against yagcd §13
(hitmen.c02.at/files/yagcd/yagcd/chap13.html):

1. **Disc header fields (offsets from disc start):**
   - `0x000` — game ID (6 bytes: `GHKE7D`)
   - `0x01c` — disc magic `0xC2339F3D` (GameCube; Wii is `0x5D1C9EA3`)
   - `0x420` — main DOL offset (not parsed by this unit)
   - `0x424` — FST offset
   - `0x428` — FST size in bytes
2. **FST node size is 0x0C (12 bytes), NOT 0x20.** This was the load-bearing
   discovery — several secondary sources and an initial assumption used
   0x20, which made the 251-byte FST look unparseable (12 nodes × 0x20 = 384
   > 251). At 0x0C: 12 × 12 = 144-byte node table + string table at byte
   144 = 251 total. Reconciles exactly. yagcd §13.4 confirms the 0x0C entry.
3. **FST node layout (12 bytes):**
   - byte 0 — type (`0` = file, `1` = directory)
   - bytes 1–3 — name offset into string table (big-endian 24-bit)
   - bytes 4–7 — file: absolute byte offset from disc start; dir: parent index
   - bytes 8–11 — file: size in bytes; dir: "next" index (end of this dir's scope)
4. **Root node (index 0):** type=1, name offset=0 (empty name), parent=0,
   next = total node count. The string table begins at
   `node_count × 0x0C`. Strings are null-terminated ASCII.
5. **File offsets are absolute from disc start** (not FST-relative). Verified:
   node 1 `args.txt` offset `0x379b650` size 24 — matches wit's listing
   (`379b650+  18  24`) exactly, byte for byte.
6. **The FST describes only the user-data filesystem.** wit's `sys/`
   directory (`boot.bin`, `bi2.bin`, `apploader.img`, `main.dol`, `fst.bin`)
   is a *virtual* view of fixed disc-header regions — those are not FST
   entries. This unit parses the FST only; disc-container topology is a
   different concern (analogous to how `chd` wraps and the caller re-parses).

## Scope (deliberately bounded — mirrors iso9660's discipline)

**In scope:**
- Parse the FST at `header[0x424]` with size `header[0x428]`.
- Walk the node table (generic over nesting — supports nested dirs even
  though the fixture is flat).
- Build a `FileTree` of `FileEntry(path, kind, offset, size)` with posix-style
  relative paths. Directory entries get `offset=0` (they have no payload).
- `sniff()`: recognize a GameCube disc via magic `0xC2339F3D` at `0x01c`.
  (Wii `0x5D1C9EA3` is NOT sniffed — Wii partitions are a deferred keyed
  platform per NORMALIZERS.md.)

**Out of scope (refuse rather than guess — structural reds):**
- Wii discs (different magic; deferred).
- TGC (embedded GCM / multiboot) — yagcd §14.1 notes the header FST fields
  contain bogus data that must be substituted from the TGC header. Refuse
  on detection.
- Disc-system-file extraction (`sys/`) — not an FST concern.
- DOL parsing — not an FST concern.

**Structural reds (refuse):**
- Bad disc magic (neither GC nor recognized → structural failure).
- FST extends past end of disc (header lies).
- Node count × 0x0C + string table exceeds declared FST size.
- File entry offset+size out of disc bounds.
- Directory parent/next indices out of range or forming an impossible scope
  (next ≤ own index, or next > node count).
- Name offset past end of string table, or missing null terminator.
- Non-ASCII bytes in names (GC FST names are ASCII).

## Independence chain (DESIGN §3 — the gate that bites)

The GC-FST format has **one** reference tool: `wit`. There is no second
independent GC-FST reader (pycdlib is ISO9660-only; no Python GC-FST lib
exists). Per DESIGN §3's explicit allowance, a format with no second
reference tool carries a **structural self-consistency proof** in lieu of
two-tool differential. This unit's green rests on:

1. **Structural (check 1):** the parser refuses every malformed case above;
   every file range is in-bounds and the node table/string table are
   self-consistent (ranges tile the declared FST region, offsets re-derivable).
2. **Manifest match (check 2):** emitted manifest byte-equals the
   independently-authored expected manifest (see below — authored from wit's
   listing + the format spec, never from the parser under test).
3. **Byte-stability (check 3):** two runs produce byte-identical manifests.
4. **Differential + byte-range fidelity (check 4):** compare the tree against
   wit's `files-ll` listing (enumeration + offsets + sizes) AND read sampled
   files *through* the FileTree, asserting byte-identity against bytes
   extracted by `wit extract`. This is a one-tool differential (wit is the
   only extractor), which is exactly why the structural proof (1) is
   load-bearing — it is what keeps this from being a one-party round-trip.
   The forbidden pattern would be generating the expected manifest *from the
   parser's own output*; that never happens here.

**Sampling:** The Hulk FST has 11 files ≤ 16, so check 4 samples **all**
files (DESIGN §3: all when ≤16). Seed recorded as 1 for registry consistency.

## Expected manifest (independence-critical artifact)

Authored by `seedtools/stage_gc_fst.py` (a new committed seedtool, mirroring
`stage_homebrew_iso.py`'s shape). It builds the expected manifest from
**wit's listing** (`wit files-ll`) cross-referenced with the **format spec**
(header fields + node layout) — never from substratum's parser. Reference
bytes come from `wit extract` into a staging dir (NOT committed — retail
bytes). The manifest carries:
- `source.name` = `game.iso`, `source.sha256` = sha256 of the retail ISO,
  `source.size` = 1459978240.
- `tool_versions`: `wit` = `v3.05a r8638`, `generator` = `stage_gc_fst v1`.
- `entries`: the FST's user-data files only (no `sys/` virtual entries).

The manifest IS committed (metadata only — paths, offsets, sizes; no file
payloads). The retail ISO is not.

## Architecture

```
substratum/formats/gc_fst.py          # sniff() + normalize_gc_fst() -> FileTree
seedtools/stage_gc_fst.py             # one-shot: wit listing -> expected manifest + reference bytes
tests/test_gc_fst.py                  # run_checks gate + structural reds + sniff + schema
fixtures/gc_fst/hulk/                 # committed: expected.manifest.json, PROVENANCE.md
fixtures/_local/game.iso              # NOT committed (gitignored): the retail ISO
```

**Dual-path relationship (important — differs from iso9660/chd units):**
Unlike S1/S3 where the fixture ISO lives *inside* the committed fixture dir,
this retail ISO stays in gitignored `fixtures/_local/game.iso`. The
*committed* artifact is only `fixtures/gc_fst/hulk/expected.manifest.json`
(metadata: paths, offsets, sizes, sha256). The test module resolves the ISO
by a **fixed absolute path** (`ROOT / "fixtures" / "_local" / "game.iso"`)
rather than via `doc["source"]["name"]` relative to the fixture dir, because
the source name `game.iso` must not be assumed to sit beside the manifest.
The test **skips with a clear message** if `game.iso` is absent (so the suite
stays green on a fresh clone that has no retail drop). The manifest's
`source.name` is still `game.iso` for truthful handoff metadata.

**`normalize_gc_fst(source) -> FileTree`** (stdlib-only, mirrors iso9660.py):
1. Resolve `ByteSource` (accept path or `ByteSource`).
2. Read disc magic at `0x01c`; require GC `0xC2339F3D` (Wii → refuse; other →
   structural red).
3. Read FST offset (`0x424`) and size (`0x428`); load FST bytes.
4. Parse root node → node count; compute string-table base (`count × 0x0C`).
5. Walk nodes. For files: validate offset+size in-bounds, decode name. For
   dirs: validate parent/next scope, recurse to build nested paths.
6. Return `FileTree(source=src, format="gc-fst", entries=...)`.

No `sys/` synthesis, no DOL touch, no recursion into inner archives (RCF
containers are Quarry's concern, not this unit's).

## Test plan (mirrors test_iso9660.py)

- `test_green_full_gate` — `run_checks` returns `[]` on the Hulk fixture.
- `test_corrupted_magic_is_structural_red` — flip `0x01c` → structural red.
- `test_corrupted_fst_offset_is_structural_red` — lie about FST location.
- `test_truncated_fst_is_structural_red` — declare more nodes than bytes allow.
- `test_out_of_bounds_file_is_structural_red` — a node pointing past disc end.
- `test_sniff` — GC disc sniffs true; Wii magic / toy fixture sniff false.
- `test_manifest_validates_against_schema` — schema + `format == "gc-fst"`.
- `test_paths_posix_and_no_leading_slash` — entry paths are clean posix.

## Open items (not S2 gates)

1. **Nested-directory fixture:** a second GC title with real `data/`/`audio/`
   nesting would exercise the directory-walking path on real bytes. The
   parser supports it; the fixture doesn't exercise it. Future
   proof-strengthening, optional `FIXTURE REQUEST`.
2. **Sampling depth:** with 11 files all sampled, the fidelity gate is
   maximally strict for this fixture. A larger-nested fixture would exercise
   the deterministic-16 sampling path. Same future item as (1).
