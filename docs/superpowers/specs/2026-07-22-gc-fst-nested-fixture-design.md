# GC-FST Nested-Directory Fixture — Design Spec

> **Status:** Proposed (2026-07-22). Proof-strengthening for the GREEN gc-fst
> normalizer (NORMALIZERS.md row `gc-fst`). Not a new normalizer, not a new
> gate row — adds a second fixture that exercises the recursive FST traversal
> the flat Hulk fixture cannot test. Follows
> `2026-07-22-gc-fst-normalizer-design.md` (the normalizer's own spec).

## 1. Motivation

The gc-fst normalizer shipped GREEN with a flat fixture (the retail Hulk drop,
11 files, no directories). Its parser supports directory nesting generically
(the `_recurse` walk in `gc_fst.py` handles subtree open/close), but no test
exercises that code path on real bytes. This is the deferred
proof-strengthening item recorded in the brief and the normalizer log — the
same item a non-atelier trial agent attempted and failed at (2026-07-22) by
authoring an image whose FST declared offsets far past a truncated stub and
then never running the four-check gate.

This spec closes that gap with a **valid** nested-directory fixture and a
genuine two-party differential against wit.

## 2. Scope

**In scope:**
- One committed seedtool: `seedtools/make_gc_fst_nested_fixture.py`.
- One fixture directory: `fixtures/gc_fst/nested/` (committed: the expected
  manifest + a `.gitignore`; gitignored: the materialized disc image and the
  wit-extracted reference bytes).
- New tests in `tests/test_gc_fst.py` (additive).

**Out of scope (frozen / unchanged):**
- `substratum/formats/gc_fst.py` — the parser already handles nesting; proven
  in the feasibility probe (Section 6). No edits.
- `substratum/contract.py`, `schema/manifest.schema.json`, `verify.py` —
  frozen program-wide.
- No new vendored deps (wit at `tools/wit/` is reused).

**Boundaries (mirrors the existing unit):** one layer only (FST user-data
filesystem); `sys/` virtual header regions are not synthesized into the tree;
refuses Wii/malformed structurally.

## 3. Feasibility findings (load-bearing)

Probed 2026-07-22 before this spec. Three facts determine the design:

1. **wit cannot *compose* a GameCube ISO from an extracted directory.** `wit
   COPY --source <P-GAMEID dir>` always emits a Wii disc (partition table +
   encryption, 4.7 GiB), ignoring `setup.txt`'s `disc-type = GameCube`. This
   is a known open wit limitation: [wiimms-iso-tools issue
   #24](https://github.com/Wiimm/wiimms-iso-tools/issues/24), unanswered, on
   the same wit v3.05a r8638 we have vendored. A bare directory of files is
   treated as a search folder, not an FST tree. → rules out compose-from-tree.
2. **wit CAN *read* a hand-authored GC disc — but only a complete one.** A
   minimal magic+FST image fails (`Invalid BOOT.BIN (no MAIN.DOL and no
   FST)`): wit validates the full GC disc structure (boot.bin/bi2.bin/
   apploader.img/main.dol at standard offsets) and requires the image padded
   to full GC disc size (1,459,978,240 B). → the fixture must be a complete
   disc image, not a minimal FST stub.
3. **The viable path (proven end-to-end):** graft the Hulk's real `sys/`
   files into a hand-authored image, append a nested FST + file payloads,
   patch the header FST pointers (0x424/0x428), pad to GC disc size. wit
   reads it back and **independently decodes the nested FST** — its listed
   offsets/sizes for the nested files matched substratum's parser exactly.
   substratum's parser also walked the nested tree correctly. → wit serves as
   a genuine differential tool for a hand-authored nested fixture.

## 4. Approach

**Hand-authored nested FST + Hulk sys files, wit as differential (Approach A
from the brainstorm).** A committed seedtool materializes the disc image from
the retail ISO's sys region + a hand-authored nested FST. The expected
manifest is authored from **wit's `files-ll` listing** (the independent
reader) + the FST format spec, never from substratum's parser. Check 4 reads
the nested files through the FileTree and asserts byte-identity against
wit-extracted reference bytes.

This is a genuine two-party differential on nested bytes — strictly stronger
than the DESIGN §3 self-consistency fallback the flat fixture carries. It
does not replace the flat fixture's self-consistency proof; it adds an
orthogonal nested-bytes proof.

## 5. Fixture shape

### 5.1 Nested FST structure

Four files, two nested directories (7 FST nodes total). The structure is
deliberately shaped to exercise every branch of the recursive `_recurse` walk:

```
files/
├── top.txt              (root-level file)
└── data/                (depth-1 directory)
    ├── mid.txt          (file under data/)
    ├── nested/          (depth-2 directory)
    │   └── deep.txt     (file under data/nested/)
    └── after.txt        (file AFTER nested/ closes — sibling-after-subtree)
```

The `after.txt` placement is the key edge case: it sits *after* the `nested/`
subtree closes, so the parser must resume at `data`'s `next` boundary rather
than fall off the end of the closed subtree. The flat fixture cannot test
this.

### 5.2 Node table

7 nodes, 0x0C (12) bytes each (the load-bearing node size confirmed in the
normalizer spec). Big-endian fields: byte 0 = type (0=file, 1=dir); bytes
1-3 = name offset into string table; bytes 4-7 = file offset / dir parent
index; bytes 8-11 = file size / dir next-index.

```
node 0: root    dir  name=""      parent=0 next=7
node 1: top.txt      file
node 2: data    dir  name="data"  parent=0 next=7   (children: 3,4,6)
node 3: mid.txt      file
node 4: nested  dir  name="nested" parent=2 next=6   (child: 5)
node 5: deep.txt     file
node 6: after.txt    file                            (data's last child)
```

`data.next = 7` (== root.next == total node count): `data` is the last child
of root, so its scope runs to the table end. `nested.next = 6`: `nested` is
*not* the last child of `data` — `after.txt` (node 6) follows it — so
`nested` closes at 6 and the parser resumes in `data`'s scope to emit node 6.
This is the sibling-after-subtree mechanic.

### 5.3 Disc layout

Standard GC disc layout; offsets for boot/bi2/apploader/dol borrowed from the
real Hulk header so wit validates the image. The disc ID is synthetic
(`TESTN01` — "nested") so the committed artifact is unambiguously a test
fixture, not retail.

```
0x000      header / boot.bin (0x440)   disc id "TESTN01", GC magic @0x1c,
                                       FST offset @0x424, FST size @0x428
0x440      bi2.bin        (0x2000)
0x2440     apploader.img
0x1ec00    main.dol       (Hulk's real dol, unchanged — needed for wit validation)
<data>     file payloads  (deterministic, path-derived — see 5.4)
<fst>      nested FST     (node table + string table)
<padded>   zeros to 1,459,978,240 B (full GC disc size — wit requires this)
```

### 5.4 Deterministic payloads

Each file's bytes are generated deterministically from its path (mirrors the
iso9660 seedtool's approach): a reproducible byte pattern so the expected
manifest is stable across regenerations and check 4 (byte-range fidelity) has
real, non-trivial content to verify. Exact generator is an implementation
detail (e.g. a seeded PRNG keyed on the path, or a repeated path-derived
block) — the contract is: same path → same bytes, every run.

### 5.5 Storage: recipe + build-on-demand (settled)

The full padded image (~1.4 GiB, mostly zeros) is **not** committed. The
fixture directory commits only:
- `expected.manifest.json` — the wit-derived manifest (metadata only).
- `.gitignore` — excludes `game.iso` and `reference/`.

The seedtool (the committed recipe) materializes the image on demand:
- The FST structure, payload generator, disc ID, and layout offsets are all
  literal constants in the seedtool — the seedtool *is* the recipe.
- The materialized image lives at `fixtures/gc_fst/nested/game.iso`
  (gitignored), built on first test run.
- The wit-extracted reference bytes live at
  `fixtures/gc_fst/nested/reference/` (gitignored), re-derived by the
  seedtool.

The materialized image contains the Hulk's main.dol (4.3 MB) and is built
from the gitignored retail ISO; no retail bytes enter git — only the manifest
commits. This matches the existing gc-fst tier-3 metadata-only policy.

## 6. Seedtool design

**`seedtools/make_gc_fst_nested_fixture.py`** — two jobs, run in order.

### 6.1 Job 1: build the nested disc image (gitignored output)

1. Verify the retail ISO at `fixtures/_local/game.iso`; abort if absent.
2. `wit extract` it to a temp dir; read the `sys/` files (boot.bin, bi2.bin,
   apploader.img, main.dol).
3. Read the real disc header's dol offset (0x420) to place main.dol at the
   same offset the original uses (so the apploader's size fields stay valid).
4. Author the nested FST (7-node table from §5.2) + string table.
5. Lay out the disc: sys files at standard offsets; deterministic payloads
   after main.dol (4-byte aligned); FST after the payloads (4-byte aligned).
6. Patch the header: synthetic disc id, GC magic @0x1c, FST offset @0x424,
   FST size @0x428.
7. Pad to 1,459,978,240 B with zeros; write to
   `fixtures/gc_fst/nested/game.iso`.
8. Clean up the temp dir (no leak — the chd.py `_TempFileSource.__del__`
   lesson).

### 6.2 Job 2: build expected manifest + reference bytes (independence-critical)

5. `wit files-ll <image>` — parse the listing for nested `.../files/`
   entries. Reuse the existing flat stager's `entries_from_wit_listing`
   logic (the regex + `files/`-prefix strip), adapted so nested paths
   survive intact (the flat stager already passes nested paths through; the
   strip keeps everything after `files/`). This is the **independent
   reader** — truth never derives from substratum's parser.
6. `wit extract <image>` → flatten the `.../files/` subtree into
   `fixtures/gc_fst/nested/reference/` preserving nested directories, so
   verify.py's check 4 finds bytes at `reference/<entry.path>`.
7. `canonical_manifest(tree, image.name, sha256_of(image), tools)` from the
   wit-derived entries; write `fixtures/gc_fst/nested/expected.manifest.json`.

### 6.3 Idempotency & determinism

Re-running on the same retail ISO reproduces byte-identical artifacts (same
payloads, same offsets, same manifest) — so check 3 (byte-stability) is
meaningful and the manifest is a stable committed truth. The seedtool
overwrites its outputs.

### 6.4 Independence discipline (load-bearing)

The expected manifest is derived from **wit's** decode of the FST, never from
substratum's parser. The FST we author is the *input*; wit's listing is the
*truth*; substratum's parser is the *system under test*. This is symmetric to
the flat stager and keeps the differential a real two-party proof on nested
bytes.

## 7. Test design

Additive to `tests/test_gc_fst.py` (existing 9 tests untouched). All nested
tests gated by the same retail-ISO-present skip as the Hulk tests, since the
build-on-demand seedtool needs the retail ISO for sys files.

### 7.1 Build-on-demand plumbing

A session-scoped pytest fixture `_nested_iso()` (or equivalent) that runs the
seedtool if `fixtures/gc_fst/nested/game.iso` is absent, then yields the
path. Green-path and structural tests depend on it. If the retail ISO is
absent, the whole nested test group skips (not fails) — fresh clones stay
green.

### 7.2 Green path

- `test_nested_fixture_full_gate` — runs the full four-check `run_checks` on
  the nested fixture. The proof-strengthening payoff: recursive traversal +
  byte-range fidelity against wit, on nested bytes.

### 7.3 Structural reds (new nesting coverage)

- `test_nested_dir_close_resume` — corrupt the `nested/` directory node's
  `next` field to equal its own index (subtree never closes). Parser must
  refuse it (structural red) rather than mis-walk. Targets the exact
  traversal mechanic the flat fixture cannot test.
- `test_nested_parent_mismatch` — flip a child directory's parent-index
  field to point at the wrong parent. Parser refuses (`directory parent !=
  enclosing dir`).

### 7.4 Schema assertion (no ISO needed)

- `test_nested_manifest_validates_against_schema` — the nested
  `expected.manifest.json` validates against the schema; format is `gc-fst`;
  entry kinds include both `file` and `dir` (the flat fixture is `{file}`
  only — this asserts nesting actually appears in the committed manifest).

### 7.5 Red-team positioning

The load-bearing red-team case is the same mutant class the seed-time toy
fixture proved: a self-consistent-but-wrong slicer dies at check 4
(fidelity). The nested traversal adds a *new* way to be wrong (mis-resume
after a subtree closes), caught early by `test_nested_dir_close_resume`.
Together they keep a green-but-wrong nested parser from passing.

### 7.6 Suite impact

32 → 36 (4 new tests). No existing test changes.

## 8. Risks & mitigations

| Risk | Mitigation |
|---|---|
| wit changes behavior on a future re-vendor | wit is pinned (v3.05a r8638) in the manifest `tool_versions`; check 2 fails loudly on drift, same as the flat fixture. |
| The materialized image's main.dol is a retail derivative | Image is gitignored; built only from the gitignored retail ISO; only the manifest commits. Matches tier-3 policy. |
| Build-on-demand adds test runtime (~seconds for wit extract + image pad) | One-shot per session via the session-scoped fixture; subsequent runs use the cache. |
| The seedtool is more intricate than the flat stager | Bounded: the disc layout is worked out (§5.3) and was proven in the feasibility probe. The FST encoder is ~30 lines. |
| `after.txt` node-indexing is easy to get wrong | The node table (§5.2) is fully specified; the `dir_close_resume` structural test is the safety net. |

## 9. Out of scope / deferred

- A *second* nested fixture at greater depth (3+ levels) — marginal coverage;
  the two-level fixture exercises both the close-and-resume and the
  parent-mismatch mechanics. Not a gate.
- Larger-sample-depth exercise (>16 files) — the fixture stays ≤16 entries so
  check 4 samples all files (DESIGN §3); a large fixture is a separate
  proof-strengthening item.
- GitHub remote — Kenrin's call, unchanged.
