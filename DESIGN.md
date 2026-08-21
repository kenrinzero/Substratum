# Substratum — Design Contract (FROZEN)

> **Status: FROZEN at seed time (2026-07-07).** This document +
> `substratum/contract.py` + `schema/manifest.schema.json` + the
> `verify.py` gate semantics are the contract **four downstream segments
> bind to** (Stratum, Quarry, Kura, Interlinear — see the Spolia program
> plan). Interface changes are contract-change units with program-wide
> blast radius; a normalizer unit only ever adds
> `substratum/formats/<format>.py`, its fixtures, and its NORMALIZERS.md
> row.

Substratum turns any game dump — disc image, cartridge, archive — into a
normalized byte view behind one interface, so downstream tools walk the
corpus without re-implementing the preservation-container zoo. It
normalizes access and does nothing else: extraction is Quarry's, detection
is Stratum's, asset-container specs are Palimpsest's.

## 0. Build-start verification (2026-07-07)

- **Corpus:** `F:\game` re-verified live — mounted, 17.7 TB used, 16
  platform folders (PlayStation, PS2, Saturn, Dreamcast, XBOX, GameCube,
  N64, DS, 3DS, GB/GBC/GBA, Wii, PSP, NES, SNES). **Agents do NOT get
  standing access** (§ 5) — verified only so the program's premise is
  known-true.
- **Host:** Windows (Kenrin's call — "this can live in windows"). Python
  3.13.13 + uv + **7-Zip already on PATH** (scoop) — the ISO9660
  differential oracle is pre-installed. Repo:
  `C:\Users\kenrin\Project\Substratum`.
- WSL access via `/mnt/f` exists but is irrelevant under § 5; the
  drvfs-performance caveat moves to Stratum's census planning.

## 1. The interface (THE Stage-0 T1 decision)

Normative code: `substratum/contract.py`. Shape:

- **`ByteSource`** — the one read primitive everything shares:
  `read_at(offset, size) -> bytes` + `size()`. Implementations:
  `FileSource` (an on-disk dump), `SliceSource` (a byte range of another
  source), and future decoded sources (e.g. CHD-decoded).
- **`ByteView`** — a flat, seekable view over a `ByteSource`
  (carts / raw images / decoded containers).
- **`FileTree`** — an **eager list of entry metadata** (`FileEntry`:
  posix-style `path`, `kind: file|dir`, `offset`, `size` — a byte range
  into the underlying source) with **lazy byte access**
  (`tree.open(entry) -> SliceSource`, `tree.read(entry) -> bytes`).
  Nothing is materialized; downstream reads go through the source.
  **Directory ranges are format-dependent (clarified 2026-08-21, no code
  or manifest change).** `offset`/`size` are normative for `kind ==
  "file"` only. A walker whose format records a real on-media directory
  extent may report it — ISO9660 does, and so therefore does everything
  composed through it (chd, cso, ciso, ps1-bincue, saturn-dc-raw) — while
  FST/table-style walkers with no such record report `(0, 0)` (gc-fst,
  wii-fst, wii-u8-arc, xdvdfs, 3ds-romfs, zip). The gate bounds-checks and
  byte-diffs **files only** (§ 3), so a directory range carries no proof
  obligation and consumers must not rely on either convention.
- **`normalize(source, *, format=None) -> ByteView | FileTree`** — accepts
  a path or a `ByteSource`; auto-detects via each registered normalizer's
  `sniff()` unless `format` pins it.
- **Nested containers DO NOT recurse (settled).** One normalizer = one
  layer. A CHD normalizer returns the decoded raw image as a `ByteView`;
  the caller explicitly re-normalizes that view with the disc-filesystem
  walker (`normalize(view)`). Composition is always the caller's visible
  act — no hidden recursion, so units stay bounded and blame stays local.

## 2. The manifest (what downstream consumes)

Every normalization can be serialized as a **manifest** —
`schema/manifest.schema.json` (2020-12): format id, source filename +
sha256 + size, pinned tool versions, and the entry list. Canonical
serialization mirrors the house rule: sorted keys, `ensure_ascii` (JP
filenames survive as `\uXXXX` — the manifest itself can never mojibake),
sorted entries by path, trailing newline. Manifests are the
fixture-expected-outputs AND the downstream handoff shape — Stratum/Quarry
consume contract types and manifests, never normalizer internals (settled
boundary).

## 3. The gate (`verify.py`, four checks in increasing strength)

Per fixture row in NORMALIZERS.md:
1. **Structural** (necessary, never sufficient): the normalizer parses
   without error and every entry range is in-bounds and non-overlapping
   where the format demands it.
2. **Fixture match:** emitted manifest byte-equals the checked-in
   expected manifest.
3. **Byte-stability:** two runs produce byte-identical manifests.
4. **Differential + byte-range fidelity (the gate that bites):** compare
   the tree against an independent tool's listing AND read sampled files
   *through* the FileTree, asserting byte-identity against independently
   extracted reference bytes. Enumeration parity alone is insufficient —
   a tree that lists correctly but slices wrong must die here.

**Sampling policy (settled):** all files when a fixture has ≤ 16 entries;
otherwise 16 chosen deterministically (first + last + largest + seeded
picks, seed recorded in the fixture row). **No-second-tool rule (settled,
from the plan):** structural-only green is never sufficient; a format with
no reference tool must carry a self-consistency proof (ranges tile the
source, offsets re-derived from records) or it stays out of the routine
backlog.

**Red-team cases (proven at seed time on the toy format):**
(a) corrupted fixture header → structural red;
(b) **mutant normalizer** — off-by-one slicing that still emits a fully
self-consistent, walkable, enumeration-correct tree → red via byte-range
fidelity. (b) is the load-bearing case: it is exactly what a green-but-
wrong normalizer looks like, and checks 1–3 alone would pass it.

## 4. Stack (settled)

Python ≥ 3.13 on the Windows host, uv-managed; runtime stdlib-only.
Dev-only deps: `pytest`, `jsonschema`, and `pycdlib` (fixture authoring —
it writes ISO9660 programmatically AND serves as a second independent
implementation for the ISO differential). Differential tools pinned per
unit in NORMALIZERS.md (7z version recorded at unit time).

## 5. Fixture policy (settled — NO standing corpus access)

Agents never read `F:\game`. Three tiers, per Kenrin's design (2026-07-07):
1. **Synthetic canonical images** — authored by committed seedtools
   (pycdlib etc.); public-domain, committed.
2. **Homebrew / openly-licensed dumps** — fetched on demand by a
   web-capable agent; real third-party-authored bytes (the symmetric-bug
   antidote), committed when license-clean, else `fixtures/_local/`.
3. **Retail anchors on request** — a unit that benefits from a real
   pressing carries `FIXTURE REQUEST: <platform, any small title>` in its
   NORMALIZERS.md row; **Kenrin copies one file** into the gitignored
   `fixtures/_local/` at his convenience. Retail bytes never enter git or
   leave the machine; published artifacts are metadata only (trees,
   ranges, headers).

Bulk corpus access resurfaces only at **Stratum's census** — and the
recorded default there is operator-run sweep scripts emitting metadata,
not agent access.

## 6. Settled decisions (the plan's "Decisions Still Needed")

| Plan decision | Resolution |
|---|---|
| Interface surface | § 1 — `read_at` primitive; eager metadata + lazy reads; explicit non-recursive composition |
| Language / runtime | § 4 — Python 3.13 on Windows, stdlib runtime; no Rust split until a unit proves the need |
| Byte-range-fidelity sampling | § 3 — all ≤16, else deterministic 16 (first/last/largest/seeded, seed recorded) |
| Tooling pinning | § 4 / NORMALIZERS.md — exact versions per row, recorded into expected manifests |
| Fixture sourcing & redistribution | § 5 — three tiers; metadata-only publication; FIXTURE REQUEST mechanism |
| Downstream boundary | § 2 — contract types + manifests only |

## 7. What the seed shipped vs did not

Shipped: the frozen contract (code + schema), `verify.py` with all four
checks, the TOYFS toy format + committed toy fixture + reference bytes,
red-team proofs (a) and (b) green-as-red, NORMALIZERS.md with the three
starter rows (iso9660 / gc-fst / chd) and their fixture plans. NOT
shipped: any real normalizer (S1 `iso9660` is the first floor unit),
chdman vendoring (S3's one-time dep), homebrew fixture downloads.
