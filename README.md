# Substratum

One normalized byte view over the game-preservation container zoo: any
dump — disc image, cartridge, archive — becomes a flat `ByteView` or an
enumerable `FileTree` of seekable byte ranges behind a single
`normalize()` interface, so downstream tools (technology census, asset
extraction, VN text pipelines) never re-implement ISO9660 offsets or CHD
decode. Foundation segment of the **Spolia** game-media program
(Substratum → Stratum + Quarry → Kura → Interlinear).

A green means the tree is provably the *right* tree: fixture-matched,
byte-stable, and — the check that bites — every sampled file read
*through* the tree is byte-identical to an independent tool's extraction.
A normalizer with perfect enumeration and wrong slicing dies at that gate
(proven at seed time by a deliberately self-consistent mutant).

## Status

Stage-0 seed (2026-07-07): interface + manifest schema frozen, four-check
gate live, TOYFS harness fixture committed, both red-team cases proven
(corrupted header → structural red; self-consistent off-by-one slicer →
red **only** at byte-range fidelity, exactly as designed). **No real
normalizers yet** — S1 (`iso9660`) is the first floor unit
(`NORMALIZERS.md`).

## How a unit works

```powershell
uv sync
# read DESIGN.md, take a READY row from NORMALIZERS.md
# write substratum/formats/<format>.py  (sniff + normalize per the contract)
# stage fixtures per the row's fixture plan (never from F:\game — DESIGN § 5)
# author the expected manifest INDEPENDENTLY (from the differential tool's
#   listing, not from your parser's output), then:
uv run pytest
```

## Fixture policy (short version)

Synthetic (committed) · homebrew (fetched, committed if license-clean) ·
`FIXTURE REQUEST` rows that Kenrin fulfils by dropping one retail file
into the gitignored `fixtures/_local/`. Agents have **no standing corpus
access**; published outputs are metadata only.

## License

MIT. Committed fixtures are synthetic or license-clean homebrew with
per-file provenance noted in their NORMALIZERS.md row.
