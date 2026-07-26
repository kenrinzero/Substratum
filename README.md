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

Version 0.0.8 (2026-07-26): the interface and manifest schema remain
frozen, the public one-layer dispatcher is live, and eight real
normalizers are green: `iso9660`, `gc-fst`, `chd`, `ps1-bincue`,
`saturn-dc-raw`, `cso`, `wii-u8-arc`, and `xdvdfs`. Every unit runs
through the same four-check structural, manifest, round-trip, and
byte-fidelity gate; the large GameCube fixtures also carry a 1 GB
per-test peak-RSS guard. `ps1-bincue` additionally preserves general
Mode-2 Form-2 payloads through its public sector API while retaining the
fixed 2048-byte cooked view needed for ISO9660 LBA composition.

The two keyed-platform families (`wii partitions` and `3ds ncch-cia`)
remain deliberately deferred. See `NORMALIZERS.md` for exact format
bounds, fixture provenance, and optional proof-strengthening requests.

## Use

```python
from substratum import normalize
from substratum.contract import ByteView

result = normalize("disc.cso")  # auto-detect one layer
if isinstance(result, ByteView):
    result = normalize(result.source)  # caller-visible composition

# Pinning bypasses sniffing while retaining that normalizer's validation:
tree = normalize("archive.arc", format="wii-u8-arc")
```

`normalize()` never recurses. Container and raw-sector decoders return a
`ByteView`; filesystem/archive walkers return a `FileTree`.

For a mixed PS1 XA BIN/CUE, ordinary reads keep ISO LBAs stable and the
format-specific source exposes complete sector payloads:

```python
from substratum.formats.ps1_bincue import Mode2XASource

view = normalize("game.bin", format="ps1-bincue")
assert isinstance(view.source, Mode2XASource)
sector = view.source.read_sector(1234)
print(sector.form, len(sector.payload), sector.channel_number)
```

Form-1 payloads are 2048 bytes; Form-2 payloads are 2324 bytes. Substratum
does not decode XA audio/video codecs—the encoded payload and its file,
channel, submode, and coding fields are the normalization boundary.

## Installation posture

Substratum currently targets Python 3.13+ and is maintained as a
local-only source project (no Git remote or published package yet):

```powershell
uv sync
uv run pytest
```

The runtime package itself is stdlib-only. CHD decoding additionally
requires `chdman`: set `SUBSTRATUM_CHDMAN` to its executable, install it
on `PATH`, or use the pinned repo-local `tools/chdman/chdman.exe`
restored with `uv run python seedtools/vendor_tools.py chdman`. That is
the resolution order. Other vendored tools are fixture-authoring or
differential anchors. A wheel can be built locally with `uv build`, but
publishing/promotion is intentionally deferred.

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
