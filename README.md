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
per-test peak-RSS guard. `iso9660`, `gc-fst`, and `wii-u8-arc` refuse
traversal-capable path components; ISO9660 also refuses directory records
that overrun an extent or logical block. Its real-pressing proof is the
preservation-metadata-matching Gallop Racer 2001 USA PS2 disc
(`SLUS-20255`): ten files independently agreed by pycdlib and pinned
7-Zip, with only metadata committed.
`ps1-bincue` additionally preserves general
Mode-2 Form-2 payloads through its public sector API while retaining the
fixed 2048-byte cooked view needed for ISO9660 LBA composition; its
deliberately narrow CUE grammar fails closed on unmatched syntax and
duplicate index declarations.
`saturn-dc-raw` is anchored by the GPL-3.0 Save Game Copier 3.7.1
release: 412 complete Mode-1 sectors independently reconstructed and
verified by pinned ECM/UNECM, then decoded byte-exactly to the upstream
ISO. Both raw-CD normalizers require valid BCD addresses and a
monotonically advancing MSF sequence from any valid starting address.
For `saturn-dc-raw`, full EDC/P-Q ECC stays with the staging oracle after
its stdlib runtime cost was benchmarked at roughly 162 seconds for a
full-sized disc.

Qualified local retail anchors have split the former combined keyed-platform
row into honest one-layer units. `3ds-cci`, decrypted-only `3ds-ncch`, and
the unkeyed outer `wii-disc` container are READY. Wii partition AES-CBC
decoding is prepared but waits on a caller-supplied local common-key file;
the decrypted Wii FST follows that ByteView. Encrypted/seeded NCCH and CIA
remain deferred. See `NORMALIZERS.md` for exact format bounds, fixture
provenance, proof tools, and the dispatch order.

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

The pinned 3DS differential readers are restored with:

```powershell
uv run python seedtools/vendor_tools.py 3ds
```

This retains only `ctrtool.exe` and `3dstool.exe` under gitignored `tools/`;
no 3DS key file is fetched or vendored.

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
