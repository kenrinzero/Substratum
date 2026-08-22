# Substratum

One normalized byte view over the game-preservation container zoo: any
dump — disc image, cartridge, archive — becomes a flat `ByteView` or an
enumerable `FileTree` of seekable byte ranges behind a single
`normalize()` interface, so downstream tools (technology census, asset
extraction, VN text pipelines) never re-implement ISO9660 offsets or CHD
decode. Foundation segment of the **Spolia** game-media program
(Substratum → Stratum + Quarry → Kura → Interlinear).

For a quick project orientation, see [`BACKLOG.md`](BACKLOG.md); detailed
unit status and proof obligations remain in [`NORMALIZERS.md`](NORMALIZERS.md).

A green means the tree is provably the *right* tree: fixture-matched,
byte-stable, and — the check that bites — every sampled file read
*through* the tree is byte-identical to an independent tool's extraction.
A normalizer with perfect enumeration and wrong slicing dies at that gate
(proven at seed time by a deliberately self-consistent mutant).

## Status

Version 0.0.28 (2026-08-22): the interface and manifest schema remain
frozen, the public one-layer dispatcher is live, and twenty-four real
normalizers are green: `iso9660`, `gc-fst`, `chd`, `ps1-bincue`,
`saturn-dc-raw`, `ciso`, `cso`, `zip`, `rvz`, `gcz`, `wbfs`, `nkit`,
`wii-u8-arc`, `xdvdfs`, `3ds-cci`, `3ds-ncch`, `3ds-romfs`,
the complete Wii chain (`wii-disc` → `wii-partition` → `wii-fst`),
`3ds-ncch-enc`, `cia`, `3ds-ncch-enc-seed`, and `3ds-ncch-enc-96`. The
3DS encrypted-NCCH family is complete for all available anchors: standard
+ plain-7.x, 7.x-seed, and New3DS 9.6 — the last via a pure-Python
AES-CTR path that bypasses vendored ctrtool (which cannot decrypt keyslot
`0x1B`) and implements the 3DS two-key NCCH model (exheader/ExeFS-superblock/
ExeFS-tail under Key0, `.code`+RomFS under Key1). Every unit runs
through the same four-check
structural, manifest,
round-trip, and byte-fidelity gate; the large GameCube fixtures also carry
a 1 GB per-test peak-RSS guard. `zip` spools DEFLATE members into a
one-file decompression spool (the `chd` pattern) and returns a FileTree
whose byte ranges point into it — per-member CRC-32 and inflated sizes
are validated during the streaming extract, and its expected manifest is
authored from pinned 7-Zip's independent listing and extraction.
`rvz` decompresses Dolphin's RVZ block stream (`DolphinTool 2606a`, `zstd:5`, `131072`-byte blocks) into a `ByteView` of the raw GC/Wii ISO — `GT Cube` (GC, 661 `gc-fst` files) and `Ghost Squad` (Wii, 2 partitions) proven via `wit` second reader; the full `zip → rvz → gc-fst` chain now covers the 2,573-title GC+Wii corpus.
`gcz` decodes Dolphin's legacy CompressedBlob GCZ (magic `0xB10BC001`) through the same vendored DolphinTool, with the container differential provided by a spec-derived pure-Python block decoder in the tests (wit cannot read GCZ); a full-disc `iso → gcz → decode` round-trip is sha256-identical, and an operator-staged mislabeled `.gcz` (a compacted raw GC ISO) is kept as the sniff/dispatch regression that must route to `gc-fst`.
`wbfs` reconstructs the scrubbed Wii container through wit (`wit copy`), zero-filling scrubbed clusters to the canonical full-size image — the independent differential is a spec-derived wlba-LUT decoder in the tests (DolphinTool's WBFS decode is mangled and unusable as an oracle; recorded), proven sha256-identical to wit over the entire 4.7 GB anchor.
`nkit` recovers GC `.nkit.iso` to the full-size original through NKit 1.4 (the last public NKit release — NKit 2 is Discord-only, recorded); the differential is a byte-exact retail round-trip (MKDD → nkit → decode, sha256-identical) plus the recovered/compacted gc-fst file-map agreement, and the sniffer must precede `gc-fst` because an nkit begins with a real GC disc header.
`ciso` decodes wit's GC/Wii compact-ISO container — a byte-per-block map over raw 2 MiB slots in the fixed Wii-size address space (no compression) — sharing the `CISO` magic with the PSP `cso` unit; the two sniffers disambiguate on the LE u32 at 0x04 (`0x200000` block size vs PSP header size `0x18`), `ciso` is registered first, and NKit 2's appended recovery trailer is tolerated. Proven against wit's own decode on a wit-authored CISO (byte-exact over the full image) and on the NKit-authored Luigi's Mansion retail anchor through the gc-fst composition, with wit's GC junk scrubbing characterized as one-directional and never inside game files.
`xdvdfs` dispatch now probes the four known XGD descriptor bases (plain `.xiso` `0`, XGD1 `0x18300000`, XGD2 `0x0FD90000`, XGD3 `0x02080000`; consumer ask 9, 2026-08-22): a retail Xbox dump embeds its XDVDFS partition after a decoy DVD-Video region that `iso9660` legitimately claims, so `xdvdfs` is registered ahead of it and claims the embedded partition first — proven through `normalize()` on three staged XGD1 retail discs (Jade Empire, KotOR, Prince of Persia) with the double-claim and the registry order both test-pinned.
`3ds-romfs` walks the decrypted IVFC-wrapped RomFS layer with the
complete hash tree verified eagerly (master <- level0 <- level1 <- data),
proven on staged retail media through the full cci → ncch → romfs
composition against ctrtool's own extraction.
`iso9660`, `gc-fst`, and `wii-u8-arc` refuse
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

`3ds-cci` exposes only the outer NCSD partition table: Cubic Ninja's CXI
and update CFA remain lazy opaque slices into the original CCI, with complete
payload fidelity independently proved by pinned ctrtool and 3dstool. It
refuses media-size drift, malformed/overlapping/out-of-bounds partition
tables, duplicate partition IDs, NCSD/NCCH ID disagreement, and bad magics.
`3ds-ncch` takes the decrypted CXI as a separate caller-visible layer and
exposes its extended header, plain region, ExeFS, and RomFS as lazy opaque
slices. It validates the NCCH-declared protected hashes and refuses encrypted
or seeded content, malformed ranges, overlap, and hash drift without
traversing ExeFS or RomFS.
`wii-disc` similarly stops at the unkeyed outer layer: it exposes DATA,
UPDATE, or CHANNEL partitions as lazy opaque encrypted slices after validating
the disc directory, cleartext partition metadata, and complete ranges. The
Munchables anchor keeps its scrubbed retail bytes local while pinned wit
independently verifies both signed partitions and authors their boundaries.
`wii-partition` then decrypts one such partition into a lazy `ByteView` of
0x7C00-byte cluster payloads using a pure-Python AES-128-CBC (NIST SP 800-38A
anchored) — the title key is derived from the ticket with the operator-supplied
standard Wii common key (`SUBSTRATUM_WII_COMMON_KEY_FILE`), which is never
committed, hashed, or logged. `wii-fst` walks that decrypted `ByteView`'s FST
into a `FileTree` of user-data files (50 files + 3 dirs on The Munchables); the
load-bearing Wii-format finding is that FST file offsets are word offsets
(`<< 2`), unlike GameCube's byte offsets. The complete Wii chain — `wii-disc`
→ `wii-partition` → `wii-fst` — is end-to-end green. See
[`docs/WII-KEYED-WORK.md`](docs/WII-KEYED-WORK.md) for the exact local key
artifact, safe extraction/storage steps, and key-handling discipline.
The full 3DS encrypted-NCCH family is GREEN. The CIA install container
(`cia`) parses the outer container into opaque section slices whose content
blob a caller re-normalizes through `3ds-ncch-enc`. CDN-encrypted eShop
chunks (TMD type bit 0) verify their TMD SHA-256 after titlekey decrypt;
the slices themselves stay on-media. `3ds-ncch-enc` covers the
no-seed encrypted variants — standard crypto (`Secure (0)`, keyslot `0x2C`)
and plain-7.x (`Secure (1)` no-seed, keyslot `0x25`) — decrypting via vendored
ctrtool into a `ByteView` the caller composes through `three_ds_ncch`.
`3ds-ncch-enc-seed` handles 7.x-seed (`Secure (1) (KeyY seeded)`, keyslot
`0x25`) inside a CIA via ctrtool + the operator-supplied seeddb.
`3ds-ncch-enc-96` decrypts **New3DS 9.6** (`0x0B`, keyslot `0x1B`) in
**pure-Python AES-CTR**, bypassing vendored ctrtool v1.3.0 entirely (it cannot
decrypt keyslot `0x1B`): it reads the `0x2C` + `0x1B` keyX values from the
operator-supplied keyset (`SUBSTRATUM_3DS_KEYSET_FILE`) and derives the AES
normal keys via the 3DS hardware key generator. The load-bearing finding is
the **two-key NCCH model** — a 9.6 NCCH uses two normal keys from the same
keyY but different keyX slots: Key0 (`0x2C`) encrypts the extended header,
the ExeFS superblock, and the ExeFS tail; Key1 (`0x1B`) encrypts the first
ExeFS file (`.code`) and the entire RomFS (the ExeFS is one continuous CTR
stream whose key switches mid-stream). New3DS 9.3 (`0x0A`/`0x18`) is
**opportunistic only**: the tooling falls out of the 9.6 path (same module),
but a genuine `0x0A` anchor is effectively lost media. See
[`docs/3DS-KEYED-WORK.md`](docs/3DS-KEYED-WORK.md) for the crypto hierarchy,
key-discipline notes, and the two-key model; see `NORMALIZERS.md` for exact
format bounds, fixture provenance, proof tools, and the dispatch order.

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

Substratum currently targets Python 3.13+ and is developed in the open at
[github.com/kenrinzero/Substratum](https://github.com/kenrinzero/Substratum).
It is not published to PyPI; install from a checkout:

```powershell
uv sync
uv run pytest
```

The runtime package itself is stdlib-only. `RVZ` decoding additionally requires `DolphinTool` (`dolphin-tool convert`) — set `SUBSTRATUM_DOLPHIN_TOOL` or use the pinned `tools/dolphin-tool/DolphinTool.exe` via `seedtools/vendor_tools.py dolphin-tool` — and CHD decoding additionally
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

The fidelity check diffs a deterministic 16-file sample per fixture
(`DESIGN.md` § 3) — the settled policy, and what a routine run does. For a
periodic deep pass, opt one run into diffing **every** file instead:

```powershell
$env:SUBSTRATUM_FULL_FIDELITY = "1"; uv run pytest; $env:SUBSTRATUM_FULL_FIDELITY = $null
```

That takes byte coverage on the six fixtures over the cap from 96 of 2,699
reference files to all of them. It reads a lot: ~19 MB on a fresh clone,
~10 GB with every retail anchor staged. It also needs a complete extraction
for each fixture it touches — an unsampled file with no reference bytes is a
fidelity red — and it changes no default, so it can only make a run stronger.

## Fixture policy (short version)

Synthetic (committed) · homebrew (fetched, committed if license-clean) ·
`FIXTURE REQUEST` rows that Kenrin fulfils by dropping one retail file
into the gitignored `fixtures/_local/`. Agents have **no standing corpus
access**; published outputs are metadata only.

## Contributors

Development is led by **kenrinzero** with a fleet of AI agents under the
Atelier protocol. See [`CONTRIBUTORS.md`](CONTRIBUTORS.md) for the full list.

## License

MIT — see [`LICENSE`](LICENSE). Committed fixtures are synthetic or
license-clean homebrew with per-file provenance noted in their NORMALIZERS.md
row.
