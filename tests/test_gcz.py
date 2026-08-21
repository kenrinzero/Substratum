"""Gate tests for the GCZ container normalizer (NORMALIZERS.md row `gcz`).

GCZ is Dolphin's legacy compressed GC/Wii disc container (CompressedBlob).
The normalizer returns a ByteView of the decompressed disc image (DESIGN.md
§1 one-layer), which the caller composes via `gc-fst` (GC) or `wii-disc`
(Wii).  The decoder is DolphinTool 2606a; the container differential is a
spec-derived pure-Python block decoder (this file) — with wit 3.05a unable
to read GCZ at all ("WRONG FILE TYPE"), the independent second party for
the block codec is a decoder authored from the on-disk layout, never from
the normalizer's code (which has no parser to borrow).

On-disk layout (empirically characterized against DolphinTool-written
files; header little-endian):
  u32  magic = 0xB10BC001
  u32  sub_type (0 = GameCube, 1 = Wii)
  u64  compressed_data_size (exact length of the trailing block region)
  u64  disc_size (decompressed image size)
  u32  block_size
  u32  num_blocks
  u64  offsets[num_blocks]   absolute offset of block k inside the block
                             region; bit 63 set = block stored raw
  u32  hashes[num_blocks]    hash of the decompressed block (not needed
                             to decode; Dolphin validates)
  then the block region: zlib streams (or raw blocks) back to back.

Anchors in gitignored fixtures/_local/:
- GT Cube (Japan).gcz — GC, written by DolphinTool 2606a (-f gcz -b 16384)
  from the staged retail .rvz (sha256 a14f114bb10b7caea234d82c4698663
  4514f05b10a40f6d5e9b07132a8ce0910), 1,115,451,806 -> 1,459,978,240.
- Ghost Squad (Japan).gcz — Wii (sub_type 1), written likewise (sha256
  54f9d1b8bd844737fac19ec58713a46bb264152b37f3fb265eff4c48c616f5f3),
  4,445,970,537 -> 4,699,979,776.
- Beach Spikers - Virtua Beach Volleyball.gcz — operator-staged file that
  is NOT a GCZ: a compacted raw GC ISO mislabeled with the extension (the
  existing gc-fst normalizer walks it, 1,224 files).  Kept as the
  sniff/dispatch regression: `gcz` must not claim a plain disc header.
"""

from __future__ import annotations

import hashlib
import struct
import subprocess
import tempfile
import zlib
from pathlib import Path

import pytest

from substratum.contract import FileSource, ByteView
from substratum.formats.gcz import normalize_gcz, sniff
from substratum import normalize as dispatch_normalize
from substratum.formats.gc_fst import normalize_gc_fst
from substratum.formats.wii_disc import normalize_wii_disc

ROOT = Path(__file__).resolve().parent.parent

GC_GCZ = ROOT / "fixtures" / "_local" / "GT Cube (Japan).gcz"
WII_GCZ = ROOT / "fixtures" / "_local" / "Ghost Squad (Japan).gcz"
BEACH = ROOT / "fixtures" / "_local" / "Beach Spikers - Virtua Beach Volleyball.gcz"
NESTED_ISO = ROOT / "fixtures" / "gc_fst" / "nested" / "game.iso"

DOLPHIN_TOOL = ROOT / "tools" / "dolphin-tool" / "DolphinTool.exe"

GCZ_MAGIC = b"\x01\xc0\x0b\xb1"  # 0xB10BC001 little-endian


@pytest.fixture(scope="module")
def gc_view():
    if not GC_GCZ.is_file():
        pytest.skip("GT Cube GCZ not staged")
    view = normalize_gcz(GC_GCZ)
    yield view
    view.source.close()


@pytest.fixture(scope="module")
def wii_view():
    if not WII_GCZ.is_file():
        pytest.skip("Ghost Squad GCZ not staged")
    view = normalize_gcz(WII_GCZ)
    yield view
    view.source.close()


# --- spec-derived reference decoder (independent of the normalizer) ---


def _spec_blocks(path: Path, first: int, count: int) -> bytes:
    """Decode `count` blocks starting at `first` straight from the layout."""
    with path.open("rb") as f:
        magic, sub = struct.unpack("<II", f.read(8))
        assert magic == 0xB10BC001
        compressed_size, _disc_size = struct.unpack("<QQ", f.read(16))
        block_size, num_blocks = struct.unpack("<II", f.read(8))
        offsets = struct.unpack(f"<{num_blocks}Q", f.read(8 * num_blocks))
        f.read(4 * num_blocks)  # hash array
        data_start = 32 + 12 * num_blocks
        out = bytearray()
        for k in range(first, min(first + count, num_blocks)):
            start = offsets[k] & 0x7FFFFFFFFFFFFFFF
            end = (
                offsets[k + 1] & 0x7FFFFFFFFFFFFFFF
                if k + 1 < num_blocks
                else compressed_size
            )
            f.seek(data_start + start)
            blob = f.read(end - start)
            out += blob if offsets[k] >> 63 else zlib.decompress(blob)
        return bytes(out)


def test_sniff():
    assert sniff(FileSource(GC_GCZ)) if GC_GCZ.is_file() else True
    with tempfile.NamedTemporaryFile(suffix=".gcz", delete=False) as f:
        f.write(GCZ_MAGIC + b"\x00" * 100)
        tmp = Path(f.name)
    try:
        assert sniff(FileSource(tmp))
    finally:
        tmp.unlink()
    assert not sniff(FileSource(ROOT / "fixtures" / "toy" / "toy.bin"))
    assert not sniff(FileSource(ROOT / "fixtures" / "iso9660" / "supertux" / "supertux.iso"))
    # RVZ magic must not be claimed
    with tempfile.NamedTemporaryFile(suffix=".rvz", delete=False) as f:
        f.write(b"RVZ\x01" + b"\x00" * 100)
        tmp = Path(f.name)
    try:
        assert not sniff(FileSource(tmp))
    finally:
        tmp.unlink()
    # the mislabeled Beach Spikers file starts with a plain GC disc header
    if BEACH.is_file():
        assert not sniff(FileSource(BEACH))


def test_returns_byteview(gc_view):
    assert isinstance(gc_view, ByteView)
    assert gc_view.format == "gcz"
    assert gc_view.source.size() == 1459978240


def test_header_fields_are_sane():
    with GC_GCZ.open("rb") as f:
        magic, sub_type = struct.unpack("<II", f.read(8))
        compressed_size, disc_size = struct.unpack("<QQ", f.read(16))
        block_size, num_blocks = struct.unpack("<II", f.read(8))
    assert magic == 0xB10BC001
    assert sub_type == 0
    assert disc_size == 1459978240
    assert block_size * num_blocks == disc_size
    assert 32 + 12 * num_blocks + compressed_size == GC_GCZ.stat().st_size


def test_wii_gcz_header_sub_type():
    with WII_GCZ.open("rb") as f:
        magic, sub_type = struct.unpack("<II", f.read(8))
        compressed_size, disc_size = struct.unpack("<QQ", f.read(16))
        block_size, num_blocks = struct.unpack("<II", f.read(8))
    assert magic == 0xB10BC001
    assert sub_type == 1
    assert disc_size == 4699979776
    assert block_size * num_blocks == disc_size
    assert 32 + 12 * num_blocks + compressed_size == WII_GCZ.stat().st_size


def test_spec_decoder_matches_dolphin_tool(gc_view):
    """The spec-derived block decoder agrees with DolphinTool's decode."""
    # head, mid, and tail windows: 1 MiB each
    bs = 16384
    assert gc_view.source.read_at(0, 64 * bs) == _spec_blocks(GC_GCZ, 0, 64)
    assert (
        gc_view.source.read_at(44000 * bs, 64 * bs) == _spec_blocks(GC_GCZ, 44000, 64)
    )
    assert (
        gc_view.source.read_at(89046 * bs, 64 * bs) == _spec_blocks(GC_GCZ, 89046, 64)
    )


def test_gc_gcz_composes_to_gc_fst(gc_view):
    tree = normalize_gc_fst(gc_view.source)
    assert len(tree.entries) == 661
    car = next(e for e in tree.entries if e.path == "car/car_001.g3d")
    assert car.size == 339628
    data = tree.read(car)
    assert len(data) == 339628
    assert data[:4] != b"\x00\x00\x00\x00"


def test_wii_gcz_composes_to_wii_disc(wii_view):
    assert wii_view.source.size() == 4699979776
    tree = normalize_wii_disc(wii_view.source)
    assert len(tree.entries) == 2
    paths = {e.path for e in tree.entries}
    assert "partition-data.bin" in paths
    assert "partition-update.bin" in paths
    data_part = next(e for e in tree.entries if e.path == "partition-data.bin")
    assert data_part.size == 4424728576
    assert data_part.offset == 260046848


def test_round_trip_from_iso_is_byte_exact():
    """iso -> gcz (DolphinTool) -> normalize -> byte-identical to the iso."""
    if not NESTED_ISO.is_file() or not DOLPHIN_TOOL.is_file():
        pytest.skip("nested synthetic GC iso or dolphin-tool not available")
    with tempfile.TemporaryDirectory(prefix="gcz-roundtrip-") as tmp:
        gcz = Path(tmp) / "roundtrip.gcz"
        subprocess.run(
            [
                str(DOLPHIN_TOOL),
                "convert",
                "-i",
                str(NESTED_ISO),
                "-o",
                str(gcz),
                "-f",
                "gcz",
                "-b",
                "16384",
            ],
            capture_output=True,
            check=True,
            timeout=300,
        )
        view = normalize_gcz(gcz)
        try:
            assert view.source.size() == NESTED_ISO.stat().st_size
            sha = hashlib.sha256()
            with NESTED_ISO.open("rb") as f:
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    sha.update(chunk)
            out = hashlib.sha256()
            pos = 0
            total = view.source.size()
            while pos < total:
                out.update(view.source.read_at(pos, min(1 << 20, total - pos)))
                pos += 1 << 20
            assert out.hexdigest() == sha.hexdigest()
        finally:
            view.source.close()


def test_truncated_gcz_is_structural_red(tmp_path):
    bad = tmp_path / "bad.gcz"
    bad.write_bytes(GCZ_MAGIC + b"\x00" * 100)
    with pytest.raises((ValueError, RuntimeError, subprocess.CalledProcessError)):
        view = normalize_gcz(bad)
        try:
            view.source.read_at(0, 1)
        finally:
            try:
                view.source.close()
            except:  # noqa
                pass


def test_empty_gcz_refused(tmp_path):
    bad = tmp_path / "empty.gcz"
    bad.write_bytes(b"")
    with pytest.raises((ValueError, RuntimeError, subprocess.CalledProcessError)):
        normalize_gcz(bad)


def test_mislabeled_beach_spikers_routes_to_gc_fst():
    """The operator-staged `.gcz` that is a plain compacted GC ISO."""
    if not BEACH.is_file():
        pytest.skip("Beach Spikers mislabel anchor not staged")
    assert not sniff(FileSource(BEACH))
    tree = dispatch_normalize(BEACH)
    try:
        assert len(tree.entries) == 1224
    finally:
        source = getattr(tree, "source", None)
        if source is not None and hasattr(source, "close"):
            source.close()


def test_dispatch_via_normalize():
    if not GC_GCZ.is_file():
        pytest.skip("no GC GCZ")
    view = dispatch_normalize(GC_GCZ)
    assert isinstance(view, ByteView)
    assert view.format == "gcz"
    view.source.close()
    view2 = dispatch_normalize(GC_GCZ, format="gcz")
    assert view2.format == "gcz"
    view2.source.close()
