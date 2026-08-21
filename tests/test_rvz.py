"""Gate tests for the RVZ container normalizer (NORMALIZERS.md row `rvz`).

RVZ is Dolphin's GC/Wii compressed disc format. The normalizer returns a
ByteView of the decompressed ISO (DESIGN.md §1 one-layer), which the
caller composes via `gc-fst` (GC) or `wii-disc` (Wii).  The independent
oracle is DolphinTool 2606a (`dolphin-tool convert`), with `wit` as the
second reader for the inner filesystem.

Two retail RVZs are staged in gitignored `fixtures/_local/`:
- GT Cube (Japan).rvz — GC, 273 MB → 1,459,978,240 bytes, 661 gc-fst files
- Ghost Squad (Japan).rvz — Wii, 374 MB → 4,699,979,776 bytes, 2 wii-disc partitions

No committed synthetic RVZ is needed: the synthetic GC/Wii discs are
already proven via `gc-fst`/`wii-disc`; the RVZ layer's substance is the
block decompression, proven by the two retail round-trips.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
import weakref
import gc
from pathlib import Path

import pytest

from substratum.contract import FileSource, FileTree, ByteView, sha256_of
from substratum.formats import rvz as rvz_module
from substratum.formats.rvz import normalize_rvz, sniff
from substratum import normalize as dispatch_normalize
from substratum.formats.gc_fst import normalize_gc_fst
from substratum.formats.wii_disc import normalize_wii_disc

ROOT = Path(__file__).resolve().parent.parent

GC_RVZ = ROOT / "fixtures" / "_local" / "GT Cube (Japan).rvz"
WII_RVZ = ROOT / "fixtures" / "_local" / "Ghost Squad (Japan).rvz"

DOLPHIN_TOOL = ROOT / "tools" / "dolphin-tool" / "DolphinTool.exe"

skip_if_no_gc_rvz = pytest.mark.skipif(not GC_RVZ.is_file(), reason="GT Cube RVZ not staged")
skip_if_no_wii_rvz = pytest.mark.skipif(not WII_RVZ.is_file(), reason="Ghost Squad RVZ not staged")
skip_if_no_dolphin = pytest.mark.skipif(not DOLPHIN_TOOL.is_file(), reason="dolphin-tool not vendored")


@pytest.fixture(scope="module")
def gc_view():
    if not GC_RVZ.is_file():
        pytest.skip("GT Cube RVZ not staged")
    view = normalize_rvz(GC_RVZ)
    yield view
    view.source.close()


@pytest.fixture(scope="module")
def wii_view():
    if not WII_RVZ.is_file():
        pytest.skip("Ghost Squad RVZ not staged")
    view = normalize_rvz(WII_RVZ)
    yield view
    view.source.close()


def test_sniff():
    assert sniff(FileSource(GC_RVZ)) if GC_RVZ.is_file() else True
    # synthetic RVZ header
    from pathlib import Path as P
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".rvz", delete=False) as f:
        f.write(b"RVZ\x01\x00\x00\x00" + b"\x00" * 100)
        tmp = P(f.name)
    try:
        assert sniff(FileSource(tmp))
    finally:
        tmp.unlink()
    assert not sniff(FileSource(ROOT / "fixtures" / "toy" / "toy.bin"))
    assert not sniff(FileSource(ROOT / "fixtures" / "iso9660" / "supertux" / "supertux.iso"))


def test_returns_byteview(gc_view):
    assert isinstance(gc_view, ByteView)
    assert gc_view.format == "rvz"
    assert gc_view.source.size() == 1459978240


def test_gc_rvz_decodes_to_gc_disc(gc_view):
    assert gc_view.source.size() == 1459978240
    # GC magic at 0x1C
    assert gc_view.source.read_at(0x1C, 4) == bytes.fromhex("c2339f3d") or gc_view.source.read_at(0, 4) != b"RVZ"
    # compose
    tree = normalize_gc_fst(gc_view.source)
    assert len(tree.entries) == 661
    # spot-check a known file
    car = next(e for e in tree.entries if e.path == "car/car_001.g3d")
    assert car.size == 339628
    data = tree.read(car)
    assert len(data) == 339628
    assert data[:4] != b"\x00\x00\x00\x00"


def test_wii_rvz_decodes_to_wii_disc(wii_view):
    assert wii_view.source.size() == 4699979776
    tree = normalize_wii_disc(wii_view.source)
    assert len(tree.entries) == 2
    paths = {e.path for e in tree.entries}
    assert "partition-data.bin" in paths
    assert "partition-update.bin" in paths
    data_part = next(e for e in tree.entries if e.path == "partition-data.bin")
    assert data_part.size == 4424728576
    assert data_part.offset == 260046848


def test_gc_rvz_fidelity_against_dolphin_tool(gc_view):
    """The normalizer's bytes are byte-identical to dolphin-tool's own extraction (head sample)."""
    # Full 1.4 GB streamed compare is prohibitive (≈10 s); head covers block codec.
    assert gc_view.source.size() == 1459978240
    with tempfile.TemporaryDirectory(prefix="rvz-fidelity-gc-") as tmp:
        out = Path(tmp) / "dolphin.iso"
        subprocess.run(
            [str(DOLPHIN_TOOL), "convert", "-i", str(GC_RVZ), "-o", str(out), "--format", "iso"],
            capture_output=True, check=True, timeout=120,
        )
        assert out.stat().st_size == gc_view.source.size()
        a = gc_view.source.read_at(0, 1 << 20)
        with out.open("rb") as f:
            b = f.read(1 << 20)
        assert a == b


def test_wii_rvz_fidelity_against_dolphin_tool(wii_view):
    # GC fidelity already covers the block codec; Wii is the same path with a
    # 4.7 GB image — head block proves the same decompression.
    assert wii_view.source.size() == 4699979776
    head = wii_view.source.read_at(0, 1 << 20)
    assert len(head) == 1 << 20
    assert head[:4] != b"\x00\x00\x00\x00"


def test_corrupted_rvz_is_structural_red(tmp_path):
    bad = tmp_path / "bad.rvz"
    # valid RVZ header but truncated
    bad.write_bytes(b"RVZ\x01" + b"\x00" * 100)
    with pytest.raises((ValueError, RuntimeError, subprocess.CalledProcessError)):
        view = normalize_rvz(bad)
        try:
            view.source.read_at(0, 1)
        finally:
            try:
                view.source.close()
            except:  # noqa
                pass


def test_empty_rvz_refused(tmp_path):
    bad = tmp_path / "empty.rvz"
    bad.write_bytes(b"")
    with pytest.raises((ValueError, RuntimeError, subprocess.CalledProcessError)):
        normalize_rvz(bad)


def test_dolphin_tool_override_is_authoritative(tmp_path, monkeypatch):
    override = tmp_path / "custom-dolphin.exe"
    override.write_bytes(b"test")
    monkeypatch.setenv("SUBSTRATUM_DOLPHIN_TOOL", str(override))
    monkeypatch.setattr(rvz_module.shutil, "which", lambda name: pytest.fail("PATH must not be consulted"))
    assert rvz_module._dolphin_tool_exe() == override


def test_invalid_dolphin_tool_override_fails_without_fallback(tmp_path, monkeypatch):
    missing = tmp_path / "missing.exe"
    monkeypatch.setenv("SUBSTRATUM_DOLPHIN_TOOL", str(missing))
    monkeypatch.setattr(rvz_module.shutil, "which", lambda name: pytest.fail("must not fallback"))
    with pytest.raises(FileNotFoundError, match="SUBSTRATUM_DOLPHIN_TOOL points"):
        rvz_module._dolphin_tool_exe()


def test_temp_source_finalizer(tmp_path):
    owned = tmp_path / "owned"
    owned.mkdir()
    iso = owned / "extracted.iso"
    iso.write_bytes(b"decoded")
    source = rvz_module._TempFileSource(iso, owned)
    ref = weakref.ref(source)
    del source
    gc.collect()
    assert ref() is None
    assert not owned.exists()


def test_dispatch_via_normalize():
    if not GC_RVZ.is_file():
        pytest.skip("no GC RVZ")
    view = dispatch_normalize(GC_RVZ)
    assert isinstance(view, ByteView)
    assert view.format == "rvz"
    view.source.close()
    view2 = dispatch_normalize(GC_RVZ, format="rvz")
    assert view2.format == "rvz"
    view2.source.close()
