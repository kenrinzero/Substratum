"""Gate tests for the NKit container normalizer (NORMALIZERS.md row `nkit`).

GC `.nkit.iso` is NKit's compacted GameCube image: a real GC disc header
at 0x000, the ``NKIT`` signature block at 0x200, then the compacted
filesystem (FST rewritten to the compacted layout — which is why the
existing `gc-fst` normalizer walks it at FILE level; see the BACKLOG
finding).  The normalizer returns the RECOVERED full-size image (NKit
restore: junk regenerated, original FST order restored), composed by the
caller via `gc-fst`.

Decoder: NKit 1.4 (Nanook), the reference implementation — the last
public NKit release (NKit 2 is Discord-distributed with no public source;
recorded).  The tool writes into `<exe-dir>/Processed/` with no output
flag, so the normalizer runs an isolated ~1 MB copy of the tool per call
(`Processed/` then lands inside the call's temp spool).

Differential:
- **Round-trip on independent retail bytes**: `Mario Kart - Double
  Dash!! (USA).iso` (user-dropped, identity-verified GM4E01) is converted
  to `.nkit.iso` by the tool (VerifySuccess), and `normalize_nkit`'s
  decode is sha256-identical to the original over the entire
  1,459,978,240-byte image — NKit's preserve claim, proven.
- The recovered retail anchor walk: the path/size map equals the
  compacted image's `gc-fst` walk (same files, recovered layout).
- The tool's own 3-pass full verify (VerifySuccess) is the structural
  anchor.

Scope: GC `.nkit.iso` only (the staged shape).  Wii NKit (RVT-H-ish
`nkit.iso`, `nkit.gcz`) has no sample and stays out; `.nkit.gcz` wraps
the compacted image in a Dolphin-GCZ block stream, so it sniffs/decodes
via `gcz` to the COMPACTED image (file-level correct via `gc-fst`) —
documented, not recovered.

Anchors in gitignored fixtures/_local/:
- Yu-Gi-Oh! The Falsebound Kingdom (Europe).nkit.iso — operator-staged,
  440,041,472 bytes, sha256 4c471bf5dc624c65dafe3f8f179b12697df22c0b
  1067a8452dd26c328e7a8b86, disc GYFPA4.
"""

from __future__ import annotations

import hashlib
import shutil
import struct
import subprocess
import tempfile
from pathlib import Path

import pytest

from substratum.contract import FileSource, ByteView
from substratum.formats.nkit import normalize_nkit, sniff
from substratum import normalize as dispatch_normalize
from substratum.formats.gc_fst import normalize_gc_fst

ROOT = Path(__file__).resolve().parent.parent

NKIT_FILE = ROOT / "fixtures" / "_local" / "Yu-Gi-Oh! The Falsebound Kingdom (Europe).nkit.iso"
MKDD_ISO = ROOT / "fixtures" / "_local" / "Mario Kart - Double Dash!! (USA).iso"
TOOL_DIR = ROOT / "tools" / "nkit"

DISC_SIZE = 1459978240


@pytest.fixture(scope="module")
def view():
    if not NKIT_FILE.is_file():
        pytest.skip("Yu-Gi-Oh NKit not staged")
    v = normalize_nkit(NKIT_FILE)
    yield v
    v.source.close()


def test_sniff():
    if NKIT_FILE.is_file():
        assert sniff(FileSource(NKIT_FILE))
    # synthetic: GC disc header + NKIT at 0x200
    with tempfile.NamedTemporaryFile(suffix=".nkit.iso", delete=False) as f:
        f.write(b"GYFPA4" + b"\x00" * 22)
        f.write(bytes.fromhex("c2339f3d"))  # GC magic at 0x1C
        f.write(b"\x00" * (0x200 - 0x20))
        f.write(b"NKIT" + b"\x00" * 100)
        tmp = Path(f.name)
    try:
        assert sniff(FileSource(tmp))
    finally:
        tmp.unlink()
    # a plain GC ISO (disc header but no NKIT block) must NOT be claimed
    with tempfile.NamedTemporaryFile(suffix=".iso", delete=False) as f:
        f.write(b"GM4E01" + b"\x00" * 22)
        f.write(bytes.fromhex("c2339f3d"))
        f.write(b"\x00" * 0x400)
        tmp = Path(f.name)
    try:
        assert not sniff(FileSource(tmp))
    finally:
        tmp.unlink()
    assert not sniff(FileSource(ROOT / "fixtures" / "toy" / "toy.bin"))
    assert not sniff(FileSource(ROOT / "fixtures" / "iso9660" / "supertux" / "supertux.iso"))


def test_sniff_requires_disc_magic_corroboration(tmp_path):
    # NKIT signature at 0x200 alone (no GC magic at 0x1C) must not sniff
    p = tmp_path / "fake.nkit.iso"
    p.write_bytes(b"\x00" * 0x200 + b"NKIT" + b"\x00" * 100)
    assert not sniff(FileSource(p))


def test_returns_byteview(view):
    assert isinstance(view, ByteView)
    assert view.format == "nkit"
    assert view.source.size() == DISC_SIZE
    assert view.source.read_at(0, 4) == b"GYFP"


def test_recovered_walks_gc_fst_with_same_file_map(view):
    """The recovered image's gc-fst walk matches the compacted walk's files."""
    recovered = normalize_gc_fst(view.source)
    assert len(recovered.entries) == 415
    compacted = dispatch_normalize(NKIT_FILE, format="gc-fst")
    assert {e.path: e.size for e in recovered.entries} == {
        e.path: e.size for e in compacted.entries
    }


def test_round_trip_from_retail_iso():
    """MKDD (retail) -> nkit -> normalize -> sha256-identical to the original."""
    if not MKDD_ISO.is_file() or not (TOOL_DIR / "ConvertToNKit.exe").is_file():
        pytest.skip("MKDD retail ISO or NKit tool not available")
    with tempfile.TemporaryDirectory(prefix="nkit-roundtrip-") as tmp:
        tool = Path(tmp) / "tool"
        shutil.copytree(TOOL_DIR, tool)
        # force the .nkit.iso form (default config writes gcz)
        cfg = tool / "NKit.dll.config"
        s = cfg.read_text(encoding="utf-8-sig")
        s2 = s.replace('key="NkitFormat" value="gcz"', 'key="NkitFormat" value="iso"')
        assert s2 != s, "NkitFormat key not found"
        cfg.write_text(s2, encoding="utf-8", newline="")
        # no check=True: a verified conversion still exits nonzero when the
        # CRC is absent from the (empty) Redump/Custom dats — the produced
        # .nkit.iso is the success criterion, mirroring the normalizer.
        subprocess.run(
            [str(tool / "ConvertToNKit.exe"), str(MKDD_ISO)],
            capture_output=True,
            timeout=300,
        )
        nkits = [p for p in (tool / "Processed").rglob("*.nkit.iso")]
        assert len(nkits) == 1
        v = normalize_nkit(nkits[0])
        try:
            assert v.source.size() == MKDD_ISO.stat().st_size == DISC_SIZE

            def sha_of_file(p):
                h = hashlib.sha256()
                with open(p, "rb") as f:
                    for c in iter(lambda: f.read(1 << 20), b""):
                        h.update(c)
                return h.hexdigest()

            out = hashlib.sha256()
            pos = 0
            while pos < DISC_SIZE:
                out.update(v.source.read_at(pos, min(1 << 20, DISC_SIZE - pos)))
                pos += 1 << 20
            assert out.hexdigest() == sha_of_file(MKDD_ISO)
        finally:
            v.source.close()


def test_truncated_nkit_is_structural_red(tmp_path):
    bad = tmp_path / "bad.nkit.iso"
    bad.write_bytes(b"\x00" * 0x200 + b"NKIT" + b"\x00" * 100)
    with pytest.raises((ValueError, RuntimeError, subprocess.CalledProcessError)):
        view = normalize_nkit(bad)
        try:
            view.source.read_at(0, 1)
        finally:
            try:
                view.source.close()
            except:  # noqa
                pass


def test_empty_nkit_refused(tmp_path):
    bad = tmp_path / "empty.nkit.iso"
    bad.write_bytes(b"")
    with pytest.raises((ValueError, RuntimeError, subprocess.CalledProcessError)):
        normalize_nkit(bad)


def test_dispatch_routes_nkit_not_gc_fst():
    """The nkit starts with a GC disc header; dispatch must still pick nkit."""
    if not NKIT_FILE.is_file():
        pytest.skip("Yu-Gi-Oh NKit not staged")
    view = dispatch_normalize(NKIT_FILE)
    assert isinstance(view, ByteView)
    assert view.format == "nkit"
    view.source.close()
    view2 = dispatch_normalize(NKIT_FILE, format="nkit")
    assert view2.format == "nkit"
    view2.source.close()
