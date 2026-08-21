"""Gate tests for the WBFS container normalizer (NORMALIZERS.md row `wbfs`).

WBFS (Wii Backup File System) is the scrubbed container used by Wii USB
loaders.  The normalizer returns a ByteView of the reconstructed disc image
(DESIGN.md §1 one-layer), which the caller composes via `wii-disc`.  The
decoder is wit 3.05a — the reference implementation for WBFS.

**Load-bearing oracle finding (2026-08-21):** DolphinTool 2606a CANNOT serve
as the second party for WBFS — its `convert --format iso` output on the
staged anchor is mangled: 2x the disc size (9,399,959,552), the WBFS
container header embedded verbatim at 0x200000, and partition bytes that
disagree with wit's decode.  The independent container differential is
therefore a **spec-derived pure-Python decoder in this file**, authored from
the libwbfs reference layout (never from the normalizer's code — the
normalizer delegates to wit and has no parser): it reconstructs the full
disc from the wlba LUT and its sha256 matches wit's decode over the entire
4,699,979,776-byte image on the staged anchor.

On-disk layout (libwbfs `wbfs_head` / `wbfs_disc_info`, big-endian scalars):
  u32  magic = "WBFS"                       (0x00)
  u32  n_hd_sec   — nominal size in hd sectors   (0x04)
  u8   hd_sec_sz_s  — hd sector size as 2^shift   (0x08, here 9 = 512)
  u8   wbfs_sec_sz_s — wbfs sector size as 2^shift (0x09, here 0x15 = 2 MiB)
  u8   disc_table[] — 1 byte per disc slot, at 0x0C
  per disc slot i: disc_info at hd-sector 1 + i*disc_info_sz, holding
    u8   disc_header_copy[0x100]
    u16  wlba_table[n] — disc cluster k <-> file cluster wlba_table[k]
                         (BE; 0 = scrubbed/absent -> zero-fill on rebuild)
  n = (143432*2) >> (wbfs_sec_sz_s - 15);  disc_info_sz = align512(0x100+2n).
Scrub semantics: absent clusters (junk, and on this anchor the whole update
partition) are zero-filled by wit's reconstruction; original junk bytes are
unrecoverable from a WBFS by design.

Anchor in gitignored fixtures/_local/:
- Ghost Squad (Europe).wbfs — 1,096,810,496 bytes, sha256
  f17e764dbe0984766a5ddd8497da87f0f60eff5c4610a6838f6e00a05d4c5cca,
  operator-staged.  Single-layer Wii disc RGSP8P; scrubbed (no update
  partition; 522 of 4,482 LUT clusters present).  The JP `.rvz` anchor in
  the same drop zone is the same title unscrubbed (2 partitions).
"""

from __future__ import annotations

import hashlib
import struct
import subprocess
import tempfile
from pathlib import Path

import pytest

from substratum.contract import FileSource, ByteView
from substratum.formats.wbfs import normalize_wbfs, sniff
from substratum import normalize as dispatch_normalize
from substratum.formats.wii_disc import normalize_wii_disc

ROOT = Path(__file__).resolve().parent.parent

WBFS_FILE = ROOT / "fixtures" / "_local" / "Ghost Squad (Europe).wbfs"

DISC_SIZE = 4699979776

skip_if_no_wbfs = pytest.mark.skipif(not WBFS_FILE.is_file(), reason="Ghost Squad EU WBFS not staged")


@pytest.fixture(scope="module")
def view():
    if not WBFS_FILE.is_file():
        pytest.skip("Ghost Squad EU WBFS not staged")
    v = normalize_wbfs(WBFS_FILE)
    yield v
    v.source.close()


# --- spec-derived reference decoder (independent of the normalizer) ---


def _parse_header(path: Path):
    with path.open("rb") as f:
        hdr = f.read(512)
    assert hdr[:4] == b"WBFS"
    n_hd_sec = struct.unpack(">I", hdr[4:8])[0]
    hd_sec_sz = 1 << hdr[8]
    wbfs_sec_sz = 1 << hdr[9]
    n_lut = (143432 * 2) >> (hdr[9] - 15)
    disc_info_sz = (0x100 + 2 * n_lut + hd_sec_sz - 1) // hd_sec_sz * hd_sec_sz
    return n_hd_sec, hd_sec_sz, wbfs_sec_sz, n_lut, disc_info_sz, hdr[0x0C]


def _spec_disc_sha256(path: Path) -> str:
    """Stream-reconstruct the disc from the wlba LUT and hash it."""
    n_hd_sec, hd_sec_sz, wbfs_sec_sz, n_lut, disc_info_sz, slot0 = _parse_header(path)
    assert slot0, "no disc in slot 0"
    with path.open("rb") as f:
        f.seek(hd_sec_sz)  # disc slot 0
        info = f.read(0x100 + 2 * n_lut)
        lut = struct.unpack(f">{n_lut}H", info[0x100:])
        h = hashlib.sha256()
        remaining = DISC_SIZE
        for k, entry in enumerate(lut):
            if remaining <= 0:
                break
            take = min(wbfs_sec_sz, remaining)
            if entry:
                f.seek(entry * wbfs_sec_sz)
                blob = f.read(take)
                assert len(blob) == take
                h.update(blob)
            else:
                h.update(b"\x00" * take)
            remaining -= take
        assert remaining == 0
        return h.hexdigest()


def _view_sha256(v) -> str:
    h = hashlib.sha256()
    pos = 0
    while pos < DISC_SIZE:
        h.update(v.source.read_at(pos, min(1 << 20, DISC_SIZE - pos)))
        pos += 1 << 20
    return h.hexdigest()


def test_sniff():
    if WBFS_FILE.is_file():
        assert sniff(FileSource(WBFS_FILE))
    with tempfile.NamedTemporaryFile(suffix=".wbfs", delete=False) as f:
        f.write(b"WBFS" + b"\x00" * 100)
        tmp = Path(f.name)
    try:
        assert sniff(FileSource(tmp))
    finally:
        tmp.unlink()
    assert not sniff(FileSource(ROOT / "fixtures" / "toy" / "toy.bin"))
    assert not sniff(FileSource(ROOT / "fixtures" / "iso9660" / "supertux" / "supertux.iso"))
    # the other Dolphin-container magics must not be claimed
    with tempfile.NamedTemporaryFile(suffix=".rvz", delete=False) as f:
        f.write(b"RVZ\x01" + b"\x00" * 100)
        tmp = Path(f.name)
    try:
        assert not sniff(FileSource(tmp))
    finally:
        tmp.unlink()
    with tempfile.NamedTemporaryFile(suffix=".gcz", delete=False) as f:
        f.write(b"\x01\xc0\x0b\xb1" + b"\x00" * 100)
        tmp = Path(f.name)
    try:
        assert not sniff(FileSource(tmp))
    finally:
        tmp.unlink()


@skip_if_no_wbfs
def test_returns_byteview(view):
    assert isinstance(view, ByteView)
    assert view.format == "wbfs"
    assert view.source.size() == DISC_SIZE


@skip_if_no_wbfs
def test_header_fields_are_sane():
    n_hd_sec, hd_sec_sz, wbfs_sec_sz, n_lut, disc_info_sz, slot0 = _parse_header(WBFS_FILE)
    assert slot0 == 1
    assert n_hd_sec * hd_sec_sz == WBFS_FILE.stat().st_size
    assert hd_sec_sz == 512
    assert wbfs_sec_sz == 1 << 21
    assert n_lut == 4482


@skip_if_no_wbfs
def test_disc_header_copy_matches(view):
    _, hd_sec_sz, _, _, _, _ = _parse_header(WBFS_FILE)
    with WBFS_FILE.open("rb") as f:
        f.seek(hd_sec_sz)
        header_copy = f.read(0x100)
    assert view.source.read_at(0, 0x100) == header_copy
    assert header_copy[:4] == b"RGSP"


@skip_if_no_wbfs
def test_spec_decoder_matches_wit(view):
    """Full-disc differential: the LUT reconstruction equals wit's decode."""
    assert _view_sha256(view) == _spec_disc_sha256(WBFS_FILE)


@skip_if_no_wbfs
def test_composes_to_wii_disc(view):
    """Scrubbed EU anchor: data partition present, update partition absent."""
    tree = normalize_wii_disc(view.source)
    paths = {e.path for e in tree.entries}
    assert paths == {"partition-data.bin"}
    data_part = tree.entries[0]
    assert data_part.size == 4424728576
    assert data_part.offset == 260046848


def test_truncated_wbfs_is_structural_red(tmp_path):
    bad = tmp_path / "bad.wbfs"
    bad.write_bytes(b"WBFS" + b"\x00" * 100)
    with pytest.raises((ValueError, RuntimeError, subprocess.CalledProcessError)):
        view = normalize_wbfs(bad)
        try:
            view.source.read_at(0, 1)
        finally:
            try:
                view.source.close()
            except:  # noqa
                pass


def test_empty_wbfs_refused(tmp_path):
    bad = tmp_path / "empty.wbfs"
    bad.write_bytes(b"")
    with pytest.raises((ValueError, RuntimeError, subprocess.CalledProcessError)):
        normalize_wbfs(bad)


@skip_if_no_wbfs
def test_dispatch_via_normalize():
    view = dispatch_normalize(WBFS_FILE)
    assert isinstance(view, ByteView)
    assert view.format == "wbfs"
    view.source.close()
    view2 = dispatch_normalize(WBFS_FILE, format="wbfs")
    assert view2.format == "wbfs"
    view2.source.close()
