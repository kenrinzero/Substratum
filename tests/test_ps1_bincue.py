"""Gate tests for the ps1-bincue normalizer (NORMALIZERS.md row `ps1-bincue`).

The ps1-bincue normalizer returns a ByteView of the inner 2048-byte user-data
stream (DESIGN.md §1 composition rule: one layer, never recurse). The test
wraps that ByteView through `normalize_iso9660` to get a FileTree for the
four-check gate — the same shape test_chd.py and test_cso.py use.

Expected manifest entries are authored by seedtools/make_ps1_bincue_fixture.py
from pycdlib's records (second independent reader, never the parser under
test); reference bytes are 7-Zip's extraction of the inner ISO (the
byte-fidelity substrate). Tool pins include chdman 0.288 (structural anchor)
and pycdlib 1.16.0 (byte differential).
"""

import json
from pathlib import Path

import jsonschema
import pytest

from substratum.contract import ByteView, FileSource, FileTree, sha256_of
from substratum.formats.ps1_bincue import normalize_ps1_bincue, sniff
from substratum.formats.iso9660 import normalize_iso9660
from substratum.verify import run_checks

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "fixtures" / "ps1_bincue" / "synthetic"
BIN = FIXTURE / "game.bin"
CUE = FIXTURE / "game.cue"
ISO = FIXTURE / "synthetic.iso"
REFERENCE = FIXTURE / "reference"

# Tool versions — must byte-match what make_ps1_bincue_fixture stamped
# into the expected manifest. Re-authoring on a drifted tool changes the
# expected manifest and fails check 2 loudly.
TOOLS = {
    "7z": "7-Zip 26.02 (x64) 2026-06-25",
    "chdman": "0.288 (mame0288)",
    "pycdlib": "1.16.0",
    "generator": "make_ps1_bincue_fixture v1",
}


def _normalize_ps1_to_tree(source):
    """Wrapper for run_checks: PS1 .bin -> ByteView -> iso9660 -> FileTree.

    format is "ps1-bincue" so the manifest records the container.
    """
    view = normalize_ps1_bincue(source)  # ByteView over the inner ISO
    tree = normalize_iso9660(view.source)  # FileTree over the 2048 stream
    return FileTree(source=tree.source, format="ps1-bincue", entries=tree.entries)


def _checks(fixture=BIN):
    return run_checks(
        _normalize_ps1_to_tree,
        fixture,
        FIXTURE / "expected.manifest.json",
        REFERENCE,
        "game.bin",
        sha256_of(ISO),  # decoded inner stream == synthetic.iso sha256
        TOOLS,
    )


def _stage_pair(tmp_path: Path, data: bytes) -> Path:
    """Stage a matching game.bin/game.cue pair so sector tests reach the parser."""
    bad_bin = tmp_path / "game.bin"
    bad_cue = tmp_path / "game.cue"
    bad_bin.write_bytes(data)
    bad_cue.write_text(CUE.read_text(), encoding="utf-8")
    return bad_bin


# --- green + basic shape -------------------------------------------------


def test_ps1_bincue_is_green():
    """The full four-check gate passes on the PS1 BIN/CUE fixture."""
    assert _checks() == []


def test_sniff():
    """Sync-pattern detection: MODE2_RAW .bin sniffs true; plain ISO false."""
    assert sniff(FileSource(BIN))
    assert not sniff(FileSource(ISO))
    assert not sniff(FileSource(ROOT / "fixtures" / "toy" / "toy.bin"))
    assert not sniff(FileSource(ROOT / "fixtures" / "chd" / "supertux" / "supertux.chd"))


def test_normalize_ps1_bincue_returns_byteview():
    """normalize_ps1_bincue returns a ByteView, not a FileTree (composition rule)."""
    view = normalize_ps1_bincue(BIN)
    assert isinstance(view, ByteView)
    assert view.format == "ps1-bincue"
    # decoded size matches the inner ISO's 2048-byte-sector layout
    assert view.source.size() == ISO.stat().st_size
    assert view.source.size() % 2048 == 0


def test_decoded_stream_byte_equal_inner_iso():
    """The decoded user-data stream is byte-identical to the inner ISO."""
    view = normalize_ps1_bincue(BIN)
    got = view.source.read_at(0, view.source.size())
    want = ISO.read_bytes()
    assert got == want
    # Spot-check a known file's size and that the structural pipeline
    # reads through the lazy source correctly.
    tree = normalize_iso9660(view.source)
    app = next(e for e in tree.entries if e.path == "BOOT/APP.ELF")
    elf = tree.read(app)
    assert len(elf) == 100_000
    # The strong byte-equal check is the gate's fidelity pass at check 4;
    # this test confirms the lazy read pipeline delivers the same bytes.


def test_composed_iso9660_tree_matches_expected():
    """The normalizer's ByteView re-normalized through iso9660 yields a
    FileTree whose entries match the expected manifest exactly. This is
    the composition-correctness gate — closes the raw -> 2048 -> tree loop
    against the independently-authored manifest."""
    view = normalize_ps1_bincue(BIN)
    tree = normalize_iso9660(view.source)
    expected = json.loads((FIXTURE / "expected.manifest.json").read_text("ascii"))
    got_paths = sorted(e.path for e in tree.entries)
    want_paths = sorted(e["path"] for e in expected["entries"])
    assert got_paths == want_paths
    # All file entries read byte-equal to the 7z-extracted reference/
    for e in tree.entries:
        if e.kind != "file":
            continue
        ref = REFERENCE / e.path
        assert ref.is_file(), f"no reference for {e.path}"
        assert tree.read(e) == ref.read_bytes(), f"fidelity fail on {e.path}"


def test_expected_manifest_validates_against_schema():
    schema = json.loads((ROOT / "schema" / "manifest.schema.json").read_text("utf-8"))
    doc = json.loads((FIXTURE / "expected.manifest.json").read_text("ascii"))
    jsonschema.Draft202012Validator(schema).validate(doc)
    assert doc["format"] == "ps1-bincue"
    assert {e["kind"] for e in doc["entries"]} == {"file", "dir"}
    # source describes the .bin (the on-disk carrier) but the sha256/size
    # match the inner ISO (the ByteView's decoded stream) — the same
    # shape test_chd.py uses.
    assert doc["source"]["name"] == "game.bin"
    assert doc["source"]["sha256"] == sha256_of(ISO)
    assert doc["source"]["size"] == ISO.stat().st_size


# --- structural reds (bounded discipline) --------------------------------


def test_corrupted_sync_is_structural_red(tmp_path):
    """Flipping a sync byte in sector 0 fires a structural red at normalize."""
    data = bytearray(BIN.read_bytes())
    data[0] ^= 0xFF  # first sync byte
    bad_bin = _stage_pair(tmp_path, bytes(data))
    problems = _checks(bad_bin)
    assert problems and any(p.startswith("structural:") for p in problems)


def test_mode1_refused(tmp_path):
    """A sector with mode byte = 1 (Mode 1) is refused structurally."""
    data = bytearray(BIN.read_bytes())
    # header is at offset 12; mode byte is the 4th byte of the header
    # (header[3]) -> absolute offset 15
    data[15] = 0x01  # mode 1 instead of 2
    bad_bin = _stage_pair(tmp_path, bytes(data))
    problems = _checks(bad_bin)
    assert problems and any(p.startswith("structural:") for p in problems)


def test_mode2_form2_refused_structurally(tmp_path):
    """XA submode bit 0x20 marks Form 2 and must never reach the user-data view."""
    data = bytearray(BIN.read_bytes())
    data[18] |= 0x20
    data[22] |= 0x20
    bad_bin = _stage_pair(tmp_path, bytes(data))

    with pytest.raises(ValueError, match="Form 2"):
        normalize_ps1_bincue(bad_bin)
    assert any("Form 2" in problem for problem in _checks(bad_bin))


def test_mismatched_xa_subheader_copies_refused_structurally(tmp_path):
    """The repeated four-byte XA subheaders must agree before Form is trusted."""
    data = bytearray(BIN.read_bytes())
    data[22] ^= 0x01
    bad_bin = _stage_pair(tmp_path, bytes(data))

    with pytest.raises(ValueError, match="subheader copies differ"):
        normalize_ps1_bincue(bad_bin)
    assert any("subheader copies differ" in problem for problem in _checks(bad_bin))


def test_audio_track_refused(tmp_path):
    """A .cue with an AUDIO track is refused (multi-mode discs are a
    different row; ps1-bincue is data-track-only)."""
    bad_cue = tmp_path / "bad.cue"
    # Re-stage the .bin next to it so .cue resolves
    bad_bin = tmp_path / "bad.bin"
    bad_bin.write_bytes(BIN.read_bytes())
    bad_cue.write_text(
        f'FILE "{bad_bin.name}" BINARY\n'
        f'  TRACK 01 AUDIO\n    INDEX 01 00:00:00\n'
    )
    problems = _checks(bad_bin)
    assert problems and any(p.startswith("structural:") for p in problems)


def test_truncated_bin_refused(tmp_path):
    """A .bin whose size is not a multiple of 2352 is refused."""
    data = BIN.read_bytes()[: -100]  # chop 100 bytes (not a sector multiple)
    bad_bin = _stage_pair(tmp_path, data)
    problems = _checks(bad_bin)
    assert problems and any(p.startswith("structural:") for p in problems)


def test_missing_cue_refused(tmp_path):
    """A .bin with no .cue sibling is refused (raw sector inference is
    out of scope; the unit is .bin/.cue pair only)."""
    bad_bin = tmp_path / "no_cue.bin"
    bad_bin.write_bytes(BIN.read_bytes())
    problems = _checks(bad_bin)
    assert problems and any(p.startswith("structural:") for p in problems)


# --- red-team: wrong-offset slicer (the load-bearing mutant) -------------


def test_wrong_offset_slicer_dies_structurally():
    """The spec's load-bearing red-team case: a normalizer mutant that
    reads the wrong byte range from each sector (e.g. [16:2064] instead
    of [24:2072]). The spec anticipated this would die at check 4
    (fidelity vs the pycdlib reference stream), but in practice any
    wrong sector offset corrupts the PVD signature at LBA 16
    (type byte + "CD001" standard identifier), so the mutant is caught
    at check 1 (structural) — an even stronger guarantee.

    We simulate the mutant inline rather than building a parallel
    normalizer module: the ByteView's source is replaced with one
    that returns the wrong offset, and we assert the iso9660 walker
    fails structurally (PVD signature mismatch).
    """
    from substratum.contract import ByteView, FileTree
    from substratum.formats.iso9660 import normalize_iso9660

    class _WrongOffsetSource:
        """Mutant: extract bytes [16:16+2048] from each sector (the XA
        subheader as the first 8 bytes, then 2040 bytes of user data
        starting from the wrong offset). Enumeration is unchanged
        (still 2048 bytes per sector) but the bytes are wrong."""

        def __init__(self, raw):
            self._raw = raw

        def size(self):
            return (self._raw.size() // 2352) * 2048

        def read_at(self, offset, size):
            out = bytearray()
            pos, stop = offset, offset + size
            while pos < stop:
                i = pos // 2048
                within = pos % 2048
                sec = self._raw.read_at(i * 2352, 2352)
                take = min(2048 - within, stop - pos)
                out += sec[16 + within : 16 + within + take]
                pos += take
            return bytes(out)

    raw = FileSource(BIN)
    mutated_view = ByteView(source=_WrongOffsetSource(raw), format="ps1-bincue")
    # The mutated user stream's "PVD" at offset 16*2048 starts with the
    # XA subheader bytes (00 00 08 00 00 00 08 00), not (01 CD001 ...).
    # The iso9660 walker must refuse this structurally.
    try:
        normalize_iso9660(mutated_view.source)
    except ValueError as exc:
        # The PVD check fires at sector 16 with "lacks CD001 standard
        # identifier" or similar; the mutant is caught.
        assert "CD001" in str(exc) or "volume descriptor" in str(exc), (
            f"unexpected ValueError: {exc}"
        )
    else:
        raise AssertionError(
            "mutant not caught — wrong-offset slicer is green-as-red"
        )
