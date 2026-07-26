"""Gate tests for the saturn/dc-raw normalizer (NORMALIZERS.md row
`saturn/dc-raw`).

The saturn-dc-raw normalizer returns a ByteView of the inner 2048-byte
user-data stream (DESIGN.md §1 composition rule: one layer, never
recurse). The test wraps that ByteView through `normalize_iso9660` to get
a FileTree for the four-check gate — the same shape test_chd.py,
test_cso.py, and test_ps1_bincue.py use.

Expected manifest entries are authored by
seedtools/make_saturn_dc_raw_fixture.py from pycdlib's records (second
independent reader, never the parser under test); reference bytes are
7-Zip's extraction of the inner ISO (the byte-fidelity substrate). Tool
pins include 7-Zip 26.02 (structural anchor) and pycdlib 1.16.0 (byte
differential).
"""

import json
from pathlib import Path

import jsonschema

from substratum.contract import ByteView, FileSource, FileTree, sha256_of
from substratum.formats.iso9660 import normalize_iso9660
from substratum.formats.saturn_dc_raw import normalize_saturn_dc_raw, sniff
from substratum.verify import run_checks
from tests.assertions import assert_structural_failure

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "fixtures" / "saturn_dc_raw" / "synthetic"
BIN = FIXTURE / "game_2352.bin"
ISO = FIXTURE / "synthetic.iso"
REFERENCE = FIXTURE / "reference"
# A sibling unit's fixture: proves the Mode 1 sniff rejects Mode 2 raw.
PS1_BIN = ROOT / "fixtures" / "ps1_bincue" / "synthetic" / "game.bin"

# Tool versions — must byte-match what make_saturn_dc_raw_fixture stamped
# into the expected manifest. Re-authoring on a drifted tool changes the
# expected manifest and fails check 2 loudly.
TOOLS = {
    "7z": "7-Zip 26.02 (x64) 2026-06-25",
    "pycdlib": "1.16.0",
    "generator": "make_saturn_dc_raw_fixture v1",
}


def _normalize_saturn_to_tree(source):
    """Wrapper for run_checks: Saturn raw -> ByteView -> iso9660 -> FileTree.

    format is "saturn-dc-raw" so the manifest records the container.
    """
    view = normalize_saturn_dc_raw(source)  # ByteView over the inner ISO
    tree = normalize_iso9660(view.source)  # FileTree over the 2048 stream
    return FileTree(source=tree.source, format="saturn-dc-raw", entries=tree.entries)


def _checks(fixture=BIN):
    return run_checks(
        _normalize_saturn_to_tree,
        fixture,
        FIXTURE / "expected.manifest.json",
        REFERENCE,
        "game_2352.bin",
        sha256_of(ISO),  # decoded inner stream == synthetic.iso sha256
        TOOLS,
    )


# --- green + basic shape -------------------------------------------------


def test_saturn_dc_raw_is_green():
    """The full four-check gate passes on the Saturn/Dreamcast raw fixture."""
    assert _checks() == []


def test_sniff():
    """Mode 1 sync + mode-byte detection: saturn raw sniffs true; plain
    ISO false; ps1 Mode 2 raw false (mode byte differs)."""
    assert sniff(FileSource(BIN))
    assert not sniff(FileSource(ISO))
    assert not sniff(FileSource(PS1_BIN))


def test_normalize_saturn_dc_raw_returns_byteview():
    """normalize_saturn_dc_raw returns a ByteView, not a FileTree (composition rule)."""
    view = normalize_saturn_dc_raw(BIN)
    assert isinstance(view, ByteView)
    assert view.format == "saturn-dc-raw"
    # decoded size matches the inner ISO's 2048-byte-sector layout
    assert view.source.size() == ISO.stat().st_size
    assert view.source.size() % 2048 == 0


def test_decoded_stream_byte_equal_inner_iso():
    """The decoded user-data stream is byte-identical to the inner ISO."""
    view = normalize_saturn_dc_raw(BIN)
    got = view.source.read_at(0, view.source.size())
    want = ISO.read_bytes()
    assert got == want
    # Spot-check a known file's size and that the structural pipeline
    # reads through the lazy source correctly.
    tree = normalize_iso9660(view.source)
    app = next(e for e in tree.entries if e.path == "BOOT/APP.BIN")
    elf = tree.read(app)
    assert len(elf) == 100_000
    # The strong byte-equal check is the gate's fidelity pass at check 4;
    # this test confirms the lazy read pipeline delivers the same bytes.


def test_composed_iso9660_tree_matches_expected():
    """The normalizer's ByteView re-normalized through iso9660 yields a
    FileTree whose entries match the expected manifest exactly. This is
    the composition-correctness gate — closes the raw -> 2048 -> tree loop
    against the independently-authored manifest."""
    view = normalize_saturn_dc_raw(BIN)
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
    assert doc["format"] == "saturn-dc-raw"
    assert {e["kind"] for e in doc["entries"]} == {"file", "dir"}
    # source describes the .bin (the on-disk carrier) but the sha256/size
    # match the inner ISO (the ByteView's decoded stream) — the same
    # shape test_chd.py / test_ps1_bincue.py use.
    assert doc["source"]["name"] == "game_2352.bin"
    assert doc["source"]["sha256"] == sha256_of(ISO)
    assert doc["source"]["size"] == ISO.stat().st_size


# --- structural reds (bounded discipline) --------------------------------


def test_corrupted_sync_is_structural_red(tmp_path):
    """Flipping a sync byte in sector 0 fires a structural red at normalize."""
    bad_bin = tmp_path / "bad.bin"
    data = bytearray(BIN.read_bytes())
    data[0] ^= 0xFF  # first sync byte
    bad_bin.write_bytes(bytes(data))
    problems = _checks(bad_bin)
    assert_structural_failure(problems, "bad sync pattern")


def test_mode2_refused(tmp_path):
    """A sector with mode byte = 2 (Mode 2, ps1's domain) is refused structurally."""
    bad_bin = tmp_path / "bad.bin"
    data = bytearray(BIN.read_bytes())
    # mode byte is the 4th byte of the header (header[3]) -> absolute offset 15
    data[15] = 0x02  # mode 2 instead of 1
    bad_bin.write_bytes(bytes(data))
    problems = _checks(bad_bin)
    assert_structural_failure(problems, "mode 2 != 1")


def test_truncated_refused(tmp_path):
    """A raw image whose size is not a multiple of 2352 is refused (not a raw disc)."""
    bad_bin = tmp_path / "bad.bin"
    data = BIN.read_bytes()[: -100]  # chop 100 bytes (not a sector multiple)
    bad_bin.write_bytes(data)
    problems = _checks(bad_bin)
    assert_structural_failure(problems, "not a multiple of 2352")


def test_not_a_raw_disc_refused(tmp_path):
    """A 2048-byte ISO sniffs False here; passed directly it is refused
    because its size is not a multiple of 2352 (iso9660's domain)."""
    # Copy the plain inner ISO into tmp to hand to the normalizer directly.
    bad = tmp_path / "not_raw.iso"
    bad.write_bytes(ISO.read_bytes())
    problems = _checks(bad)
    assert_structural_failure(problems, "not a multiple of 2352")


# --- red-team: wrong-offset slicer (the load-bearing mutant) -------------


def test_wrong_offset_slicer_dies_structurally():
    """The spec's load-bearing red-team case: a normalizer mutant that
    reads the wrong byte range from each sector (e.g. [12:2060] instead
    of [16:2064]). The spec anticipated this would die at check 4
    (fidelity vs the pycdlib reference stream), but in practice any
    wrong sector offset corrupts the PVD signature at LBA 16
    (type byte + "CD001" standard identifier), so the mutant is caught
    at check 1 (structural) — an even stronger guarantee.

    We simulate the mutant inline rather than building a parallel
    normalizer module: the ByteView's source is replaced with one
    that returns the wrong offset, and we assert the iso9660 walker
    fails structurally (PVD signature mismatch).
    """
    class _WrongOffsetSource:
        """Mutant: extract bytes [12:12+2048] from each sector (4 header
        bytes as the first 4 bytes, then 2044 user bytes starting from
        the wrong offset). Enumeration is unchanged (still 2048 bytes per
        sector) but the bytes are wrong."""

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
                out += sec[12 + within : 12 + within + take]
                pos += take
            return bytes(out)

    raw = FileSource(BIN)
    mutated_view = ByteView(source=_WrongOffsetSource(raw), format="saturn-dc-raw")
    # The mutated user stream's "PVD" at offset 16*2048 is built from the
    # sector header bytes (BCD address), not (01 CD001 ...). The iso9660
    # walker must refuse this structurally.
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
