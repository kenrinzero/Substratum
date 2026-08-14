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
differential). The GPL-3.0 Save Game Copier 3.7.1 fixture adds a
third-party-authored ISO and ECM/UNECM-verified real EDC/ECC sectors.
"""

import json
from pathlib import Path

import jsonschema

from substratum.contract import ByteView, FileSource, FileTree, sha256_of
from substratum.formats import saturn_dc_raw as raw_module
from substratum.formats.iso9660 import normalize_iso9660
from substratum.formats.saturn_dc_raw import normalize_saturn_dc_raw, sniff
from substratum.verify import run_checks
from tests.assertions import assert_structural_failure

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "fixtures" / "saturn_dc_raw" / "synthetic"
BIN = FIXTURE / "game_2352.bin"
ISO = FIXTURE / "synthetic.iso"
REFERENCE = FIXTURE / "reference"
HOMEBREW = ROOT / "fixtures" / "saturn_dc_raw" / "save-game-copier-3.7.1"
HOMEBREW_BIN = HOMEBREW / "game_2352.bin"
HOMEBREW_ISO = HOMEBREW / "game.iso"
HOMEBREW_REFERENCE = HOMEBREW / "reference"
# A sibling unit's fixture: proves the Mode 1 sniff rejects Mode 2 raw.
PS1_BIN = ROOT / "fixtures" / "ps1_bincue" / "synthetic" / "game.bin"

# Tool versions — must byte-match what make_saturn_dc_raw_fixture stamped
# into the expected manifest. Re-authoring on a drifted tool changes the
# expected manifest and fails check 2 loudly.
TOOLS = {
    "7z": "7-Zip 26.02 (x64) 2026-06-25",
    "ecm": "ECM/UNECM v1.3.0 (v1.3.1 release asset)",
    "pycdlib": "1.16.0",
    "generator": "make_saturn_dc_raw_fixture v2",
}
HOMEBREW_TOOLS = {
    "7z": "7-Zip 26.02 (x64) 2026-06-25",
    "ecm": "ECM/UNECM v1.3.0 (v1.3.1 release asset)",
    "generator": "stage_saturn_homebrew_anchor v1",
    "pycdlib": "1.16.0",
}


def _bcd(value: int) -> int:
    return ((value // 10) << 4) | (value % 10)


def _set_msf_sequence(data: bytearray, origin_frames: int) -> None:
    for sector, base in enumerate(range(0, len(data), raw_module.SECTOR)):
        absolute = origin_frames + sector
        minute, remainder = divmod(absolute, 60 * 75)
        second, frame = divmod(remainder, 75)
        data[base + raw_module.MSF_OFFSET : base + raw_module.MSF_OFFSET + 3] = (
            bytes((_bcd(minute), _bcd(second), _bcd(frame)))
        )


def _normalize_saturn_to_tree(source):
    """Wrapper for run_checks: Saturn raw -> ByteView -> iso9660 -> FileTree.

    format is "saturn-dc-raw" so the manifest records the container.
    """
    view = normalize_saturn_dc_raw(source)  # ByteView over the inner ISO
    tree = normalize_iso9660(view.source)  # FileTree over the 2048 stream
    return FileTree(source=tree.source, format="saturn-dc-raw", entries=tree.entries)


def _checks(
    fixture=BIN,
    *,
    expected=FIXTURE / "expected.manifest.json",
    reference=REFERENCE,
    source_name="game_2352.bin",
    source_sha256=None,
    tools=TOOLS,
):
    return run_checks(
        _normalize_saturn_to_tree,
        fixture,
        expected,
        reference,
        source_name,
        source_sha256 or sha256_of(ISO),
        tools,
    )


# --- green + basic shape -------------------------------------------------


def test_saturn_dc_raw_is_green():
    """The full four-check gate passes on the Saturn/Dreamcast raw fixture."""
    assert _checks() == []


def test_save_game_copier_homebrew_is_green():
    """The licensed third-party anchor passes the complete four-check gate."""
    assert _checks(
        HOMEBREW_BIN,
        expected=HOMEBREW / "expected.manifest.json",
        reference=HOMEBREW_REFERENCE,
        source_sha256=sha256_of(HOMEBREW_ISO),
        tools=HOMEBREW_TOOLS,
    ) == []


def test_save_game_copier_raw_proof_is_pinned_and_byte_exact():
    """The ECM-verified raw artifact decodes exactly to the upstream ISO."""
    assert HOMEBREW_BIN.stat().st_size == 969_024
    assert sha256_of(HOMEBREW_BIN) == (
        "8392e7d6f6e9606ba91b502191dc0ee9972fbd729e41697c26a098e35f7a239e"
    )
    assert HOMEBREW_ISO.stat().st_size == 843_776
    assert sha256_of(HOMEBREW_ISO) == (
        "e1832e07d4e8273f0db45bcd61fbacffac21468554f87c328619a66a5f4871a8"
    )
    assert sha256_of(HOMEBREW / "LICENSE") == (
        "3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986"
    )
    view = normalize_saturn_dc_raw(HOMEBREW_BIN)
    assert view.source.read_at(0, view.source.size()) == HOMEBREW_ISO.read_bytes()

    first = HOMEBREW_BIN.read_bytes()[: raw_module.SECTOR]
    assert first[:16] == bytes.fromhex("00ffffffffffffffffffff0000020001")
    assert first[2068:2076] == b"\x00" * 8
    assert any(first[2076:])  # independently reconstructed P/Q ECC is present


def test_synthetic_carrier_has_real_error_correction():
    """The small layout fixture also carries ECM-accepted EDC and P/Q ECC."""
    assert sha256_of(BIN) == (
        "d046ac95bfef5fc90922413f804f24975ece791d3167b8504f055b361a18ef76"
    )
    first = BIN.read_bytes()[: raw_module.SECTOR]
    assert first[2068:2076] == b"\x00" * 8
    assert any(first[2076:])


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


def test_eager_validation_batches_raw_reads(monkeypatch):
    """A full structural scan reads bounded batches, not one file-open per sector."""

    class CountingFileSource(FileSource):
        calls: list[tuple[int, int]] = []

        def read_at(self, offset: int, size: int) -> bytes:
            self.calls.append((offset, size))
            return super().read_at(offset, size)

    monkeypatch.setattr(raw_module, "FileSource", CountingFileSource)
    view = raw_module.normalize_saturn_dc_raw(BIN)
    sector_count = view.source.size() // raw_module.USER_LEN
    expected_batches = (
        sector_count + raw_module._RAW_BATCH_SECTORS - 1
    ) // raw_module._RAW_BATCH_SECTORS
    assert len(CountingFileSource.calls) == expected_batches
    assert max(size for _offset, size in CountingFileSource.calls) <= (
        raw_module._RAW_BATCH_SECTORS * raw_module.SECTOR
    )


def test_cooked_reads_batch_raw_sectors():
    """The cooked view preserves bytes while bounding underlying read calls."""

    class CountingSource:
        def __init__(self, path: Path):
            self.inner = FileSource(path)
            self.calls: list[tuple[int, int]] = []

        def size(self) -> int:
            return self.inner.size()

        def read_at(self, offset: int, size: int) -> bytes:
            self.calls.append((offset, size))
            return self.inner.read_at(offset, size)

    raw = CountingSource(BIN)
    sector_count = raw.size() // raw_module.SECTOR
    first = raw.inner.read_at(0, raw_module.SECTOR)
    origin_msf = raw_module._decode_msf(first, 0)
    source = raw_module._Mode1RemapSource(raw, sector_count, origin_msf)
    assert source.read_at(0, source.size()) == ISO.read_bytes()
    expected_batches = (
        sector_count + raw_module._RAW_BATCH_SECTORS - 1
    ) // raw_module._RAW_BATCH_SECTORS
    assert len(raw.calls) == expected_batches
    assert max(size for _offset, size in raw.calls) <= (
        raw_module._RAW_BATCH_SECTORS * raw_module.SECTOR
    )


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


def test_invalid_bcd_msf_refused(tmp_path):
    bad_bin = tmp_path / "bad.bin"
    data = bytearray(BIN.read_bytes())
    data[raw_module.MSF_OFFSET] = 0xFA
    bad_bin.write_bytes(data)
    assert_structural_failure(_checks(bad_bin), "invalid BCD minute 0xfa")


def test_out_of_range_msf_refused(tmp_path):
    bad_bin = tmp_path / "bad.bin"
    data = bytearray(BIN.read_bytes())
    data[raw_module.MSF_OFFSET + 1] = 0x60
    bad_bin.write_bytes(data)
    assert_structural_failure(_checks(bad_bin), "MSF second 60 >= 60")


def test_out_of_range_msf_frame_refused(tmp_path):
    bad_bin = tmp_path / "bad.bin"
    data = bytearray(BIN.read_bytes())
    data[raw_module.MSF_OFFSET + 2] = 0x75
    bad_bin.write_bytes(data)
    assert_structural_failure(_checks(bad_bin), "MSF frame 75 >= 75")


def test_non_contiguous_msf_refused(tmp_path):
    bad_bin = tmp_path / "bad.bin"
    data = bytearray(BIN.read_bytes())
    second = raw_module.SECTOR
    data[second + raw_module.MSF_OFFSET : second + raw_module.MSF_OFFSET + 3] = (
        data[raw_module.MSF_OFFSET : raw_module.MSF_OFFSET + 3]
    )
    bad_bin.write_bytes(data)
    assert_structural_failure(
        _checks(bad_bin),
        "sector 1 MSF 00:02:00 is not contiguous (expected 00:02:01)",
    )


def test_arbitrary_valid_starting_msf_is_accepted(tmp_path):
    shifted_bin = tmp_path / "shifted.bin"
    data = bytearray(BIN.read_bytes())
    _set_msf_sequence(data, (10 * 60 + 2) * 75)
    shifted_bin.write_bytes(data)

    view = normalize_saturn_dc_raw(shifted_bin)
    assert view.source.read_at(0, view.source.size()) == ISO.read_bytes()


def test_corruption_at_batch_boundary_reports_exact_sector(tmp_path):
    """Batched validation retains absolute sector diagnostics."""
    sector = raw_module._RAW_BATCH_SECTORS
    original = BIN.read_bytes()
    original_sectors = len(original) // raw_module.SECTOR
    repeats = (sector + original_sectors) // original_sectors
    data = bytearray(original * repeats)
    _set_msf_sequence(data, 2 * 75)
    data[sector * raw_module.SECTOR] ^= 0xFF
    bad_bin = tmp_path / "bad.bin"
    bad_bin.write_bytes(data)
    problems = _checks(bad_bin)
    assert_structural_failure(problems, f"sector {sector} bad sync pattern")


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


# ---------------------------------------------------------------------------
# GD-ROM high-density minute continuation (BACKLOG "saturn-dc-raw rejects the
# Dreamcast GD-ROM high-density area", 2026-08-14)
#
# Real-disc finding (staged Sonic Adventure 2 track03.bin, 504,150 sectors):
# addresses run contiguously from absolute MSF 10:02:00 (LBA 45,000 + the
# 150-frame pregap); BCD holds to the last representable 99:59:74, then
# minute 100 encodes as 0xA0 — the BCD pattern continued with hexadecimal
# tens digits (0xA=10, 0xB=11, 0xC=12 ... up to 0xC2 = minute 122 at the
# track end). Seconds/frames stay strict BCD; sync and mode hold throughout.
# Genuine Saturn media tops out at 99:59:74, so relaxing the minute's high
# nibble cannot fire there, and per-sector MSF contiguity stays the gate.
# ---------------------------------------------------------------------------


def test_gdrom_minute_100_continuation_accepted(tmp_path):
    """Addresses running through 99:59:74 -> 0xA0:00:00 normalize cleanly
    and the user stream is untouched by the header encoding."""
    data = bytearray(BIN.read_bytes())
    n_sectors = len(data) // raw_module.SECTOR
    origin = 449_999  # 99:59:74; the next sector is 100:00:00 (0xA0:00:00)
    _set_msf_sequence(data, origin)
    assert data[raw_module.SECTOR + raw_module.MSF_OFFSET] == 0xA0
    assert data[raw_module.SECTOR + raw_module.MSF_OFFSET + 1] == 0x00
    gd_bin = tmp_path / "gd.bin"
    gd_bin.write_bytes(data)

    original = normalize_saturn_dc_raw(BIN)
    continued = normalize_saturn_dc_raw(gd_bin)
    # The user stream is byte-identical: only the header encoding changed.
    span = min(4, n_sectors) * raw_module.USER_LEN
    assert continued.source.read_at(0, span) == original.source.read_at(0, span)


def test_high_density_minute_not_at_expected_position_refused(tmp_path):
    """The relaxed minute never blanket-accepts: a hex-continuation minute
    planted where contiguity expects a different frame is still red."""
    data = bytearray(BIN.read_bytes())
    _set_msf_sequence(data, 0)
    data[2 * raw_module.SECTOR + raw_module.MSF_OFFSET] = 0xC2  # minute 122
    bad_bin = tmp_path / "bad.bin"
    bad_bin.write_bytes(data)
    assert_structural_failure(_checks(bad_bin), "not contiguous")


def test_high_density_minute_with_invalid_low_nibble_refused(tmp_path):
    """0xFA-style minutes (invalid low nibble) stay red — the existing
    structural-red class is unchanged by the relaxation."""
    data = bytearray(BIN.read_bytes())
    _set_msf_sequence(data, 449_999)
    data[0]  # no-op; keep sector 1's minute but corrupt its low nibble
    data[raw_module.SECTOR + raw_module.MSF_OFFSET] = 0xFA
    bad_bin = tmp_path / "bad.bin"
    bad_bin.write_bytes(data)
    assert_structural_failure(_checks(bad_bin), "invalid BCD minute 0xfa")
