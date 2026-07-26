"""Gate tests for the ps1-bincue normalizer (NORMALIZERS.md row `ps1-bincue`).

The ps1-bincue normalizer returns a ByteView whose ordinary reads expose the
fixed 2048-byte cooked stream used for ISO9660 composition, while its concrete
Mode2XASource also exposes complete 2048/2324-byte sector payloads. The test
wraps the cooked view through `normalize_iso9660` for the four-check gate and
proves the sector API independently against raw offsets.

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
from substratum.formats import ps1_bincue as ps1_module
from substratum.formats.ps1_bincue import (
    Mode2XASource,
    XASector,
    normalize_ps1_bincue,
    sniff,
)
from substratum.formats.iso9660 import normalize_iso9660
from substratum.verify import run_checks
from tests.assertions import assert_structural_failure

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "fixtures" / "ps1_bincue" / "synthetic"
BIN = FIXTURE / "game.bin"
CUE = FIXTURE / "game.cue"
ISO = FIXTURE / "synthetic.iso"
REFERENCE = FIXTURE / "reference"
RETAIL_FIXTURE = ROOT / "fixtures" / "ps1_bincue" / "kings-field"
RETAIL_BIN = (
    ROOT
    / "fixtures"
    / "_local"
    / "King's Field (Japan)"
    / "King's Field (Japan)"
    / "King's Field (Japan).bin"
)
RETAIL_REFERENCE = RETAIL_FIXTURE / "reference"
RETAIL_CUE = RETAIL_BIN.with_suffix(".cue")
RETAIL_BIN_SHA256 = (
    "ae74beba377d686bfaa292ea40df8ade4454ec3139c2b5152364e02aac90b3d9"
)
RETAIL_CUE_SHA256 = (
    "955b14c0a14254dd2866c0ee0ab15e02906f8020120295f6a681a62aeeb90ab7"
)
FORM2_RETAIL_BIN = (
    ROOT
    / "fixtures"
    / "_local"
    / "bin-chd-playstation"
    / "BursTrick - Wake Boarding!! (USA).bin"
)
FORM2_RETAIL_CUE = FORM2_RETAIL_BIN.with_suffix(".cue")
FORM2_RETAIL_FIXTURE = ROOT / "fixtures" / "ps1_bincue" / "burstrick"
FORM2_RETAIL_REFERENCE = FORM2_RETAIL_FIXTURE / "reference"
FORM2_RETAIL_BIN_SHA256 = (
    "21f02044173b2298199fb3d0adf1673520a3b044fd61e7f0b7b1f30a0b90ce40"
)
FORM2_RETAIL_CUE_SHA256 = (
    "c37e5918d9eaaf7ceedb456210d60e98c3d515bf23b2dc909c83bf7b82b9a445"
)

# Tool versions — must byte-match what make_ps1_bincue_fixture stamped
# into the expected manifest. Re-authoring on a drifted tool changes the
# expected manifest and fails check 2 loudly.
TOOLS = {
    "7z": "7-Zip 26.02 (x64) 2026-06-25",
    "chdman": "0.288 (mame0288)",
    "pycdlib": "1.16.0",
    "generator": "make_ps1_bincue_fixture v1",
}
RETAIL_TOOLS = {
    "7z": "7-Zip 26.02 (x64) 2026-06-25",
    "chdman": "0.288 (mame0288)",
    "pycdlib": "1.16.0",
    "generator": "stage_ps1_retail_anchor v1",
}
FORM2_RETAIL_TOOLS = {
    "7z": "7-Zip 26.02 (x64) 2026-06-25",
    "chdman": "0.288 (mame0288)",
    "pycdlib": "1.16.0",
    "generator": "stage_ps1_form2_retail_anchor v1",
}

skip_if_no_retail_anchor = pytest.mark.skipif(
    not RETAIL_BIN.exists() or not RETAIL_REFERENCE.exists(),
    reason="King's Field retail BIN/CUE or gitignored reference extraction absent",
)
skip_if_no_form2_retail = pytest.mark.skipif(
    not FORM2_RETAIL_BIN.exists() or not FORM2_RETAIL_CUE.exists(),
    reason="BursTrick mixed-XA retail BIN/CUE absent",
)
skip_if_no_form2_retail_anchor = pytest.mark.skipif(
    not FORM2_RETAIL_BIN.exists() or not FORM2_RETAIL_REFERENCE.exists(),
    reason="BursTrick retail BIN/CUE or gitignored reference extraction absent",
)


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


def _mark_form2(data: bytearray, sector: int, payload: bytes) -> None:
    """Turn one raw sector into Form 2 with matching XA copies."""
    assert len(payload) == 2324
    base = sector * 2352
    data[base + 18] |= 0x20
    data[base + 22] |= 0x20
    data[base + 24 : base + 2348] = payload


def _bcd(value: int) -> int:
    return ((value // 10) << 4) | (value % 10)


def _set_msf_sequence(data: bytearray, origin_frames: int) -> None:
    for sector, base in enumerate(range(0, len(data), ps1_module.SECTOR)):
        absolute = origin_frames + sector
        minute, remainder = divmod(absolute, 60 * 75)
        second, frame = divmod(remainder, 75)
        data[base + ps1_module.MSF_OFFSET : base + ps1_module.MSF_OFFSET + 3] = (
            bytes((_bcd(minute), _bcd(second), _bcd(frame)))
        )


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
    assert isinstance(view.source, Mode2XASource)
    # decoded size matches the inner ISO's 2048-byte-sector layout
    assert view.source.size() == ISO.stat().st_size
    assert view.source.size() % 2048 == 0
    assert view.source.sector_count() == ISO.stat().st_size // 2048


def test_eager_validation_batches_raw_reads(monkeypatch):
    """A full structural scan reads bounded batches, not one file-open per sector."""

    class CountingFileSource(FileSource):
        calls: list[tuple[int, int]] = []

        def read_at(self, offset: int, size: int) -> bytes:
            self.calls.append((offset, size))
            return super().read_at(offset, size)

    monkeypatch.setattr(ps1_module, "FileSource", CountingFileSource)
    view = ps1_module.normalize_ps1_bincue(BIN)
    expected_batches = (
        view.source.sector_count() + ps1_module._RAW_BATCH_SECTORS - 1
    ) // ps1_module._RAW_BATCH_SECTORS
    assert len(CountingFileSource.calls) == expected_batches
    assert max(size for _offset, size in CountingFileSource.calls) <= (
        ps1_module._RAW_BATCH_SECTORS * ps1_module.SECTOR
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
    sector_count = raw.size() // ps1_module.SECTOR
    first = raw.inner.read_at(0, ps1_module.SECTOR)
    origin_msf = ps1_module._decode_sector_msf(first, 0)
    source = Mode2XASource(
        raw,
        0,
        sector_count,
        bytes([1]) * sector_count,
        origin_msf,
    )
    assert source.read_at(0, source.size()) == ISO.read_bytes()
    expected_batches = (
        sector_count + ps1_module._RAW_BATCH_SECTORS - 1
    ) // ps1_module._RAW_BATCH_SECTORS
    assert len(raw.calls) == expected_batches
    assert max(size for _offset, size in raw.calls) <= (
        ps1_module._RAW_BATCH_SECTORS * ps1_module.SECTOR
    )


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
    assert_structural_failure(problems, "bad sync pattern")


def test_mode1_refused(tmp_path):
    """A sector with mode byte = 1 (Mode 1) is refused structurally."""
    data = bytearray(BIN.read_bytes())
    # header is at offset 12; mode byte is the 4th byte of the header
    # (header[3]) -> absolute offset 15
    data[15] = 0x01  # mode 1 instead of 2
    bad_bin = _stage_pair(tmp_path, bytes(data))
    problems = _checks(bad_bin)
    assert_structural_failure(problems, "mode 1 != 2")


def test_invalid_bcd_msf_refused(tmp_path):
    data = bytearray(BIN.read_bytes())
    data[ps1_module.MSF_OFFSET] = 0xFA
    bad_bin = _stage_pair(tmp_path, bytes(data))
    assert_structural_failure(_checks(bad_bin), "invalid BCD minute 0xfa")


def test_out_of_range_msf_refused(tmp_path):
    data = bytearray(BIN.read_bytes())
    data[ps1_module.MSF_OFFSET + 1] = 0x60
    bad_bin = _stage_pair(tmp_path, bytes(data))
    assert_structural_failure(_checks(bad_bin), "MSF second 60 >= 60")


def test_out_of_range_msf_frame_refused(tmp_path):
    data = bytearray(BIN.read_bytes())
    data[ps1_module.MSF_OFFSET + 2] = 0x75
    bad_bin = _stage_pair(tmp_path, bytes(data))
    assert_structural_failure(_checks(bad_bin), "MSF frame 75 >= 75")


def test_non_contiguous_msf_refused(tmp_path):
    data = bytearray(BIN.read_bytes())
    second = ps1_module.SECTOR
    data[second + ps1_module.MSF_OFFSET : second + ps1_module.MSF_OFFSET + 3] = (
        data[ps1_module.MSF_OFFSET : ps1_module.MSF_OFFSET + 3]
    )
    bad_bin = _stage_pair(tmp_path, bytes(data))
    assert_structural_failure(
        _checks(bad_bin),
        "sector 1 MSF 00:00:00 is not contiguous (expected 00:00:01)",
    )


def test_arbitrary_valid_starting_msf_is_accepted(tmp_path):
    data = bytearray(BIN.read_bytes())
    _set_msf_sequence(data, (10 * 60 + 2) * 75)
    shifted_bin = _stage_pair(tmp_path, bytes(data))

    view = normalize_ps1_bincue(shifted_bin)
    assert view.source.read_at(0, view.source.size()) == ISO.read_bytes()


def test_lazy_read_revalidates_msf_after_normalization(tmp_path):
    data = bytearray(BIN.read_bytes())
    staged_bin = _stage_pair(tmp_path, bytes(data))
    source = normalize_ps1_bincue(staged_bin).source

    second = ps1_module.SECTOR
    data[second + ps1_module.MSF_OFFSET : second + ps1_module.MSF_OFFSET + 3] = (
        data[ps1_module.MSF_OFFSET : ps1_module.MSF_OFFSET + 3]
    )
    staged_bin.write_bytes(data)

    with pytest.raises(
        ValueError,
        match=(
            "sector 1 MSF 00:00:00 is not contiguous "
            r"\(expected 00:00:01\)"
        ),
    ):
        source.read_sector(1)


def test_corruption_at_batch_boundary_reports_exact_sector(tmp_path):
    """Batched validation retains absolute sector diagnostics."""
    sector = ps1_module._RAW_BATCH_SECTORS
    original = BIN.read_bytes()
    original_sectors = len(original) // ps1_module.SECTOR
    repeats = (sector + original_sectors) // original_sectors
    data = bytearray(original * repeats)
    _set_msf_sequence(data, 0)
    data[sector * ps1_module.SECTOR] ^= 0xFF
    bad_bin = _stage_pair(tmp_path, bytes(data))
    problems = _checks(bad_bin)
    assert_structural_failure(problems, f"sector {sector} bad sync pattern")


def test_zero_filled_form2_system_area_is_accepted(tmp_path):
    """Zero-filled Form-2 sectors before the PVD preserve the 2048-byte view."""
    data = bytearray(BIN.read_bytes())
    for sector in range(12, 16):
        _mark_form2(data, sector, b"\x00" * 2324)
    mixed_bin = _stage_pair(tmp_path, bytes(data))

    view = normalize_ps1_bincue(mixed_bin)
    assert view.source.read_at(0, view.source.size()) == ISO.read_bytes()
    assert tuple(view.source.form2_sectors()) == (12, 13, 14, 15)
    assert _checks(mixed_bin) == []


def test_nonzero_form2_system_area_payload_is_preserved(tmp_path):
    """General Form 2 preserves all 2324 payload bytes without moving LBAs."""
    data = bytearray(BIN.read_bytes())
    payload = bytes(i % 251 for i in range(2324))
    _mark_form2(data, 12, payload)
    mixed_bin = _stage_pair(tmp_path, bytes(data))

    view = normalize_ps1_bincue(mixed_bin)
    assert isinstance(view.source, Mode2XASource)
    sector = view.source.read_sector(12)
    assert isinstance(sector, XASector)
    assert sector.index == 12
    assert sector.form == 2
    assert sector.payload == payload
    assert view.source.read_at(12 * 2048, 2048) == payload[:2048]
    # Sector 12 is in ISO9660's ignored system area. Changing it must not
    # shift the PVD at sector 16 or corrupt the filesystem walk.
    assert len(normalize_iso9660(view.source).entries) == len(
        normalize_iso9660(FileSource(ISO)).entries
    )


def test_form2_at_pvd_or_later_keeps_cooked_iso_view_and_full_payload(tmp_path):
    """The 2048 cooked view stays LBA-stable while sector API keeps the tail."""
    data = bytearray(BIN.read_bytes())
    base = 16 * 2352
    original_user = bytes(data[base + 24 : base + 24 + 2048])
    tail = bytes((255 - i) % 256 for i in range(276))
    payload = original_user + tail
    _mark_form2(data, 16, payload)
    mixed_bin = _stage_pair(tmp_path, bytes(data))

    view = normalize_ps1_bincue(mixed_bin)
    assert view.source.sector_form(16) == 2
    assert tuple(view.source.form2_sectors()) == (16,)
    sector = view.source.read_sector(16)
    assert sector.payload == payload
    assert sector.payload[2048:] == tail
    assert view.source.read_at(16 * 2048, 2048) == original_user
    next_user = bytes(data[17 * 2352 + 24 : 17 * 2352 + 24 + 2048])
    assert view.source.read_at(17 * 2048 - 8, 16) == (
        original_user[-8:] + next_user[:8]
    )
    # The existing four-check ISO gate remains byte-identical because the
    # cooked view is still exactly 2048 bytes per logical sector.
    assert _checks(mixed_bin) == []


def test_form1_sector_api_and_bounds():
    """The sector API is uniform across forms and rejects invalid indices."""
    view = normalize_ps1_bincue(BIN)
    source = view.source
    sector = source.read_sector(16)
    raw = BIN.read_bytes()[16 * 2352 : 17 * 2352]
    assert sector == XASector(
        index=16,
        form=1,
        file_number=0,
        channel_number=0,
        submode=0x08,
        coding_info=0,
        payload=raw[24:2072],
    )
    with pytest.raises(ValueError, match="sector index -1 out of bounds"):
        source.read_sector(-1)
    with pytest.raises(ValueError, match="sector index .* out of bounds"):
        source.read_sector(source.sector_count())


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
    assert_structural_failure(problems, "track mode 'AUDIO' out of scope")


def test_truncated_bin_refused(tmp_path):
    """A .bin whose size is not a multiple of 2352 is refused."""
    data = BIN.read_bytes()[: -100]  # chop 100 bytes (not a sector multiple)
    bad_bin = _stage_pair(tmp_path, data)
    problems = _checks(bad_bin)
    assert_structural_failure(problems, "not a multiple of 2352")


def test_missing_cue_refused(tmp_path):
    """A .bin with no .cue sibling is refused (raw sector inference is
    out of scope; the unit is .bin/.cue pair only)."""
    bad_bin = tmp_path / "no_cue.bin"
    bad_bin.write_bytes(BIN.read_bytes())
    problems = _checks(bad_bin)
    assert_structural_failure(problems, "no .cue sibling")


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


# --- gitignored retail-anchor proof ---------------------------------------


def test_kings_field_metadata_manifest_is_valid():
    """Committed metadata remains useful when the retail drop is absent."""
    schema = json.loads((ROOT / "schema" / "manifest.schema.json").read_text("utf-8"))
    doc = json.loads(
        (RETAIL_FIXTURE / "expected.manifest.json").read_text("ascii")
    )
    jsonschema.Draft202012Validator(schema).validate(doc)
    assert doc["format"] == "ps1-bincue"
    assert doc["source"] == {
        "name": "King's Field (Japan).bin",
        "sha256": "b2604dc885a00c18caa2212b30fdccab9459c2ffacb7d3852671bbd5addedc9b",
        "size": 26_451_968,
    }
    assert doc["tool_versions"] == RETAIL_TOOLS
    assert len(doc["entries"]) == 470
    assert {"LICENSEJ.DAT", "PSX.EXE"} <= {
        entry["path"] for entry in doc["entries"]
    }


@skip_if_no_retail_anchor
def test_kings_field_retail_anchor_is_green():
    """The Redump-matching retail anchor passes the complete four-check gate."""
    expected = json.loads(
        (RETAIL_FIXTURE / "expected.manifest.json").read_text("ascii")
    )

    def normalize_retail(source):
        view = normalize_ps1_bincue(source)
        tree = normalize_iso9660(view.source)
        return FileTree(
            source=tree.source, format="ps1-bincue", entries=tree.entries
        )

    assert run_checks(
        normalize_retail,
        RETAIL_BIN,
        RETAIL_FIXTURE / "expected.manifest.json",
        RETAIL_REFERENCE,
        RETAIL_BIN.name,
        expected["source"]["sha256"],
        RETAIL_TOOLS,
    ) == []


@skip_if_no_retail_anchor
def test_kings_field_identity_and_form2_scope():
    """Anchor metadata names the Japanese retail disc and its bounded exception."""
    assert sha256_of(RETAIL_BIN) == RETAIL_BIN_SHA256
    assert sha256_of(RETAIL_CUE) == RETAIL_CUE_SHA256
    view = normalize_ps1_bincue(RETAIL_BIN)
    tree = normalize_iso9660(view.source)
    paths = {entry.path for entry in tree.entries}
    assert {"LICENSEJ.DAT", "PSX.EXE"} <= paths
    assert len(tree.entries) == 470


def test_burstrick_metadata_manifest_is_valid():
    """Committed mixed-XA metadata remains useful without the retail bytes."""
    schema = json.loads((ROOT / "schema" / "manifest.schema.json").read_text("utf-8"))
    doc = json.loads(
        (FORM2_RETAIL_FIXTURE / "expected.manifest.json").read_text("ascii")
    )
    jsonschema.Draft202012Validator(schema).validate(doc)
    assert doc["format"] == "ps1-bincue"
    assert doc["source"] == {
        "name": "BursTrick - Wake Boarding!! (USA).bin",
        "sha256": "293af0bc2523225c31940b6af3b62109c1063213a2fd891b3fd927e2281db7bd",
        "size": 322_039_808,
    }
    assert doc["tool_versions"] == FORM2_RETAIL_TOOLS
    assert len(doc["entries"]) == 9
    assert {
        "SLUS_013.17",
        "SYSTEM.CNF",
        "XA/SOTOMAWA.XA",
        "XA/STAGEBGM.XA",
    } <= {entry["path"] for entry in doc["entries"]}


@skip_if_no_form2_retail_anchor
def test_burstrick_retail_anchor_is_green():
    """The Archive-matched mixed-XA anchor passes the complete four-check gate."""
    expected = json.loads(
        (FORM2_RETAIL_FIXTURE / "expected.manifest.json").read_text("ascii")
    )
    assert run_checks(
        _normalize_ps1_to_tree,
        FORM2_RETAIL_BIN,
        FORM2_RETAIL_FIXTURE / "expected.manifest.json",
        FORM2_RETAIL_REFERENCE,
        FORM2_RETAIL_BIN.name,
        expected["source"]["sha256"],
        FORM2_RETAIL_TOOLS,
    ) == []


@skip_if_no_form2_retail
def test_burstrick_mixed_xa_exposes_full_form2_payloads():
    """The genuine PS1 mixed-XA anchor exercises general Form-2 support."""
    assert sha256_of(FORM2_RETAIL_BIN) == FORM2_RETAIL_BIN_SHA256
    assert sha256_of(FORM2_RETAIL_CUE) == FORM2_RETAIL_CUE_SHA256

    view = normalize_ps1_bincue(FORM2_RETAIL_BIN)
    source = view.source
    assert isinstance(source, Mode2XASource)
    assert source.sector_count() == 157_246
    form2 = tuple(source.form2_sectors())
    assert len(form2) == 60_666
    assert form2[:5] == (12, 13, 14, 15, 5555)
    assert form2[-5:] == (132_832, 132_837, 132_838, 132_839, 132_840)

    sector = source.read_sector(24_829)
    assert sector.form == 2
    assert (
        sector.file_number,
        sector.channel_number,
        sector.submode,
        sector.coding_info,
    ) == (1, 0, 0x64, 1)
    raw = FileSource(FORM2_RETAIL_BIN).read_at(24_829 * 2352, 2352)
    assert sector.payload == raw[24:2348]
    assert len(sector.payload) == 2324

    tree = normalize_iso9660(source)
    paths = {entry.path for entry in tree.entries}
    assert {"SYSTEM.CNF", "XA/SOTOMAWA.XA", "XA/STAGEBGM.XA"} <= paths
    system = next(entry for entry in tree.entries if entry.path == "SYSTEM.CNF")
    assert b"SLUS_013.17" in tree.read(system)
