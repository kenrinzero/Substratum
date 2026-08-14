"""Gate tests for the Wii decrypted-partition FST normalizer.

Two proof pillars (NORMALIZERS.md row `wii-fst`):

1. **Synthetic round-trip (committed):** a seedtool-authored decrypted DATA
   partition with a known nested FST (3 files, 2 dirs) is parsed by the
   normalizer and compared against an independently-authored manifest plus
   known-payload byte fidelity. Proves the FST walker and the word-offset
   convention without any retail bytes.

2. **Retail differential (gitignored, sampled):** when the operator has
   supplied the common key and the Munchables ISO, the normalizer's tree is
   compared against pinned wit's independent listing (manifest match) AND
   sampled file payloads are read through the tree and byte-compared against
   wit's extraction (fidelity — check 4, the gate that bites). Skips cleanly
   otherwise. No key bytes or decrypted retail payloads are committed.

The normalizer composes wii-disc → wii-partition → FST walk; the retail
tests exercise that full chain.
"""

from __future__ import annotations

import json
import struct
from pathlib import Path

import jsonschema
import pytest

from substratum.contract import (
    ByteView,
    FileEntry,
    FileSource,
    SliceSource,
    sha256_of,
)
from substratum.formats.wii_disc import normalize_wii_disc
from substratum.formats.wii_fst import normalize_wii_fst, sniff
from substratum.formats.wii_partition import normalize_wii_partition
from substratum.verify import run_checks, sample_entries
from tests.assertions import assert_structural_failure

ROOT = Path(__file__).resolve().parent.parent
SYNTHETIC = ROOT / "fixtures" / "wii_fst" / "synthetic"
SYNTHETIC_BIN = SYNTHETIC / "partition.bin"
SYNTHETIC_MANIFEST = SYNTHETIC / "expected.manifest.json"
SYNTHETIC_PAYLOADS = SYNTHETIC / "payloads.json"

RETAIL = ROOT / "fixtures" / "wii_fst" / "munchables"
RETAIL_MANIFEST = RETAIL / "expected.manifest.json"
RETAIL_REFERENCE = RETAIL / "reference"
ISO = ROOT / "fixtures" / "_local" / "The Munchables (USA).iso"
COMMON_KEY = ROOT / "fixtures" / "_local" / "wii-common-key.bin"

TOOLS_SYNTHETIC = {"generator": "make_wii_fst_fixture v1"}
TOOLS_RETAIL = {
    "generator": "stage_wii_fst_retail_anchor v1",
    "wit": "Wiimms ISO Tool v3.05a r8638 cygwin64 - Dirk Clemens - 2022-08-27",
}

ISO_SHA256 = (
    "64c012f35d0c8b97e34c13e47060550b36d89fc36bed2691661cfdf108671cbb"
)

skip_if_no_retail_key = pytest.mark.skipif(
    not COMMON_KEY.is_file() or COMMON_KEY.stat().st_size != 16,
    reason="fixtures/_local/wii-common-key.bin absent or not 16 bytes",
)
skip_if_no_retail_anchor = pytest.mark.skipif(
    not ISO.is_file() or not RETAIL_REFERENCE.is_dir(),
    reason="Munchables ISO or gitignored FST references absent",
)


@pytest.fixture
def retail_key_env(monkeypatch):
    if not COMMON_KEY.is_file() or COMMON_KEY.stat().st_size != 16:
        pytest.skip("retail common key absent")
    monkeypatch.setenv("SUBSTRATUM_WII_COMMON_KEY_FILE", str(COMMON_KEY))
    yield


# ---------------------------------------------------------------------------
# Pillar 1: synthetic round-trip (committed fixture)
# ---------------------------------------------------------------------------

def test_synthetic_manifest_validates_and_matches():
    """Check 2: the normalizer's emitted manifest equals the independently-
    authored expected manifest."""
    schema = json.loads(
        (ROOT / "schema" / "manifest.schema.json").read_text("utf-8")
    )
    expected = json.loads(SYNTHETIC_MANIFEST.read_text("ascii"))
    jsonschema.Draft202012Validator(schema).validate(expected)
    problems = run_checks(
        normalize_wii_fst,
        SYNTHETIC_BIN,
        SYNTHETIC_MANIFEST,
        SYNTHETIC,  # reference = payloads resolved by path below
        SYNTHETIC_BIN.name,
        sha256_of(SYNTHETIC_BIN),
        TOOLS_SYNTHETIC,
    )
    # The synthetic fixture has no separate reference files; check 4 needs
    # them, so we verify manifest/stability here and fidelity separately.
    manifest_problems = [p for p in problems if not p.startswith("fidelity:")]
    assert manifest_problems == [], manifest_problems


def test_synthetic_tree_structure():
    """The normalizer produces the known 5-entry nested tree."""
    tree = normalize_wii_fst(SYNTHETIC_BIN)
    assert tree.format == "wii-fst"
    assert len(tree.entries) == 5
    by_path = {e.path: e for e in tree.entries}
    assert by_path["files"].kind == "dir"
    assert by_path["files/a.bin"].kind == "file"
    assert by_path["files/a.bin"].offset == 0x440
    assert by_path["files/a.bin"].size == 16
    assert by_path["files/sub"].kind == "dir"
    assert by_path["files/sub/c.txt"].kind == "file"
    assert by_path["files/sub/c.txt"].size == 8


def test_synthetic_fidelity_known_payloads():
    """Check 4 (the gate that bites): file payloads read through the tree
    equal the known plaintext."""
    tree = normalize_wii_fst(SYNTHETIC_BIN)
    payloads = json.loads(SYNTHETIC_PAYLOADS.read_text("ascii"))
    for path, spec in payloads.items():
        entry = next(e for e in tree.entries if e.path == path)
        got = tree.read(entry)
        want = bytes.fromhex(spec["fill"]) * spec["size"]
        assert got == want, f"{path} payload mismatch"


def test_synthetic_byte_stability():
    """Check 3: two runs produce byte-identical manifests."""
    from substratum.contract import canonical_manifest

    a = canonical_manifest(
        normalize_wii_fst(SYNTHETIC_BIN),
        SYNTHETIC_BIN.name,
        sha256_of(SYNTHETIC_BIN),
        TOOLS_SYNTHETIC,
    )
    b = canonical_manifest(
        normalize_wii_fst(SYNTHETIC_BIN),
        SYNTHETIC_BIN.name,
        sha256_of(SYNTHETIC_BIN),
        TOOLS_SYNTHETIC,
    )
    assert a == b


def test_sniff_accepts_synthetic():
    assert sniff(FileSource(SYNTHETIC_BIN))


def test_sniff_rejects_non_partition():
    assert not sniff(FileSource(ROOT / "fixtures" / "toy" / "toy.bin"))


def test_sniff_rejects_gamecube_disc():
    """A GC disc has a printable game ID at offset 0 but must be left for
    gc-fst (its magic at 0x1C)."""
    gc_iso = ROOT / "fixtures" / "_local" / "The Hulk (USA).iso"
    if not gc_iso.is_file():
        pytest.skip("GC Hulk ISO not present")
    assert not sniff(FileSource(gc_iso))


# ---------------------------------------------------------------------------
# Structural-red cases (synthetic)
# ---------------------------------------------------------------------------

def test_bad_fst_root_type_is_structural_red(tmp_path):
    data = bytearray(SYNTHETIC_BIN.read_bytes())
    fst_off = struct.unpack(">I", data[0x424:0x428])[0] << 2
    data[fst_off] = 0  # root type -> file (0), not dir (1)
    bad = tmp_path / "bad.bin"
    bad.write_bytes(bytes(data))
    with pytest.raises(ValueError, match="root node is not a directory"):
        normalize_wii_fst(bad)


def test_zero_fst_size_is_structural_red(tmp_path):
    data = bytearray(SYNTHETIC_BIN.read_bytes())
    struct.pack_into(">I", data, 0x428, 0)  # word-shifted 0 stays 0
    bad = tmp_path / "bad.bin"
    bad.write_bytes(bytes(data))
    with pytest.raises(ValueError, match="FST size is zero"):
        normalize_wii_fst(bad)


def test_fst_out_of_bounds_is_structural_red(tmp_path):
    data = bytearray(SYNTHETIC_BIN.read_bytes())
    # Point FST offset past the end of the source.
    struct.pack_into(">I", data, 0x424, len(data) << 2 if False else (len(data) + 0x100) >> 2)
    bad = tmp_path / "bad.bin"
    bad.write_bytes(bytes(data))
    with pytest.raises(ValueError, match="exceeds decrypted size"):
        normalize_wii_fst(bad)


def test_file_range_out_of_bounds_is_structural_red(tmp_path):
    data = bytearray(SYNTHETIC_BIN.read_bytes())
    fst_off = struct.unpack(">I", data[0x424:0x428])[0] << 2
    # Corrupt the first file's size (node 2 = index 1, at fst_off + 12*2)
    # to exceed the source size.
    node_base = fst_off + 12 * 2
    struct.pack_into(">I", data, node_base + 8, 0xFFFFFF)
    bad = tmp_path / "bad.bin"
    bad.write_bytes(bytes(data))
    with pytest.raises(ValueError, match="exceeds decrypted size"):
        normalize_wii_fst(bad)


# ---------------------------------------------------------------------------
# Pillar 2: retail differential (gitignored, sampled)
# ---------------------------------------------------------------------------

def _retail_tree():
    """Compose wii-disc → wii-partition → wii-fst over the Munchables."""
    iso_src = FileSource(ISO)
    disc_tree = normalize_wii_disc(iso_src)
    data_entry = next(e for e in disc_tree.entries if e.path == "partition-data.bin")
    view = normalize_wii_partition(
        SliceSource(disc_tree.source, data_entry.offset, data_entry.size)
    )
    return normalize_wii_fst(view.source)


@skip_if_no_retail_key
@skip_if_no_retail_anchor
def test_retail_manifest_matches_wit_listing(retail_key_env):
    """Checks 1-3: the normalizer's emitted manifest equals wit's independent
    listing, and two runs are byte-stable. Fidelity (check 4) is proven in the
    dedicated bounded test below — run_checks reads full files for check 4,
    which is impractical under pure-Python AES for the Munchables' large files."""
    from substratum.contract import canonical_manifest

    tree = _retail_tree()
    manifest = canonical_manifest(tree, ISO.name, ISO_SHA256, TOOLS_RETAIL)
    expected = RETAIL_MANIFEST.read_bytes()
    assert manifest == expected, "retail manifest drift (metadata — offsets/sizes/names)"


@skip_if_no_retail_key
@skip_if_no_retail_anchor
def test_retail_tree_structure_matches_wit(retail_key_env):
    """The retail tree has 50 files + 3 dirs (53 entries) per wit."""
    tree = _retail_tree()
    files = [e for e in tree.entries if e.kind == "file"]
    dirs = [e for e in tree.entries if e.kind == "dir"]
    assert len(files) == 50
    assert len(dirs) == 3


@skip_if_no_retail_key
@skip_if_no_retail_anchor
def test_retail_fidelity_sampled_files_match_wit(retail_key_env):
    """Check 4 (the gate that bites): sampled file payloads read through the
    tree byte-equal wit's independent extraction.

    Pure-Python AES (~0.5 MiB/s, DESIGN §4 stdlib-only) makes full reads of the
    Munchables' large files (up to 220 MB) impractical in-test, so each sampled
    file is verified by a bounded head+tail slice — enough to prove the offset
    and slicing are correct without decrypting gigabytes. Small files (≤ the
    bound) are verified whole. Total decrypted bytes stay bounded (~a few MB).
    """
    BOUND = 1 << 16  # 64 KiB head + 64 KiB tail per file
    tree = _retail_tree()
    sample = sample_entries(tree, seed=1)
    assert len(sample) <= 16  # DESIGN §3 sampling cap
    for entry in sample:
        ref = RETAIL_REFERENCE / entry.path
        assert ref.is_file(), f"missing reference: {entry.path}"
        if entry.size <= BOUND:
            got = tree.read(entry)
            with ref.open("rb") as fh:
                theirs = fh.read()
        else:
            got = tree.open(entry).read_at(0, BOUND)
            got_tail = tree.open(entry).read_at(entry.size - BOUND, BOUND)
            with ref.open("rb") as fh:
                theirs = fh.read(BOUND)
                fh.seek(entry.size - BOUND)
                theirs_tail = fh.read(BOUND)
            assert got_tail == theirs_tail, (
                f"fidelity: {entry.path} tail differs from wit reference"
            )
        assert got == theirs, (
            f"fidelity: {entry.path} head differs from wit reference "
            f"(lengths {len(got)} vs {len(theirs)})"
        )


@skip_if_no_retail_key
@skip_if_no_retail_anchor
def test_retail_wrong_offset_mutant_dies_at_fidelity(retail_key_env):
    """The decode-layer analogue of check 4's load-bearing red case: a
    normalizer that returns correct paths/sizes but wrong offsets must die at
    fidelity, not pass checks 1-3. Verified on a bounded slice (pure-Python AES
    makes full reads impractical)."""
    from substratum.contract import FileTree

    tree = _retail_tree()
    shifted = tuple(
        FileEntry(e.path, e.kind, e.offset + 1, max(e.size - 1, 0))
        if e.kind == "file"
        else e
        for e in tree.entries
    )
    mutant_tree = FileTree(tree.source, tree.format, shifted)
    # Pick a small sampled file for a fast bounded check.
    small = min(
        (e for e in mutant_tree.entries if e.kind == "file"),
        key=lambda e: e.size,
    )
    ref = RETAIL_REFERENCE / small.path
    bound = min(small.size, 1 << 16)
    got = mutant_tree.open(small).read_at(0, bound)
    with ref.open("rb") as fh:
        theirs = fh.read(bound)
    assert got != theirs, "mutant with shifted offsets should not match reference"
