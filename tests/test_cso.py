"""Gate tests for the cso normalizer (NORMALIZERS.md row `cso`).

The cso normalizer returns a ByteView (DESIGN.md §1 composition rule: one
layer, never recurse). The test wraps that ByteView through
normalize_iso9660 to get a FileTree for the four-check gate — the same
shape test_chd.py uses.

The fixture reuses the iso9660 synthetic disc as the inner truth: game.cso
is maxcso's CISO of fixtures/iso9660/synthetic/synthetic.iso, so the
expected manifest entries and reference bytes are that disc's (offsets are
into the byte-identical decompressed stream). source.sha256/size describe
the decompressed inner ISO; source.name identifies the .cso.
"""

import hashlib
import json
import struct
from pathlib import Path

import jsonschema
import pytest

from substratum.contract import ByteView, FileSource, FileTree, sha256_of
from substratum.formats.cso import normalize_cso, sniff
from substratum.formats.iso9660 import normalize_iso9660
from substratum.verify import run_checks
from tests.assertions import assert_structural_failure

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "fixtures" / "cso" / "synthetic"
ISO = ROOT / "fixtures" / "iso9660" / "synthetic" / "synthetic.iso"
ISO_REF = ROOT / "fixtures" / "iso9660" / "synthetic" / "reference"
RETAIL_FIXTURE = ROOT / "fixtures" / "cso" / "ape-escape"
RETAIL_CSO = ROOT / "fixtures" / "_local" / "cso" / "Ape Escape (EU).cso"
RETAIL_REFERENCE = RETAIL_FIXTURE / "reference"
RETAIL_CSO_SHA256 = (
    "2298624db25dc7615b1fc69605824f635a59202827107de74988255b56d505f1"
)

# Tool versions — must byte-match what make_cso_fixture stamped into the
# expected manifest (maxcso authored the .cso; pycdlib read the entries).
TOOLS = {
    "maxcso": "v1.13.0",
    "pycdlib": "1.16.0",
    "generator": "make_cso_fixture v1",
}
RETAIL_TOOLS = {
    "7z": "7-Zip 26.02 (x64) 2026-06-25",
    "maxcso": "v1.13.0",
    "pycdlib": "1.16.0",
    "generator": "stage_cso_retail_anchor v1",
}

skip_if_no_retail_anchor = pytest.mark.skipif(
    not RETAIL_CSO.exists() or not RETAIL_REFERENCE.exists(),
    reason="Ape Escape retail CSO or gitignored reference extraction absent",
)

_HDR = struct.Struct("<4sIQIBBBB")  # magic, header_size, total, block, ver, align, u, u


def _normalize_cso_to_tree(source):
    """Wrapper for run_checks: CSO -> ByteView -> iso9660 -> FileTree."""
    view = normalize_cso(source)  # ByteView over the decoded inner ISO
    tree = normalize_iso9660(view.source)
    # Record the container format on the manifest.
    return FileTree(source=tree.source, format="cso", entries=tree.entries)


def _checks(fixture=FIXTURE / "game.cso"):
    return run_checks(
        _normalize_cso_to_tree,
        fixture,
        FIXTURE / "expected.manifest.json",
        ISO_REF,
        "game.cso",
        sha256_of(ISO),  # decompressed inner disc == original ISO sha256
        TOOLS,
    )


def _parse(data: bytes):
    """Minimal independent CISO parse for surgical fixture corruption."""
    magic, header_size, total, block, ver, align, _u0, _u1 = _HDR.unpack(data[:24])
    idx_off = header_size if header_size else 24
    nblocks = (total + block - 1) // block
    index = list(struct.unpack_from(f"<{nblocks + 1}I", data, idx_off))
    return header_size, total, block, ver, align, idx_off, index


def _write_bad(tmp_path: Path, mutate) -> Path:
    data = bytearray((FIXTURE / "game.cso").read_bytes())
    data = mutate(data)
    bad = tmp_path / "bad.cso"
    bad.write_bytes(bytes(data))
    return bad


# --- green + basic shape -------------------------------------------------


def test_cso_is_green():
    """The full four-check gate passes on the CISO fixture."""
    assert _checks() == []


def test_sniff(tmp_path):
    assert sniff(FileSource(FIXTURE / "game.cso"))
    assert not sniff(FileSource(ISO))
    assert not sniff(FileSource(ROOT / "fixtures" / "toy" / "toy.bin"))
    ziso = tmp_path / "z.zso"
    ziso.write_bytes(b"ZISO" + b"\x00" * 60)
    assert not sniff(FileSource(ziso))


def test_normalize_cso_returns_byteview():
    """normalize_cso returns a ByteView, not a FileTree (composition rule)."""
    view = normalize_cso(FIXTURE / "game.cso")
    assert isinstance(view, ByteView)
    assert view.format == "cso"
    assert view.source.size() == ISO.stat().st_size  # decoded == inner ISO size


def test_decompressed_matches_iso():
    """The decoded stream is byte-identical to the inner ISO (spot-check PVD)."""
    view = normalize_cso(FIXTURE / "game.cso")
    pvd_cso = view.source.read_at(16 * 2048, 2048)
    with ISO.open("rb") as fh:
        fh.seek(16 * 2048)
        pvd_iso = fh.read(2048)
    assert pvd_cso == pvd_iso


def test_expected_manifest_validates_against_schema():
    schema = json.loads((ROOT / "schema" / "manifest.schema.json").read_text("utf-8"))
    doc = json.loads((FIXTURE / "expected.manifest.json").read_text("ascii"))
    jsonschema.Draft202012Validator(schema).validate(doc)
    assert doc["format"] == "cso"
    assert {e["kind"] for e in doc["entries"]} == {"file", "dir"}


# --- structural reds (bounded discipline) --------------------------------


def _mutate_byte(i, xor):
    def f(data):
        data[i] ^= xor
        return data
    return f


def test_bad_magic_is_structural_red(tmp_path):
    bad = _write_bad(tmp_path, _mutate_byte(0, 0xFF))
    problems = _checks(bad)
    assert_structural_failure(problems, "bad magic")


def test_zso_refused(tmp_path):
    """A ZSO (lz4) image is refused by magic, not misparsed."""
    def f(data):
        data[0:4] = b"ZISO"
        return data
    problems = _checks(_write_bad(tmp_path, f))
    assert_structural_failure(problems, "bad magic")


def test_csov2_version_refused(tmp_path):
    """CSO v2 (version byte != 1) is out of scope — refused."""
    def f(data):
        data[20] = 2  # ver
        return data
    problems = _checks(_write_bad(tmp_path, f))
    assert_structural_failure(problems, "unsupported version 2")


def test_unsupported_blocksize_refused(tmp_path):
    def f(data):
        struct.pack_into("<I", data, 16, 4096)  # block_size 4096
        return data
    problems = _checks(_write_bad(tmp_path, f))
    assert_structural_failure(problems, "unsupported block size 4096")


def test_truncated_index_is_structural_red(tmp_path):
    """A file cut off inside the index table fails structurally."""
    def f(data):
        return data[:26]  # header + 2 index bytes only
    problems = _checks(_write_bad(tmp_path, f))
    assert_structural_failure(problems, "out of bounds")


def test_corrupt_index_offset_refused(tmp_path):
    """An index entry pointing past EOF is caught by eager validation."""
    def f(data):
        _hs, _t, _b, _v, _a, idx_off, index = _parse(bytes(data))
        struct.pack_into("<I", data, idx_off + 4 * 5, 0xFFFFFFFF)  # offset ~2GB
        return data
    problems = _checks(_write_bad(tmp_path, f))
    assert_structural_failure(problems, "past EOF")


def test_corrupted_block_is_structural_red(tmp_path):
    """Corrupting the on-disk block that holds the PVD (sector 16) fails
    structurally — the decode error (or the resulting bad PVD) surfaces at
    check 1 during enumeration."""
    def f(data):
        _hs, _t, block, _v, align, _io, index = _parse(bytes(data))
        start = (index[16] & 0x7FFFFFFF) << align
        end = (index[17] & 0x7FFFFFFF) << align
        for j in range(start, end):
            data[j] = 0
        return data
    problems = _checks(_write_bad(tmp_path, f))
    assert_structural_failure(problems, "decompress")


# --- gitignored retail-anchor proof ---------------------------------------


def _normalize_retail_cso_to_tree(source):
    view = normalize_cso(source)
    tree = normalize_iso9660(view.source)
    return FileTree(source=tree.source, format="cso", entries=tree.entries)


def _sha256_source(source) -> str:
    digest = hashlib.sha256()
    for offset in range(0, source.size(), 1 << 20):
        digest.update(source.read_at(offset, min(1 << 20, source.size() - offset)))
    return digest.hexdigest()


def test_ape_escape_metadata_manifest_is_valid():
    """Committed metadata remains useful when the retail drop is absent."""
    schema = json.loads((ROOT / "schema" / "manifest.schema.json").read_text("utf-8"))
    doc = json.loads(
        (RETAIL_FIXTURE / "expected.manifest.json").read_text("ascii")
    )
    jsonschema.Draft202012Validator(schema).validate(doc)
    assert doc["format"] == "cso"
    assert doc["source"] == {
        "name": "Ape Escape (EU).cso",
        "sha256": "1733f2c7fda4e8ccbf1a1440a8bbd133705d4c5da436a7a65f686de78810ef61",
        "size": 801_603_584,
    }
    assert doc["tool_versions"] == RETAIL_TOOLS
    assert len(doc["entries"]) == 550
    assert {"PSP_GAME/PARAM.SFO", "UMD_DATA.BIN"} <= {
        entry["path"] for entry in doc["entries"]
    }


@skip_if_no_retail_anchor
def test_ape_escape_retail_anchor_is_green():
    """The Archive-matching retail anchor passes the complete four-check gate."""
    expected = json.loads(
        (RETAIL_FIXTURE / "expected.manifest.json").read_text("ascii")
    )
    assert run_checks(
        _normalize_retail_cso_to_tree,
        RETAIL_CSO,
        RETAIL_FIXTURE / "expected.manifest.json",
        RETAIL_REFERENCE,
        RETAIL_CSO.name,
        expected["source"]["sha256"],
        RETAIL_TOOLS,
    ) == []


@skip_if_no_retail_anchor
def test_ape_escape_carrier_decode_and_identity():
    """Carrier fixity and the complete decoded stream match independent truth."""
    expected = json.loads(
        (RETAIL_FIXTURE / "expected.manifest.json").read_text("ascii")
    )
    assert sha256_of(RETAIL_CSO) == RETAIL_CSO_SHA256
    view = normalize_cso(RETAIL_CSO)
    assert _sha256_source(view.source) == expected["source"]["sha256"]

    tree = normalize_iso9660(view.source)
    by_path = {entry.path: entry for entry in tree.entries}
    param = tree.read(by_path["PSP_GAME/PARAM.SFO"])
    umd_data = tree.read(by_path["UMD_DATA.BIN"])
    assert b"Ape Escape" in param
    assert b"UCES00045" in param
    assert b"1.00" in param
    assert b"UCES-00045" in umd_data
