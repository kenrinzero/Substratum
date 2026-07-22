"""S2 gate tests for the gc-fst normalizer (NORMALIZERS.md row `gc-fst`).

The expected manifest was authored by seedtools/stage_gc_fst.py from wit's
files-ll listing (the sole differential tool), cross-referenced with the
format spec — never from substratum's parser. Reference bytes come from
`wit extract` (re-extracted by the stager into fixtures/gc_fst/hulk/reference/,
gitignored — retail bytes never enter git).

The retail ISO lives in gitignored fixtures/_local/game.iso (FIXTURE REQUEST
drop). The suite SKIPS cleanly when it is absent, so a fresh clone with no
retail drop stays green; only the manifest is committed.
"""

import json
import struct
from pathlib import Path

import jsonschema
import pytest

from substratum.contract import FileSource, sha256_of
from substratum.formats.gc_fst import normalize_gc_fst, sniff
from substratum.verify import run_checks

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "fixtures" / "gc_fst" / "hulk"
ISO = ROOT / "fixtures" / "_local" / "game.iso"
REFERENCE = FIXTURE / "reference"

# Tool pin — matches what stage_gc_fst.py wrote into the manifest.
# Re-authoring on a drifted wit changes the expected manifest and fails
# check 2 loudly.
TOOLS = {
    "wit": "Wiimms ISO Tool v3.05a r8638 cygwin64 - Dirk Clemens - 2022-08-27",
    "generator": "stage_gc_fst v1",
}

skip_if_no_iso = pytest.mark.skipif(
    not ISO.exists(),
    reason="retail GameCube ISO not present in fixtures/_local/game.iso "
    "(FIXTURE REQUEST drop — metadata-only publication per DESIGN.md § 5)",
)


@skip_if_no_iso
def checks():
    return run_checks(
        normalize_gc_fst,
        ISO,
        FIXTURE / "expected.manifest.json",
        REFERENCE,
        ISO.name,
        sha256_of(ISO),
        TOOLS,
    )


@skip_if_no_iso
def test_green_full_gate():
    """The full four-check gate passes on the Hulk fixture."""
    assert checks() == []


@skip_if_no_iso
def test_corrupted_magic_is_structural_red(tmp_path):
    """Flipping the disc magic at 0x01c fails structurally."""
    bad = tmp_path / "bad.iso"
    data = bytearray(ISO.read_bytes())
    data[0x01C] ^= 0xFF  # break GC magic
    bad.write_bytes(bytes(data))
    problems = run_checks(
        normalize_gc_fst, bad, FIXTURE / "expected.manifest.json",
        REFERENCE, ISO.name, sha256_of(ISO), TOOLS,
    )
    assert problems and problems[0].startswith("structural:")


@skip_if_no_iso
def test_wii_magic_is_structural_red(tmp_path):
    """A Wii disc magic is refused (deferred keyed platform)."""
    bad = tmp_path / "wii.iso"
    data = bytearray(ISO.read_bytes())
    struct.pack_into(">I", data, 0x01C, 0x5D1C9EA3)
    bad.write_bytes(bytes(data))
    with pytest.raises(ValueError, match="Wii"):
        normalize_gc_fst(bad)


@skip_if_no_iso
def test_corrupted_fst_offset_is_structural_red(tmp_path):
    """A lying FST offset (pointing past disc end) fails structurally."""
    bad = tmp_path / "bad.iso"
    data = bytearray(ISO.read_bytes())
    struct.pack_into(">I", data, 0x424, 0xFFFFFFFF)  # FST off past end
    bad.write_bytes(bytes(data))
    with pytest.raises(ValueError, match="exceeds disc size"):
        normalize_gc_fst(bad)


@skip_if_no_iso
def test_truncated_fst_is_structural_red(tmp_path):
    """Declaring more nodes than the FST bytes allow fails structurally."""
    bad = tmp_path / "bad.iso"
    data = bytearray(ISO.read_bytes())
    # Inflate the root node's next/count to claim more nodes than bytes hold.
    struct.pack_into(">I", data, struct.unpack(">I", ISO.read_bytes()[0x424:0x428])[0] + 8, 0xFFFF)
    bad.write_bytes(bytes(data))
    with pytest.raises(ValueError):
        normalize_gc_fst(bad)


@skip_if_no_iso
def test_out_of_bounds_file_is_structural_red(tmp_path):
    """A file node pointing past disc end fails at check 1."""
    bad = tmp_path / "bad.iso"
    data = bytearray(ISO.read_bytes())
    fst_off = struct.unpack(">I", bytes(data[0x424:0x428]))[0]
    # Corrupt node 1's offset (the first real file, 12 bytes into the FST):
    # set its absolute offset field (node byte 4..7) to near-disc-end so the
    # declared range overruns the disc.
    struct.pack_into(">I", data, fst_off + _NODE_SIZE + 4, len(data) - 1)
    bad.write_bytes(bytes(data))
    problems = run_checks(
        normalize_gc_fst, bad, FIXTURE / "expected.manifest.json",
        REFERENCE, ISO.name, sha256_of(ISO), TOOLS,
    )
    assert problems and problems[0].startswith("structural:")


@skip_if_no_iso
def test_sniff():
    assert sniff(FileSource(ISO))
    assert not sniff(FileSource(ROOT / "fixtures" / "toy" / "toy.bin"))


def test_expected_manifest_validates_against_schema():
    schema = json.loads((ROOT / "schema" / "manifest.schema.json").read_text("utf-8"))
    doc = json.loads((FIXTURE / "expected.manifest.json").read_text("ascii"))
    jsonschema.Draft202012Validator(schema).validate(doc)
    assert doc["format"] == "gc-fst"
    assert doc["source"]["name"] == "game.iso"
    assert doc["source"]["size"] == 1459978240
    # fixture is flat: only files, no dirs (root is implicit)
    kinds = {e["kind"] for e in doc["entries"]}
    assert kinds == {"file"}
    assert len(doc["entries"]) == 11


def test_paths_posix_and_no_leading_slash():
    doc = json.loads((FIXTURE / "expected.manifest.json").read_text("ascii"))
    for e in doc["entries"]:
        assert not e["path"].startswith("/")
        assert "\\" not in e["path"]


# mirror the normalizer's node-size constant for the truncation test
_NODE_SIZE = 0x0C
