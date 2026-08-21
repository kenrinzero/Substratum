"""S2 gate tests for the gc-fst normalizer (NORMALIZERS.md row `gc-fst`).

The expected manifest was authored by seedtools/stage_gc_fst.py from wit's
files-ll listing (the sole differential tool), cross-referenced with the
format spec — never from substratum's parser. Reference bytes come from
`wit extract` (re-extracted by the stager into fixtures/gc_fst/hulk/reference/,
gitignored — retail bytes never enter git).

The retail ISO lives in gitignored fixtures/_local/The Hulk (USA).iso (FIXTURE
drop). The suite SKIPS cleanly when it is absent, so a fresh clone with no
retail drop stays green; only the manifest is committed.
"""

import builtins
import json
import shutil
import struct
import subprocess
from pathlib import Path

import jsonschema
import pytest

from substratum.contract import FileSource, sha256_of
from substratum.formats.gc_fst import normalize_gc_fst, sniff
from substratum.verify import run_checks
from seedtools import make_gc_fst_nested_fixture as seedtool
from tests.assertions import assert_structural_failure

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "fixtures" / "gc_fst" / "hulk"
ISO = ROOT / "fixtures" / "_local" / "The Hulk (USA).iso"
REFERENCE = FIXTURE / "reference"

# Nested fixture (proof-strengthening): built on demand by the seedtool
# because the ~1.4 GiB image is gitignored. See the design spec at
# docs/specs/2026-07-22-gc-fst-nested-fixture-design.md.
NESTED = ROOT / "fixtures" / "gc_fst" / "nested"
NESTED_ISO = NESTED / "game.iso"
NESTED_REFERENCE = NESTED / "reference"
SEEDTOOL_TIMEOUT_SECONDS = 600

# Tool pin — matches what stage_gc_fst.py wrote into the manifest.
# Re-authoring on a drifted wit changes the expected manifest and fails
# check 2 loudly.
TOOLS = {
    "wit": "Wiimms ISO Tool v3.05a r8638 cygwin64 - Dirk Clemens - 2022-08-27",
    "generator": "stage_gc_fst v1",
}
NESTED_TOOLS = {
    "wit": TOOLS["wit"],
    "generator": "make_gc_fst_nested_fixture v1",
}

skip_if_no_iso = pytest.mark.skipif(
    not ISO.exists(),
    reason="retail GameCube ISO not present in fixtures/_local/The Hulk (USA).iso "
    "(FIXTURE REQUEST drop — metadata-only publication per DESIGN.md § 5)",
)


# --- memory discipline -----------------------------------------------------
# The retail and nested ISOs are ~1.36 GiB each. The structural-red tests
# below mutate a handful of bytes at known offsets; they must NOT materialize
# the whole image (the earlier `bytearray(ISO.read_bytes())` pattern peaked the
# suite at ~2.8 GB — 2x ISO, violating the lazy-slice architecture the gate
# exists to defend). Instead: stream-copy the ISO to tmp_path (shutil.copyfile
# chunks at 1 MiB), then patch the copy in place via seek+write. Peak memory
# for a mutant is now the patch payload (a few bytes), not the disc.


def _patched_copy(src: Path, tmp_path: Path, name: str, patches) -> Path:
    """Stream-copy `src` to tmp_path/name and overwrite each (offset, bytes)
    patch in place. Never holds more than the patch payload in memory."""
    bad = tmp_path / name
    shutil.copyfile(src, bad)  # streamed at shutil.COPY_BUFSIZE (1 MiB)
    with open(bad, "r+b") as fh:
        for offset, payload in patches:
            fh.seek(offset)
            fh.write(payload)
    return bad


def _read_u32_be(src: Path, offset: int) -> int:
    """Read one big-endian u32 from `src` without loading the file."""
    with open(src, "rb") as fh:
        fh.seek(offset)
        return struct.unpack(">I", fh.read(4))[0]


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
    # read the one byte we're going to flip, without loading the disc
    with open(ISO, "rb") as fh:
        fh.seek(0x01C)
        b = fh.read(1)
    bad = _patched_copy(ISO, tmp_path, "bad.iso", [(0x01C, bytes([b[0] ^ 0xFF]))])
    problems = run_checks(
        normalize_gc_fst, bad, FIXTURE / "expected.manifest.json",
        REFERENCE, ISO.name, sha256_of(ISO), TOOLS,
    )
    assert_structural_failure(problems, "not a GameCube disc")


@skip_if_no_iso
def test_wii_magic_is_structural_red(tmp_path):
    """A Wii disc magic is refused (deferred keyed platform)."""
    bad = _patched_copy(ISO, tmp_path, "wii.iso", [(0x01C, struct.pack(">I", 0x5D1C9EA3))])
    with pytest.raises(ValueError, match="Wii"):
        normalize_gc_fst(bad)


@skip_if_no_iso
def test_corrupted_fst_offset_is_structural_red(tmp_path):
    """A lying FST offset (pointing past disc end) fails structurally."""
    bad = _patched_copy(ISO, tmp_path, "bad.iso", [(0x424, struct.pack(">I", 0xFFFFFFFF))])
    with pytest.raises(ValueError, match="exceeds disc size"):
        normalize_gc_fst(bad)


@skip_if_no_iso
def test_truncated_fst_is_structural_red(tmp_path):
    """Declaring more nodes than the FST bytes allow fails structurally."""
    # Inflate the root node's next/count to claim more nodes than bytes hold.
    # The patched offset = (real FST offset field @0x424) + 8, read as 4 bytes.
    fst_off = _read_u32_be(ISO, 0x424)
    bad = _patched_copy(ISO, tmp_path, "bad.iso", [(fst_off + 8, struct.pack(">I", 0xFFFF))])
    with pytest.raises(ValueError, match="node table"):
        normalize_gc_fst(bad)


@skip_if_no_iso
def test_out_of_bounds_file_is_structural_red(tmp_path):
    """A file node pointing past disc end fails at check 1."""
    fst_off = _read_u32_be(ISO, 0x424)
    # Corrupt node 1's offset (the first real file, 12 bytes into the FST):
    # set its absolute offset field (node byte 4..7) to near-disc-end so the
    # declared range overruns the disc.
    disc_end = ISO.stat().st_size - 1
    bad = _patched_copy(
        ISO, tmp_path, "bad.iso",
        [(fst_off + _NODE_SIZE + 4, struct.pack(">I", disc_end))],
    )
    problems = run_checks(
        normalize_gc_fst, bad, FIXTURE / "expected.manifest.json",
        REFERENCE, ISO.name, sha256_of(ISO), TOOLS,
    )
    assert_structural_failure(problems, "exceeds disc size")


@skip_if_no_iso
def test_sniff():
    assert sniff(FileSource(ISO))
    assert not sniff(FileSource(ROOT / "fixtures" / "toy" / "toy.bin"))


def test_expected_manifest_validates_against_schema():
    schema = json.loads((ROOT / "schema" / "manifest.schema.json").read_text("utf-8"))
    doc = json.loads((FIXTURE / "expected.manifest.json").read_text("ascii"))
    jsonschema.Draft202012Validator(schema).validate(doc)
    assert doc["format"] == "gc-fst"
    assert doc["source"]["name"] == "The Hulk (USA).iso"
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


def _minimal_gc_image(name: bytes) -> bytes:
    fst = bytearray(24) + name + b"\x00"
    fst[0] = 1
    struct.pack_into(">I", fst, 8, 2)
    fst[12] = 0
    fst[13:16] = (0).to_bytes(3, "big")

    fst_offset = 0x440
    image = bytearray(fst_offset + len(fst))
    struct.pack_into(">I", image, 0x01C, 0xC2339F3D)
    struct.pack_into(">I", image, 0x424, fst_offset)
    struct.pack_into(">I", image, 0x428, len(fst))
    image[fst_offset:] = fst
    return bytes(image)


@pytest.mark.parametrize("name", [b"", b".", b"..", b"../X", b"..\\X"])
def test_invalid_path_component_is_structural_red(tmp_path, name):
    bad = tmp_path / "bad.iso"
    bad.write_bytes(_minimal_gc_image(name))

    with pytest.raises(ValueError, match="invalid FST path component"):
        normalize_gc_fst(bad)


# mirror the normalizer's node-size constant for the truncation test
_NODE_SIZE = 0x0C


# ---------------------------------------------------------------------------
# Nested-directory fixture (proof-strengthening — see design spec
# docs/specs/2026-07-22-gc-fst-nested-fixture-design.md).
# The flat Hulk fixture above cannot exercise the recursive FST traversal;
# this block adds a hand-authored nested FST (4 files, 2 dirs) with a genuine
# wit two-party differential on nested bytes.
# ---------------------------------------------------------------------------


def _ensure_nested_fixture():
    """Materialize the nested disc image + reference bytes on first use.

    The ~1.4 GiB image is gitignored; the seedtool is the committed recipe.
    Skips the whole nested group when the retail ISO is absent (the seedtool
    borrows its sys/ region).
    """
    if not ISO.exists():
        pytest.skip("retail ISO absent — nested fixture cannot be staged")
    if NESTED_ISO.exists() and NESTED_REFERENCE.exists():
        return
    subprocess.run(
        ["uv", "run", "python", str(ROOT / "seedtools" / "make_gc_fst_nested_fixture.py")],
        cwd=str(ROOT), check=True, capture_output=True,
        timeout=SEEDTOOL_TIMEOUT_SECONDS,
    )


@pytest.fixture(scope="session")
def nested_iso():
    _ensure_nested_fixture()
    return NESTED_ISO


def test_nested_seedtool_streams_disc_authoring(tmp_path, monkeypatch):
    """Disc-sized integer allocations are forbidden; authoring seeks and writes."""
    disc_size = 1 * 1024 * 1024
    monkeypatch.setattr(seedtool, "_GC_DISC_SIZE", disc_size)
    monkeypatch.setattr(seedtool, "_wit_exe", lambda: Path("wit.exe"))

    def fake_wit_extract(command, **kwargs):
        extract_target = Path(command[-1])
        sys_dir = extract_target / "P-TEST" / "sys"
        sys_dir.mkdir(parents=True)
        boot = bytearray(seedtool._HEADER_LEN)
        struct.pack_into(">I", boot, seedtool._DOL_OFF, 0x4000)
        (sys_dir / "boot.bin").write_bytes(boot)
        (sys_dir / "bi2.bin").write_bytes(b"B" * 0x200)
        (sys_dir / "apploader.img").write_bytes(b"A" * 0x100)
        (sys_dir / "main.dol").write_bytes(b"D" * 0x200)

    monkeypatch.setattr(seedtool.subprocess, "run", fake_wit_extract)
    real_bytearray = builtins.bytearray

    def guarded_bytearray(value=0, *args, **kwargs):
        if isinstance(value, int) and value >= disc_size:
            raise AssertionError("seedtool attempted a disc-sized allocation")
        return real_bytearray(value, *args, **kwargs)

    monkeypatch.setattr(builtins, "bytearray", guarded_bytearray)
    image = seedtool.build_image(tmp_path / "retail.iso", tmp_path / "nested.iso")

    assert image.stat().st_size == disc_size
    with image.open("rb") as fh:
        header = fh.read(seedtool._HEADER_LEN)
    assert header[: len(seedtool._DISC_ID)] == seedtool._DISC_ID
    assert struct.unpack_from(">I", header, seedtool._MAGIC_OFF)[0] == seedtool._GC_MAGIC


@skip_if_no_iso
def test_nested_fixture_full_gate(nested_iso):
    """The full four-check gate passes on the nested fixture.

    This is the proof-strengthening payoff: recursive traversal + byte-range
    fidelity against wit, on nested bytes (the flat fixture tests neither).
    """
    problems = run_checks(
        normalize_gc_fst,
        nested_iso,
        NESTED / "expected.manifest.json",
        NESTED_REFERENCE,
        nested_iso.name,
        sha256_of(nested_iso),
        NESTED_TOOLS,
    )
    assert problems == []


@skip_if_no_iso
def test_nested_dir_close_resume_is_structural_red(nested_iso, tmp_path):
    """Corrupting the nested/ directory's `next` (close) field fails structurally.

    Sets nested/'s next to its own index so the subtree never closes — the
    parser must refuse this rather than mis-walk. This targets the exact
    traversal mechanic (subtree close + resume) the flat fixture cannot test.
    """
    fst_off = _read_u32_be(nested_iso, 0x424)
    # node 4 (nested dir): base = fst_off + 4*_NODE_SIZE; next field at +8.
    node_base = fst_off + 4 * _NODE_SIZE
    bad = _patched_copy(
        nested_iso, tmp_path, "nested_bad_close.iso",
        [(node_base + 8, struct.pack(">I", 4))],  # next = self -> never closes
    )
    problems = run_checks(
        normalize_gc_fst, bad, NESTED / "expected.manifest.json",
        NESTED_REFERENCE, nested_iso.name, sha256_of(nested_iso), NESTED_TOOLS,
    )
    assert_structural_failure(problems, "invalid next=4")


@skip_if_no_iso
def test_nested_parent_mismatch_is_structural_red(nested_iso, tmp_path):
    """A child directory whose parent index points at the wrong parent fails.

    Flips the nested/ dir's parent field to a bogus value; the parser refuses
    (parent != enclosing dir).
    """
    fst_off = _read_u32_be(nested_iso, 0x424)
    # node 4 (nested dir): parent field at node_base+4..+7. Set to a bogus
    # index (not 2 = data, its real parent).
    node_base = fst_off + 4 * _NODE_SIZE
    bad = _patched_copy(
        nested_iso, tmp_path, "nested_bad_parent.iso",
        [(node_base + 4, struct.pack(">I", 99))],
    )
    problems = run_checks(
        normalize_gc_fst, bad, NESTED / "expected.manifest.json",
        NESTED_REFERENCE, nested_iso.name, sha256_of(nested_iso), NESTED_TOOLS,
    )
    assert_structural_failure(problems, "parent=99")


def test_nested_manifest_validates_against_schema():
    """The nested manifest validates and carries both file and dir kinds.

    The flat fixture's manifest is {file} only; this asserts nesting actually
    appears in the committed manifest (no ISO needed — it's committed truth).
    """
    schema = json.loads((ROOT / "schema" / "manifest.schema.json").read_text("utf-8"))
    doc = json.loads((NESTED / "expected.manifest.json").read_text("ascii"))
    jsonschema.Draft202012Validator(schema).validate(doc)
    assert doc["format"] == "gc-fst"
    assert doc["source"]["name"] == "game.iso"
    assert doc["source"]["size"] == 1459978240
    kinds = {e["kind"] for e in doc["entries"]}
    assert kinds == {"file", "dir"}
    # the resume edge-case file is present
    paths = {e["path"] for e in doc["entries"]}
    assert "data/after.txt" in paths
    assert "data/nested/deep.txt" in paths
