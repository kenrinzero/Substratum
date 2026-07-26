"""Gate self-tests on TOYFS: green on the correct normalizer, red-team (a)
corrupted input, red-team (b) the wrong-but-self-consistent slicer that
ONLY byte-range fidelity catches, plus schema/contract checks."""

import json
import shutil
from pathlib import Path

import jsonschema
import pytest

from substratum.contract import (
    FileEntry,
    FileSource,
    FileTree,
    SliceSource,
    canonical_manifest,
    sha256_of,
)
from substratum.verify import run_checks, sample_entries
from tests.toyfs import (
    normalize_toy,
    normalize_toy_mutant_metadata,
    normalize_toy_mutant_slicer,
)

ROOT = Path(__file__).resolve().parent.parent
TOY = ROOT / "fixtures" / "toy"
TOOLS = {"generator": "make_toy_fixture v1"}


def checks(normalize_fn, fixture=None):
    fixture = fixture or TOY / "toy.bin"
    return run_checks(
        normalize_fn,
        fixture,
        TOY / "expected.manifest.json",
        TOY / "reference",
        "toy.bin",
        sha256_of(TOY / "toy.bin"),
        TOOLS,
    )


def test_correct_normalizer_is_green():
    assert checks(normalize_toy) == []


def test_redteam_a_corrupted_header_is_structural_red(tmp_path):
    bad = tmp_path / "toy.bin"
    data = bytearray((TOY / "toy.bin").read_bytes())
    data[0] ^= 0xFF
    bad.write_bytes(bytes(data))
    problems = checks(normalize_toy, fixture=bad)
    assert problems and problems[0].startswith("structural:")


def test_redteam_b_selfconsistent_slicer_dies_ONLY_at_fidelity():
    """The load-bearing case: perfect metadata, walkable tree, byte-stable,
    manifest byte-equal — and every sliced byte wrong. Checks 1-3 must all
    pass it; check 4 must kill it."""
    problems = checks(normalize_toy_mutant_slicer)
    assert problems, "slicer mutant passed the whole gate"
    assert all(p.startswith("fidelity:") for p in problems), problems


def test_metadata_mutant_dies_at_manifest_check():
    problems = checks(normalize_toy_mutant_metadata)
    assert any(p.startswith("manifest:") for p in problems)


def test_expected_manifest_validates_against_schema():
    schema = json.loads((ROOT / "schema" / "manifest.schema.json").read_text("utf-8"))
    doc = json.loads((TOY / "expected.manifest.json").read_text("ascii"))
    jsonschema.Draft202012Validator(schema).validate(doc)
    doc["source"]["sha256"] = "nope"
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(schema).validate(doc)


def test_canonical_manifest_is_ascii_sorted_stable(tmp_path):
    f = tmp_path / "x.bin"
    f.write_bytes(b"\x00" * 64)
    entries = (
        FileEntry("b/ファイル.dat", "file", 8, 8),
        FileEntry("a.txt", "file", 0, 8),
    )
    tree = FileTree(FileSource(f), "toyfs", entries)
    out = canonical_manifest(tree, "x.bin", "0" * 64, {})
    out.decode("ascii")  # JP filename escaped, manifest can never mojibake
    assert out.endswith(b"\n")
    assert out.index(b"a.txt") < out.index(b"\\u30d5")  # sorted by path
    assert canonical_manifest(tree, "x.bin", "0" * 64, {}) == out


def test_sample_entries_deterministic_and_capped(tmp_path):
    f = tmp_path / "x.bin"
    f.write_bytes(b"\x00" * 4096)
    entries = tuple(
        FileEntry(f"f{i:02}.bin", "file", i * 16, 16 if i != 7 else 99)
        for i in range(24)
    )
    tree = FileTree(FileSource(f), "toyfs", entries)
    s1 = [e.path for e in sample_entries(tree, seed=1)]
    s2 = [e.path for e in sample_entries(tree, seed=1)]
    assert s1 == s2 and len(s1) == 16
    assert "f00.bin" in s1 and "f23.bin" in s1 and "f07.bin" in s1  # first/last/largest


def test_slice_source_bounds():
    src = FileSource(TOY / "toy.bin")
    with pytest.raises(ValueError, match="slice out of parent bounds"):
        SliceSource(src, src.size() - 4, 8)
    sl = SliceSource(src, 0, 4)
    assert sl.read_at(0, 4) == b"TOYF"
    with pytest.raises(ValueError, match="read out of slice bounds"):
        sl.read_at(2, 4)
