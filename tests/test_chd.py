"""S3 gate tests for the chd normalizer (NORMALIZERS.md row `chd`).

The chd normalizer returns a ByteView (DESIGN.md §1 composition rule:
one layer, never recurse).  The test wraps that ByteView through
normalize_iso9660 to get a FileTree for the four-check gate.

Expected manifest entries are the pre-compression iso manifest entries
(authored independently by pycdlib/7z at S1 time — not derived from the
parser under test).  Reference bytes are the iso reference bytes
(decompressed disc is byte-identical).  Tool pins include chdman 0.288.
"""

import gc
import json
import subprocess
import weakref
from pathlib import Path

import jsonschema
import pytest

from substratum.contract import FileSource, FileTree, ByteView, sha256_of
from substratum.formats import chd as chd_module
from substratum.formats.chd import normalize_chd, sniff
from substratum.formats.iso9660 import normalize_iso9660
from substratum.verify import run_checks
from tests.assertions import assert_structural_failure

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "fixtures" / "chd" / "supertux"
ISO_REF = ROOT / "fixtures" / "iso9660" / "supertux" / "reference"

# Tool versions — match what canonical_manifest will emit.
# source.sha256 and source.size come from the decompressed output
# (byte-identical to original ISO); source.name identifies the input .chd.
TOOLS = {
    "chdman": "0.288 (mame0288)",
    "7z": "7-Zip 26.02 (x64) 2026-06-25",
    "pycdlib": "1.16.0",
}


def _normalize_chd_to_tree(source):
    """Wrapper for run_checks: CHD -> ByteView -> iso9660 -> FileTree."""
    view = normalize_chd(source)  # ByteView over decompressed .bin
    tree = normalize_iso9660(view.source)  # FileTree over the .bin
    # Override format to "chd" so the manifest records the container.
    return FileTree(source=tree.source, format="chd", entries=tree.entries)


def checks():
    """Run the four-check gate on the CHD fixture."""
    iso_path = ROOT / "fixtures" / "iso9660" / "supertux" / "supertux.iso"
    return run_checks(
        _normalize_chd_to_tree,
        FIXTURE / "supertux.chd",
        FIXTURE / "expected.manifest.json",
        ISO_REF,
        "supertux.chd",
        sha256_of(iso_path),  # decompressed data = original ISO sha256
        TOOLS,
    )


def test_chd_is_green():
    """The full four-check gate passes on the CHD fixture."""
    assert checks() == []


def test_sniff():
    """CHD magic detection."""
    assert sniff(FileSource(FIXTURE / "supertux.chd"))
    assert not sniff(FileSource(ROOT / "fixtures" / "toy" / "toy.bin"))
    assert not sniff(FileSource(
        ROOT / "fixtures" / "iso9660" / "supertux" / "supertux.iso"
    ))


def test_expected_manifest_validates_against_schema():
    schema = json.loads((ROOT / "schema" / "manifest.schema.json").read_text("utf-8"))
    doc = json.loads((FIXTURE / "expected.manifest.json").read_text("ascii"))
    jsonschema.Draft202012Validator(schema).validate(doc)
    assert doc["format"] == "chd"
    kinds = {e["kind"] for e in doc["entries"]}
    assert kinds == {"file", "dir"}


def test_normalize_chd_returns_bytemeasure():
    """normalize_chd returns a ByteView, not a FileTree (composition rule)."""
    view = normalize_chd(FIXTURE / "supertux.chd")
    assert isinstance(view, ByteView)
    assert view.format == "chd"
    tmp_dir = view.source._tmp_dir
    with view.source as source:
        # size matches the decompressed ISO
        assert source.size() == 21823488
        assert tmp_dir.is_dir()
    assert not tmp_dir.exists()
    # Explicit cleanup remains safe after context-manager cleanup.
    view.source.close()


def test_decompressed_data_matches_original():
    """The decompressed CHD data is byte-identical to the original ISO."""
    view = normalize_chd(FIXTURE / "supertux.chd")
    try:
        iso = ROOT / "fixtures" / "iso9660" / "supertux" / "supertux.iso"
        # spot-check: read the PVD area
        pvd_chd = view.source.read_at(16 * 2048, 2048)
        with iso.open("rb") as fh:
            fh.seek(16 * 2048)
            pvd_iso = fh.read(2048)
        assert pvd_chd == pvd_iso
    finally:
        view.source.close()


@pytest.mark.parametrize(
    ("tag", "command"),
    [("CD  ", "extractcd"), ("DVD ", "extractdvd")],
)
def test_chd_dispatches_by_media_tag(monkeypatch, tmp_path, tag, command):
    chd_path = tmp_path / "game.chd"
    chd_path.write_bytes(b"MComprHD")
    output_path = tmp_path / "out"
    seen = {}

    def fake_run(cmd, **kwargs):
        seen["cmd"] = cmd
        if cmd[1] == "info":
            return subprocess.CompletedProcess(cmd, 0, stdout=f"Metadata: Tag='{tag}'\n", stderr="")
        if cmd[1] == command:
            out = Path(cmd[cmd.index("-o") + 1])
            out.parent.mkdir(parents=True, exist_ok=True)
            if command == "extractcd":
                out.write_text("FILE \"extracted.bin\" BINARY\n", encoding="utf-8")
                out.with_suffix(".bin").write_bytes(b"raw-image")
            else:
                out.write_bytes(b"raw-image")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        raise AssertionError(f"unexpected chdman command: {cmd}")

    monkeypatch.setattr(chd_module, "_chdman_exe", lambda: tmp_path / "chdman.exe")
    monkeypatch.setattr(chd_module.subprocess, "run", fake_run)

    view = chd_module.normalize_chd(chd_path)
    try:
        assert seen["cmd"][1] == command
        assert Path(seen["cmd"][seen["cmd"].index("-o") + 1]).suffix == (".cue" if command == "extractcd" else ".bin")
        assert view.source.read_at(0, len(b"raw-image")) == b"raw-image"
    finally:
        view.source.close()


def test_metadata_probe_timeout_falls_back_to_cd_extraction(monkeypatch, tmp_path):
    """A `chdman info` timeout must take the CD fallback, not abort.

    Regression for the dead `TimeoutError` arm (AUDIT-2026-08-21 entry 1):
    subprocess timeouts raise `subprocess.TimeoutExpired`, which is neither
    a builtin `TimeoutError` nor an `OSError`.
    """
    chd_path = tmp_path / "game.chd"
    chd_path.write_bytes(b"MComprHD")
    seen = {}

    def fake_run(cmd, **kwargs):
        seen["cmd"] = cmd
        if cmd[1] == "info":
            raise subprocess.TimeoutExpired(cmd, timeout=1)
        assert cmd[1] == "extractcd", f"unexpected chdman command: {cmd}"
        out = Path(cmd[cmd.index("-o") + 1])
        out.write_text("FILE \"extracted.bin\" BINARY\n", encoding="utf-8")
        out.with_suffix(".bin").write_bytes(b"raw-image")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(chd_module, "_chdman_exe", lambda: tmp_path / "chdman.exe")
    monkeypatch.setattr(chd_module.subprocess, "run", fake_run)

    view = chd_module.normalize_chd(chd_path)
    try:
        assert seen["cmd"][1] == "extractcd"
        assert view.source.read_at(0, len(b"raw-image")) == b"raw-image"
    finally:
        view.source.close()


def test_chdman_environment_override_is_authoritative(tmp_path, monkeypatch):
    override = tmp_path / "custom-chdman.exe"
    override.write_bytes(b"test executable")
    monkeypatch.setenv("SUBSTRATUM_CHDMAN", str(override))
    monkeypatch.setattr(
        chd_module.shutil,
        "which",
        lambda name: pytest.fail("PATH must not be consulted after an override"),
    )

    assert chd_module._chdman_exe() == override


def test_invalid_chdman_environment_override_fails_without_fallback(
    tmp_path, monkeypatch
):
    missing = tmp_path / "missing-chdman.exe"
    monkeypatch.setenv("SUBSTRATUM_CHDMAN", str(missing))
    monkeypatch.setattr(
        chd_module.shutil,
        "which",
        lambda name: pytest.fail("invalid explicit override must not fall back"),
    )

    with pytest.raises(FileNotFoundError, match="SUBSTRATUM_CHDMAN points"):
        chd_module._chdman_exe()


def test_chdman_path_precedes_source_checkout(tmp_path, monkeypatch):
    on_path = tmp_path / "chdman.exe"
    on_path.write_bytes(b"test executable")
    monkeypatch.delenv("SUBSTRATUM_CHDMAN", raising=False)
    monkeypatch.setattr(chd_module.shutil, "which", lambda name: str(on_path))
    monkeypatch.setattr(
        chd_module,
        "_repo_chdman_candidate",
        lambda: pytest.fail("repo fallback must not be consulted after PATH"),
    )

    assert chd_module._chdman_exe() == on_path


def test_missing_chdman_error_lists_install_options(tmp_path, monkeypatch):
    monkeypatch.delenv("SUBSTRATUM_CHDMAN", raising=False)
    monkeypatch.setattr(chd_module.shutil, "which", lambda name: None)
    monkeypatch.setattr(
        chd_module, "_repo_chdman_candidate", lambda: tmp_path / "missing.exe"
    )

    with pytest.raises(FileNotFoundError, match="install chdman on PATH"):
        chd_module._chdman_exe()


def test_temp_source_finalizer_removes_owned_tree(tmp_path):
    owned = tmp_path / "owned"
    owned.mkdir()
    extracted = owned / "extracted.bin"
    extracted.write_bytes(b"decoded bytes")
    source = chd_module._TempFileSource(extracted, owned)
    source_ref = weakref.ref(source)

    del source
    gc.collect()

    assert source_ref() is None
    assert not owned.exists()


def test_corrupted_chd_is_structural_red(tmp_path):
    """A corrupted CHD (broken magic) fails structurally."""
    bad = tmp_path / "corrupt.chd"
    data = bytearray((FIXTURE / "supertux.chd").read_bytes())
    data[0] ^= 0xFF  # break magic
    bad.write_bytes(bytes(data))
    problems = run_checks(
        _normalize_chd_to_tree,
        bad,
        FIXTURE / "expected.manifest.json",
        ISO_REF,
        "supertux.chd",
        sha256_of(ROOT / "fixtures" / "iso9660" / "supertux" / "supertux.iso"),
        TOOLS,
    )
    assert_structural_failure(problems, "extractcd")
