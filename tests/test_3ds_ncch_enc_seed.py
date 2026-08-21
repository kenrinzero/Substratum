"""Gate tests for the 7.x-seed encrypted-NCCH decode normalizer.

The normalizer consumes a whole CIA whose NCCH content is 7.x-seed encrypted
(``Crypto Key Secure (1) (KeyY seeded)``, ``ncchflag[3] == 0x01`` + seed bit),
decrypts it via vendored ctrtool v1.3.0 (7.x keyslot `0x25` compiled in) + the
operator-supplied seeddb, and returns a decrypted ``ByteView`` that the caller
composes through ``three_ds_ncch`` (DESIGN section 1 — one layer, no recursion).

Two proof pillars (NORMALIZERS.md row ``3ds-ncch-enc-seed``):

1. **Composition + correctness anchor:** the decrypted ByteView composes
   through ``three_ds_ncch``, which validates the NCCH-declared protected
   SHA-256 hashes — cryptographic proof the decryption is byte-correct (a
   wrong decrypt fails them). This is the load-bearing correctness check.

2. **Retail differential (gitignored, skip-if-absent):** when the operator
   has supplied the seeddb and a 7.x-seed CIA, the decrypted region bytes
   equal ctrtool's independently extracted reference (BoxBoxBoy primary,
   Mini Sports secondary). 3dstool cannot serve as a second decryptor here
   (it handles neither the CIA nor a raw 7.x-seed slice), so the protected-
   hash anchor carries the correctness proof on its own.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from substratum.contract import ByteView, FileSource, FileTree
from substratum.formats.three_ds_ncch import normalize_3ds_ncch
from substratum.formats.three_ds_ncch_enc_seed import (
    normalize_3ds_ncch_enc_seed,
    sniff,
)

ROOT = Path(__file__).resolve().parent.parent
SEEDDB = ROOT / "fixtures" / "_local" / "seeddb.bin"

BOXBOY_DIR = ROOT / "fixtures" / "3ds_ncch_enc_seed" / "boxboxboy"
BOXBOY_CIA = ROOT / "fixtures" / "_local" / "BoxBoxBoy! (USA) (eShop).cia"
BOXBOY_REF = BOXBOY_DIR / "reference"

MINI_DIR = ROOT / "fixtures" / "3ds_ncch_enc_seed" / "mini-sports"
MINI_CIA = ROOT / "fixtures" / "_local" / "Mini Sports Collection (USA) (eShop).cia"
MINI_REF = MINI_DIR / "reference"

skip_if_no_seeddb = pytest.mark.skipif(
    not SEEDDB.is_file(), reason="fixtures/_local/seeddb.bin absent"
)
skip_if_no_boxboy = pytest.mark.skipif(
    not BOXBOY_CIA.is_file() or not BOXBOY_REF.is_dir() or not BOXBOY_DIR.is_dir(),
    reason="BoxBoxBoy CIA or gitignored references/manifest absent",
)
skip_if_no_mini = pytest.mark.skipif(
    not MINI_CIA.is_file() or not MINI_REF.is_dir() or not MINI_DIR.is_dir(),
    reason="Mini Sports CIA or gitignored references/manifest absent",
)


@pytest.fixture
def seeddb_env(monkeypatch):
    if not SEEDDB.is_file():
        pytest.skip("seeddb absent")
    monkeypatch.setenv("SUBSTRATUM_CTRTOOL_SEEDDB", str(SEEDDB))
    yield


# ---------------------------------------------------------------------------
# Sniffer
# ---------------------------------------------------------------------------

def test_sniff_rejects_non_cia():
    assert not sniff(FileSource(ROOT / "fixtures" / "toy" / "toy.bin"))


@skip_if_no_boxboy
def test_sniff_accepts_7x_seed_cia():
    assert sniff(FileSource(BOXBOY_CIA))


@skip_if_no_boxboy
def test_sniff_rejects_standard_crypto_cia():
    """A standard-crypto CIA (plaintext NCCH header) must NOT sniff as 7.x-seed."""
    biohazard = ROOT / "fixtures" / "_local" / "Biohazard - The Mercenaries 3D (Japan).cia"
    if not biohazard.is_file():
        pytest.skip("Biohazard standard-crypto CIA absent")
    assert not sniff(FileSource(biohazard))


# ---------------------------------------------------------------------------
# Key-loader discipline (docs/3DS-KEYED-WORK.md)
# ---------------------------------------------------------------------------

def test_missing_seeddb_env_is_structural_red(monkeypatch):
    monkeypatch.delenv("SUBSTRATUM_CTRTOOL_SEEDDB", raising=False)
    if not BOXBOY_CIA.is_file():
        pytest.skip("BoxBoxBoy CIA absent")
    with pytest.raises(ValueError, match="SUBSTRATUM_CTRTOOL_SEEDDB is not set"):
        normalize_3ds_ncch_enc_seed(BOXBOY_CIA)


def test_missing_seeddb_file_is_structural_red(monkeypatch, tmp_path):
    missing = tmp_path / "absent.bin"
    monkeypatch.setenv("SUBSTRATUM_CTRTOOL_SEEDDB", str(missing))
    if not BOXBOY_CIA.is_file():
        pytest.skip("BoxBoxBoy CIA absent")
    with pytest.raises(ValueError, match="missing file"):
        normalize_3ds_ncch_enc_seed(BOXBOY_CIA)


def test_non_cia_is_structural_red(tmp_path):
    bad = tmp_path / "not-a-cia.bin"
    bad.write_bytes(b"\x00" * 0x1000)
    with pytest.raises(ValueError, match="not a CIA container"):
        normalize_3ds_ncch_enc_seed(bad)


# ---------------------------------------------------------------------------
# Pillar 1: composition + correctness anchor (the load-bearing check)
# ---------------------------------------------------------------------------

@skip_if_no_seeddb
@skip_if_no_boxboy
def test_boxboy_decrypts_and_composes_to_region_tree(seeddb_env):
    """The decrypted ByteView composes through three_ds_ncch — protected
    hashes validate, proving the decryption is byte-correct."""
    view = normalize_3ds_ncch_enc_seed(BOXBOY_CIA)
    assert isinstance(view, ByteView)
    assert view.format == "3ds-ncch-enc-seed"
    tree = normalize_3ds_ncch(view.source)
    assert isinstance(tree, FileTree)
    paths = {e.path for e in tree.entries}
    assert {"exefs.bin", "romfs.bin", "extendedheader.bin"} <= paths
    view.source.close()


# ---------------------------------------------------------------------------
# Pillar 2: retail differential vs ctrtool's reference (BoxBoxBoy + Mini Sports)
# ---------------------------------------------------------------------------

@skip_if_no_seeddb
@skip_if_no_boxboy
def test_boxboy_decrypted_regions_match_reference(seeddb_env):
    """Every decrypted region byte-equals ctrtool's independent extraction."""
    view = normalize_3ds_ncch_enc_seed(BOXBOY_CIA)
    tree = normalize_3ds_ncch(view.source)
    for entry in tree.entries:
        ref = BOXBOY_REF / entry.path
        assert ref.is_file(), f"missing reference {entry.path}"
        assert entry.size == ref.stat().st_size, entry.path
        got = tree.read(entry)
        theirs = ref.read_bytes()
        assert got == theirs, f"fidelity: {entry.path} differs from reference"
    view.source.close()


@skip_if_no_seeddb
@skip_if_no_mini
def test_mini_sports_decrypts_and_matches_reference(seeddb_env):
    """Second anchor (different title, same variant) — catches variant bugs."""
    view = normalize_3ds_ncch_enc_seed(MINI_CIA)
    tree = normalize_3ds_ncch(view.source)
    for entry in tree.entries:
        ref = MINI_REF / entry.path
        if not ref.is_file():
            continue  # some regions absent on some titles
        assert tree.read(entry) == ref.read_bytes(), f"fidelity: {entry.path}"
    view.source.close()


@skip_if_no_boxboy
def test_boxboy_manifest_records_pinned_oracle():
    doc = json.loads((BOXBOY_DIR / "anchor.json").read_text("ascii"))
    assert doc["identity"]["crypto"].startswith("7.x-seed")
    assert doc["tool_versions"]["ctrtool"] == "CTRTool v1.3.0 (C) jakcron"
