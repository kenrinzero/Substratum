"""Gate tests for the encrypted-NCCH (standard crypto) decode normalizer.

The normalizer is a decode layer: it shells out to vendored ctrtool v1.3.0
(retail AES keys compiled in) and returns a decrypted ``ByteView`` that the
caller composes through the existing ``three_ds_ncch`` to walk the region
``FileTree`` (DESIGN §1 — one layer, no recursion; the ``chd``→``iso9660``
composition pattern applied to 3DS).

Two proof pillars (NORMALIZERS.md row ``3ds-ncch-enc``):

1. **Structural + composition (committed synthetic):** a small NoCrypto NCCH
   with known region payloads exercises the header-validation, region-assembly,
   and ``three_ds_ncch`` composition paths. A committed encrypted fixture that
   the production ctrtool can decrypt is NOT authorable without retail key
   material (3dstool's ``--fixed-key`` debug key isn't decryptable by ctrtool),
   so the committed synthetic covers everything except the live decrypt, and
   structural-red cases mutate it to assert the refusal paths fire *before*
   any ctrtool call.

2. **Retail decrypt + two-party differential (gitignored, skip-if-absent):**
   when the operator has supplied the Biohazard — The Mercenaries 3D CIA, the
   normalizer decrypts the encrypted NCCH content slice and the decrypted
   region bytes are compared against ctrtool's AND 3dstool's independent
   decryption (both using retail keys) — the genuine two-party oracle. The
   NCCH header's declared protected hashes provide the independent correctness
   anchor (a wrong decrypt fails them at the composed gate).
"""

from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

import pytest

from substratum import normalize
from substratum.contract import ByteView, FileSource, FileTree
from substratum.formats.three_ds_ncch import normalize_3ds_ncch
from substratum.formats.three_ds_ncch_enc import (
    normalize_3ds_ncch_enc,
    sniff,
)

ROOT = Path(__file__).resolve().parent.parent
SYNTHETIC = ROOT / "fixtures" / "3ds_ncch_enc" / "synthetic" / "decrypted.ncch"

RETAIL = ROOT / "fixtures" / "3ds_ncch_enc" / "biohazard"
RETAIL_MANIFEST = RETAIL / "expected.manifest.json"
RETAIL_REFERENCE = RETAIL / "reference"
CIA = ROOT / "fixtures" / "_local" / "Biohazard - The Mercenaries 3D (Japan).cia"

# NCCH header field offsets (mirror the normalizer).
_HEADER_SIZE = 0x200
_MAGIC_OFFSET = 0x100
_FORMAT_VERSION_OFFSET = 0x112
_NCCH_FLAGS_OFFSET = 0x188
_OTHER_FLAGS_OFFSET = 0x18F
_NO_ENCRYPTION = 1 << 2
_SEEDED_AES_KEY_Y = 1 << 5

skip_if_no_retail_anchor = pytest.mark.skipif(
    not CIA.is_file() or not RETAIL_REFERENCE.is_dir() or not RETAIL_MANIFEST.is_file(),
    reason="Biohazard CIA or gitignored decrypted references/manifest absent",
)


# ---------------------------------------------------------------------------
# Sniffer
# ---------------------------------------------------------------------------

def test_sniff_rejects_decrypted_ncch():
    """The decrypted synthetic (NoCrypto) must NOT sniff as encrypted."""
    assert not sniff(FileSource(SYNTHETIC))


def test_sniff_accepts_encrypted_ncch(tmp_path):
    """Flipping the synthetic's NoCrypto bit off makes it sniff as encrypted."""
    data = bytearray(SYNTHETIC.read_bytes())
    data[_OTHER_FLAGS_OFFSET] = data[_OTHER_FLAGS_OFFSET] & ~_NO_ENCRYPTION
    ncch = tmp_path / "enc.ncch"
    ncch.write_bytes(bytes(data))
    assert sniff(FileSource(ncch))


def test_sniff_rejects_non_ncch():
    assert not sniff(FileSource(ROOT / "fixtures" / "toy" / "toy.bin"))


# ---------------------------------------------------------------------------
# Structural-red cases — the normalizer must refuse before any ctrtool call.
# These run on synthetic bytes with NO ctrtool dependency, so they always run.
# ---------------------------------------------------------------------------

def _synthetic_with(patches: dict[int, int] | None = None) -> bytes:
    """Return the committed synthetic with header bytes patched.

    Starts from the decrypted NoCrypto NCCH, clears the NoCrypto bit (so it
    reads as encrypted for the normalizer), then applies ``patches``
    (offset -> single byte).
    """
    data = bytearray(SYNTHETIC.read_bytes())
    data[_OTHER_FLAGS_OFFSET] = data[_OTHER_FLAGS_OFFSET] & ~_NO_ENCRYPTION
    for offset, value in (patches or {}).items():
        data[offset] = value
    return bytes(data)


def test_non_standard_crypto_is_structural_red(tmp_path):
    # ncchflag[3] = 0x01 (7.x secured) instead of 0x00 standard.
    data = _synthetic_with({_NCCH_FLAGS_OFFSET + 3: 0x01})
    ncch = tmp_path / "7x.ncch"
    ncch.write_bytes(data)
    with pytest.raises(ValueError, match="non-standard NCCH crypto"):
        normalize_3ds_ncch_enc(ncch)


def test_seed_crypto_is_structural_red(tmp_path):
    data = bytearray(_synthetic_with())
    data[_OTHER_FLAGS_OFFSET] |= _SEEDED_AES_KEY_Y
    ncch = tmp_path / "seed.ncch"
    ncch.write_bytes(bytes(data))
    with pytest.raises(ValueError, match="seed-encrypted"):
        normalize_3ds_ncch_enc(ncch)


def test_bad_magic_is_structural_red(tmp_path):
    data = bytearray(_synthetic_with())
    data[_MAGIC_OFFSET : _MAGIC_OFFSET + 4] = b"NOPE"
    ncch = tmp_path / "badmagic.ncch"
    ncch.write_bytes(bytes(data))
    with pytest.raises(ValueError, match="not a 3DS NCCH image"):
        normalize_3ds_ncch_enc(ncch)


def test_prototype_format_is_structural_red(tmp_path):
    data = _synthetic_with()
    data = bytearray(data)
    struct.pack_into("<H", data, _FORMAT_VERSION_OFFSET, 1)
    ncch = tmp_path / "v1.ncch"
    ncch.write_bytes(bytes(data))
    with pytest.raises(ValueError, match="prototype format version 1"):
        normalize_3ds_ncch_enc(ncch)


def test_already_decrypted_is_structural_red(tmp_path):
    """The committed NoCrypto synthetic must route to 3ds-ncch, not here."""
    with pytest.raises(ValueError, match="already decrypted"):
        normalize_3ds_ncch_enc(SYNTHETIC)


def test_content_size_mismatch_is_structural_red(tmp_path):
    data = bytearray(_synthetic_with())
    struct.pack_into("<I", data, 0x104, len(data) // 0x200 + 1)
    ncch = tmp_path / "sizedrift.ncch"
    ncch.write_bytes(bytes(data))
    with pytest.raises(ValueError, match="declared NCCH content size"):
        normalize_3ds_ncch_enc(ncch)


def test_ctrtool_env_override_resolution(tmp_path, monkeypatch):
    """SUBSTRATUM_CTRTOOL overrides PATH and the repo-local candidate.

    The resolution order is tested structurally (the normalizer reaches the
    override before invoking ctrtool), mirroring the chd env-override tests.
    """
    import substratum.formats.three_ds_ncch_enc as mod

    override = tmp_path / "custom-ctrtool.exe"
    override.write_bytes(b"stub")
    monkeypatch.setenv("SUBSTRATUM_CTRTOOL", str(override))
    monkeypatch.setattr(
        mod.shutil, "which", lambda name: pytest.fail("PATH must not be consulted")
    )
    assert mod._ctrtool_exe() == override


def test_ctrtool_missing_raises_with_install_hint(tmp_path, monkeypatch):
    import substratum.formats.three_ds_ncch_enc as mod

    monkeypatch.delenv("SUBSTRATUM_CTRTOOL", raising=False)
    monkeypatch.setattr(mod.shutil, "which", lambda name: None)
    monkeypatch.setattr(
        mod, "_repo_ctrtool_candidate", lambda: tmp_path / "missing.exe"
    )
    with pytest.raises(FileNotFoundError, match="vendor_tools.py ctrtool"):
        mod._ctrtool_exe()


# ---------------------------------------------------------------------------
# Pillar 2: composition over the committed synthetic (decrypted path)
# ---------------------------------------------------------------------------

def test_synthetic_decrypts_and_composes_to_region_tree():
    """The committed NoCrypto NCCH composes straight through three_ds_ncch.

    This is the composition contract: a decrypted NCCH ByteView walks into a
    region FileTree. (For the live decrypt see the retail pillar below.)"""
    tree = normalize_3ds_ncch(SYNTHETIC)
    assert isinstance(tree, FileTree)
    assert tree.format == "3ds-ncch"
    assert [e.path for e in tree.entries] == [
        "extendedheader.bin",
        "plain.bin",
        "exefs.bin",
        "romfs.bin",
    ]


# ---------------------------------------------------------------------------
# Pillar 3: retail decrypt + two-party differential (the gate that bites)
# ---------------------------------------------------------------------------

def _locate_encrypted_ncch(cia: Path) -> tuple[int, int]:
    """Parse the CIA header to find the encrypted NCCH content slice."""
    with cia.open("rb") as fh:
        header = fh.read(0x20)
    footer_size = struct.unpack_from("<I", header, 0x14)[0]
    content_size = struct.unpack_from("<I", header, 0x18)[0]
    content_offset = cia.stat().st_size - footer_size - content_size
    return content_offset, content_size


def _slice_ncch(cia: Path, dest: Path) -> None:
    offset, size = _locate_encrypted_ncch(cia)
    remaining = size
    with cia.open("rb") as src, dest.open("wb") as out:
        src.seek(offset)
        while remaining:
            chunk = src.read(min(1 << 20, remaining))
            out.write(chunk)
            remaining -= len(chunk)


def _expected_region_sha(name: str) -> str:
    """The manifest's region SHA expectations come from ctrtool/3dstool's
    independent decryption (authored by the seedtool, not the normalizer)."""
    doc = json.loads(RETAIL_MANIFEST.read_text("ascii"))
    region = next(r for r in doc["regions"] if r["path"] == name)
    return region["offset"], region["size"]


@skip_if_no_retail_anchor
def test_retail_decrypts_to_byteview_then_region_tree():
    """The normalizer decrypts the encrypted NCCH content and the resulting
    ByteView composes through three_ds_ncch — with all protected hashes
    validating (the independent correctness anchor)."""
    ncch = CIA.parent / "_ncch_enc_probe.ncch"
    try:
        _slice_ncch(CIA, ncch)
        view = normalize_3ds_ncch_enc(ncch)
        assert isinstance(view, ByteView)
        assert view.format == "3ds-ncch-enc"
        tree = normalize_3ds_ncch(view.source)
        assert {e.path for e in tree.entries} == {
            "extendedheader.bin",
            "plain.bin",
            "exefs.bin",
            "romfs.bin",
        }
        view.source.close()
    finally:
        ncch.unlink(missing_ok=True)


@skip_if_no_retail_anchor
def test_retail_decrypted_regions_match_two_party_reference():
    """The gate that bites: every decrypted region byte-equals the independent
    ctrtool/3dstool reference (both retail-keyed). A wrong decrypt diverges
    here AND fails the protected-hash check at the composed gate. Streamed
    chunk-wise so the 693 MB romfs never materializes whole (memory gate)."""
    from substratum.verify import _first_diff

    ncch = CIA.parent / "_ncch_enc_probe.ncch"
    try:
        _slice_ncch(CIA, ncch)
        view = normalize_3ds_ncch_enc(ncch)
        tree = normalize_3ds_ncch(view.source)
        for entry in tree.entries:
            ref = RETAIL_REFERENCE / entry.path
            assert ref.is_file(), f"missing reference {entry.path}"
            want_len = ref.stat().st_size
            assert entry.size == want_len, (
                f"{entry.path} length {entry.size} != reference {want_len}"
            )
            first = _first_diff(tree.open(entry), ref, entry.size, want_len)
            assert first is None, (
                f"fidelity: {entry.path} differs from two-party reference "
                f"at byte {first} (lengths {entry.size} vs {want_len})"
            )
        view.source.close()
    finally:
        ncch.unlink(missing_ok=True)


@skip_if_no_retail_anchor
def test_retail_manifest_records_pinned_oracle():
    doc = json.loads(RETAIL_MANIFEST.read_text("ascii"))
    assert doc["identity"]["crypto"].startswith("standard")
    assert doc["identity"]["seed_encrypted"] is False
    assert doc["tool_versions"]["ctrtool"] == "CTRTool v1.3.0 (C) jakcron"
    assert doc["tool_versions"]["3dstool"] == "3dstool 1.2.6 by dnasdw"
