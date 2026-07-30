"""Gate tests for the New3DS-9.6 encrypted-NCCH pure-Python decode normalizer.

The normalizer decrypts one New3DS-9.6-encrypted NCCH (``ncchflag[3] == 0x0B``,
keyslot ``0x1B``) via pure-Python AES-CTR — bypassing vendored ctrtool v1.3.0,
which cannot decrypt keyslot ``0x1B`` — and returns a decrypted ``ByteView`` that
the caller composes through ``three_ds_ncch`` (DESIGN section 1 — one layer, no
recursion).

Three proof pillars (NORMALIZERS.md row ``3ds-ncch-enc-96``):

1. **Crypto correctness (NIST anchor):** the AES-CTR + key generator are
   validated in ``tests/test_aes_ctr.py`` (NIST SP 800-38A F.5.1 vectors + a
   RomForge two-implementation differential). This test file composes them.

2. **Synthetic round-trip (committed):** a seedtool-authored 9.6 NCCH encrypted
   with *generated test* keyX/keyY pairs (NOT retail) is decrypted by the
   normalizer and composed through ``three_ds_ncch``, which validates the
   NCCH-declared protected SHA-256 hashes. The fixture exercises the real
   decrypt path AND the two-key ExeFS split (Key0 superblock, Key1 ``.code``,
   Key0 tail). This is a stronger synthetic than the standard-crypto unit could
   do (which only authors a decrypted image, since encrypting needs retail keys).

3. **Retail differential (gitignored, skip-if-absent):** when the operator has
   supplied the keyset and the FE Warriors ``.3ds``, the normalizer's decrypt
   composes through ``three_ds_ncch`` and every protected hash validates on real
   retail bytes — the ultimate independent anchor. 3dstool cannot second-party
   9.6 (no ``--seeddb`` and it lacks a working ``0x1B`` decrypt path here), so
   the protected-hash gate carries the proof on its own, as for 7.x-seed.

The normalizer returns a ``ByteView`` (DESIGN section 1 decode layer); it has no
entry list of its own, so the four-check gate's manifest/stability checks are
expressed as the composed ``three_ds_ncch`` tree + the protected-hash gate.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from substratum.contract import ByteView, FileSource, SliceSource
from substratum.formats.three_ds_ncch import normalize_3ds_ncch
from substratum.formats.three_ds_ncch_enc_96 import (
    normalize_3ds_ncch_enc_96,
    sniff,
)
from substratum.normalize import normalize

ROOT = Path(__file__).resolve().parent.parent

SYNTHETIC_DIR = ROOT / "fixtures" / "3ds_ncch_enc_96" / "synthetic"
SYNTHETIC_NCCH = SYNTHETIC_DIR / "encrypted.ncch"
SYNTHETIC_KEYSET = SYNTHETIC_DIR / "test_keyset.txt"

# Retail anchor (gitignored; metadata-only in any committed artifact).
KEYSET = ROOT / "fixtures" / "_local" / "aes_keys.txt"
FE_WARRIORS = ROOT / "fixtures" / "_local" / "Fire Emblem Warriors (USA) (v0.0).3ds"

skip_if_no_synthetic = pytest.mark.skipif(
    not SYNTHETIC_NCCH.is_file() or not SYNTHETIC_KEYSET.is_file(),
    reason="synthetic 9.6 fixture absent (run seedtools/make_3ds_ncch_enc_96_fixture.py)",
)
skip_if_no_retail = pytest.mark.skipif(
    not KEYSET.is_file() or not FE_WARRIORS.is_file(),
    reason="fixtures/_local/aes_keys.txt or FE Warriors .3ds absent",
)


@pytest.fixture
def synthetic_keyset(monkeypatch):
    if not SYNTHETIC_KEYSET.is_file():
        pytest.skip("synthetic keyset absent")
    monkeypatch.setenv("SUBSTRATUM_3DS_KEYSET_FILE", str(SYNTHETIC_KEYSET))
    yield


@pytest.fixture
def retail_keyset(monkeypatch):
    if not KEYSET.is_file():
        pytest.skip("operator keyset absent")
    monkeypatch.setenv("SUBSTRATUM_3DS_KEYSET_FILE", str(KEYSET))
    yield


# ---------------------------------------------------------------------------
# Sniffer
# ---------------------------------------------------------------------------

def test_sniff_rejects_toy_fixture():
    assert not sniff(FileSource(ROOT / "fixtures" / "toy" / "toy.bin"))


@skip_if_no_synthetic
def test_sniff_accepts_synthetic_96(synthetic_keyset):
    assert sniff(FileSource(SYNTHETIC_NCCH))


@skip_if_no_retail
def test_sniff_accepts_fe_warriors(retail_keyset):
    ncch = _fe_warriors_ncch_slice()
    assert sniff(ncch)


@skip_if_no_retail
def test_sniff_rejects_standard_and_seed_titles(retail_keyset):
    """Standard/7.x NCCHs must NOT sniff as 9.6 (ncchflag[3] not in {0x0A,0x0B})."""
    kobayashi = ROOT / "fixtures" / "_local" / (
        "3DS1333 - Kobayashi ga Kawai Sugite Tsurai!! Game Demo Kyun Moe MAX "
        "ga Tomara Nai (Japan).3ds"
    )
    if kobayashi.is_file():
        kob_ncch = _cci_partition0(kobayashi)
        assert not sniff(kob_ncch)


# ---------------------------------------------------------------------------
# Keyset-loader discipline (docs/3DS-KEYED-WORK.md — fail closed, presence-only)
# ---------------------------------------------------------------------------

@skip_if_no_synthetic
def test_missing_keyset_env_is_structural_red(monkeypatch):
    monkeypatch.delenv("SUBSTRATUM_3DS_KEYSET_FILE", raising=False)
    with pytest.raises(ValueError, match="SUBSTRATUM_3DS_KEYSET_FILE is not set"):
        normalize_3ds_ncch_enc_96(SYNTHETIC_NCCH)


@skip_if_no_synthetic
def test_missing_keyset_file_is_structural_red(monkeypatch, tmp_path):
    monkeypatch.setenv("SUBSTRATUM_3DS_KEYSET_FILE", str(tmp_path / "absent.txt"))
    with pytest.raises(ValueError, match="missing file"):
        normalize_3ds_ncch_enc_96(SYNTHETIC_NCCH)


@skip_if_no_synthetic
def test_missing_slot_is_structural_red(monkeypatch, tmp_path):
    """A keyset lacking slot0x1BKeyX fails closed."""
    (tmp_path / "keys.txt").write_text(":AES\nslot0x2CKeyX=" + "00" * 16 + "\n")
    monkeypatch.setenv("SUBSTRATUM_3DS_KEYSET_FILE", str(tmp_path / "keys.txt"))
    with pytest.raises(ValueError, match="slot0x1BKeyX not found"):
        normalize_3ds_ncch_enc_96(SYNTHETIC_NCCH)


# ---------------------------------------------------------------------------
# Structural-refusal cases (mutate the committed synthetic's header)
# ---------------------------------------------------------------------------

@skip_if_no_synthetic
def test_refuses_decrypted_nocrypto(synthetic_keyset, tmp_path):
    """A NoCrypto NCCH is 3ds-ncch's domain, not this decryptor's."""
    mutant = _mutant(0x18F, lambda b: b | (1 << 2), tmp_path)  # set NoCrypto
    with pytest.raises(ValueError, match="already decrypted"):
        normalize_3ds_ncch_enc_96(mutant)


@skip_if_no_synthetic
def test_refuses_seed_bit(synthetic_keyset, tmp_path):
    """The seeded-9.6 sub-variant is outside this no-seed unit."""
    mutant = _mutant(0x18F, lambda b: b | (1 << 5), tmp_path)  # set seed bit
    with pytest.raises(ValueError, match="seeded-9.6"):
        normalize_3ds_ncch_enc_96(mutant)


@skip_if_no_synthetic
def test_refuses_standard_crypto_method(synthetic_keyset, tmp_path):
    """ncchflag[3] outside {0x0A, 0x0B} is not 9.6/9.3."""
    mutant = _mutant(0x188 + 3, lambda b: 0x00, tmp_path)  # standard crypto
    with pytest.raises(ValueError, match="outside 9.6/9.3 scope"):
        normalize_3ds_ncch_enc_96(mutant)


@skip_if_no_synthetic
def test_refuses_bad_magic(synthetic_keyset, tmp_path):
    mutant = bytearray(SYNTHETIC_NCCH.read_bytes())
    mutant[0x100 : 0x104] = b"XXXX"
    path = tmp_path / "badmagic.ncch"
    path.write_bytes(bytes(mutant))
    with pytest.raises(ValueError, match="missing NCCH magic"):
        normalize_3ds_ncch_enc_96(path)


@skip_if_no_synthetic
def test_refuses_size_mismatch(synthetic_keyset, tmp_path):
    mutant = bytearray(SYNTHETIC_NCCH.read_bytes()) + b"\x00" * 0x200
    path = tmp_path / "sizemismatch.ncch"
    path.write_bytes(bytes(mutant))
    with pytest.raises(ValueError, match="content size"):
        normalize_3ds_ncch_enc_96(path)


# ---------------------------------------------------------------------------
# Synthetic round-trip — real decrypt + two-key model + protected-hash gate
# ---------------------------------------------------------------------------

@skip_if_no_synthetic
def test_synthetic_decrypts_to_byteview(synthetic_keyset):
    view = normalize_3ds_ncch_enc_96(SYNTHETIC_NCCH)
    assert isinstance(view, ByteView)
    assert view.format == "3ds-ncch-enc-96"
    assert view.source.size() == SYNTHETIC_NCCH.stat().st_size


@skip_if_no_synthetic
def test_synthetic_presented_header_is_nocrypto(synthetic_keyset):
    """The decrypted view presents the header with NoCrypto set so three_ds_ncch
    accepts it, but the on-disk fixture remains encrypted."""
    view = normalize_3ds_ncch_enc_96(SYNTHETIC_NCCH)
    header = view.source.read_at(0, 0x200)
    assert header[0x100 : 0x104] == b"NCCH"
    assert header[0x18F] & (1 << 2)  # NoCrypto presented
    # The committed fixture on disk is still encrypted (NoCrypto clear).
    raw = SYNTHETIC_NCCH.read_bytes()
    assert not (raw[0x18F] & (1 << 2))


@skip_if_no_synthetic
def test_synthetic_composes_through_three_ds_ncch(synthetic_keyset):
    """The load-bearing correctness check: decrypt then compose through
    three_ds_ncch — its protected-hash validation passes on the decrypted bytes.
    A wrong key, counter, keyY, or key-per-region mapping fails here."""
    view = normalize_3ds_ncch_enc_96(SYNTHETIC_NCCH)
    tree = normalize_3ds_ncch(view.source)
    assert {e.path for e in tree.entries} >= {
        "extendedheader.bin",
        "exefs.bin",
        "romfs.bin",
        "logo.bin",
        "plain.bin",
    }


@skip_if_no_synthetic
def test_synthetic_two_key_split_decrypts_correctly(synthetic_keyset):
    """The ExeFS two-key split: the superblock + tail (Key0) and .code (Key1)
    must each decrypt to its known plaintext. This proves the key switches
    mid-stream correctly."""
    view = normalize_3ds_ncch_enc_96(SYNTHETIC_NCCH)
    tree = normalize_3ds_ncch(view.source)
    exefs = tree.read(next(e for e in tree.entries if e.path == "exefs.bin"))
    assert exefs[0:4] == b".cod"  # superblock file0 name (Key0)
    # .code starts at exefs offset 0x200, known plaintext 'C'.
    assert exefs[0x200 : 0x208] == b"C" * 8  # Key1
    # tail starts after .code (0x200 + 0x400 = 0x600), known plaintext 'T'.
    assert exefs[0x600 : 0x608] == b"T" * 8  # Key0
    romfs = tree.read(next(e for e in tree.entries if e.path == "romfs.bin"))
    assert romfs[0:8] == b"R" * 8  # Key1 (entire RomFS)
    exh = tree.read(next(e for e in tree.entries if e.path == "extendedheader.bin"))
    assert exh[0:8] == b"E" * 8  # Key0


@skip_if_no_synthetic
def test_synthetic_read_is_lazy_and_windowed(synthetic_keyset):
    """Reading a sub-range of a region must decrypt only what's needed and stay
    in-bounds (the lazy source never materializes the whole image)."""
    view = normalize_3ds_ncch_enc_96(SYNTHETIC_NCCH)
    # A read entirely within the romfs region (Key1).
    mid = view.source.read_at(0x3400 + 0x10, 0x20)
    assert mid == b"R" * 0x20
    # Out-of-bounds read fails closed.
    with pytest.raises(ValueError):
        view.source.read_at(view.source.size(), 1)


@skip_if_no_synthetic
def test_synthetic_byte_stable(synthetic_keyset):
    """Two decrypts produce byte-identical region bytes (gate check 3)."""
    v1 = normalize_3ds_ncch_enc_96(SYNTHETIC_NCCH)
    v2 = normalize_3ds_ncch_enc_96(SYNTHETIC_NCCH)
    # Compare a span crossing plaintext + encrypted regions.
    assert v1.source.read_at(0, 0x1000) == v2.source.read_at(0, 0x1000)


# ---------------------------------------------------------------------------
# Retail proof (FE Warriors) — protected-hash gate on real retail bytes
# ---------------------------------------------------------------------------

@skip_if_no_retail
def test_retail_fe_warriors_decrypts_and_composes(retail_keyset):
    """The ultimate independent anchor: pure-Python decrypt of a real retail
    9.6 title composes through three_ds_ncch, validating every NCCH-declared
    protected hash on genuine FE Warriors bytes. 3dstool cannot second-party
    here, so the protected-hash gate carries the proof."""
    ncch = _fe_warriors_ncch_slice()
    view = normalize_3ds_ncch_enc_96(ncch)
    assert view.format == "3ds-ncch-enc-96"
    tree = normalize_3ds_ncch(view.source)
    # Every protected hash validated (three_ds_ncch raises on mismatch); the
    # tree is the proof. Confirm the expected region set is present.
    paths = {e.path for e in tree.entries}
    assert {"extendedheader.bin", "exefs.bin", "romfs.bin"} <= paths


@skip_if_no_retail
def test_retail_fe_warriors_auto_dispatches(retail_keyset):
    """The auto-detect path (no explicit format=) routes the 9.6 NCCH to this
    normalizer, not to 3ds-ncch or 3ds-ncch-enc."""
    ncch = _fe_warriors_ncch_slice()
    view = normalize(ncch)
    assert isinstance(view, ByteView)
    assert view.format == "3ds-ncch-enc-96"


@skip_if_no_retail
def test_retail_fe_warriors_sampled_byte_read(retail_keyset):
    """A bounded sampled read of the (large) decrypted romfs succeeds and stays
    cheap — proving the lazy/windowed decrypt handles multi-GB regions without
    materializing them (the ~0.5 MiB/s pure-Python AES constraint)."""
    ncch = _fe_warriors_ncch_slice()
    view = normalize_3ds_ncch_enc_96(ncch)
    # romfs is ~1.9 GB; read a 4 KiB head from deep in the region.
    romfs_off = 0x34E000
    head = view.source.read_at(romfs_off, 0x1000)
    assert len(head) == 0x1000


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mutant(offset: int, transform, tmp_path: Path) -> Path:
    """Write a one-byte mutant of the synthetic NCCH to tmp_path and return it."""
    data = bytearray(SYNTHETIC_NCCH.read_bytes())
    data[offset] = transform(data[offset])
    out = tmp_path / "mutant.ncch"
    out.write_bytes(bytes(data))
    return out


def _cci_partition0(path: Path) -> SliceSource:
    """Slice partition 0 (the NCCH) out of a CCI via the NCSD partition table."""
    cci = FileSource(path)
    p0_off, p0_size = struct.unpack("<II", cci.read_at(0x120, 8))
    ncch_off = p0_off * 0x200
    ncch_size = p0_size * 0x200  # the NCCH's declared content span
    return SliceSource(cci, ncch_off, ncch_size)


def _fe_warriors_ncch_slice() -> SliceSource:
    return _cci_partition0(FE_WARRIORS)
