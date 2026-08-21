"""Integration coverage for the frozen package-level normalize() API.

Two layers, because they have very different costs:

1. **Dispatch** — for every one of the registered formats, the sniffer that
   claims an available fixture is the *right* one. This runs the registry's
   selection loop without invoking the normalizer, so the tool-shelling
   container units (rvz/gcz/wbfs/nkit) are covered for pennies instead of a
   multi-gigabyte external decode each.
2. **Result type** — `normalize()` actually returns the declared
   `ByteView` / `FileTree` for the cheap, committed fixtures.

`test_every_registered_format_has_a_dispatch_case` is the part that keeps
this file honest: the CASES table is checked against the live registry, so a
new normalizer cannot be added without a dispatch case. That guard exists
because this module had fallen fourteen units behind `_FORMATS` — it covered
10 of 24 registered formats while claiming to cover the API.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest

from substratum import normalize
from substratum.contract import ByteView, FileSource, FileTree
from substratum.normalize import _FORMATS

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "fixtures"
LOCAL = FIXTURES / "_local"


@dataclass(frozen=True)
class Case:
    """One dispatch case: which fixture, what `normalize()` should return.

    `env` names environment variables the normalizer needs (keyed units);
    `cheap` marks a fixture the result-type test may actually normalize —
    everything else is dispatch-only because normalizing it shells out to an
    external tool over a retail-sized image.
    """

    fixture: Path
    result: type
    env: tuple[tuple[str, Path], ...] = ()
    cheap: bool = True
    pin_only: bool = False  # correctly shadowed in the registry; see below

    def available(self) -> bool:
        return self.fixture.is_file() and all(p.is_file() for _, p in self.env)


_WII_TEST_KEY = FIXTURES / "wii_partition" / "synthetic" / "test-common-key.bin"
_3DS_TEST_KEYSET = FIXTURES / "3ds_ncch_enc_96" / "synthetic" / "test_keyset.txt"
_SEEDDB = LOCAL / "seeddb.bin"

CASES: dict[str, Case] = {
    # --- committed synthetic / homebrew fixtures ------------------------
    "iso9660": Case(FIXTURES / "iso9660" / "synthetic" / "synthetic.iso", FileTree),
    "cso": Case(FIXTURES / "cso" / "synthetic" / "game.cso", ByteView),
    "ciso": Case(FIXTURES / "ciso" / "synthetic" / "game.ciso", ByteView),
    "zip": Case(FIXTURES / "zip" / "synthetic" / "game.zip", FileTree),
    "xdvdfs": Case(FIXTURES / "xdvdfs" / "synthetic" / "game.xiso", FileTree),
    "wii-u8-arc": Case(FIXTURES / "wii_u8_arc" / "synthetic" / "archive.arc", FileTree),
    "3ds-romfs": Case(FIXTURES / "3ds_romfs" / "synthetic" / "game.romfs", FileTree),
    "ps1-bincue": Case(FIXTURES / "ps1_bincue" / "synthetic" / "game.bin", ByteView),
    "saturn-dc-raw": Case(
        FIXTURES / "saturn_dc_raw" / "synthetic" / "game_2352.bin", ByteView
    ),
    "chd": Case(FIXTURES / "chd" / "supertux" / "supertux.chd", ByteView),
    "cia": Case(FIXTURES / "3ds_cia" / "synthetic" / "game.cia", FileTree),
    "wii-fst": Case(FIXTURES / "wii_fst" / "synthetic" / "partition.bin", FileTree),
    # Keyed synthetics ship their own committed test key, so they need no
    # operator material — only the env var pointing at it.
    "wii-partition": Case(
        FIXTURES / "wii_partition" / "synthetic" / "partition.bin",
        ByteView,
        env=(("SUBSTRATUM_WII_COMMON_KEY_FILE", _WII_TEST_KEY),),
    ),
    "3ds-ncch-enc-96": Case(
        FIXTURES / "3ds_ncch_enc_96" / "synthetic" / "encrypted.ncch",
        ByteView,
        env=(("SUBSTRATUM_3DS_KEYSET_FILE", _3DS_TEST_KEYSET),),
    ),
    # --- generated on demand -------------------------------------------
    "gc-fst": Case(FIXTURES / "gc_fst" / "nested" / "game.iso", FileTree),
    # --- operator-staged retail anchors (gitignored) --------------------
    "3ds-cci": Case(LOCAL / "Cubic Ninja (Japan).3ds", FileTree),
    "3ds-ncch": Case(
        FIXTURES / "3ds_cci" / "cubic-ninja" / "reference" / "partition0.cxi", FileTree
    ),
    "wii-disc": Case(LOCAL / "The Munchables (USA).iso", FileTree),
    # An encrypted NCCH *slice*, not a whole CIA: a CIA is claimed by the
    # `cia` container walker (correctly — it is the outer layer).
    "3ds-ncch-enc": Case(
        FIXTURES / "3ds_cia" / "biohazard" / "reference" / "content.0000.ncch",
        ByteView,
        cheap=False,
    ),
    # Pin-only. The seed sniffer accepts CIAs and nothing else, and `cia` is
    # registered ahead of it, so this unit can never win auto-detection. That
    # is by design — the documented path is walk the CIA, then decrypt the
    # selected content — and `test_the_seed_unit_is_pin_only` pins it.
    "3ds-ncch-enc-seed": Case(
        LOCAL / "BoxBoxBoy! (USA) (eShop).cia",
        ByteView,
        env=(("SUBSTRATUM_CTRTOOL_SEEDDB", _SEEDDB),),
        cheap=False,
        pin_only=True,
    ),
    # Dispatch-only: normalizing these shells out to an external tool over a
    # retail-sized image, which the per-unit modules already do once each.
    "rvz": Case(LOCAL / "GT Cube (Japan).rvz", ByteView, cheap=False),
    "gcz": Case(LOCAL / "GT Cube (Japan).gcz", ByteView, cheap=False),
    "wbfs": Case(LOCAL / "Ghost Squad (Europe).wbfs", ByteView, cheap=False),
    "nkit": Case(
        LOCAL / "Yu-Gi-Oh! The Falsebound Kingdom (Europe).nkit.iso",
        ByteView,
        cheap=False,
    ),
}


def _dispatch(fixture: Path) -> str:
    """The registry's selection, without invoking the normalizer.

    Mirrors `normalize()`'s sniff loop exactly (`normalize.py`): first
    registered format whose `sniff` accepts the source wins.
    """
    probe = FileSource(fixture)
    for entry in _FORMATS:
        if entry.sniff(probe):
            return entry.name
    raise AssertionError(f"no registered sniffer claimed {fixture}")


def test_every_registered_format_has_a_dispatch_case():
    """The guard. A normalizer added to `_FORMATS` without a case here is a
    format whose auto-detection nothing checks.
    """
    registered = {entry.name for entry in _FORMATS}
    assert set(CASES) == registered, {
        "missing a case": sorted(registered - set(CASES)),
        "case for an unregistered format": sorted(set(CASES) - registered),
    }


_AUTO = sorted(n for n, c in CASES.items() if not c.pin_only)


@pytest.mark.parametrize("name", _AUTO, ids=_AUTO)
def test_sniff_dispatch_selects_the_registered_format(name, monkeypatch):
    case = CASES[name]
    if not case.available():
        pytest.skip(f"fixture for {name!r} is not staged: {case.fixture.name}")
    for var, path in case.env:
        monkeypatch.setenv(var, str(path))
    assert _dispatch(case.fixture) == name


def test_the_seed_unit_is_pin_only():
    """`3ds-ncch-enc-seed` cannot win auto-detection, and that is deliberate.

    Its sniffer accepts a CIA and nothing else, and `cia` sits ahead of it in
    the registry, so every source it could claim is claimed first. The unit is
    reached by `format=` pin or by composition — walk the CIA, then decrypt
    the content you selected. Pinned here so the dead-looking sniffer is a
    recorded design fact rather than something a later reader "fixes" by
    reordering the registry and silently breaking CIA walking.
    """
    case = CASES["3ds-ncch-enc-seed"]
    if not case.fixture.is_file():
        pytest.skip("seed-encrypted retail CIA not staged")
    claimants = [e.name for e in _FORMATS if e.sniff(FileSource(case.fixture))]
    assert "3ds-ncch-enc-seed" in claimants, claimants
    assert claimants[0] == "cia", claimants


@pytest.mark.parametrize(
    "name",
    sorted(n for n, c in CASES.items() if c.cheap),
    ids=sorted(n for n, c in CASES.items() if c.cheap),
)
def test_auto_detected_normalize_returns_the_declared_type(name, monkeypatch):
    case = CASES[name]
    if not case.available():
        pytest.skip(f"fixture for {name!r} is not staged: {case.fixture.name}")
    for var, path in case.env:
        monkeypatch.setenv(var, str(path))
    result = normalize(case.fixture)
    try:
        assert isinstance(result, case.result)
        assert result.format == name
    finally:
        close = getattr(result.source, "close", None)
        if close is not None:
            close()


def test_the_cia_ordering_is_load_bearing():
    """`cia` and `3ds-ncch-enc-seed` both claim a seed-encrypted CIA (the seed
    sniffer's test is "a valid CIA whose content NCCH magic is not
    plaintext"). Only registry order sends the file to the container walker.
    Pins the ordering the registry comment documents.
    """
    cia = CASES["cia"].fixture
    claimants = [e.name for e in _FORMATS if e.sniff(FileSource(cia))]
    assert claimants[0] == "cia", claimants
    assert "3ds-ncch-enc-seed" in claimants, (
        "the double-claim this ordering exists to resolve has gone away — "
        "re-check the seed sniffer before relaxing the registry order"
    )


def test_format_pin_selects_normalizer_without_sniffing():
    fixture = FIXTURES / "wii_u8_arc" / "synthetic" / "archive.arc"
    result = normalize(FileSource(fixture), format="wii-u8-arc")
    assert isinstance(result, FileTree)
    assert result.format == "wii-u8-arc"


def test_caller_visible_composition_normalizes_one_layer_at_a_time():
    cso = FIXTURES / "cso" / "synthetic" / "game.cso"
    view = normalize(cso)
    assert isinstance(view, ByteView)

    tree = normalize(view.source)
    assert isinstance(tree, FileTree)
    assert tree.format == "iso9660"


def test_unknown_format_pin_is_bounded():
    with pytest.raises(ValueError, match="unknown format 'not-a-format'"):
        normalize(ROOT / "does-not-need-to-exist.bin", format="not-a-format")


def test_unrecognized_source_is_bounded():
    with pytest.raises(ValueError, match="unrecognized format"):
        normalize(FIXTURES / "toy" / "toy.bin")
