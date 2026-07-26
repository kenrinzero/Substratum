"""Integration coverage for the frozen package-level normalize() API."""

from pathlib import Path

import pytest

from substratum import normalize
from substratum.contract import ByteView, FileSource, FileTree

ROOT = Path(__file__).resolve().parent.parent

CASES = (
    (
        "3ds-ncch",
        ROOT
        / "fixtures/3ds_cci/cubic-ninja/reference/partition0.cxi",
        FileTree,
    ),
    (
        "3ds-cci",
        ROOT / "fixtures/_local/Cubic Ninja (Japan).3ds",
        FileTree,
    ),
    ("chd", ROOT / "fixtures/chd/supertux/supertux.chd", ByteView),
    ("cso", ROOT / "fixtures/cso/synthetic/game.cso", ByteView),
    ("iso9660", ROOT / "fixtures/iso9660/synthetic/synthetic.iso", FileTree),
    ("wii-u8-arc", ROOT / "fixtures/wii_u8_arc/synthetic/archive.arc", FileTree),
    ("xdvdfs", ROOT / "fixtures/xdvdfs/synthetic/game.xiso", FileTree),
    (
        "saturn-dc-raw",
        ROOT / "fixtures/saturn_dc_raw/synthetic/game_2352.bin",
        ByteView,
    ),
    ("ps1-bincue", ROOT / "fixtures/ps1_bincue/synthetic/game.bin", ByteView),
)


@pytest.mark.parametrize(("format_name", "fixture", "result_type"), CASES)
def test_auto_detects_registered_committed_fixtures(format_name, fixture, result_type):
    if format_name in {"3ds-cci", "3ds-ncch"} and not fixture.exists():
        pytest.skip("operator-provided 3DS fixture is not staged")
    result = normalize(fixture)
    assert isinstance(result, result_type)
    assert result.format == format_name


def test_auto_detects_optional_gc_fst_fixture():
    fixture = ROOT / "fixtures/gc_fst/nested/game.iso"
    if not fixture.exists():
        pytest.skip("generated GameCube fixture is not staged")
    result = normalize(fixture)
    assert isinstance(result, FileTree)
    assert result.format == "gc-fst"


def test_format_pin_selects_normalizer_without_sniffing():
    fixture = ROOT / "fixtures/wii_u8_arc/synthetic/archive.arc"
    result = normalize(FileSource(fixture), format="wii-u8-arc")
    assert isinstance(result, FileTree)
    assert result.format == "wii-u8-arc"


def test_caller_visible_composition_normalizes_one_layer_at_a_time():
    cso = ROOT / "fixtures/cso/synthetic/game.cso"
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
        normalize(ROOT / "fixtures/toy/toy.bin")
