"""Measured recursion depth of the recursive tree walkers (audit D2, closed).

Five walkers recurse: `gc_fst`, `wii_fst`, `wii_u8_arc` and `three_ds_romfs`
recurse once per directory *nesting level* (their sibling chains are `while`
loops), and `xdvdfs` recurses on both the left child AND the right sibling of
its LCRS binary tree, so its depth tracks the tree's shape rather than the
directory depth.

The audit asked whether those should be rewritten to explicit stacks. The
answer is no, and this module is the reason: it measures what the depths
actually are instead of arguing about them. Every committed fixture and every
staged retail anchor sits orders of magnitude under `sys.getrecursionlimit()`,
and the gate already turns a `RecursionError` into a structural red, so an
explicit-stack rewrite of five walkers that are GREEN and retail-proven would
buy nothing and risk the code this repo is most confident about.

A measurement recorded once in a memo rots. These assertions run every time,
so a future fixture that does approach the limit fails here — with the number —
rather than surfacing as a mystery `RecursionError` inside a normalizer.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from substratum.formats import xdvdfs

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "fixtures"
XISO = FIXTURES / "xdvdfs" / "synthetic" / "game.xiso"
RETAIL_XISO = FIXTURES / "_local" / "Jade Empire (Japan).iso"
RETAIL_BASE_OFFSET = 0x18300000

# Generous: the deepest thing measured is 29, the interpreter's limit is 1000.
# This is a "something changed shape" tripwire, not a tight bound.
HEADROOM_CEILING = 100


def _manifests() -> list[Path]:
    return sorted(FIXTURES.rglob("expected.manifest.json"))


MANIFESTS = _manifests()


def _rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def test_the_sweep_actually_finds_manifests():
    """Guard against a glob that matches nothing and passes vacuously."""
    assert len(MANIFESTS) > 20, len(MANIFESTS)


@pytest.mark.parametrize("manifest", MANIFESTS, ids=_rel)
def test_no_committed_tree_nests_deeply(manifest):
    """Directory nesting depth bounds four of the five walkers.

    Read off the checked-in manifests rather than by re-walking, so this
    covers every fixture including the ones whose carrier is gitignored.
    """
    doc = json.loads(manifest.read_text("ascii"))
    depth = max((e["path"].count("/") for e in doc["entries"]), default=0)
    assert depth < HEADROOM_CEILING, (
        f"{_rel(manifest)} nests {depth} deep; the recursive walkers recurse "
        f"once per level against a limit of {sys.getrecursionlimit()}"
    )


class _DepthProbe:
    """Wrap `xdvdfs._walk_table` and record how deep it actually goes."""

    def __init__(self) -> None:
        self.depth = 0
        self.max_depth = 0
        self._real = xdvdfs._walk_table

    def __call__(self, *args, **kwargs):
        self.depth += 1
        self.max_depth = max(self.max_depth, self.depth)
        try:
            return self._real(*args, **kwargs)
        finally:
            self.depth -= 1


def _measure_xdvdfs(monkeypatch, source, **kwargs) -> tuple[int, int]:
    probe = _DepthProbe()
    monkeypatch.setattr(xdvdfs, "_walk_table", probe)
    tree = xdvdfs.normalize_xdvdfs(source, **kwargs)
    return probe.max_depth, len(tree.entries)


def test_xdvdfs_lcrs_depth_is_measured_on_the_synthetic_fixture(monkeypatch):
    """The LCRS walker is the one whose depth is not the directory depth."""
    depth, entries = _measure_xdvdfs(monkeypatch, XISO)
    assert depth > 0, "the probe never fired — the walker was not instrumented"
    assert depth < HEADROOM_CEILING, f"{entries} entries reached depth {depth}"


@pytest.mark.skipif(
    not RETAIL_XISO.exists(), reason="staged Jade Empire retail XGD1 image absent"
)
def test_xdvdfs_lcrs_depth_stays_shallow_on_a_real_pressing(monkeypatch):
    """The real shape question: a retail directory table with thousands of
    entries. Jade Empire's 4,022 reach depth 29 against a limit of 1,000 —
    a balanced-enough LCRS tree, roughly 2x its ~12-level ideal. Reaching
    the limit would take a near-degenerate tree of order 100,000 entries in
    a single directory, which is not a shape optical media produces."""
    depth, entries = _measure_xdvdfs(
        monkeypatch, RETAIL_XISO, base_offset=RETAIL_BASE_OFFSET
    )
    assert entries > 1000, entries
    assert depth < HEADROOM_CEILING, f"{entries} entries reached depth {depth}"
