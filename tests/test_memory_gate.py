"""Red-team proof that the memory gate BITES — load-bearing.

A gate that doesn't catch the bug it exists for is just a metric. This module
re-introduces the exact ~2.8 GB pattern of 2026-07-23
(``bytearray(ISO.read_bytes())`` on the retail ISO) and asserts the gate's
measurement mechanism *sees* it — i.e. that the process peak RSS sampled by
the autouse fixture in ``conftest.py`` exceeds the 1 GB budget and trips the
assertion. Green here = the gate's measurement is sound; a future regression
that made psutil miss this allocation would red this test.

Why a direct measurement (approach b) over ``xfail(strict=True)`` on the
forbidden pattern (approach a): under pytest 8+, xfail only honors failures
in the *call* phase, while the autouse budget fixture asserts in *teardown*.
Marking the forbidden-pattern test xfail produces a self-contradictory report
(call passes → XPASS → strict→FAILED; teardown fails → XFAIL — one test, two
outcomes). The direct-measurement form is unambiguous and exercises the same
``psutil.Process().memory_full_info().rss`` call the autouse fixture makes.

Why the retail ISO (not a synthetic ``bytearray(600 * 1024 * 1024)``): the
proof must be the *exact* regression — a 1.36 GB ``read_bytes()``
materialization on the fixture the original 2.8 GB peak came from. A synthetic
blob would prove psutil works in the abstract, not that it catches this bug
on this fixture; the differential is load-bearing.

Skips cleanly when the retail ISO is absent (fresh clones stay green).
"""

from __future__ import annotations

import psutil
import pytest

from tests.conftest import MEM_BUDGET, _rss
from tests.test_gc_fst import ISO, skip_if_no_iso


@skip_if_no_iso
@pytest.mark.no_memory_budget  # opt out of autouse — we measure the gate directly
def test_whole_fixture_read_is_caught_by_gate():
    """The exact regression of 2026-07-23 must register above the budget.

    Samples process RSS before, during, and after the forbidden
    ``bytearray(ISO.read_bytes())`` pattern, and asserts the peak exceeds
    ``MEM_BUDGET``. That proves the autouse fixture's
    ``assert peak < MEM_BUDGET`` would fire on this pattern — i.e. the gate
    bites. If this assertion ever flips (peak measured *under* budget),
    the RSS sampler has stopped seeing the allocation and the gate is blind
    to the 2026-07-23 class — investigate before proceeding.
    """
    proc = psutil.Process()
    baseline = _rss(proc)
    peak = baseline

    data = bytearray(ISO.read_bytes())  # the forbidden pattern — ~1.36 GB
    assert len(data) > 0  # keep `data` alive so the peak is real

    # Sample after the allocation is held — the worst-case peak. (A real
    # transient spike would require sampling in a thread during allocation;
    # this class is a held allocation, so a steady-state sample suffices and
    # matches how the autouse gate would see it.)
    while_held = _rss(proc)
    if while_held > peak:
        peak = while_held

    del data  # release before the budget assertion, mirroring the real path

    # The load-bearing assertion: the forbidden pattern must measure above the
    # same budget the autouse gate enforces. Uses > (not >=) so a pattern
    # landing exactly on the boundary still reds — the budget is a ceiling,
    # not a target.
    assert peak > MEM_BUDGET, (
        f"memory gate is blind to the forbidden pattern: process RSS peaked at "
        f"{peak / 1e9:.2f} GB (baseline {baseline / 1e9:.2f} GB) for "
        f"bytearray(ISO.read_bytes()) on the 1.36 GB retail ISO — under the "
        f"{MEM_BUDGET / 1e9:.2f} GB budget. The autouse fixture would NOT "
        f"catch this regression; the gate no longer bites."
    )
