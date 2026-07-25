"""Memory-discipline gate: assert no test's peak RSS exceeds budget.

Catches the regression class where a test materializes a whole fixture into
memory (``bytearray(x.read_bytes())``, ``tree.read(large_entry)``) instead of
streaming. The ~2.8 GB peak of 2026-07-23 was exactly this — the four-check
gate cannot see RAM, so the suite stayed green while peaking. This fixture
makes that class die loudly. See ``verify._first_diff`` for the stream
discipline this defends, and ``test_memory_gate`` for the red-team proof.

Mechanism — process peak-RSS polling (psutil), NOT ``tracemalloc``: the
first-cut design used ``tracemalloc.start()`` + ``get_traced_memory()`` in an
autouse fixture, but tracemalloc traces every Python allocation and the
streamed gate (``_first_diff``'s 1 MiB chunk loop) does ~2600 allocations per
sampled fidelity file on the 1.36 GB Hulk fixture — under tracing that one
test went 46 s → ~990 s (~20x, all CPU), which would take the whole suite
from ~2 min to 30+ min. The bug class (a held-for-the-test's-duration
``bytearray`` of the whole fixture) is not a sub-millisecond transient, so a
background thread sampling RSS every ~25 ms catches it trivially and adds
zero overhead to the streamed reads. psutil is also the canonical
Windows-side measurement used throughout the prior memory sweep
(``memory_full_info().rss``); it additionally catches mmap / C-extension
buffers tracemalloc misses entirely.

Budget: the streamed gc-fst module peaks at ~45 MB RSS under psutil;
large-fixture streaming stays well under 150 MB (the 1 MiB chunks +
subprocess chdman/maxcso/wit buffers). 1 GB leaves generous headroom for
subprocess address-space while still catching the 1.36 GB whole-fixture
class with room to spare.
"""

from __future__ import annotations

import threading
import time

import psutil
import pytest

MEM_BUDGET = 1 * 1024 * 1024 * 1024  # 1 GB process RSS peak per test
_SAMPLE_INTERVAL = 0.025  # 25 ms — fine enough to catch a held bytearray


def _rss(proc: psutil.Process) -> int:
    """memory_full_info is preferred (includes shared/uss) but is Windows-
    restricted to memory_info's subset; use it where available, else the
    portable memory_info().rss. Both expose ``rss``."""
    try:
        return proc.memory_full_info().rss
    except (psutil.AccessDenied, AttributeError):
        return proc.memory_info().rss


@pytest.fixture(autouse=True)
def _memory_budget(request):
    """Assert the test's process peak RSS stays under ``MEM_BUDGET``.

    Samples RSS from a daemon thread at ``_SAMPLE_INTERVAL`` during the test
    body; asserts the peak in teardown. Opt out with
    ``@pytest.mark.no_memory_budget`` (used only by the red-team proof in
    ``test_memory_gate``, which measures the gate directly instead of relying
    on this autouse assertion — see that module for why).
    """
    if request.node.get_closest_marker("no_memory_budget"):
        yield
        return

    proc = psutil.Process()
    baseline = _rss(proc)
    peak_box = [baseline]  # list-closure so the thread can mutate it

    stop = threading.Event()

    def _sample():
        while not stop.is_set():
            try:
                r = _rss(proc)
            except psutil.NoSuchProcess:  # pragma: no cover — defensive
                break
            if r > peak_box[0]:
                peak_box[0] = r
            time.sleep(_SAMPLE_INTERVAL)

    worker = threading.Thread(target=_sample, daemon=True)
    worker.start()
    try:
        yield
    finally:
        stop.set()
        worker.join(timeout=2.0)

    peak = peak_box[0]
    assert peak < MEM_BUDGET, (
        f"test exceeded memory budget: process peak RSS {peak / 1e9:.2f} GB > "
        f"{MEM_BUDGET / 1e9:.2f} GB budget — likely a whole-fixture read "
        f"(bytearray(read_bytes()) / tree.read(large_entry)); stream instead "
        f"(see substratum/verify.py _first_diff)."
    )


def pytest_configure(config):
    """Register the opt-out marker so ``--strict-markers`` (if ever set) and
    ``-W error`` don't complain about an unknown mark on the red-team test."""
    config.addinivalue_line(
        "markers",
        "no_memory_budget: opt this test out of the peak-RSS budget gate "
        "(red-team proof in test_memory_gate measures the gate directly instead)",
    )
