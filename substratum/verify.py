"""The four-check gate — FROZEN semantics (DESIGN.md § 3).

Library functions a unit's test module calls; `run_checks` returns a list
of human-readable problems (empty == green). Check order is strength
order: structural, manifest match, byte-stability, then the gate that
bites — differential byte-range fidelity against independently-produced
reference bytes. Enumeration parity alone is never sufficient.
"""

from __future__ import annotations

import random
from pathlib import Path

from substratum.contract import FileTree, canonical_manifest

__all__ = ["run_checks", "sample_entries"]

SAMPLE_CAP = 16


def sample_entries(tree: FileTree, seed: int) -> list:
    """Deterministic fidelity sample (DESIGN.md § 3): all files when <=16,
    else first + last + largest + seeded picks up to the cap."""
    files = sorted(tree.files(), key=lambda e: e.path)
    if len(files) <= SAMPLE_CAP:
        return files
    picked = {files[0].path: files[0], files[-1].path: files[-1]}
    largest = max(files, key=lambda e: e.size)
    picked[largest.path] = largest
    rng = random.Random(seed)
    pool = [e for e in files if e.path not in picked]
    for e in rng.sample(pool, SAMPLE_CAP - len(picked)):
        picked[e.path] = e
    return sorted(picked.values(), key=lambda e: e.path)


def run_checks(
    normalize_fn,
    fixture_path: Path,
    expected_manifest: Path,
    reference_dir: Path,
    source_name: str,
    source_sha256: str,
    tool_versions: dict[str, str],
    sample_seed: int = 1,
) -> list[str]:
    problems: list[str] = []

    # 1. structural — parse + every range in-bounds
    try:
        tree = normalize_fn(fixture_path)
    except Exception as exc:  # noqa: BLE001 — any parse failure is the red
        return [f"structural: normalizer failed: {exc}"]
    src_size = tree.source.size()
    for e in tree.entries:
        if e.kind == "file" and not (0 <= e.offset and e.offset + e.size <= src_size):
            problems.append(f"structural: {e.path} range out of bounds")
    if problems:
        return problems

    # 2. fixture match — canonical manifest byte-equals the checked-in truth
    manifest = canonical_manifest(tree, source_name, source_sha256, tool_versions)
    expected = expected_manifest.read_bytes()
    if manifest != expected:
        problems.append(
            "manifest: emitted manifest differs from expected "
            "(metadata drift — offsets, sizes, names, or tool pins)"
        )

    # 3. byte-stability — a second run is byte-identical
    manifest2 = canonical_manifest(
        normalize_fn(fixture_path), source_name, source_sha256, tool_versions
    )
    if manifest2 != manifest:
        problems.append("stability: two runs produced different manifests")

    # 4. differential byte-range fidelity — read THROUGH the tree, diff
    #    against independently-produced reference bytes (the gate that
    #    bites: catches correct-enumeration/wrong-slicing normalizers that
    #    checks 1-3 wave through)
    for entry in sample_entries(tree, sample_seed):
        ref = reference_dir / entry.path
        if not ref.exists():
            problems.append(f"fidelity: no reference bytes for {entry.path}")
            continue
        got = tree.read(entry)
        want = ref.read_bytes()
        if got != want:
            first = next(
                (i for i, (a, b) in enumerate(zip(got, want)) if a != b),
                min(len(got), len(want)),
            )
            problems.append(
                f"fidelity: {entry.path} differs from reference at byte {first} "
                f"(lengths {len(got)} vs {len(want)}) — wrong slicing"
            )
    return problems
