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
_FIDELITY_CHUNK = 1 << 20  # 1 MiB — matches contract.sha256_of's stream chunk


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


def _first_diff(src, ref_path: Path, got_len: int, want_len: int):
    """Chunked byte compare of a lazy `src` (a SliceSource over the entry's
    range) against the reference file at `ref_path`. Returns the index of the
    first differing byte, or `None` if they're byte-equal. A length mismatch
    with identical prefixes returns `min(got_len, want_len)` (the original
    eager compare's `min()` fallthrough). Reads 1 MiB at a time; neither side
    is materialized whole. Short-circuits at the first differing chunk."""
    if got_len == want_len == 0:
        return None
    overlap = min(got_len, want_len)
    pos = 0
    with ref_path.open("rb") as ref:
        while pos < overlap:
            chunk_size = min(_FIDELITY_CHUNK, overlap - pos)
            got_chunk = src.read_at(pos, chunk_size)
            want_chunk = ref.read(chunk_size)
            # a short read on either side means the declared length lied
            if len(got_chunk) != chunk_size or len(want_chunk) != chunk_size:
                # treat as a diff at the first missing byte — matches the
                # eager path's behavior when the stream ends early
                return pos + min(len(got_chunk), len(want_chunk))
            for i in range(chunk_size):
                if got_chunk[i] != want_chunk[i]:
                    return pos + i
            pos += chunk_size
    # prefixes match up to the overlap; a length difference is itself the diff
    if got_len != want_len:
        return overlap
    return None


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
    #    checks 1-3 wave through). Streamed chunk-wise (1 MiB) so neither the
    #    entry nor the reference file is materialized whole — the gate defends
    #    the same lazy-slice discipline it enforces on normalizers. Reports the
    #    same first-diff index and message format the eager compare produced.
    for entry in sample_entries(tree, sample_seed):
        ref = reference_dir / entry.path
        if not ref.exists():
            problems.append(f"fidelity: no reference bytes for {entry.path}")
            continue
        got_len = entry.size
        want_len = ref.stat().st_size
        first = _first_diff(tree.open(entry), ref, got_len, want_len)
        if first is not None:
            problems.append(
                f"fidelity: {entry.path} differs from reference at byte {first} "
                f"(lengths {got_len} vs {want_len}) — wrong slicing"
            )
    return problems
