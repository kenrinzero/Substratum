"""Gate tests for the ciso normalizer (NORMALIZERS.md row `ciso`).

The ciso normalizer returns a ByteView (DESIGN.md §1 composition rule: one
layer, never recurse). The synthetic gate wraps that ByteView through
normalize_iso9660 — the same composition shape test_cso.py uses, over the
same committed inner disc — and the retail gate wraps it through
normalize_gc_fst (the real GC path).

Proof pillars:
1. **Synthetic four-check gate (committed):** a hand-packed fixture whose
   block 2 lives at slot 1 (present-rank != block index), so a parser that
   maps blocks to slots by index serves wrong bytes.
2. **Retail differential (gitignored):** the operator-staged Luigi's
   Mansion .ciso (NKit 2's wit-compatible container + recovery trailer)
   against wit's independent listing/extraction, plus the container-level
   wit decode with the GC junk-scrub difference characterized (blocks 1
   and 604, one-directional nonzero->zero, never inside game files), and
   a wit-authored CISO round-trip on the staged Hulk ISO (byte-exact
   full-image agreement, no junk caveat).
"""

import hashlib
import json
import struct
import subprocess
from pathlib import Path

import jsonschema
import pytest

from substratum.contract import ByteView, FileSource, FileTree, sha256_of
from substratum.formats.ciso import normalize_ciso, sniff
from substratum.formats.cso import sniff as sniff_cso
from substratum.formats.gc_fst import normalize_gc_fst
from substratum.formats.iso9660 import normalize_iso9660
from substratum.formats.wbfs import wit_exe
from substratum.verify import run_checks
from tests.assertions import assert_structural_failure

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "fixtures" / "ciso" / "synthetic"
ISO = ROOT / "fixtures" / "iso9660" / "synthetic" / "synthetic.iso"
ISO_REF = ROOT / "fixtures" / "iso9660" / "synthetic" / "reference"
PSP_CSO = ROOT / "fixtures" / "cso" / "synthetic" / "game.cso"

RETAIL_FIXTURE = ROOT / "fixtures" / "ciso" / "luigi"
RETAIL_CSO = ROOT / "fixtures" / "_local" / "Luigi's Mansion (USA, Canada).ciso"
RETAIL_REFERENCE = RETAIL_FIXTURE / "reference"
HULK_ISO = ROOT / "fixtures" / "_local" / "The Hulk (USA).iso"
HULK_SHA256 = (
    "dd1aeb238ca410e02a43ad6ec020fab1c71fdca47db5f42242c1d9f566d6fdcf"
)

# Pinned by seedtools/make_ciso_fixture.py's authoring run.
VIEW_SHA256 = (
    "c3ac6860ee82a2114acfea97b5ad996b65c2c69df0eb57d4a2a497a72858ed12"
)
TOOLS = {"generator": "make_ciso_fixture v1", "pycdlib": "1.16.0"}

# Pinned by seedtools/stage_ciso_retail_anchor.py's staging run.
RETAIL_CSO_SHA256 = (
    "a868fd4bcf4d304aae74fb32ddb067e605d64db35e035c248a630d05a7d8ac4f"
)
RETAIL_VIEW_SHA256 = (
    "05bedd94d0e81c08fff69e7cfc97dcdf4436836ba37679960d01266cbbb54a70"
)
RETAIL_TOOLS = {
    "generator": "stage_ciso_retail_anchor v1",
    "wit": "Wiimms ISO Tool v3.05a r8638 cygwin64 - Dirk Clemens - 2022-08-27",
}

BLOCK = 0x200000
TOTAL = 4_699_979_776
NBLOCKS = (TOTAL + BLOCK - 1) // BLOCK
CHUNK = 1 << 20
ORACLE_TIMEOUT_SECONDS = 600
# NKit preserved the GC junk spans in these slots; wit's copy zeroes them
# (characterized 2026-08-21 — every difference is nonzero->zero).
WIT_SCRUBBED_BLOCKS = (1, 604)

skip_if_no_retail_anchor = pytest.mark.skipif(
    not RETAIL_CSO.exists() or not RETAIL_REFERENCE.exists(),
    reason="Luigi's Mansion retail CISO or gitignored reference extraction absent",
)
skip_if_no_hulk_or_wit = pytest.mark.skipif(
    not HULK_ISO.exists(),
    reason="staged Hulk retail ISO absent (wit is resolved at test time)",
)


def _normalize_ciso_to_tree(source):
    """Wrapper for run_checks: CISO -> ByteView -> iso9660 -> FileTree."""
    view = normalize_ciso(source)
    tree = normalize_iso9660(view.source)
    return FileTree(source=tree.source, format="ciso", entries=tree.entries)


def _normalize_retail_ciso_to_tree(source):
    view = normalize_ciso(source)
    tree = normalize_gc_fst(view.source)
    return FileTree(source=tree.source, format="ciso", entries=tree.entries)


def _checks(fixture=FIXTURE / "game.ciso"):
    return run_checks(
        _normalize_ciso_to_tree,
        fixture,
        FIXTURE / "expected.manifest.json",
        ISO_REF,
        "game.ciso",  # manifest source.name, independent of the temp filename
        VIEW_SHA256,
        TOOLS,
    )


def _write_bad(tmp_path: Path, mutate) -> Path:
    data = bytearray((FIXTURE / "game.ciso").read_bytes())
    data = mutate(data)
    bad = tmp_path / "bad.cso"
    bad.write_bytes(bytes(data))
    return bad


def _sha256_source(source) -> str:
    digest = hashlib.sha256()
    for offset in range(0, source.size(), CHUNK):
        digest.update(source.read_at(offset, min(CHUNK, source.size() - offset)))
    return digest.hexdigest()


def _chain(seed: bytes, size: int) -> bytes:
    out = bytearray()
    digest = hashlib.sha256(seed).digest()
    while len(out) < size:
        out += digest
        digest = hashlib.sha256(digest).digest()
    return bytes(out[:size])


def _wit_copy(source: Path, dest: Path) -> None:
    subprocess.run(
        [str(wit_exe()), "COPY", str(source), "--dest", str(dest)],
        capture_output=True,
        check=True,
        timeout=ORACLE_TIMEOUT_SECONDS,
    )


# --- green + basic shape -------------------------------------------------


def test_ciso_is_green():
    """The full four-check gate passes on the synthetic fixture."""
    assert _checks() == []


def test_sniff_disambiguates_from_psp_cso():
    """The shared 'CISO' magic routes by the LE u32 at 0x04, both ways."""
    assert sniff(FileSource(FIXTURE / "game.ciso"))
    assert not sniff_cso(FileSource(FIXTURE / "game.ciso"))
    assert sniff_cso(FileSource(PSP_CSO))
    assert not sniff(FileSource(PSP_CSO))
    assert not sniff(FileSource(ISO))
    assert not sniff(FileSource(ROOT / "fixtures" / "toy" / "toy.bin"))


def test_normalize_ciso_returns_byteview():
    """normalize_ciso returns a ByteView, not a FileTree (composition rule)."""
    view = normalize_ciso(FIXTURE / "game.ciso")
    assert isinstance(view, ByteView)
    assert view.format == "ciso"
    assert view.source.size() == TOTAL  # fixed single-layer Wii-size space


def test_expected_manifest_validates_against_schema():
    schema = json.loads((ROOT / "schema" / "manifest.schema.json").read_text("utf-8"))
    doc = json.loads((FIXTURE / "expected.manifest.json").read_text("ascii"))
    jsonschema.Draft202012Validator(schema).validate(doc)
    assert doc["format"] == "ciso"
    assert doc["source"]["size"] == TOTAL
    assert doc["source"]["sha256"] == VIEW_SHA256


# --- container mapping (the rank-mapping mutant-catcher) -------------------


def test_view_maps_slots_by_present_rank():
    """Block 2's bytes are slot 1's payload (sha chain), block 1 is zeros —
    a parser mapping block->slot by index serves zeros or wrong bytes."""
    view = normalize_ciso(FIXTURE / "game.ciso")
    block2 = view.source.read_at(2 * BLOCK, 32)
    assert block2 == _chain(b"ciso-synthetic-block2", 32)
    assert view.source.read_at(BLOCK, 32) == bytes(32)
    pad = view.source.read_at(ISO.stat().st_size, 32)
    assert pad == _chain(b"ciso-synthetic-block0-tail", 32)


def test_spanning_reads_cross_absent_boundaries():
    view = normalize_ciso(FIXTURE / "game.ciso")
    span = view.source.read_at(BLOCK - 4, 8)  # block 0 tail -> block 1 head
    assert span[:4] != bytes(4)
    assert span[4:] == bytes(4)
    span2 = view.source.read_at(2 * BLOCK - 4, 8)  # block 1 tail -> block 2 head
    assert span2[:4] == bytes(4)
    assert span2[4:] != bytes(4)


def test_view_sha_matches_seedtool_pin():
    """The parser's decoded view hashes to the seedtool's independently
    placed view hash (two-party identity over the full address space)."""
    view = normalize_ciso(FIXTURE / "game.ciso")
    assert _sha256_source(view.source) == VIEW_SHA256


# --- structural reds (bounded discipline) --------------------------------


def _mutate_byte(i, xor):
    def f(data):
        data[i] ^= xor
        return data
    return f


def test_bad_magic_is_structural_red(tmp_path):
    problems = _checks(_write_bad(tmp_path, _mutate_byte(0, 0xFF)))
    assert_structural_failure(problems, "bad magic")


def test_unsupported_block_size_refused(tmp_path):
    def f(data):
        struct.pack_into("<I", data, 4, 0x1000)
        return data
    problems = _checks(_write_bad(tmp_path, f))
    assert_structural_failure(problems, "unsupported block size")


def test_unknown_map_value_refused(tmp_path):
    def f(data):
        data[8 + 2] = 2  # block 2's map byte
        return data
    problems = _checks(_write_bad(tmp_path, f))
    assert_structural_failure(problems, "unknown map value")


def test_nonzero_past_map_refused(tmp_path):
    def f(data):
        data[8 + NBLOCKS] = 1  # first byte past the 2242-entry map
        return data
    problems = _checks(_write_bad(tmp_path, f))
    assert_structural_failure(problems, "past the 2242-entry map")


def test_no_present_blocks_refused(tmp_path):
    def f(data):
        data[8] = 0
        data[8 + 2] = 0
        return data
    problems = _checks(_write_bad(tmp_path, f))
    assert_structural_failure(problems, "marks no blocks present")


def test_truncated_slot_is_structural_red(tmp_path):
    def f(data):
        return data[: 0x8000 + BLOCK + 100]
    problems = _checks(_write_bad(tmp_path, f))
    assert_structural_failure(problems, "inside slot")


def _final_block_ciso(tmp_path: Path, *, short: bool) -> tuple[Path, bytes]:
    """A minimal CISO with blocks 0 and 2241 present — 0x8000 + two slots.

    Block 2241 is the final block, and its disc extent is only 262,144 of
    the 2,097,152 bytes a slot holds, so the two plausible layouts differ.
    `short=False` stores a whole block (what wit writes and reads);
    `short=True` stores just the disc extent (what wit refuses).
    """
    tail_size = TOTAL - (NBLOCKS - 1) * BLOCK
    tail = _chain(b"ciso-final-block", tail_size)
    head = bytearray(0x8000)
    head[:4] = b"CISO"
    struct.pack_into("<I", head, 4, BLOCK)
    head[8] = 1
    head[8 + NBLOCKS - 1] = 1
    payload = _chain(b"ciso-block0", BLOCK) + tail
    if not short:
        payload += bytes(BLOCK - tail_size)
    path = tmp_path / ("short.ciso" if short else "full.ciso")
    path.write_bytes(bytes(head) + payload)
    return path, tail


def test_final_slot_is_a_full_block_like_wit(tmp_path):
    """The final slot is a whole block — the layout wit writes and reads.

    Settled by construction rather than observation: wit scrubs the disc
    tail on every real image (block 2233 is the highest ever seen present
    across three full-size Wii ISOs), so no staged sample reaches block
    2241. See the ciso module docstring for the wit-side proof.
    """
    path, tail = _final_block_ciso(tmp_path, short=False)
    view = normalize_ciso(path)
    assert view.source.size() == TOTAL
    assert view.source.read_at((NBLOCKS - 1) * BLOCK, len(tail)) == tail
    # The slot's remaining 1,835,008 bytes are block padding past the end
    # of a single-layer disc; wit emits them, this view does not.
    with pytest.raises(ValueError, match="out of bounds"):
        view.source.read_at(TOTAL - 1, 2)


def test_short_final_slot_refused_like_wit(tmp_path):
    """A final slot stored at the block's disc extent instead of a whole
    block is not a wit CISO — wit dies with ERROR #84 in ReadCISO(),
    asking for a full block at the slot base."""
    path, _ = _final_block_ciso(tmp_path, short=True)
    with pytest.raises(ValueError, match="inside slot"):
        normalize_ciso(path)


def test_trailing_garbage_refused(tmp_path):
    def f(data):
        return data + b"JUNKJUNKJUNK"
    problems = _checks(_write_bad(tmp_path, f))
    assert_structural_failure(problems, "neither EOF nor an NKit recovery trailer")


def test_nkit_trailer_tolerated(tmp_path):
    """An appended NKit recovery trailer changes neither the decoded view
    nor the manifest, so the four-check gate stays green."""
    good = (FIXTURE / "game.ciso").read_bytes()
    staged = tmp_path / "with_trailer.cso"
    staged.write_bytes(good + b"NKIT" + bytes(0x23C))
    assert _checks(staged) == []


# --- gate mutants (the checks that bite) ----------------------------------


def test_flipped_payload_byte_fails_fidelity(tmp_path):
    """A flipped byte inside a slot-0 file extent dies at check 4, not at
    enumeration — the off-by-one-slicing class the gate exists for."""
    doc = json.loads((FIXTURE / "expected.manifest.json").read_text("ascii"))
    entry = min((e for e in doc["entries"] if e["kind"] == "file"), key=lambda e: e["path"])
    at = 0x8000 + entry["offset"] + min(8, entry["size"] - 1)  # slot 0 base
    problems = _checks(_write_bad(tmp_path, _mutate_byte(at, 0xFF)))
    assert problems and problems[0].startswith("fidelity:"), problems


def test_flipped_slot1_byte_serves_wrong_bytes(tmp_path):
    """A flipped byte in slot 1 (block 2's payload, outside the iso9660
    volume) is invisible to the tree walk — the direct view read catches
    what enumeration cannot."""
    view = normalize_ciso(
        _write_bad(tmp_path, _mutate_byte(0x8000 + BLOCK + 5, 0xFF))
    )
    got = view.source.read_at(2 * BLOCK, 32)
    assert got != _chain(b"ciso-synthetic-block2", 32)


# --- gitignored retail-anchor proof ---------------------------------------


def test_luigi_metadata_manifest_is_valid():
    """Committed metadata remains useful when the retail drop is absent."""
    schema = json.loads((ROOT / "schema" / "manifest.schema.json").read_text("utf-8"))
    doc = json.loads((RETAIL_FIXTURE / "expected.manifest.json").read_text("ascii"))
    jsonschema.Draft202012Validator(schema).validate(doc)
    assert doc["format"] == "ciso"
    assert doc["source"] == {
        "name": "Luigi's Mansion (USA, Canada).ciso",
        "sha256": RETAIL_VIEW_SHA256,
        "size": TOTAL,
    }
    assert doc["tool_versions"] == RETAIL_TOOLS
    files = [e for e in doc["entries"] if e["kind"] == "file"]
    dirs = [e for e in doc["entries"] if e["kind"] == "dir"]
    assert (len(files), len(dirs)) == (847, 64)
    assert "Ajioka/ADemo/codemo01.szp" in {e["path"] for e in files}


@skip_if_no_retail_anchor
def test_luigi_retail_anchor_is_green():
    """The wit-authored manifest + extraction pass the four-check gate."""
    assert run_checks(
        _normalize_retail_ciso_to_tree,
        RETAIL_CSO,
        RETAIL_FIXTURE / "expected.manifest.json",
        RETAIL_REFERENCE,
        RETAIL_CSO.name,
        RETAIL_VIEW_SHA256,
        RETAIL_TOOLS,
    ) == []


@skip_if_no_retail_anchor
def test_luigi_carrier_and_view_identity():
    """Carrier fixity + the parser's view hash equals the stager's
    independently placed view hash over the whole address space."""
    assert sha256_of(RETAIL_CSO) == RETAIL_CSO_SHA256
    view = normalize_ciso(RETAIL_CSO)
    assert _sha256_source(view.source) == RETAIL_VIEW_SHA256
    assert view.source.read_at(0, 6) == b"GLME01"


@skip_if_no_retail_anchor
def test_luigi_wit_decode_agrees_with_junk_scrub_characterized(tmp_path):
    """wit's own decode of the same container agrees byte-exact on every
    present block except the two junk-bearing ones, where every difference
    is wit zeroing original junk (one-directional, never inside files —
    the per-file gate above carries that proof)."""
    view = normalize_ciso(RETAIL_CSO)
    with RETAIL_CSO.open("rb") as fh:
        head = fh.read(0x8000)
    present = [i for i in range(NBLOCKS) if head[8 + i] == 1]
    wit_iso = tmp_path / "luigi_wit.iso"
    _wit_copy(RETAIL_CSO, wit_iso)
    with wit_iso.open("rb") as wit_fh:
        for slot, block in enumerate(present):
            wit_fh.seek(block * BLOCK)
            want = wit_fh.read(BLOCK)
            got = view.source.read_at(block * BLOCK, BLOCK)
            if block in WIT_SCRUBBED_BLOCKS:
                diffs = [i for i in range(BLOCK) if got[i] != want[i]]
                assert diffs, f"block {block}: expected characterized junk diffs"
                assert all(got[i] != 0 and want[i] == 0 for i in diffs), (
                    f"block {block}: non-junk difference at +{diffs[0]:#x}"
                )
            else:
                assert got == want, f"block {block}: wit decode disagrees"
        for block in (2, 300, 603, 697, 2240, 2241):
            if block in present:
                continue
            want_len = min(BLOCK, TOTAL - block * BLOCK)
            wit_fh.seek(block * BLOCK)
            assert wit_fh.read(want_len) == bytes(want_len), (
                f"absent block {block} nonzero in wit decode"
            )


@skip_if_no_hulk_or_wit
def test_wit_authored_ciso_round_trips(tmp_path):
    """wit writes a CISO from the staged Hulk retail ISO; our decode and
    wit's decode of it agree byte-exact over the entire address space (no
    junk caveat — wit authored the container, so its scrub already
    happened at write time). Proves the parser against the reference
    implementation on a wit-authored file."""
    assert sha256_of(HULK_ISO) == HULK_SHA256
    ciso = tmp_path / "hulk.ciso"
    _wit_copy(HULK_ISO, ciso)
    view = normalize_ciso(ciso)
    rt = tmp_path / "hulk_rt.iso"
    _wit_copy(ciso, rt)
    pos = 0
    with rt.open("rb") as wit_fh:
        while pos < TOTAL:
            take = min(CHUNK, TOTAL - pos)
            assert view.source.read_at(pos, take) == wit_fh.read(take), (
                f"wit-authored round-trip disagrees at {pos:#x}"
            )
            pos += take
