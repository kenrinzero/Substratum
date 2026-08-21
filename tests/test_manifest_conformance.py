"""Repo-wide conformance sweep over every committed fixture manifest.

Each unit's own module validates *its* manifest against
`schema/manifest.schema.json`. Nothing validated the set, so the two
document types drifted apart under one filename: 27 of 33 committed
`expected.manifest.json` files were canonical manifests that
`verify.run_checks` check 2 byte-compares, and six were hand-written
provenance records for the keyed retail anchors using `sections` /
`regions` / `samples` instead of `entries`. The schema declares
`additionalProperties: false`, so those six were invalid rather than
extended, and a consumer globbing the tree for `d["entries"]` would
KeyError on them.

The six now live under `anchor.json`. These tests keep the split honest:
`expected.manifest.json` means exactly one thing, `anchor.json` means the
other, and neither can quietly become the other again.
"""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "fixtures"
SCHEMA = json.loads((ROOT / "schema" / "manifest.schema.json").read_text("utf-8"))

MANIFESTS = sorted(FIXTURES.rglob("expected.manifest.json"))
ANCHORS = sorted(FIXTURES.rglob("anchor.json"))


def _rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def test_the_sweep_actually_finds_manifests():
    """Guard against a glob that silently matches nothing."""
    assert len(MANIFESTS) >= 25, [_rel(p) for p in MANIFESTS]
    assert len(ANCHORS) >= 6, [_rel(p) for p in ANCHORS]


@pytest.mark.parametrize("manifest", MANIFESTS, ids=_rel)
def test_every_expected_manifest_validates_against_the_schema(manifest):
    """DESIGN.md section 2: the manifest is the downstream handoff shape, and
    the schema is normative for it. A file named `expected.manifest.json`
    must be one.
    """
    doc = json.loads(manifest.read_text("utf-8"))
    jsonschema.Draft202012Validator(SCHEMA).validate(doc)


@pytest.mark.parametrize("manifest", MANIFESTS, ids=_rel)
def test_every_expected_manifest_is_canonically_serialized(manifest):
    """Check 2 byte-compares the emitted manifest against these files, so a
    committed manifest that is not in `canonical_manifest`'s exact
    serialization can never match: sorted keys, entries sorted by path,
    ensure_ascii, compact separators, one trailing newline.
    """
    raw = manifest.read_bytes()
    doc = json.loads(raw.decode("ascii"))
    canonical = json.dumps(
        doc, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    )
    assert raw == (canonical + "\n").encode("ascii"), (
        f"{_rel(manifest)} is not in canonical serialization"
    )
    paths = [e["path"] for e in doc["entries"]]
    assert paths == sorted(paths), f"{_rel(manifest)} entries are not path-sorted"


@pytest.mark.parametrize("anchor", ANCHORS, ids=_rel)
def test_every_anchor_record_is_not_a_canonical_manifest(anchor):
    """The other half of the split. An `anchor.json` is a free-form
    provenance record for a keyed retail fixture — it carries the oracle
    rationale and identity fields the schema forbids. If one ever validates
    as a canonical manifest it should have been named `expected.manifest.json`
    instead, and the gate should be byte-comparing it.
    """
    doc = json.loads(anchor.read_text("utf-8"))
    validator = jsonschema.Draft202012Validator(SCHEMA)
    assert list(validator.iter_errors(doc)), (
        f"{_rel(anchor)} validates as a canonical manifest — "
        "name it expected.manifest.json and wire it into the gate"
    )
    assert "entries" not in doc, (
        f"{_rel(anchor)} carries an `entries` list; that is manifest shape"
    )


def test_no_fixture_directory_holds_both_document_types():
    """A directory with both names would leave it ambiguous which one the
    unit's gate consumes.
    """
    both = [
        _rel(m.parent)
        for m in MANIFESTS
        if (m.parent / "anchor.json").is_file()
    ]
    assert both == [], f"fixture dirs holding both document types: {both}"
