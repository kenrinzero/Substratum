"""Repo-wide encoding conformance: UTF-8 everywhere, LF outside `reference/`.

`AGENTS.md` and the atelier charter both require UTF-8 with LF. Nothing
checked it, and `.gitattributes` sets `* -text` — correct for a repo whose
premise is byte-exactness, but it means Git will never normalize on checkout
or check-in, so whatever line endings get committed are permanent. Twenty-one
tracked text files had drifted to CRLF, most of them written by
`Path.write_text`, which maps ``\\n`` to the platform newline on Windows.

The `reference/` exemption is load-bearing, not a loophole. Those files are
the independently-extracted bytes that gate check 4 diffs entry payloads
against. Their line endings are whatever the source medium holds — the PS1
`SYSTEM.CNF` files and the SuperTux `.STL` levels are genuinely CRLF inside
the ISO — so "normalizing" them would falsify the oracle and turn a passing
fidelity check into a lie.
"""

from __future__ import annotations

import ast
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _tracked() -> list[Path]:
    out = subprocess.run(
        ["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout
    return [ROOT / line.strip() for line in out.split("\n") if line.strip()]


def _is_text(raw: bytes) -> bool:
    """Text = UTF-8 decodable, NUL-free, and actually line-terminated.

    A binary fixture can hold a CR LF byte pair by coincidence; that is not a
    line-ending problem, and this repo is mostly binary fixtures.
    """
    if b"\x00" in raw or not raw:
        return False
    try:
        raw.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return b"\n" in raw


TRACKED = _tracked()
TEXT = [p for p in TRACKED if p.is_file() and _is_text(p.read_bytes())]
SOURCE = [p for p in TEXT if "reference" not in p.relative_to(ROOT).parts]


def _rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def test_the_sweep_actually_finds_files():
    """Guard against a `git ls-files` that returns nothing and passes vacuously."""
    assert len(TRACKED) > 500, len(TRACKED)
    assert len(SOURCE) > 60, len(SOURCE)


def test_every_tracked_file_that_decodes_as_text_is_utf8():
    """`_is_text` already requires UTF-8, so this asserts the complement: no
    tracked file is *almost* text — decodable but for a stray byte.
    """
    bad = []
    for p in TRACKED:
        if not p.is_file():
            continue
        raw = p.read_bytes()
        if b"\x00" in raw or p.suffix.lower() not in {
            ".md", ".py", ".toml", ".json", ".cue", ".txt", ".cfg", ".yml", ".yaml"
        }:
            continue
        try:
            raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            bad.append(f"{_rel(p)}: {exc}")
    assert bad == [], bad


@pytest.mark.parametrize("path", SOURCE, ids=_rel)
def test_source_and_docs_use_lf_line_endings(path):
    raw = path.read_bytes()
    assert b"\r\n" not in raw, (
        f"{_rel(path)} has CRLF line endings. `.gitattributes` sets `* -text`, "
        "so Git will never normalize this — it stays CRLF until converted "
        "deliberately. If a seedtool wrote it, use `write_bytes` rather than "
        "`write_text`, which maps \\n to the platform newline on Windows."
    )
    assert b"\r" not in raw, f"{_rel(path)} contains a lone CR"


def test_reference_bytes_are_exempt_and_still_hold_their_original_endings():
    """The exemption is real, so prove it is doing something: at least one
    `reference/` file is CRLF and must stay that way. If this ever fails,
    someone has "normalized" an oracle — check `git log` for the file before
    assuming the fixture is fine.
    """
    crlf_refs = [
        _rel(p)
        for p in TEXT
        if "reference" in p.relative_to(ROOT).parts and b"\r\n" in p.read_bytes()
    ]
    assert crlf_refs, (
        "no reference file carries CRLF any more — the PS1 SYSTEM.CNF and "
        "SuperTux .STL levels should. Verify none were rewritten."
    )


def test_no_generator_writes_text_with_platform_newline_translation():
    """Root cause, not symptom.

    `Path.write_text` and `open(..., "w")` translate ``\\n`` to the platform
    newline unless `newline=""` is passed explicitly, which is how thirteen
    text artifacts in this repo became CRLF. AST-based rather than
    line-matching, so a call split across lines cannot slip through and a
    correctly-guarded one (`vendor_tools`' `newline=""` config patch) is not
    a false positive.
    """
    offenders = []
    for p in sorted((ROOT / "seedtools").rglob("*.py")) + sorted(
        (ROOT / "substratum").rglob("*.py")
    ):
        if "__pycache__" in str(p):
            continue
        tree = ast.parse(p.read_text(encoding="utf-8"), filename=str(p))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            if node.func.attr not in {"write_text", "open"}:
                continue
            if node.func.attr == "open":
                mode = next(
                    (
                        a.value
                        for a in node.args[:1]
                        if isinstance(a, ast.Constant) and isinstance(a.value, str)
                    ),
                    "",
                )
                if "w" not in mode and "a" not in mode:
                    continue
                if "b" in mode:
                    continue
            if any(kw.arg == "newline" for kw in node.keywords):
                continue  # translation explicitly disabled
            offenders.append(f"{_rel(p)}:{node.lineno} .{node.func.attr}(...)")
    assert offenders == [], (
        "these writes translate newlines on Windows; use write_bytes(...) or "
        f'pass newline="": {offenders}'
    )
