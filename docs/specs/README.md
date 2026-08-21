# Unit design specs — partial, early units only

Seven pre-implementation design notes written for units 2–8 between
2026-07-22 and 2026-07-24, when the per-unit workflow still produced a
written spec before the code. That practice stopped after `xdvdfs`; the
sixteen units built since (`3ds-*`, the Wii chain, `zip`, `rvz`, `gcz`,
`wbfs`, `nkit`, `ciso`, `3ds-romfs`) have **no spec here** and are not
missing anything — their design rationale lives where it is maintained:

- **`NORMALIZERS.md`** — the per-unit row: format bounds, fixture plan,
  pinned differential tool and version, proof obligations, refusals.
- **The module docstring** — layout, the load-bearing findings, and the
  scope the unit deliberately does not cover.
- **`DESIGN.md`** — the frozen contract every unit binds to.

So this directory is a historical record, not a reference set, and not a
template for new work. Read `NORMALIZERS.md` first; come here only for the
seven units named in the filenames, and expect the module docstring to be
newer where the two disagree.

(These files previously sat under `docs/superpowers/`, a directory named
after the agent harness that generated them. Moved 2026-08-21 — the
tooling that produced a document is not a useful way to file it.)
