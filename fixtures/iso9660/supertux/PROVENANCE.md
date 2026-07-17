# supertux.iso — provenance

- **What:** SuperTux Milestone 1 PS2 port ("Milestone 1 - CD comfort"),
  bootable PS2 CD image — a real third-party-mastered ISO9660 disc
  (DESIGN.md § 5 tier 2, the symmetric-bug antidote).
- **Upstream:** https://github.com/headshot2017/supertux-ps2
  release **v0.1.1a** (2022-04-05), asset `supertux-ps2-cd.zip`
  (8,919,511 bytes, sha256
  `27829aaf15efc44744c9e55b758407f4d96386d2707659e2995e821aa04da9e0`),
  fetched 2026-07-17.
- **This file:** `supertux.iso`, the zip's sole member — 21,823,488
  bytes, sha256
  `d1c71407242ce8802af7b3599719a8f34e6f8a534746ced7b0df491dcd29c0c4`
  (also recorded in `expected.manifest.json`).
- **License:** GPL-2.0 — the repo's license field and its root `COPYING`;
  upstream SuperTux Milestone 1 code and assets are GPL, so the whole
  disc is redistribution-clean and committed (not `fixtures/_local/`).
- **Staged by:** `seedtools/stage_homebrew_iso.py` (pycdlib records
  cross-checked against 7-Zip's listing; reference bytes are 7-Zip's
  extraction). 779 files / 17 dirs; fidelity sampling uses the default
  seed 1.
