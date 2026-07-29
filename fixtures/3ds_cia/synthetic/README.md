# Synthetic CIA fixture

Authored by `seedtools/make_3ds_cia_fixture.py`. A minimal two-content CIA
with a valid CiaHeader + TMD whose content-chunk records carry each content
blob's SHA-256 — the independent correctness anchor.

No crypto: the ticket's title key is a zero stub, the TMD RSA signature is
zero, and the content blobs are deterministic plaintext. This exercises the
normalizer's section-table parsing, 64-byte alignment, multi-content splitting,
and the TMD content-hash anchor — without any retail bytes or keys.

## Shape

- `game.cia` — 12,992 bytes; two content blobs (index `0x0000` @0x2C80/0x400,
  index `0x0001` @0x3080/0x200), each followed by 64-byte alignment padding.
- Sections: `header.bin` (0x2020) · `cert.bin` (0x80) · `ticket.bin` (0x40) ·
  `tmd.bin` (0xB64) · `content.0000.ncch` · `content.0001.ncch` ·
  `footer.bin` (0x40).
- `expected.manifest.json` and `reference/` are derived from this seedtool's
  own layout (independent of the runtime parser).

Re-generate with `uv run python seedtools/make_3ds_cia_fixture.py`.
