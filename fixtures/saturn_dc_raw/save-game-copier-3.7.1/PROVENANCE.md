# Slinga Save Game Copier 3.7.1

This is a DESIGN §5 tier-2, openly licensed Saturn homebrew anchor.

- Project: Slinga Save Game Copier
- Release: 3.7.1, published 2026-05-14
- Release page: https://github.com/slinga-homebrew/Save-Game-Copier/releases/tag/3.7.1
- Source tag commit: `59e80b5617982b40ba48e422a448596439475708`
- License: GPL-3.0; the exact upstream `LICENSE` is committed beside this file
- Upstream asset: `game.iso`, 843,776 bytes
- Upstream and local SHA-256: `e1832e07d4e8273f0db45bcd61fbacffac21468554f87c328619a66a5f4871a8`
- Upstream `LICENSE` SHA-256: `3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986`

The release is a cooked single-track MODE1/2048 ISO, so
`seedtools/stage_saturn_homebrew_anchor.py` converts it into a raw
2352-byte Mode-1 stream. Pinned UNECM reconstructs EDC, the reserved
field, and P/Q ECC for every sector. Pinned ECM then independently
classifies the result as 412 Mode-1 sectors, zero literal bytes, zero
Mode-2 sectors, and a canonical ECM/UNECM round-trip must preserve every
raw byte.

- Raw artifact: `game_2352.bin`, 969,024 bytes (412 sectors)
- Raw SHA-256: `8392e7d6f6e9606ba91b502191dc0ee9972fbd729e41697c26a098e35f7a239e`
- ECM project/release: https://github.com/kidoz/ecm/releases/tag/v1.3.1
- ECM release asset SHA-256: `c480d5535580cd776cc4b7928cc77d02919b1d1ff19adb45f600a82ff83823a4`
- ECM source tag commit: `e5cea4e6795cfc5612953c8b9c0ec300a66f2b48`
- `ecm.exe` SHA-256: `1d5e5eef9bbaa84cd32dd4a4eacd9a6274e66a5a2e09c5804e4b4c6264ec9819`
- `unecm.exe` SHA-256: `eda85f9a7b49dd55d918bce80b862a69650a0f7497b94c89b0fa8f395228d545`
- Tool banner: `v1.3.0` from the pinned `v1.3.1` release asset

The expected manifest is independently authored from pycdlib 1.16.0
records and cross-checked against 7-Zip 26.02. The committed `reference/`
bytes are 7-Zip's extraction, not bytes read through Substratum.
