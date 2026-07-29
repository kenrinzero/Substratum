# Mini Sports Collection (USA) — 7.x-seed second anchor

Same 7.x-seed crypto variant as BoxBoxBoy! (title ID `00040000001b6e00`,
product code `CTR-N-KTNE`, `> Crypto Key Secure (1) (KeyY seeded)`). Staged as
a **second** anchor to catch variant-specific bugs: two independent titles
decrypting byte-identically to ctrtool's reference is stronger evidence than
one. See [`../boxboxboy/README.md`](../boxboxboy/README.md) for the full
provenance and anchor mechanics.

Staged with:
`uv run python seedtools/stage_3ds_ncch_enc_seed_retail_anchor.py "fixtures/_local/Mini Sports Collection (USA) (eShop).cia" mini-sports`
