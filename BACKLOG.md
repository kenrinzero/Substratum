# Substratum — backlog (Kenrin-paced; one normalizer per session)

Substratum is the normalization foundation for the Spolia program. Its
contract is frozen: each unit adds exactly one container/filesystem layer and
proves it with the four-check gate, including independent differential
byte-range fidelity where available.

## Current boundary

Version **0.0.27** is clean (the `ciso` sibling unit landed 2026-08-21,
after `nkit` on 0.0.26, `wbfs` on 0.0.25, `gcz` on 0.0.24 over a
shared-DolphinTool refactor, `rvz` on 0.0.23, `chd` retail closure on
0.0.22, `3ds-romfs` on 0.0.21 and `zip` on 0.0.20). **24 normalizers**
are GREEN:
the keyless/decrypted floor, the complete Wii chain, the CIA container, the
full 3DS encrypted-NCCH family — standard + plain-7.x crypto (`3ds-ncch-enc`,
no-seed `{0x00, 0x01}`), 7.x-seed (`3ds-ncch-enc-seed`), and New3DS 9.6
(`3ds-ncch-enc-96`, pure-Python AES-CTR, `0x0B`/`0x1B`). The 9.6 unit bypasses
vendored ctrtool entirely and implements the **two-key NCCH model**
(exheader/ExeFS-superblock/ExeFS-tail = Key0/`0x2C`; `.code`+RomFS =
Key1/`0x1B`). The `rvz` unit closes the GC+Wii gap via `DolphinTool 2606a` (`GT Cube` 661 files + `Ghost Squad` 2 partitions, `wit` second reader; `zip → rvz → gc-fst` now covers 2,573 titles). The `chd` unit is now closed through the retail proof gate —
DVD-type PSP CHD extractdvd + iso9660 walks clean, and CD-type PS1 CHD
composes all the way through `chd → ps1-bincue → iso9660` end-to-end on real
retail images (BursTrick round-trip; the `_TempFileSource.path` exposure makes
sibling `.cue` discovery work in the composed path). **Next: nothing — the queue is empty.** The `wux` / Wii U platform call
was **resolved 2026-08-21 (user decision): out of scope for Substratum**,
split as a future standalone project — the chain assessment lives at
`.atelier/ideas/wii-u.md` (the staged Your Shape sample was removed from
the operator staging area, sha256 recorded in the idea file).
New3DS 9.3 (`0x0A`/`0x18`) was **removed 2026-08-21 by user decision** —
the code path falls out of the 9.6 module for free, but a genuine `0x0A`
retail anchor is realistically unsourceable and not worth chasing; it
would only return if full-corpus download capacity ever exists. The
durable lesson stays (a title's firmware requirement is unrelated to its
NCCH crypto method): see
[`docs/3DS-KEYED-WORK.md`](docs/3DS-KEYED-WORK.md) § "CORRECTION
(2026-07-30)" and the two-key finding in
[`docs/3DS-PURE-PYTHON-AES-CTR-PLAN.md`](docs/3DS-PURE-PYTHON-AES-CTR-PLAN.md).

## Done

- [x] **Foundation contract and gate:** frozen `ByteSource` / `ByteView` /
      `FileTree` interface, manifests, fixture policy, and four-check
      verification gate (`DESIGN.md`, `schema/`, `substratum/verify.py`).

- [x] **Keyless/decrypted normalizer floor:** 11 GREEN units — `iso9660`,
      `gc-fst`, `chd`, `ps1-bincue`, `saturn/dc-raw`, `cso`, `wii-u8-arc`,
      `xdvdfs`, `3ds-cci`, `3ds-ncch`, and `wii-disc`.

- [x] **Wii partition decode (`wii-partition`):** pure-Python AES-128-CBC
      (NIST SP 800-38A anchored) decrypts the title key and cluster payloads
      into a lazy `ByteView`; synthetic generated-key fixture + wit-extracted
      retail proof against The Munchables. Standard common key supplied
      locally and never committed.

- [x] **Wii decrypted FST (`wii-fst`):** walks the decrypted DATA-partition
      `ByteView` into a `FileTree`. Completes the Wii chain:
      `wii-disc` → `wii-partition` → `wii-fst`.

- [x] **Encrypted 3DS NCCH (`3ds-ncch-enc`):** ctrtool-at-runtime decrypts
      standard-encrypted NCCH content into a decrypted `ByteView` the caller
      composes through `three_ds_ncch` (the `chd`→`iso9660` pattern applied to
      3DS). Genuine two-party differential: ctrtool-decrypt vs 3dstool-decrypt
      on the Biohazard Mercenaries 3D anchor (byte-identical regions); NCCH
      protected hashes are the independent correctness anchor. Standard crypto
      only; 7.x/9.3/seed refused.

- [x] **CIA install container (`cia`):** parses the header-driven section table
      and exposes each section (header/certs/ticket/tmd/content blobs/footer)
      as an opaque slice. Full multi-content support; the TMD content-chunk
      records' declared SHA-256 is the correctness anchor (on-media for
      unencrypted chunks; titlekey-decrypted for CDN-encrypted eShop CIAs).
      Completes the 3DS stack from outer container to decrypted NCCH regions.

- [x] **7.x-seed encrypted NCCH (`3ds-ncch-enc-seed`):** decrypts
      `Secure (1) (KeyY seeded)` NCCH content inside a CIA via vendored ctrtool
      (7.x keyslot `0x25` compiled in) + the operator-supplied seeddb. Consumes
      a whole CIA (the variant encrypts the NCCH header itself, so a raw slice
      can't be decrypted). Two retail anchors: BoxBoxBoy + Mini Sports.

- [x] **Plain-7.x encrypted NCCH (`3ds-ncch-enc` widening):** widened the
      no-seed scope of `3ds-ncch-enc` to accept `ncchflag[3]` in `{0x00, 0x01}`
      — standard crypto (`0x2C`) plus plain-7.x (`Secure (1)` no-seed, keyslot
      `0x25`). Plaintext header (unlike 7.x-seed), so slice-decryptable from a
      CCI via `3ds-cci`. Retail anchor: Kobayashi (CCI). Load-bearing finding:
      ctrtool and 3dstool agree on `.code`/`icon`/`plain`/`logo`/`exheader`/
      `romfs` content; 3dstool strips a ~207-byte banner signature region that
      ctrtool preserves (documented tooling difference, not a decrypt
      disagreement).

- [x] **9.3 anchor hunt (investigation, 2026-07-30):** confirmed genuine
      `0x0A`-crypto titles are effectively lost media. Three database-"9.3"
      eShop candidates (Adventure Bar Story, Shin Hyu Stone, 3D Gunstar
      Heroes) all qualified as `ncchflag[3]==0x01` (one plain-7.x, two
      7.x-seed) — i.e. already-covered variants. **Load-bearing lesson: a
      title's firmware requirement is unrelated to its NCCH crypto method.**
      "9.3" in title databases usually means the *required FW*, not the
      keyslot; a late-shipping title can require FW 9.3+ yet still ship 7.x
      (`0x01`) crypto. Read ctrtool `-v`'s `Flags:` 4th byte (`00`/`01`/`0A`/
      `0B`), never the firmware version.

- [x] **Proof and hardening pass:** independent-tool differential checks,
      retail/homebrew anchors, path and header rejection, streaming and
      memory-discipline protections, and pinned tool versions are recorded in
      `NORMALIZERS.md` and the archived project log.

- [x] **New3DS 9.6 encrypted NCCH (`3ds-ncch-enc-96`):** pure-Python AES-128-CTR
      (NIST SP 800-38A F.5.1 anchored) + the 3DS hardware key-generator decrypt
      no-seed `0x0B` NCCH content, bypassing vendored ctrtool v1.3.0 (which
      cannot decrypt keyslot `0x1B`). Retail anchor: Fire Emblem Warriors (USA)
      `.3ds`. **Load-bearing finding — the two-key NCCH model:** a 9.6 NCCH uses
      TWO normal keys derived from the same keyY but different keyX slots —
      Key0 (`0x2C`) encrypts the extended header, the ExeFS superblock, and the
      ExeFS tail; Key1 (`0x1B`) encrypts the first ExeFS file (`.code`) and the
      entire RomFS. The ExeFS is one continuous CTR stream whose key switches
      mid-stream. The protected-hash gate caught the naive "one key per region"
      assumption before commit. The committed synthetic (generated test keys)
      exercises the real decrypt path + the ExeFS key split — a stronger
      synthetic than standard-crypto's (which could only author a decrypted
      image). No-seed 9.6 only this unit; seeded-9.6 and 9.3 are the same code
      path once an anchor exists.

## Next (in dispatch order)

- [x] **Wii partition read performance — decrypt-once / caching source
      (consumer request from Stratum, 2026-08-14; DONE same day):** the
      decrypted Wii-partition `ByteView` re-decrypts on every `read_at`, and
      pure-Python AES runs ~0.5 MiB/s, so a census that reads one header per
      file over Mario Kart Wii's data partition (2007 files) took **133 s**
      (re-measured 139.4 s), and any detector that walks structure with
      multi-read access (e.g. a Yaz0 chunk walk) would take hours. **Root
      cause found during the fix: every `read_at` decrypted a whole 0x7C00
      cluster (1,984 AES blocks ≈ 70 ms) even for a 4-byte header read.**
      Fix (key-schedule memoization + block-granular CBC): CBC *decryption*
      chains through ciphertext, so a read decrypts exactly its own 16-byte
      blocks (the preceding ciphertext block serves as the XOR IV; the
      cluster-header IV seeds only block 0), and the AES key schedule is
      expanded once per source (`_aes.expand_key` +
      `cbc_decrypt_blocks` are the new public primitives, NIST-anchored).
      Plus the explicit **`materialize()` decrypt-once spool** (temp-file
      `ByteView`, context-managed, idempotent close, `weakref.finalize`
      fallback) for bulk consumers. The old 4-cluster LRU was removed —
      block-granular reads make it strictly dominated (a repeated read
      costs only its own blocks). **Benchmark: the 2007-file MKWii census
      dropped 139.4 s → 0.61 s (228×)**; scattered small reads now read
      ≤ their own blocks from the parent (test-enforced). Sequential bulk
      throughput is data-bound and unchanged (~0.5 MiB/s: a 3.4 MB
      `.szs` reads in ~7 s; the one-time `materialize()` spool of a 4.4 GB
      partition costs the same ~2.4 h single-threaded and serves plain
      reads after). Context: Stratum BACKLOG, Unit 3 "Separate track
      (Substratum, not Stratum)".

- [x] **iso9660 both-endian extent-location mismatch (RE4 PAL, consumer
      report from Stratum, 2026-08-14; DONE same day):** the staged
      `SLES_537.02.Resident Evil 4.iso` failed
      `normalize(format="iso9660")` with "both-endian extent location
      mismatch: LE 1542097 != BE 1792". Characterization: the disc (a 2021
      re-master, volume id `20210823_211414`, filename
      `RIPADO_POR_LEGADO_GAMES_PARA_M.`) carries exactly **one corrupt
      record** — `IOPRP.IMG;1` — whose *little-endian* fields are garbage
      (extent LE = the volume space itself; size LE diverges) while the
      big-endian pair is the only structurally possible one. Even 7-Zip
      26.02 errors on this disc. Fix: `_record_extent_and_size` — when the
      byte orders disagree, trust the side whose (extent, size) pair is
      possible in this source (evaluated in track-relative space so the GD
      `lba_base` composition stays consistent), taking that side's size
      too; a both-plausible (or neither-possible) disagreement still
      refuses — ambiguity is never guessed away. TDD: single-sided
      corruption mutates to the identical FileTree; both-plausible and
      both-impossible stay structural reds. Retail proof: RE4 walks to 9
      files (`IOPRP.IMG` at extent 1792/size 275,345 — the BE pair).
      Consumer result recorded for Stratum: RE4 = `cri.afs` 2 hits
      (`BIO4MOV.AFS`, `BIO4MOV2.AFS`), zero loose ADX (its `(c)CRI` are
      AFS-packed) — so RE4 is an **afs** publisher-diversity upgrade
      (Capcom), not the adx one. Open curiosity noted: `BIO4DAT.AFS` did
      not fire — outside this unit's scope.

- [x] **saturn-dc-raw rejects the Dreamcast GD-ROM high-density area (consumer
      request from Stratum, 2026-08-14; DONE same day):** the staged Sonic
      Adventure 2 GDI set's data track (`track03.bin`, 504,200 raw sectors,
      data track at LBA 45000 per the `.gdi`) failed
      `normalize(format="saturn-dc-raw")` at **sector 404850** with
      "invalid BCD minute 0xa0". **Empirical characterization (probe over
      the whole track): addresses run contiguously from absolute MSF
      10:02:00 (= LBA 45,000 + the 150-frame pregap); BCD holds to the last
      representable 99:59:74 at sector 404,849, then minute 100 continues
      the BCD pattern with hexadecimal tens digits — 0xA0 = 100 … 0xC2 =
      122 at the track end.** Fix: the minute's high nibble may now be
      0xA–0xF (seconds/frames stay strict BCD; the low nibble stays ≤ 9);
      per-sector MSF contiguity remains the structural gate, and genuine
      Saturn media tops out at 99:59:74 so the relaxation cannot fire
      there. TDD: minute-100 continuation accepted (user stream
      byte-identical), hex-minute at a wrong position still refused
      (contiguity), invalid low nibble still refused; the pre-existing
      0xFA red test is unchanged. Verified on the real track: the eager
      pass now validates all 504,150 sectors. **Follow-up gap found while
      proving the composition (→ new ask below): `iso9660` cannot walk
      SA2's inner filesystem yet.**

- [x] **iso9660 cannot walk the SA2 GD-ROM filesystem (consumer request
      from Stratum, 2026-08-14, found while proving the DC-gap fix; DONE
      same day):** the PVD parsed but its root record claimed extent
      45,020 where bytes were high-entropy. Byte-exact diagnosis: **not
      poison — a mastering convention. Dreamcast GD-ROM data tracks are
      mastered with ISO9660 extent locations DISC-ABSOLUTE** (the data
      track begins at LBA 45,000): on the staged SA2 dump every extent —
      PVD root record, both path tables, every directory record's
      self/parent/child references — carries exactly +45,000, while the
      descriptor set sits track-relative at sectors 16-17 and the volume
      space stays the track size. The base is self-described by the
      track's own sector-0 address (MSF 10:02:00 = frame 45,150). Fix:
      `normalize_iso9660(source, *, lba_base=0)` translates extent
      locations uniformly (default 0 keeps every existing image
      byte-for-byte unchanged; an extent below the declared base is a
      structural red, never a silent misread), and
      `saturn_dc_raw.lba_base(track)` derives the base from the sector-0
      address (0 for Saturn CDs at 00:02:00). Committed mutation proof: a
      GD-style re-master of the synthetic fixture (all extents +45,000,
      origin 10:02:00) walks to the *identical* FileTree via the
      composition. Retail proof: SA2 composes to **2,572 files in ~1 s**
      (`1ST_READ.BIN` present; 137 loose `.ADX` — the disc's 11,240 raw
      `(c)CRI` are mostly Sofdec `.SFD`-embedded audio), and Stratum's
      full registry sweep over it returns **`cri.adx`=137 +
      `cri.afs`=3** — the consumer unblock this ask existed for. Unblocks
      Stratum's `cri.adx` 2nd positive (its measurement is Stratum's next
      session) and Quarry's spare-ADX enumeration.

- [x] **`xdvdfs` reads a real Xbox disc — retail proof completed on Jade
      Empire (consumer request from Stratum, 2026-08-20; resolved 2026-08-20):**
      the unit is now proven against the independent `xdvdfs-rs 0.9.0`
      oracle on a real XGD1 image (`fixtures/_local/Jade Empire (Japan).iso`),
      with the descriptor at `0x18310000` and the game partition base at
      `0x18300000` (`base_offset=0x18300000`). The parser matches the oracle's
      tree and extracted file bytes, including the embedded non-zero base
      offset and the 4-byte dword LCRS counts. The row was reclassified to
      **GREEN** only after the independent comparison and the pinned oracle
      version were recorded; the real disc and extracted references remain
      local-only and are never committed to git. This unblocks the same
      `bink.video` path the backlog called out, without broadening beyond the
      `xdvdfs` normalizer scope.

- [x] **`chd` two bugs — DVD-type CHDs crash, CD-type CHDs lose their cue
      (consumer request from Stratum, 2026-08-20; CHEAP, ~8,900 corpus
      titles; RESOLVED 2026-08-21):** an operator-authorized inventory of `F:\game`
      found PS1 (6,089 titles) and PSP (2,856) both stored as `.chd`, and
      **neither normalized**. Two independent causes, both small.
      **(1) DVD-type CHDs.** `normalize_chd` always shelled `chdman extractcd`.
      PSP CHDs are DVD-type (`chdman info` reports `Metadata: Tag='DVD '`,
      2048-byte unit size, zstd — no CD track metadata), and `extractcd`
      aborts on them: exit `3221226505`, `libc++abi: terminating due to uncaught
      exception of type std::nullptr_t`. Fix: `_chd_extract_command()` dispatches
      on the metadata tag — `DVD ` (whitespace-padded in the Tag= record) →
      `extractdvd`, otherwise → `extractcd`. DVD output is a plain 2048-byte
      image that feeds `iso9660` directly with no further composition.
      Retail proof: staged `7 Wonders of the Ancient World (USA).chd` (PSP DVD,
      sha256 `3f91c7ab…`) walks to 28 entries/22 files via the direct
      `chd → iso9660` path.
      **(2) The extracted cue was misnamed + the temp source had no path.**
      For CD-type CHDs the original call passed `-o <tmp>/extracted.cue`,
      correctly placing the cue, but `_TempFileSource` wrapped the extracted
      `.bin` in a `ByteSource` that carried no `.path` attribute and was
      not a `FileSource`, so `ps1-bincue._resolve_pair` fell through to the
      "raw ByteSources without a path" rejection branch even though the cue
      sibling existed on disk. Two-part fix:
      (a) `_TempFileSource` now exposes a `self.path` attribute set to the
      inner `FileSource`'s path (the extracted `.bin`);
      (b) `ps1_bincue._resolve_pair` now does duck-typed attribute detection
      first (`hasattr(source, "path")`) before falling back to `str`/`Path`
      and the explicit `FileSource` type check — so any path-bearing
      `ByteSource` composes naturally, not just the original `FileSource`.
      Combined with the pre-existing `-o extracted.cue` naming fix (already
      landed at backlog write time, the `_TempFileSource` half was the
      residual), the full chain now works.
      Retail proof (CD-type): `fixtures/_local/bin-chd-playstation/`
      `BursTrick - Wake Boarding!! (USA).bin` compressed to a temp CHD via
      `chdman createcd` → `normalize_chd` → `normalize_ps1_bincue` →
      `normalize_iso9660` walks a **byte-identical** FileTree to a direct
      `ps1-bincue → iso9660` walk over the original bin (identical path
      sets, spot-checked head+tail on the first/last/largest files).
      **Residual scope limit, not a bug:** `ps1-bincue` refuses multi-track
      discs by design, which is 13 of 40 sampled PS1 titles (~32%), capping
      PS1 reach near 4,100 of 6,089. Widening that is a separate decision,
      not part of this fix.

- [x] **`zip` container layer — BUILT (consumer request from Stratum,
      2026-08-20; BIGGEST REACH, 14,643 corpus titles / 62% of the disc corpus):** the same `F:\game` inventory
      found that everything except PS1 and PSP is stored **zipped**: PS2
      (5,623 → `.iso` or `.bin`+`.cue`), Saturn (2,413 → `.bin`+`.cue`), 3DS
      (2,149 → `.3ds`), GameCube (2,019 → `.rvz`), Dreamcast (1,509 →
      `.bin`+`.cue`), Wii (554 → `.rvz`), Xbox (376 → `.iso`). Substratum has
      no zip layer, so **Stratum's Unit 4 currently reaches none of them.**
      Every zip sampled is **DEFLATE, not STORED** (115/115 members across
      seven platforms), so this cannot be a cheap offset map — deflate is not
      seekable, and a zip layer must spool to a temp file the way `chd`
      already does. Multi-file members (`.bin`+`.cue`, multi-track Saturn/DC
      sets reaching 90 members in one archive) mean the layer returns a
      `FileTree`, not a single `ByteView`.

      **DECIDED 2026-08-20 — build the normalizer; operator pre-extraction is
      off the table.** The choice is forced by disk, not preference: the
      corpus is **19.13 TB compressed** (PS2 alone 7.94 TB) on a 24 TB volume
      with **4.59 TB free**. Uncompressed it exceeds 30 TB, so there is not
      room to pre-extract even one of the larger platforms, let alone nine.
      A normalizer doing per-title **extract → scan → delete** peaks at a
      single title (~8 GB worst case, Xbox), which the free space absorbs
      trivially, needs no operator labour, and leaves the archive untouched.
      It also matches the pattern `chd` already set. **Consequence for the
      consumer:** the sweep is extraction-dominated — decompressing ~30 TB of
      deflate plus chdman over 8,945 CHDs is a multi-day continuous job — so
      Stratum's runner must checkpoint per title and be resumable, which its
      Unit 4 hard rules already require. Peak disk stays flat regardless of
      corpus size, which is the property that makes the census runnable at
      all.

      **RESOLVED 2026-08-21 — the normalizer landed as `zip` (0.0.20).**
      `substratum/formats/zip.py` returns a FileTree over a one-file
      decompression spool (stored + deflate, data descriptors, and ZIP64
      sizes/offsets/records all parse; per-member CRC-32 and inflated size
      validated during the streaming extract; encrypted members, unsupported
      methods, multi-disk, and duplicate/traversal paths refused
      structurally). Synthetic fixture hand-packed by
      `seedtools/make_zip_fixture.py`; expected manifest authored from
      7-Zip 26.02's independent listing and reference bytes from its own
      extraction (two-party rule). Retail anchor not yet staged — the
      consumer sweep will exercise real corpus zips directly.

- [x] **3DS RomFS (IVFC) filesystem normalizer — BUILT (consumer request from
      Stratum, 2026-08-20; resolved 2026-08-21):** the 3DS chain previously bottomed
      out at opaque regions — `3ds-cci` → NCCH → `exefs.bin` / `romfs.bin` — so no
      file-level detector could ever see inside a 3DS title. Measured
      2026-08-20 on the staged set: Cubic Ninja composes cleanly to
      `romfs.bin` (84,975,616 bytes, one blob) and a full Stratum
      `production_registry()` sweep returns **0 hits by construction**, not by
      absence. **RESOLVED as `3ds-romfs` (0.0.21):** `substratum/formats/three_ds_romfs.py`
      walks the IVFC-wrapped RomFS region — full hash tree verified eagerly
      (master <- level0 <- level1 <- data, partial trailing block zero-padded;
      closed-form table-size identities enforced; the 3DS's data-first table
      relocation characterized on real media and cross-checked against
      ctrtool's interpretation). Retail proof on staged Cubic Ninja through
      the full cci → ncch → romfs composition: 540 files, exact path/size map
      agreement with ctrtool's own extraction plus byte-exact spot checks.
      ctrtool v1.3.0 quirk recorded: its extractor cannot materialize 0-byte
      members, so the synthetic reference for `EMPTY.BIN` is staged empty and
      the two-party test extracts a no-empty rebuild. The 3DS chain now
      reaches file level; Stratum's detectors can see inside 3DS titles.

- [x] **CIA content-chunk hash mismatch on two staged eShop titles
      (investigation, 2026-08-20):** **RESOLVED 2026-08-21.** Not bad dumps
      and not a slice-offset bug. Both titles are two-content CDN-encrypted
      CIAs (TMD type bit 0); ctrtool `-y` reports the TMD hashes GOOD because
      it hashes the **titlekey-decrypted** blob. The CIA normalizer was
      hashing on-media ciphertext. Fix: decrypt-then-hash when the encrypted
      flag is set (`slot0x3DKeyX` + `commonN` as keyY through the hardware
      key generator; content IV = index as BE u16). FileTree still exposes
      on-media slices. BoxBoxBoy (0x5956000 + 0x78000) and Mini Sports
      (0x424f000 + 0x24000) now normalize green against the parked keyset;
      Biohazard (flag clear) stays keyless. See the 2026-08-21 log entry.

- [~] **RVZ / WBFS / GCZ / NKit — dropped 2026-08-20, then the premise was
      corrected the same day. LIVE DECISION, not a settled drop.** The drop
      was made on the belief that everything else in `F:\game` already
      normalized natively, leaving RVZ as the lone emulator-format holdout.
      **That belief was wrong.** The operator-authorized inventory (same day)
      found the corpus is ~23,600 disc titles of which **none** normalize
      today: 14,643 are zipped, 8,945 are CHDs hitting the two bugs above.
      The honest comparison is therefore:
      | Work | Unlocks |
      |---|---|
      | `chd` two bugs | ~8,900 titles (one fix already verified) |
      | `zip` layer | 14,643 titles across five platforms |
      | **RVZ** | **2,573 titles — but 100% of GameCube and Wii** |
      RVZ is one unit for a comparable share of the corpus to the others, and
      it is the *only* route to two entire platforms — the ones carrying the
      Nintendo formats (Yaz0, U8) whose prevalence Stratum most needs to rank.
      **The zip decision above moved the arithmetic in RVZ's favour:** the
      runner must extract-and-delete per title regardless, so adding RVZ costs
      one normalizer unit and **zero** additional disk or operator work
      (GC/Wii are `zip → rvz → gc-fst | wii chain`, and the zip half is being
      built anyway). One unit is now the whole distance to full platform
      coverage.
      Left dropped pending an explicit re-decision rather than silently
      reinstated; whoever schedules Unit 4's prerequisites should settle it
      then. **The durable consequence stands either way:** while GC/Wii are
      out, the census under-ranks Nintendo formats and over-ranks the CRI
      family, so Stratum's run manifest must record each sweep's
      platform/image-format scope. Reopening needs no code — operator
      pre-conversion to plain `.iso` was always an option, and GC/Wii titles
      already stored as plain `.iso` sweep fine via `gc-fst` and the Wii
      chain. The original ask follows, kept verbatim for the oracle choices it
      records.

- [x] **`rvz` — GC/Wii Dolphin RVZ container (F:\game corpus formats — RVZ; DONE 2026-08-21, 0.0.23):** `substratum/formats/rvz.py` returns a `ByteView` of the Dolphin-decoded ISO (`DolphinTool 2606a` `dolphin-tool convert --format iso`, block `131072` `zstd:5`); `GT Cube (Japan).rvz` (GC, 273 MB → 1,459,978,240 bytes, 661 `gc-fst` files) and `Ghost Squad (Japan).rvz` (Wii, 374 MB → 4,699,979,776 bytes, 2 `wii-disc` partitions) both staged in `fixtures/_local/` (gitignored) and proven via `DolphinTool` + `wit` second reader; gate `444 passed`. Closes the `zip → rvz` chain for the 2,573-title GC+Wii corpus. `WBFS`/`GCZ`/`NKit` remain as follow-ons (operator-gated).

- [x] **`gcz` — Dolphin's legacy CompressedBlob GC/Wii container (F:\game
      follow-on; DONE 2026-08-21, 0.0.24):** `substratum/formats/gcz.py`
      returns a `ByteView` of the DolphinTool-decoded ISO (magic
      `0xB10BC001`; the DolphinTool plumbing now lives in
      `substratum/formats/_dolphin.py`, shared with `rvz`). wit cannot read
      GCZ (`WRONG FILE TYPE`, recorded), so the container differential is a
      **spec-derived pure-Python block decoder in `tests/test_gcz.py`**
      (32-byte LE header, `u64[num]` offsets with bit-63 stored-raw flag,
      `u32[num]` hash array, zlib blocks — size arithmetic closes to the
      byte on both anchors), agreeing with DolphinTool on head/mid/tail
      1 MiB windows; the full-disc `iso → gcz → decode` round-trip is
      sha256-identical. Anchors: `GT Cube (Japan).gcz` (GC, written by
      pinned DolphinTool from the staged retail `.rvz` — 661 `gc-fst`
      files) + `Ghost Squad (Japan).gcz` (Wii sub_type 1, 2 `wii-disc`
      partitions) + the operator-staged **mislabeled** Beach Spikers
      `.gcz` as the sniff/dispatch regression (a compacted raw GC ISO —
      see the follow-on item below). `F:\game` holds no GCZ titles
      (GC/Wii are `.rvz`): this unit is emulator-family completeness.

- [x] **`wbfs` — Wii USB-loader scrubbed container (F:\game follow-on;
      DONE 2026-08-21, 0.0.25):** `substratum/formats/wbfs.py` returns a
      `ByteView` over wit's canonical full-size reconstruction
      (`wit copy`, 4,699,979,776 bytes, zero-filled scrubbed clusters);
      the spool source moved to shared `substratum/formats/_spool.py`.
      **Load-bearing finding: DolphinTool's WBFS decode is mangled**
      (2x disc size, container header embedded at 0x200000, partition
      bytes disagree with wit) — wit is the only trustworthy decoder, and
      the container differential is a **spec-derived libwbfs-layout LUT
      decoder in `tests/test_wbfs.py`**, sha256-identical to wit over the
      entire 4.7 GB anchor (streamed). Anchor: operator-staged
      `Ghost Squad (Europe).wbfs` (scrubbed — no update partition; the
      JP `.rvz` anchor is the same title unscrubbed). `nkit` remains as
      the last named follow-on.

- [x] **`nkit` — GC NKit recovery (F:\game follow-on, the last named
      one; DONE 2026-08-21, 0.0.26):** `substratum/formats/nkit.py`
      returns a `ByteView` of the RECOVERED full-size original via
      NKit 1.4 (`ConvertToISO.exe`, per-call isolated tool copy — the
      tool hardcodes `<exe-dir>/Processed`). **Findings:** (1) GC
      `.nkit.iso` is a compacted GC ISO (real disc header at 0, `NKIT`
      block at 0x200) whose compacted filesystem `gc-fst` walks at file
      level (415 files on the anchor) — the unit adds the recovered
      original for byte fidelity, and its sniffer is registered BEFORE
      `gc-fst`; (2) NKit 2 is Discord-distributed with no public source
      — the unit pins NKit 1.4 (zip sha256 cross-pinned against the
      independent AUR package pin); (3) a verified conversion exits
      NONZERO on CRC-not-in-dat, so the produced image is the success
      criterion, never the exit code; (4) `.nkit.gcz` = the compacted
      image in a Dolphin-GCZ stream → sniffs/decodes via `gcz`
      (file-level correct; not recovered). Differential: byte-exact
      retail round-trip (MKDD → nkit → decode, full-disc sha256
      identical) + tool 3-pass Full Verify + recovered-vs-compacted
      gc-fst file-map agreement. Anchor: operator-staged Yu-Gi-Oh!
      Falsebound Kingdom (Europe) `.nkit.iso` (VerifySuccess, MD5/SHA1
      recorded by the tool).

- [x] **`ciso` — wit's GC/Wii compact-ISO sibling (the staged-samples
      follow-on; DONE 2026-08-21, 0.0.27):** `substratum/formats/ciso.py`
      decodes the container wit 3.05a reads and writes — magic `CISO`,
      LE u32 block size `0x200000` at 0x04, a byte-per-block map at
      0x08 over the fixed single-layer Wii-size address space
      (4,699,979,776 bytes — the total is declared nowhere; wit's reader
      always reconstructs that size, verified on a GC-content CISO), and
      present blocks' payloads as RAW 2 MiB slots packed in ascending
      block order (slot j = present-block j, NOT block index j — the
      load-bearing mapping). No compression anywhere in the format.
      **The disambiguation the unit existed for:** PSP CISO v1 (the
      GREEN `cso` unit) shares the magic; both sniffers now key on the
      LE u32 at 0x04 (GC/Wii `0x200000` block size vs PSP header size
      `0x18` — `cso.sniff` was tightened from magic-only to the full
      v1 header shape), and `ciso` is registered before `cso`, so the
      families can never cross-dispatch. **Findings:** (1) the staged
      Luigi's Mansion `.ciso` is NKit 2's output — the same wit
      container plus an appended `NKIT  v2` recovery trailer (0x240
      bytes carrying the original disc size as BE u32; tolerated, wit
      ignores it too); (2) **`wit copy` scrubs GC junk** — it drops
      all-junk blocks from the map and zeroes junk spans inside stored
      blocks, so wit-authored CISOs contain zeroed junk while
      NKit-authored ones preserve original bytes; on the Luigi anchor
      the wit decode differs from the view on exactly blocks 1 and 604,
      every difference one-directional nonzero→zero and never inside a
      game file (per-file proof via the retail gate); (3) dual-layer
      Wii CISOs are untested and out of scope. Differential: a
      wit-authored CISO round-trip (Hulk → wit CISO → decode ==
      wit's own decode byte-exact over the full 4.7 GB image) + the
      retail gate on Luigi's Mansion (wit-authored manifest + extraction
      through the gc-fst composition, 847 files / 64 dirs) + the
      seedtool-pinned view sha256 re-derived through the normalizer.

- [x] **`F:\game` corpus formats — WBFS / GCZ / NKit as follow-ons;
      Stratum Unit 4 prerequisite, operator-gated samples; SAMPLES STAGED
      2026-08-21, dispatch order settled `gcz` → `wbfs` → `nkit`, `ciso` as a
      sibling — **FULLY RESOLVED 2026-08-21: `gcz` (0.0.24), `wbfs` (0.0.25),
      `nkit` (0.0.26) and `ciso` (0.0.27) all shipped GREEN, and the `wux`
      platform call was resolved the same day (out of scope — see the next
      item). Nothing in this item is open**):** the operator staged five samples in
      `C:\Users\kenrin\Downloads\fixtures` (headers verified): Beach Spikers
      `.gcz` (GC), Ghost Squad (Europe) `.wbfs` (Wii — the JP `.rvz` anchor is
      the same title, giving a cross-region differential), Yu-Gi-Oh! The
      Falsebound Kingdom (Europe) `.nkit.iso` (NKit v2), Luigi's Mansion
      `.ciso` (GC compact ISO — not in the original family; the GREEN `cso`
      unit also keys on the `CISO` magic, so a sibling unit must
      disambiguate), and Your Shape FE 2013 `.wux` (**Wii U — a platform
      Substratum has no chain for and `F:\game` doesn't contain; parked as a
      new-platform decision, not a follow-on**). **Load-bearing finding
      (2026-08-21): the staged Beach Spikers `.gcz` is NOT a GCZ** — it is a
      compacted raw GC ISO mislabeled with the extension: no Dolphin
      `0xB10BC001` magic anywhere in the file, DolphinTool passthrough-copies
      it (it sees only the disc header), wit 3.05a refuses it, and the
      existing `gc-fst` normalizer already walks it cleanly (1,224 files, FST
      internally consistent to the byte — max file end == file size; loose
      `adx/bgm_*.adx` content reads as valid ADX, so it is also a Stratum
      `cri.adx` positive candidate via zero new work). Staged in
      `fixtures/_local/` as the sniff-dispatch regression anchor. The `gcz`
      unit therefore targets the **canonical Dolphin GCZ (CompressedBlob)**
      format: header `magic|sub_type|compressed_data_size u64|disc_size
      u64|block_size|num_blocks` (32B LE), `u64[num]` block-offset array
      (MSB = stored-raw block), `u32[num]` decompressed-block hash array,
      then zlib blocks — empirically characterized against a DolphinTool
      2606a-created anchor and to be proven by a spec-derived pure-Python
      block decoder in the tests (wit cannot read GCZ; recorded). Each format
      is its own normalizer unit with its own differential oracle (RVZ is Dolphin's own container → the Dolphin CLI; WBFS and GCZ → wit where applicable; NKit → the NKit tool), following the
      retail-anchor pattern: small operator-supplied samples staged into
      the gitignored drop zone, provenance + manifest committed, agents
      never reading `F:\game` autonomously. Decide and record up front
      (a) whether to normalize each container directly or define an
      operator pre-conversion path, and (b) the minimum set that makes the
      first 50-title sweep meaningful — RVZ + NKit likely cover the bulk.

- [x] **`wux` / Wii U platform decision — RESOLVED 2026-08-21 (user:
      out of scope, split as a future standalone project).** The chain
      assessment (four units to file level: `wux` container → `wud`
      structure → keyed title decrypt → `wiiu-romfs`; nothing vendored;
      zero `F:\game` reach; the `.wua` ecosystem caveat) moved to
      `.atelier/ideas/wii-u.md`, which also records the removed sample's
      identity (`Your Shape FE 2013 (Europe).wux`, 2,264,694,784 bytes,
      sha256 `ce86b17a…`) for re-acquisition. The staged sample itself
      was deleted from the operator staging area on the same decision.
      A future Wii U project would develop against Substratum's frozen
      contract (importing the published package) with the option to
      merge proven units back if the platform ever earns corpus reach.
      The assessment as first recorded follows, kept for the row's
      history:

      1. **`wux` container** (cheapest, the `gcz`/`ciso` pattern): header
         peek on the staged sample confirms magic `WUX0`, LE u32 block
         size `0x8000` (32 KiB), a ~25.03 GB declared total (the full
         Wii U disc size), and a u32-per-block index table — a
         block-compressed WUD container. Decode unit returns a ByteView
         of the inner WUD. **Oracle gap:** nothing Wii U is vendored;
         candidates (uwizard C++, JNUSTool Java, vgmtoolbox, or a
         spec-derived decoder + second reader à la gcz/wbfs) must be
         settled at unit time. One staged sample exists
         (`Your Shape FE 2013 (Europe).wux`, 2.26 GB).
      2. **`wud` disc structure:** the encrypted raw disc image —
         partition table + the WUP title layout (`.app`/`.h3`/`.tik`/
         `.tmd`/`.cert` at aligned offsets), documented on wiiubrew.
         Resembles `wii-disc`: an unkeyed table walk to a FileTree of
         opaque encrypted slices. The `wux` decode of the staged sample
         IS the WUD bytes, so one sample can anchor both — but a single
         title is a weak-variant anchor (the 9.3 lesson).
      3. **`wup-title-decrypt` (keyed):** per-title AES key from the
         dump's own `.tik` (encrypted with the Wii U common key —
         public/leaked; same operator env-var file posture as the Wii
         common key, never committed). Correctness anchor: the `.h3`
         hash trees over `.app` contents — the NCCH protected-hash
         pattern.
      4. **`wiiu-romfs`:** decrypted `.app` content is CafeOS romfs →
         FileTree (file level, where Stratum's detectors start seeing
         anything). SARC/RPX below that stay downstream, like Yaz0/U8
         are for Wii.

      **Why it stays parked unless the platform is wanted for its own
      sake:** `F:\game` holds ZERO Wii U titles (Unit 4 inventory), so
      this is a new-platform bet, not census coverage — unlike every
      unit shipped this week, which had reach or a cheap vendored
      sibling. Also note the ecosystem reality: if a Wii U corpus ever
      arrives it may well be `.wua` (Cemu's 7z-based, already-decrypted
      archive), which would skip layers 1–3 entirely and leave only
      romfs — the `wux` bet only pays if the corpus arrives as
      wud/wux. Cost if wanted: ~4 units + one vendoring prep row
      (comparable to the 3DS chain build-out).

- [x] **New3DS 9.3 variant — REMOVED 2026-08-21 (user decision, not
      landed):** `ncchflag[3] == 0x0A`, keyslot `0x18`, no seeddb.
      Tooling-wise this falls out of the 9.6 pure-Python path for free
      (`0x18` keyX is in the parked keyset, same module), but it needs a
      genuine `0x0A` retail anchor, and the 2026-07-30 hunt established
      those are effectively lost media (three database-"9.3" titles all
      turned out `0x01`). **Removed as realistically unsourceable — not
      worth further chasing; would only return with full-corpus download
      capacity, which is not a priority.** The durable lesson stays:
      read the crypto method, never the firmware version — a title can
      require FW 9.3+ and still ship 7.x (`0x01`) crypto.

- [x] **Promote the Spolia program (2026-08-05):** Stratum at
      `C:\Users\kenrin\Project\Stratum` (`37c9f74`) and Quarry at
      `C:\Users\kenrin\Project\Quarry` (`352e05a`) now consume the frozen
      public contract; Kura and Interlinear remain downstream of Quarry.

## How to orient quickly

1. Read this file for the current boundary and next unlock.
2. Read `NORMALIZERS.md` for unit status, fixtures, pinned tools, and proof
   obligations.
3. Read `DESIGN.md` before changing the contract or starting a unit.
4. Read `docs/WII-KEYED-WORK.md` when the common-key artifact is available.
5. Run `uv run pytest` for the full four-check gate after implementation;
   structural-only or self-consistency-only results are not GREEN. For a
   periodic deep pass, `SUBSTRATUM_FULL_FIDELITY=1` diffs every reference
   file instead of the 16-file sample (DESIGN.md § 3 amendment).
