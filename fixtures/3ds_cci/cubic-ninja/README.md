# Cubic Ninja (Japan) 3DS CCI metadata anchor

The local operator-provided retail image is
`fixtures/_local/Cubic Ninja (Japan).3ds`. Its original download location was
not recorded, so this fixture makes no public preservation-source claim.

Validated carrier identity:

- Size: 134,217,728 bytes
- CRC32: `240b07ee`
- MD5: `fc2ae27ca7848fed31c37d8e70700c2d`
- SHA-1: `2ee5cacaeedcb413d48f8b1e3aa2e09d16051148`
- SHA-256: `929a675e4dedd315fd6ef5565e6d97b3fd7cd281171c14f2fa0a5163b7096b42`
- NCSD title ID: `0004000000034300`
- Product code: `CTR-P-AQNJ`

`uv run python seedtools/stage_3ds_cci_retail_anchor.py` requires the
SHA-256-pinned ctrtool v1.3.0 and 3dstool v1.2.6 executables. ctrtool supplies
the independent NCSD/NCCH identities and partition ranges. 3dstool extracts
both opaque partitions, after which the stager verifies their complete hashes
against the corresponding direct source ranges:

- `partition0.cxi`: offset 16,384; size 86,430,720; SHA-256
  `b805cdfdf2965e8a6f90990982bf7386ba755811bea52c5d0902bbb799a6af80`
- `partition7.cfa`: offset 86,447,104; size 5,116,416; SHA-256
  `ee478b0313c1bdf4e3a5440b1bac69f5f859fad5671ca61b4d3b7f062c6b5fd2`

Only this provenance and `expected.manifest.json` enter Git. The retail image
and independently extracted partition references remain local and ignored.
