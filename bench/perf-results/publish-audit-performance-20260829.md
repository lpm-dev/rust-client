# Publish audit performance benchmark

- Date: 2026-08-29
- Host: Apple M5 Pro, macOS 26.6, arm64, 48 GiB RAM
- Toolchain: repository default Rust toolchain
- Build profile: release with workspace LTO
- Samples: seven alternating AB/BA pairs after one warm run per binary and fixture
- Peak RSS source: `/usr/bin/time -lp`

## Binaries

| Role | SHA-256 |
| --- | --- |
| Pre-audit baseline | `87759ecdd16a5216e1b4573bab2cb696980988b515e1670c131047eb9ff2673c` |
| Final audit candidate | `02bdd255bea899919ae4ce65d0f6e6a42d8d09836b2a2daabc8fde4c7b9d4ad9` |

Both binaries were preserved under `/tmp`. No compiler process ran during a
measured sample. Every pair used the same fixture and an isolated temporary
home. The upload fixture used one loopback HTTP server for both binaries.

## Large scannable source file

The fixture contains one 180 MiB deterministic high-entropy `bundle.js` and a
minimal manifest. The command was
`lpm --json publish --check --npm --no-provenance`. It exercises secret
scanning, source validation, archive streaming, gzip, and hashing without
network activity.

| Metric | Baseline median | Candidate median | Change |
| --- | ---: | ---: | ---: |
| Peak RSS | 1,018.69 MiB | 520.95 MiB | -48.86% |
| Wall time | 3,210 ms | 2,280 ms | -28.97% |

The candidate scans large source bytes before compressed archive construction,
then verifies the retained SHA-256 while streaming the file into the archive.
Byte-regex matching also removes the malformed-UTF-8 lossy string allocation.
The stable 497.73 MiB median RSS reduction verifies that the prior overlapping
large allocations were material.

The scan still buffers one source file at a time, bounded by the existing 200
MiB per-file publish limit. That buffer no longer coexists with a growing
compressed archive and no longer has a second lossy UTF-8 copy.

## Near-limit LPM pack metadata

The fixture contains 99,000 empty shallow JavaScript files. A loopback registry
accepts the preflight, `whoami`, and complete upload body. The command was
`lpm --registry <loopback> --insecure --json publish --yes --lpm
--allow-secrets --no-provenance --token benchmark-token`.

| Metric | Baseline median | Candidate median | Change |
| --- | ---: | ---: | ---: |
| Peak RSS | 120.88 MiB | 46.13 MiB | -61.84% |
| Wall time | 2,030 ms | 1,440 ms | -29.06% |

The candidate serializes `_npmPackMeta.files` from borrowed records rather than
building a second 99,000-element JSON value tree. One replayable JSON prefix
remains resident, but the complete near-limit upload peaks at 46.13 MiB. A
file-backed prefix would add a full write/read cycle and another lifetime
boundary for a residual allocation that is not material in this stress case.

## Near-limit file collection and matching

The same 99,000-file fixture ran locally with
`lpm --json publish --check --lpm --allow-secrets --no-provenance`. This removes
upload serialization and network work while retaining file matching, candidate
construction, archive streaming, gzip, and hashing.

| Metric | Baseline median | Candidate median | Change |
| --- | ---: | ---: | ---: |
| Peak RSS | 44.63 MiB | 35.92 MiB | -19.50% |
| Wall time | 2,010 ms | 1,440 ms | -28.36% |

The candidate stores ordinary source paths once, reuses portable archive paths,
stops ordered-rule evaluation at the decisive match, and reuses open parent
directories across sorted files. Traversal also stops when no descendant file
can fit under the archive depth or path-byte limit.

## Retained tradeoffs

- Complete workspace-generation validation remains before every release-member
  upload. The earlier 50/100/200-member benchmark measured roughly 12.06 times
  upload-span growth for four times the members. The cost is retained because
  weakening the scan misses member-set, duplicate-name, catalog, and unrelated
  manifest drift before irreversible uploads.
- Multi-target uploads remain ordered. Target operations can prompt for MFA,
  return irreversible partial success, and reuse one archive at a time. Parallel
  upload would make errors and prompts nondeterministic and increase concurrent
  archive memory.
- Release projection still parses the selected manifest during planning and
  after remote preflight. The second read/parse is linear in small manifest
  bytes and is part of the fresh-generation validation; caching the earlier
  value would not prove that the current bytes still match.

## Conclusion

The final candidate materially reduces peak memory and wall time on both the
large-file and near-entry-limit publish shapes. No measured performance
regression was retained.
