# Task-cache safety benchmark

- Date: 2026-08-15
- Host: macOS arm64
- Samples: 10 adjacent AB/BA pairs per scenario
- Hot-restore warmups: one run per binary
- Correctness-cell warmups: none

The harness used two preserved Rust 1.94.0 release binaries. It did not build
during measurement.

- Main commit: `226f5767297ff843c999d06076baec0be7c40f7d`
- Main binary: `/private/tmp/lpm-task-cache-binaries/main-lpm-rs`
- Main SHA-256: `7c3c83d2973a7ddf5ca0b9d3db661b6aaa0265d7ae036f48ea17a96c17da3cd7`
- Candidate binary: `/private/tmp/lpm-task-cache-binaries/candidate-tree-publish-lpm-rs`
- Candidate SHA-256: `e90b24c7a78a8fb24062db12ad0dc3a5c1fac76c1c280d96a7004e0055f62f3d`

All candidate samples passed their correctness contracts. The hot-restore
comparison was inconclusive. Small output trees retained an absolute overhead
of 15.74 to 29.40 ms. The 128 MiB candidate median was 51.80 ms faster, and its
peak RSS increased by 0.44 MiB.

| Scenario | Main median / p95 | Candidate median / p95 | Median change | Result |
| --- | ---: | ---: | ---: | --- |
| 128 MiB restore wall time | 612.32 / 715.89 ms | 560.52 / 791.59 ms | -8.46% (-51.80 ms) | Inconclusive; p95 increased |
| 128 MiB peak tree RSS | 16.86 / 16.92 MiB | 17.30 / 17.36 MiB | +2.59% (+0.44 MiB) | Pass |
| 1 MiB restore wall time | 59.75 / 94.64 ms | 75.49 / 107.31 ms | +26.34% (+15.74 ms) | Passes the absolute gate |
| 500-file restore wall time | 77.67 / 125.66 ms | 107.07 / 150.24 ms | +37.85% (+29.40 ms) | Inconclusive; passes the absolute gate |
| 64-level path restore wall time | 57.88 / 86.92 ms | 78.31 / 94.65 ms | +35.30% (+20.43 ms) | Inconclusive; passes the absolute gate |

The first transactional implementation took 8.55 seconds at the 500-file
median. Bounded durability syncs reduced that median to 334 ms. Parent
descriptor reuse reduced it to 307 ms. Atomic no-replace publication of a
missing top-level output tree reduced it to 107 ms. Existing and mixed output
trees keep the per-file transactional fallback.

The final candidate also reduced the 64-level path median from the initial
399 ms result to 78.31 ms. Immediate durability remains enabled for recovery
records and irreplaceable backups.

The correctness cells used no warmup because `main` contains the reproduced
faults:

- Exact stale-output removal: main failed 10/10; candidate passed 10/10.
- Concurrent same-key publication: main failed 2/10; candidate passed 10/10.

Performance deltas for these cells are advisory because the binaries did not
perform equivalent work.

Commands:

```bash
node bench/scripts/run-runtime-readiness.mjs \
  --lpm-binary main=/private/tmp/lpm-task-cache-binaries/main-lpm-rs \
  --lpm-binary candidate=/private/tmp/lpm-task-cache-binaries/candidate-tree-publish-lpm-rs \
  --compare main,candidate \
  --profile full \
  --scenarios cache/hit-1mib,cache/hit-128mib,cache/hit-500-files,cache/hit-deep-path \
  --samples 10 \
  --warmups 1 \
  --allow-inconclusive

node bench/scripts/run-runtime-readiness.mjs \
  --lpm-binary main=/private/tmp/lpm-task-cache-binaries/main-lpm-rs \
  --lpm-binary candidate=/private/tmp/lpm-task-cache-binaries/candidate-tree-publish-lpm-rs \
  --compare main,candidate \
  --profile full \
  --scenarios cache/removes-stale-output,cache/concurrent-same-key-store \
  --samples 10 \
  --warmups 0 \
  --allow-inconclusive
```

Raw artifacts:

- Hot restores: `/var/folders/p2/32lgcl857ds0wkcnkg0qk51h0000gn/T/lpm-runtime-readiness-20260815T193425527Z-90980`
- Correctness cells: `/var/folders/p2/32lgcl857ds0wkcnkg0qk51h0000gn/T/lpm-runtime-readiness-20260815T193552846Z-13038`
