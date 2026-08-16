# Task graph and cache benchmark

- Measurement dates: 2026-08-15 and 2026-08-16
- Host: Apple M5 Pro, macOS arm64, 48 GiB RAM
- Toolchain: Rust 1.94.0
- Samples: 10 adjacent AB/BA pairs for each landing scenario
- Warmups: one run for each binary

The harness used preserved release binaries. It did not build during a
measurement.

- Main commit: `226f5767297ff843c999d06076baec0be7c40f7d`
- Main binary SHA-256: `0f5c0e3bbef8a20b60077e99dee192a6f146ad9ec58335284dfe06bdedf8e870`
- Initial candidate SHA-256: `0c5925e8385b64741a43bf8d550c20ca17463a5f65d43774dc96fba8a3f1555b`
- Cache-safety candidate SHA-256: `f35eefd88649e98ba06bc0414bc70a58238b25e64b9f3db7b13170af34d7b618`
- Pre-optimization candidate SHA-256: `bfa6b3e7eb733c16875b2e8a1163b9a39d19f5e07ebbdf9ae9efd2635e41f6b4`
- Main benchmark candidate SHA-256: `4f96fa330622a604b3daccff70879e37fa857e718e3de3e47b8786e223d5f2c4`
- Exact post-review candidate SHA-256: `8add306c0b930de8609aa84b94aa20d8a29ddcbe1472f2f1fa6767ca78f31a02`

All candidate samples passed their correctness contracts. Main failed all six
workspace-graph contracts because it did not execute the required work.
Therefore, the harness reports these comparisons as inconclusive.

## Restore and publication results

The 18-scenario landing run measured restore size, file count, path depth,
concurrent writers, workspace graphs, and root lockfile size.

| Scenario | Main median | Candidate median | Change |
| --- | ---: | ---: | ---: |
| 128 MiB restore wall time | 2221.99 ms | 497.16 ms | -77.63% |
| 128 MiB restore peak RSS | 39.39 MiB | 17.53 MiB | -55.49% |
| 500-file restore wall time | 117.14 ms | 110.26 ms | -5.87% |
| Concurrent same-key publication | 284.18 ms | 177.39 ms | -37.58% |
| 1 MiB restore wall time | 75.62 ms | 74.07 ms | -2.05% |

The candidate passed ten of ten concurrent-publication samples. Each restored
entry contained one complete producer result. The candidate also removed
stale outputs and validated deep output paths in every sample.

## Workspace graph scaling

The first candidate recursively validated the complete dependency chain during
each meta-task identity resolution. This work was quadratic for a deep graph.
The final candidate validates the graph only at cache boundaries. One visited
set also prevents repeated validation of shared diamond nodes.

| Scenario | Initial candidate median | Final candidate median | Change |
| --- | ---: | ---: | ---: |
| 1,000 tasks, cold cache | 4957.50 ms | 1175.48 ms | -76.29% |
| 1,000 tasks, warm cache | 5437.97 ms | 1749.10 ms | -67.84% |

The final 10-sample distributions were:

| Tasks | Cold median / p95 | Warm median / p95 | Cold peak RSS | Warm peak RSS |
| ---: | ---: | ---: | ---: | ---: |
| 10 | 156.59 / 172.13 ms | 232.58 / 235.67 ms | 20.30 MiB | 19.27 MiB |
| 100 | 301.92 / 358.54 ms | 497.67 / 522.53 ms | 26.23 MiB | 21.03 MiB |
| 1,000 | 1175.48 / 1238.68 ms | 1749.10 / 1802.27 ms | 42.67 MiB | 31.78 MiB |

## Deep cache-boundary scaling

The expanded harness gives every task a cache boundary and a distinct output.
The 10-task and 100-task cells used ten adjacent AB/BA pairs.

| Scenario | Pre-optimization median / p95 | Current median / p95 | Median change | Current peak RSS |
| --- | ---: | ---: | ---: | ---: |
| 10 tasks, cold | 411.70 / 592.34 ms | 411.81 / 637.80 ms | +0.03% | 19.24 MiB |
| 10 tasks, warm | 658.09 / 707.20 ms | 655.52 / 697.15 ms | -0.39% | 17.84 MiB |
| 100 tasks, cold | 4670.35 / 6883.63 ms | 3935.83 / 4740.99 ms | -15.73% | 21.05 MiB |
| 100 tasks, warm | 7203.25 / 11044.49 ms | 7497.43 / 10650.22 ms | +4.08% | 18.13 MiB |

The 100-task warm median stayed inside the 5% gate. Its p95 decreased by
3.57%, and its median peak RSS was unchanged.

The 1,000-task cells used two adjacent AB/BA pairs because each old-binary
sample took more than two minutes.

| Scenario | Pre-optimization median / p95 | Current median / p95 | Median change | Current peak RSS |
| --- | ---: | ---: | ---: | ---: |
| 1,000 tasks, cold | 120202.57 / 120561.64 ms | 52803.31 / 54109.84 ms | -56.07% | 29.07 MiB |
| 1,000 tasks, warm | 132059.56 / 136408.33 ms | 80176.92 / 89236.46 ms | -39.29% | 22.73 MiB |

Cold peak RSS increased by 4.67% to 29.07 MiB. This result stayed inside the
configured gate. Warm peak RSS decreased by 1.22%.

Output-producing tasks are cache-validation boundaries. Meta tasks still
forward validation to their nearest output-producing dependencies. This rule
removes repeated validation of the same transitive cache identities.

## Workspace caret scaling

A macOS process sample found repeated workspace discovery below
`validate_runtime_with_cache`. Each member reparsed the complete workspace to
resolve its Node requirement. This behavior made a deep workspace quadratic.

The current candidate derives all member requirements from the parsed
workspace manifests. It resolves the root `engineStrict` value one time.

| Packages | Pre-optimization median / p95 | Current median / p95 | Median change | Current peak RSS |
| ---: | ---: | ---: | ---: | ---: |
| 10 | 53.41 / 77.51 ms | 53.37 / 80.69 ms | -0.07% | 1.77 MiB |
| 100 | 244.97 / 341.05 ms | 53.43 / 65.73 ms | -78.19% | 2.07 MiB |
| 1,000 | 24903.08 / 32699.65 ms | 165.13 / 458.65 ms | -99.34% | 52.55 MiB |

All ten candidate samples executed the required leaf task exactly one time.
The 1,000-package median peak RSS decreased from 53.26 MiB to 52.55 MiB.

## Post-review equivalence

The exact post-review binary includes the final error-propagation cleanup.
Alternating comparisons against the main benchmark candidate checked that this
source-only cleanup did not invalidate the performance conclusions.

| Scenario | Samples | Benchmark candidate median / p95 | Post-review median / p95 | Change |
| --- | ---: | ---: | ---: | ---: |
| 1,000-package caret graph | 10 pairs | 157.04 / 196.27 ms | 157.42 / 180.59 ms | +0.24% / -7.99% |
| 100 cold cache tasks | 10 pairs | 3801.16 / 4718.73 ms | 3878.78 / 4465.25 ms | +2.04% / -5.37% |
| 100 warm cache tasks | 4 pairs | 7290.24 / 9065.69 ms | 6559.50 / 10425.95 ms | -10.02% / +15.00% |

The expanded cold-cache run passed its wall-time and peak-RSS gates. A prior
four-pair cold sample reported an 8.35% median increase. The ten-pair run did
not reproduce it. The warm-cache median improved, while its four-pair p95 was
too noisy to establish a tail-latency change.

## File-descriptor investigation

The first landing run reported 57 baseline descriptors and 67 candidate
descriptors for ten parallel warm restores. A separate two-pair run measured a
baseline median of 62 and p95 of 68.3. The candidate used 67 descriptors.

A 10 ms `lsof` trace measured a candidate peak of 68 and a baseline peak of
62. Both traces contained the same descriptor classes:

- one task lock for each active worker
- clean and project locks held by waiting restore workers
- project and cache directory handles
- the active restore staging directory

The candidate adds handles for the active rollback-protected staging tree. The
trace found no socket, pipe, archive, or output-file leak. All processes exited
without survivors. The count is bounded by the configured workspace and task
concurrency.

## Commands and artifacts

The final graph run used:

```bash
node bench/scripts/run-runtime-readiness.mjs \
  --lpm-binary baseline=/private/tmp/lpm-task-cache-safety-baseline \
  --lpm-binary candidate=/private/tmp/lpm-task-cache-safety-candidate \
  --compare baseline,candidate \
  --profile full \
  --scenarios task/workspace-cache-cold-wide-deep-10,task/workspace-cache-warm-wide-deep-10,task/workspace-cache-cold-wide-deep-100,task/workspace-cache-warm-wide-deep-100,task/workspace-cache-cold-wide-deep-1000,task/workspace-cache-warm-wide-deep-1000 \
  --samples 10 \
  --allow-inconclusive
```

Raw artifacts:

- Landing matrix: `/private/tmp/lpm-task-cache-safety-final-bench`
- Final workspace graphs: `/private/tmp/lpm-task-cache-safety-workspace-bench-20260816`
- FD diagnostic: `/private/tmp/lpm-task-cache-fd-trace-20260816`
- Workspace discovery process sample: `/private/tmp/lpm-task-cache-workspace-debug-sample.txt`
- Final workspace caret pairs: `/private/tmp/lpm-task-cache-caret-final-20260816`
- Final 10-task and 100-task cache pairs: `/private/tmp/lpm-task-cache-chains-final-20260816`
- Final 1,000-task cold pairs: `/private/tmp/lpm-task-cache-chain-1000-final-20260816`
- Final 1,000-task warm pairs: `/private/tmp/lpm-task-cache-chain-warm-1000-final-20260816`
- Post-review workspace caret pairs: `/private/tmp/lpm-task-cache-postreview-caret-20260816`
- Post-review cache-chain pairs: `/private/tmp/lpm-task-cache-postreview-chains-20260816`
- Expanded post-review 100-task cold pairs: `/private/tmp/lpm-task-cache-postreview-cold-100-20260816`

The changes do not modify dependency installation or runtime acquisition.
Therefore, the install-readiness benchmark is not part of this gate.
