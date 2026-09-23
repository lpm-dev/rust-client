Cached T3 installs improved in three independent cohorts. Fresh-checkout warm median decreased by 7–13%. CI-warm median decreased by 12–17%. Each cohort contains 100 scored samples per state and variant.

All times in this table are median / p95 milliseconds. The p95 uses the nearest-rank method. Every outlier remains in the data.

| Cohort | State | PR869 baseline | Candidate | Bun |
|---|---|---:|---:|---:|
| Primary | Fresh checkout, warm cache | 128 / 132 | 112 / 123 | 199.5 / 219 |
| Primary | CI-warm | 118 / 124 | 98 / 106 | 189 / 205 |
| Confirmation | Fresh checkout, warm cache | 123 / 131 | 111 / 123 | 193 / 209 |
| Confirmation | CI-warm | 115 / 120 | 96 / 107 | 180 / 189 |
| Shared-path confirmation | Fresh checkout, warm cache | 126 / 135 | 117 / 126 | 204 / 241 |
| Shared-path confirmation | CI-warm | 115 / 124 | 101 / 110 | 200 / 258 |

Fresh-checkout p95 decreased by 8–9 ms. CI-warm p95 decreased by 13–18 ms. These results describe this macOS host and these cohorts.

Median peak RSS showed no material increase. Fresh-checkout confirmation increased by 0.055 MiB before rounding. Fresh-checkout confirmation measured 118.8 MiB for both LPM binaries. CI-warm confirmation decreased from 53.2 to 51.7 MiB. Bun measured 49.2 and 7.2 MiB respectively. Shared-path fresh-checkout RSS was 118.4 → 118.3 MiB; CI-warm was 53.2 → 51.6 MiB.

The change removes repeated work in three places. Install freshness returns early when required installed-state artifacts are absent or existing policy rules prohibit reuse. The general hash-returning API remains unchanged.

The final install hash now uses one fresh lockfile snapshot. The previous path parsed the owning lockfile three times and serialized it twice. Snapshot content supplies the engine key and hash. The snapshot path supplies the owning lockfile mtime. Workspace projections and transaction precedence remain intact.

Cached V2 jobs submit larger entries first, then restore their original result order. Tokio still controls actual task execution order. Standalone macOS batches with only verified cache hits use four link workers. Explicit `LPM_V2_LINK_TASKS` values retain precedence. Mixed batches and workspace coordination retain the existing concurrency limit.

That four-worker condition can also apply after speculative downloads complete every object during a first install. Cold controls therefore remain part of the evaluation. Other platforms retain their existing worker limit.

Two earlier 24-round experiments separated ordering from concurrency. Ordering alone gave no useful improvement. Ordering with four workers improved warm medians by 3.5–5.5 ms. A later 12-round experiment compared that combination with the full change. Fresh-checkout median decreased from 117 to 112 ms. CI-warm median decreased from 108 to 100 ms. These smaller experiments establish attribution limits, not tail-latency estimates.

The repeated no-op controls contain 100 samples per variant and state:

| State | Baseline | Candidate | Bun |
|---|---:|---:|---:|
| Installed, dependency cache removed | 34 / 37 | 34 / 36 | 11 / 12 |
| Up to date | 34 / 37 | 34 / 37 | 11 / 12 |

No-op medians remained unchanged. Their diagnostics execute no linking or extraction tasks. Runtime validation and fixed startup work remain separate optimization candidates.

The smaller warm controls contain 24 samples per variant and state. This table reports medians only:

| Fixture | State | Baseline | Candidate | Bun |
|---|---|---:|---:|---:|
| Vite React | Fresh checkout, warm cache | 72.5 | 66 | 33 |
| Vite React | CI-warm | 66 | 58 | 31 |
| Native Sharp | Fresh checkout, warm cache | 43.5 | 42 | 9.5 |
| Native Sharp | CI-warm | 40 | 39 | 8 |
| Nest | Fresh checkout, warm cache | 63 | 54 | 33 |
| Nest | CI-warm | 57 | 48 | 32 |

Nest fresh-checkout p95 was 66 ms for the baseline and 67 ms for the candidate. Its candidate median improved by 9 ms. These 24-sample controls do not establish a tail improvement for the smaller fixtures.

The separate-root cohorts use an isolated HOME, dependency cache, and store for each variant. The shared-path cohorts deliberately share these paths between the two LPM binaries. Each warm state starts from its own seeded root and two unscored warm gates. The harness resets installation state outside measurement and rotates variant order. Builds, tests, and profilers stop during scored runs.

Fresh-checkout warm runs remove the lockfile, `node_modules`, and project `.lpm`, while preserving the dependency cache and store. CI-warm runs retain the lockfile. Installed-cache-removed runs preserve the package store and installed tree. The harness sets `CI=1`. Bun uses `install --ignore-scripts`. LPM uses `--json install --no-security-summary --no-skills --no-editor-setup` with isolated default configuration.

The scored warm, no-op, and repeated CI-cold runs omit timing instrumentation. Separate diagnostic runs use `--timing`. The four-fixture readiness controls retain the existing harness timing instrumentation for both LPM binaries.

The primary warm cohort completed its last scored artifact 293.23 seconds after its plan file. This bounds metadata age, but does not prove freshness because server cache lifetimes can be shorter than five minutes. The first confirmation measures one state at a time. The shared-path confirmation measures both states; its final scored artifact was 279.64 seconds after plan creation. Their inventory collector skips repeated visits to the same physical `node_modules` directory. That audit runs after the timed install. A fixture check established equivalent inventories for flat, scoped, aliased, cyclic, and self-linked layouts.

These repeated cohorts differ from the earlier six-state survey, which prepared a new root for each scored sample. Absolute times across those protocols are not interchangeable. Both LPM variants use the same preparation and sample count within each cohort. Earlier cohorts use three forward rotations: baseline precedes candidate in 67 of 100 rounds. Shared-path confirmations use six forward/reverse rotations and a 50/50 pair direction.

The four-fixture cold controls used 12 scored samples per variant and mode:

| Fixture | Mode | Baseline median | Candidate median | Bun median |
|---|---|---:|---:|---:|
| T3 | First install | 1,835.5 | 1,844.5 | 1,825.5 |
| T3 | CI-cold | 1,578.5 | 1,562 | 1,495 |
| Vite React | First install | 515.5 | 518 | 431.5 |
| Vite React | CI-cold | 279.5 | 279 | 176 |
| Native Sharp | First install | 282.5 | 269.5 | 192 |
| Native Sharp | CI-cold | 160 | 158 | 119.5 |
| Nest | First install | 347.5 | 371.5 | 265.5 |
| Nest | CI-cold | 307 | 301.5 | 217.5 |

The Nest first-install difference required a separate 24-sample follow-up. Its baseline median was 333.5 ms, versus 335.5 ms for the candidate. Bun measured 258.5 ms. Resolver medians were 169 and 170 ms for the LPM variants. The original 24 ms median regression did not repeat.

The follow-up retained a 26,994 ms candidate outlier. Its resolver took 26,879 ms. The `ms` metadata request spent 26,731 ms in the HTTP interval, followed by 9 ms of body reading. These counters locate the delay; they do not distinguish registry, transport, or runtime scheduling causes. This sample remains in all raw statistics. The follow-up does not establish a first-install tail improvement.

A separate 24-sample Sharp CI-cold follow-up measured medians of 158 ms baseline, 155 ms candidate, and 124 ms Bun. The candidate retained a 397 ms maximum; the baseline retained a 343 ms maximum. Unscored seed installs are labeled `counted: false` in the raw rows.

The first 100-sample T3 CI-cold cohort measured 1,537 / 1,588 ms for baseline and 1,526.5 / 1,636 ms for candidate. Bun measured 1,480 / 1,777 ms. The candidate median improved slightly, while p95 increased by 48 ms. This required an independent confirmation with a shared physical LPM root and balanced pair direction.

The shared-path warm and CI-cold confirmation harness uses the same physical project, HOME, cache, and store paths for both LPM binaries. Bun uses a separate root. Six forward and reverse permutations balance variant position and pair direction. With 100 samples, each permutation occurs 16 or 17 times. State resets remain outside each measured interval.

Installed package sets match across the completed cohorts: T3 has 95 packages, Vite React 63, Sharp 11, and Nest 33. Inventories compare unique package names and versions. Different filesystem layouts and duplicate instances are not equated. The repeated harness excludes project self-links before collection. The earlier six-state collector includes `installbench@0.1.0`; normalized comparisons remove only that project identity and retain the raw list.

The four-fixture readiness controls save one inventory after their final mode. Those files directly establish final CI-cold parity, not independent installed-file parity immediately after first install. The repeated warm, no-op, and T3 CI-cold cohorts retain an inventory after every scored install. Name/version parity does not establish identical live registry responses.

The concept depends on PR869's existing V2 install pipeline and traces. Its parent is `120a7e9c828bb11d6fa38445ac2c2a7234dee4cf`. The Node PATH correctness fix is independent and remains outside this performance branch and its measured binaries.

The local checks passed with zero build or Clippy warnings. They include 6,711 library tests, 5,278 CLI unit tests, 116 CLI binary tests, and 662 relevant install workflows. Helper checks, dependency policy, formatting, and the release build passed. Some passing tests reported leaked child handles; no test failed.

Coverage includes result identity, size ordering, worker limits, explicit overrides, mixed cached/local/missing entries, force refetch, and frozen lockfile rejection. Snapshot tests cover standalone rewrites, workspace projections, transaction priority, owning paths, and malformed or missing lockfiles.

The research ledger distinguishes rejected attributions from disproved general opportunities. Link snapshot misses are not separately counted, so these cohorts cannot prove that no fallback tree walk occurred. Next's work outside its reuse check was less than 1–2 ms in the reviewed warm diagnostics. This bounds the possible lock-parent contribution for that task; it does not measure every package's directory setup.

Every separately instrumented T3 fresh-checkout diagnostic reported 221 metadata cache hits and zero metadata HTTP time. CI-warm diagnostics reported zero metadata calls. Scored samples omit this instrumentation, so they cannot prove that no expiration probe occurred. No measured cost establishes stale-cache probes as the explanation for these results. Full-pipeline client setup exists, but the entire external-minus-internal remainder was only 8–9 ms in the reviewed no-op diagnostics. No measurement isolates a removable polling delay or a fixed extraction-lease tail defect.

A resolver-specific MessagePack projection remains an unmeasured proposal. One TypeScript cache read and projection took approximately 28 ms for 3,832 versions and 7 MiB of input. That diagnostic supports further measurement, not a promised speedup or a new persistent cache.

The shared-path CI-cold confirmation contains 100 samples per variant:

| Variant | Median / p95, ms | Range, ms | Median peak RSS, MiB |
|---|---:|---:|---:|
| Baseline | 1,828.5 / 1,976 | 1,544–2,030 | 215.0 |
| Candidate | 1,807 / 1,975 | 1,541–2,283 | 214.5 |
| Bun | 1,715.5 / 1,974 | 1,365–2,236 | 153.5 |

The earlier 48 ms p95 increase did not repeat. These two cohorts do not establish a CI-cold tail improvement. They support a small median reduction with no consistent p95 direction. Every outlier remains in each cohort. Absolute times changed between cohorts, so comparisons use the baseline and candidate measured together.

Warm-cache improvements repeat with separate and shared paths. No-op medians remain unchanged. First-install controls show no repeatable material median regression; their sample counts and retained metadata outlier do not support a cold-tail improvement claim.

The finding ledger contains 14 findings: 3 performance changes verified and fixed, 5 report corrections verified and fixed, and 6 rejected attributions. No finding is externally blocked or pending. The separate runtime PR contains 3 findings: 2 correctness fixes and 1 rejected performance attribution.

The isolated lockfile microbenchmark measured the standalone post-install read and serialization sequence. Twenty scored pairs alternated order after three warm rounds, with 25 operations per process. Both paths returned identical content and owning paths before timing.

The old sequence took 9.019 ms per operation at the median. One snapshot took 3.664 ms, a 5.355 ms reduction. This isolates three reads/two serializations versus one read/one serialization. It does not include engine checks, hashing, linking, or the complete install. The end-to-end results establish the combined improvement.

The performance source commit is `2d5e773d8546fa6fd77bcd738961f5055341ac52`. Benchmarked production source did not change after the release build. Later changes added tests and moved the test module for Clippy.

Artifacts:

- [Raw samples](cached-install-reuse-20260923-samples.jsonl) and [summaries](cached-install-reuse-20260923-summary.json).
- [Finding ledger](cached-install-reuse-20260923-ledger.json) and [local gates](cached-install-reuse-20260923-gates.json).
- [Provenance](cached-install-reuse-20260923-provenance.json), [plans](cached-install-reuse-20260923-plans.json), and [reproduction sources](cached-install-reuse-20260923-sources.json).
- [Diagnostic traces](cached-install-reuse-20260923-diagnostics.jsonl) and [isolated lockfile measurements](cached-install-reuse-20260923-lock-snapshot-micro.json).
- [Deduplicated inventories](cached-install-reuse-20260923-inventories.json) with [sample references](cached-install-reuse-20260923-inventory-index.json).
- [Deduplicated lockfiles](cached-install-reuse-20260923-lockfiles.json) with [sample references](cached-install-reuse-20260923-lockfile-index.json).

The sample artifact retains unscored readiness seed rows with `counted: false`. Scored comparisons exclude those rows. Separate diagnostic runs are not scored samples. Reproduction sources retain the original algorithms; local path placeholders require substitution for another checkout.
