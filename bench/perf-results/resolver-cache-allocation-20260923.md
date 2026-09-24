# Resolver cache allocation

Fresh metadata cache hits decoded development dependencies that the greedy resolver immediately discarded.
The resolver now skips those fields during preferred and complete MessagePack cache reads.
All other version fields use the existing decoder and normalization rules.

Full-metadata consumers, network responses, cache writes, and 304 hydration retain development dependencies.
Expired records and range-miss fallback use the existing full path. Projected records are never persisted.
The API completeness flag describes version coverage. It does not promise development dependency fields.

## Warm-cache installs

The benchmark starts from a fresh checkout with populated metadata and package caches.
Each scored install removes the lockfile, project state, and installed layout.
Times are median / nearest-rank p95 milliseconds. RSS values are median peak MiB.

| Fixture | Samples per variant | Parent | Candidate | Bun | Parent RSS | Candidate RSS | Bun RSS |
|---|---:|---:|---:|---:|---:|---:|---:|
| T3 | 100 | 118.5 / 127 | 111 / 122 | 206 / 219 | 118.56 | 92.72 | 49.19 |
| Vite React | 36 | 71 / 78 | 69 / 77 | 35 / 36 | 100.72 | 91.97 | 22.42 |
| Native Sharp | 36 | 44 / 46 | 44 / 48 | 10 / 11 | 38.84 | 38.98 | 7.39 |
| Nest | 36 | 58.5 / 68 | 57 / 68 | 35 / 37 | 48.13 | 47.63 | 7.81 |
| T3 confirmation | 100 | 119 / 132 | 110.5 / 128 | 191 / 206 | 116.66 | 92.54 | 49.19 |
| Sharp confirmation | 100 | 43 / 46 | 43 / 46 | 10 / 11 | 38.97 | 38.90 | 7.39 |

T3 saves 7.5–8.5 ms and approximately 24–26 MiB. Vite saves 2 ms and approximately 9 MiB.
The initial Sharp p95 increase did not repeat in the larger confirmation.
The Vite candidate maximum remains 87 ms, compared with 81 ms for the parent.
No samples were removed.

The harness balances forward and reverse execution orders. Both LPM variants share the same physical project and store paths.
Seed installs and two unscored warm gates precede scoring. Cache expiry remains unchanged.
Scored installs run without timing instrumentation, builds, or profilers. Separate diagnostics collect phase timings.
All 36 diagnostics reported zero metadata cache misses and zero metadata RPCs.

All 1,224 scored inventories match by selected package name and version within each cohort.
Both LPM variants produce identical lockfile bytes within each cohort. These checks do not establish package-file byte parity.

## Decoder measurement

Five retained large package histories contain 8,287 versions. Both variants use the production decoding types.
Each variant ran 20 alternating process samples with 10 decodes per process after an unscored warm gate.
Median time per decode decreased from 38.564 to 24.608 ms.
Median peak RSS decreased from 64.773 to 33.016 MiB.
Every decoded field except development dependencies matched.

This decoder measurement bypasses expiry and uses the default process allocator.
The full CLI cohorts establish the install and RSS effects.

## Cold and unchanged-install controls

The repository readiness harness ran all four fixtures with LPM parent, LPM candidate, and Bun.
One unscored gate preceded 12 scored samples in cold, CI-warm, and up-to-date modes.
All installs completed successfully. The comparison flagged a T3 cold-tail regression.
CI-warm medians changed by at most 0.5 ms. Up-to-date medians remained unchanged.

| Cold fixture | Parent | Candidate | Bun |
|---|---:|---:|---:|
| T3 | 1,942 / 2,301 | 1,960 / 3,813 | 1,803.5 / 2,168 |
| Vite React | 673 | 706.5 | 546 |
| Native Sharp | 336 | 304.5 | 260.5 |
| Nest | 363.5 | 380.5 | 323.5 |

The 3,813 ms T3 sample spent 2,743 ms in resolution, 886 ms in fetch, and 121 ms in linking.
Its cumulative metadata HTTP interval was 41,040 ms. Body reads accounted for 9,433 ms across concurrent requests.
These intervals include scheduling and do not identify the cause of the delay.

A separate 24-sample cold follow-up passed the comparison thresholds:

| Fixture | Parent | Candidate | Bun |
|---|---:|---:|---:|
| T3 | 1,997.5 / 3,482 | 2,031.5 / 2,880 | 1,785 / 2,040 |
| Vite React | 730.5 / 1,099 | 737 / 993 | 520 / 1,167 |

The follow-up retains large maxima: T3 parent 14,457 ms, candidate 7,204 ms, and Bun 7,423 ms.
Vite Bun sample 11 completed after 112,072 ms. It remains in the results.
The harness uses interpolated percentiles for its verdict. This report uses nearest-rank percentiles.
Both cohorts remain available. Neither establishes a cold-tail improvement from this cache change.

## Review and coverage

Read-only correctness and trust reviews found no production defects.
Regression coverage compares all retained fields, including scripts, platform constraints, signatures, attestations, publisher evidence, and security metadata.
Additional tests cover malformed caches, mismatched package identities, bundle precedence, platform normalization, and full consumer reads after forced 304 rewrites.

The final local gates passed: workspace build, workspace/all-target Clippy, formatting, 6,717 library tests, 5,278 CLI unit tests, and 116 CLI surface tests.
All 664 targeted install-workflow tests and 17 helper checks passed. The optimized CLI build produced zero warnings.
Nextest marked two passing library tests and one passing CLI surface test as leaky.
Dependency policy passed with existing duplicate-dependency warnings. No dependency declarations changed.

Finding totals: 1 received, 1 verified and fixed, 0 rejected, 0 externally blocked, and 0 pending.
The source change is commit `6009247f8`.

## Scope and artifacts

The parent is PR873 at `59f88d1d9a1f3aed63d93aea082a1ce430938737`.
This concept uses the earlier preferred-metadata path. It does not require the no-op overlap implementation.
Its placement after PR873 follows the requested cumulative native stack.

The host uses an Apple M5 Pro and macOS 27.0. Both CLI binaries use Rust 1.94.0 and the normal release profile.
The local artifact root is `/tmp/lpm-resolver-cache-allocation`.
It retains both binaries, logs, raw samples, fixtures, cache data, and diagnostic traces.
The adjacent provenance file records binary hashes, harness configuration, decoder samples, and cache-hit evidence.
The adjacent sample and readiness files retain every scored row.
