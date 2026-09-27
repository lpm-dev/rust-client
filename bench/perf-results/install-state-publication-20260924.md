# Rebuildable install-state publication

The install-state cache no longer forces a full disk flush after each write.
The change retains atomic replacement and owner-only Unix permissions.
Missing or invalid cache data still requires install validation.
Recovery journals and their file and directory synchronization retain their existing behavior.
The tests cover atomic visibility and cache recovery. They do not simulate physical power loss or establish installed-tree durability.

The comparison uses PR #879 as its baseline, with Node 26.5.0, Bun 1.4.2, macOS arm64, and V2 stores.
Each warm CI fixture has 102 samples per variant. All six variant orders occur 17 times.
Both LPM binaries use the same project and store paths. Each variant has two warm gates before measurement.
Builds, tests, profilers, and other install benchmarks remained stopped during measurement.

Times are median / nearest-rank p95 milliseconds.

| Fixture | Baseline | Candidate | Bun | Paired median change | Faster pairs |
|---|---:|---:|---:|---:|---:|
| T3 | 106.53 / 115.38 | 96.05 / 104.37 | 180.27 / 198.88 | -10.91 | 96/102 |
| Vite React | 65.96 / 72.05 | 56.75 / 60.41 | 31.11 / 34.83 | -9.28 | 96/102 |
| Native Sharp | 41.98 / 44.67 | 37.45 / 39.35 | 8.90 / 9.99 | -4.86 | 102/102 |
| Nest | 58.03 / 62.68 | 46.38 / 48.79 | 31.17 / 35.76 | -11.87 | 100/102 |

All 1,224 installs succeeded. Selected package inventories matched across all variants, and LPM lockfiles matched byte for byte.
Scored LPM samples downloaded no dependencies. The live registry supplied the initial caches.
The comparison checks package inventories and LPM lockfiles. It does not compare every installed payload byte or equate filesystem layouts.
Median LPM peak RSS changed by less than 0.4 MiB on each fixture. This experiment does not establish a memory improvement.

A separate atomic-write experiment alternated 100 samples per variant.
The median/p95 changed from 3.943/4.794 ms with synchronization to 0.285/0.491 ms without synchronization.

A frozen T3 control used 24 samples per variant and state.
Its 101 tarballs passed registry integrity checks. Scoring made zero upstream requests and encountered zero replay misses or rejected requests.

| State | Baseline | Candidate | Bun | Paired candidate change | Faster pairs |
|---|---:|---:|---:|---:|---:|
| First install | 1697.29 / 1886.65 | 1634.58 / 1985.73 | 1459.54 / 1640.06 | +13.55 | 11/24 |
| CI cold | 1582.79 / 1680.04 | 1446.74 / 1621.20 | 1461.02 / 1633.45 | -57.13 | 17/24 |
| CI warm | 115.28 / 124.99 | 105.31 / 107.49 | 226.28 / 335.74 | -9.52 | 22/24 |

The cold results do not establish a first-install improvement. First-install p95 increased, and its paired median change was positive.
Much of the apparent CI-cold gain occurred before cache publication. Thus, the full cold difference cannot be attributed to this change.
The internal install timer stops before cache publication. External process time remains the measure for the complete install.
Old request labels combined different scenarios. The replay helper now includes the scenario, and a regression test checks unique labels.
The original cold samples remain in the evidence; the label correction does not change those measurements.

Rust 1.94.0 workspace build, formatting, and Clippy passed with warnings denied.
The local gates passed 6,735 non-CLI tests, 5,297 serial CLI tests, 116 CLI surface tests, and 86 affected workflows.
All 72 install-state unit tests and all eight replay-helper tests passed. Shell, Node, and npm helper gates also passed.

The review ledger contains eight reports: three verified corrections and five rejected claims or preserved constraints.
The corrections cover the flush cost, test portability, and request labels. No report remains blocked or pending for this concept.

[Samples, summaries, provenance, and review evidence](install-state-publication-20260924.json) retain both warm and cold results.
The source change is commit `03f953e7c4d0aa409d4b26ff5fc3706631ec50b7`.
The preserved release binary predates one additional portable test. Its production code matches the final change.

For reproduction, use [the paired install harness](../scripts/install-noop-benchmark/paired-warm.mjs) with the four existing fixture configurations.
Set `samples` to `102`, `states` to `["ci-warm-cache"]`, `diagnostics` to `4`, and `bareInstall` to `false`.
Remove `expectCompactNoop` from the variants. Set the baseline, candidate, Bun, and fresh output paths to absolute paths.
Retain `balancedOrders: true`, `sharedLpmRoot: true`, and two warm gates.
