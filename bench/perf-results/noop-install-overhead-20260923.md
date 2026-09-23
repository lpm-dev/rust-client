# No-op install overhead

This work extends PR872. It overlaps the required Node version probe with lockfile replay on an otherwise unchanged install.
It also reuses the authoritative lockfile path for the binary-sidecar check. The previous check repeated lockfile selection and parsing.

The runtime probe remains live on every constrained install. An unchanged shim executable can report a different version after its external data changes.
The overlap starts after the existing freshness and compatibility-bin checks pass. A thread creation failure uses the existing synchronous probe.
The shared `OnceLock` limits runtime resolution to one probe per install.

## Measurements

The combined change has two completed cohorts with 100 samples per variant and state.

| State | PR872 baseline | Combined candidate | Bun |
|---|---:|---:|---:|
| Installed, cache removed | 42 / 44 | 38 / 39 | 12 / 12 |
| Up to date | 42 / 44 | 38 / 40 | 11 / 12 |

Median peak RSS remained near 25.6–25.8 MiB for LPM and 7.86 MiB for Bun.
One unscored Bun seed took 110.47 seconds. Its stdout and stderr remain in the preparation artifacts.

The independent confirmation also includes the overlap-only binary:

| State | PR872 baseline | Overlap only | Combined candidate | Bun |
|---|---:|---:|---:|---:|
| Installed, cache removed | 42 / 43 | 40 / 42 | 39 / 40 | 12 / 13 |
| Up to date | 42 / 43 | 40 / 43 | 38 / 39 | 11 / 12 |

Path reuse saves another 1–2 ms at the median in this cohort. Median peak RSS remains within 0.2 MiB across LPM variants.
The candidate retains a 48 ms cache-removed maximum, compared with 46 ms for the baseline. The p95 gain does not guarantee lower maxima.

The earlier overlap-only cohort also contains 100 samples per variant and state. It excludes the later path-reuse change.
All times are median / nearest-rank p95 milliseconds. Every sample remains in the results.

| State | PR872 baseline | Overlap prototype | Bun |
|---|---:|---:|---:|
| Installed, cache removed | 41 / 43 | 39 / 40 | 12 / 12 |
| Up to date | 41 / 43 | 39 / 41 | 11 / 12 |

Median peak RSS was 25.84 MiB for the baseline and 25.88–25.92 MiB for the prototype.
Bun used 7.86 MiB. This earlier cohort supports the overlap change alone. The later cohorts measure and confirm the combined change.

The harness balances forward and reverse variant orders. Both LPM binaries use the same project and store paths for each state.
Warm gates precede scored samples. Builds and profilers stop before scoring. The harness retains raw samples and installed inventories.
The benchmark compares only LPM and Bun.

A separate 24-sample diagnostic measured `node --version` at 19.812 ms median and the baseline no-op at 36.265 ms median.
These measurements show the runtime-probe cost. Their absolute times are not comparable with the later cohort.

## Coverage

The focused install-state suite passed 67 tests.
The initial workflow run passed the new shim checks and existing cached-entry checks.
The extended suite also covers removal of all engine constraints after a previous constrained install.

The final local gates passed: 6,711 library tests, 5,278 CLI unit tests, 116 CLI surface tests, and 664 install-workflow tests.
Workspace build, Clippy, formatting, dependency policy, and all 17 helper checks passed. The optimized build produced zero warnings.
Nextest reported one leaky library test and two leaky CLI surface tests. All three tests passed.
The retained logs contain the complete commands, skipped-test counts, and outcomes.

## Finding ledger

No subagents contributed findings in this round. The primary agent recorded these two performance findings.

| ID | Source | Category | Location | Claim | Evidence | Disposition | Coverage | Commit | PR status |
|---|---|---|---|---|---|---|---|---|---|
| NOOP-1 | Primary | Performance | `commands/install/state.rs`, `engine_check.rs` | Live Node probing serializes with lockfile replay | Two overlap-only cohorts improve both medians by 2 ms | Verified | Shim output, probe count, root engines, engine-free install | `d89d9ed1a` | Unpublished |
| NOOP-2 | Primary | Performance | `install_state.rs` | Sidecar checks repeat authoritative lockfile path selection | Both freshness branches already selected that path. Independent comparison improves medians by another 1–2 ms | Verified | Install-state suite and workspace workflows | `d89d9ed1a` | Unpublished |

Caching a version from executable metadata alone was rejected. The shim experiment preserved executable metadata while its reported version changed.
The candidate correctly rejected the incompatible version. This rejected proposal is not an unresolved code defect.

## Four-fixture controls

The repository readiness harness ran one warm gate, then 12 adjacent baseline/candidate pairs per fixture and mode.
Bun ran as the reference. The modes were first install, CI-warm, and up to date.
Every install passed. The 12-sample up-to-date medians were:

| Fixture | PR872 | Candidate | Bun |
|---|---:|---:|---:|
| T3 | 37 | 33 | 22 |
| Vite React | 34 | 32 | 17 |
| Native Sharp | 31 | 31 | 8 |
| Nest | 31 | 31 | 12 |

The CI-warm medians changed by at most 1 ms across fixtures.
The readiness harness flagged a first-install T3 p95 regression and an inconclusive Vite median difference.
The T3 candidate maximum was 2,383 ms. Resolution used 1,738 ms, while freshness work used zero milliseconds.
The modified freshness phase exits before its new work on these clean projects.
HTTP and body intervals do not distinguish transport, registry, and runtime scheduling causes.

A 24-sample follow-up for T3 and Vite passed the comparison thresholds. Its cold medians and nearest-rank p95 values were:

| Fixture | PR872 | Candidate | Bun |
|---|---:|---:|---:|
| T3 | 1,938 / 2,261 | 1,946 / 2,290 | 1,724 / 2,027 |
| Vite React | 669 / 1,082 | 677 / 880 | 415 / 539 |

The harness uses interpolated percentiles for its verdict. The tables in this report use nearest-rank percentiles.
The original cold regression did not repeat. These small control cohorts do not establish a cold-tail improvement.
Both cohorts and all outliers remain available.

All 2,000 scored no-op inventories agree by package name and version within each cohort and state.
All LPM lockfile bytes agree within each cohort and state. These inventories do not establish package-file byte parity.
The cached-entry workflow separately checks package bytes.

The host uses an Apple M5 Pro and macOS 27.0. Builds use Rust 1.94.0 with the normal release profile.

Finding totals: 2 received, 2 verified and fixed, 0 rejected, 0 blocked, and 0 pending.

## Artifacts

The local artifact directory is `/tmp/lpm-noop-overhead`.
It contains preserved binaries, build logs, raw benchmark rows, probe evidence, and the profiling capture.
The initial cohort is `overlap-100/rows.json`. Its configuration is `overlap-100.json`.
The combined binary SHA256 is `09de81fe489b8a66356fa8d8c66d26d301efd2ea5367b5b7ef336767a1cd94f6`.
The baseline is PR872 commit `c6d7ab6ed0f41df5bd17ed7dd598ba711efecc7f`.
Its binary SHA256 is `85d3b9973d1b17f66b6936b3d18e129f3da3caed613082473d8f0a86520b4301`.

## Runtime policy reference

A separate fixture required Node `>=999.0.0` in its root manifest.
Bun 1.4.2 accepted that fixture. LPM rejected it with `engine_mismatch`.
This case shows a policy difference. It does not attribute every millisecond of the no-op gap.

Readiness artifacts are `readiness-scored/` and `readiness-cold-confirm/`.
The follow-up includes brief artifact inventory and disk-usage inspection during execution. It supports regression screening, not precise cold-tail attribution.
The dedicated no-op cohorts contain no concurrent builds, application tests, or profilers.
