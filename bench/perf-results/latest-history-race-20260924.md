# Latest-document and history race

A ranged npm request can be answered by the small `/<name>/latest` document when the latest version satisfies the range. The unpublished sequential experiment fetched that document first and requested history only after a miss, so every miss paid a full extra round trip. Graphs pinned to older majors stacked that delay at each level: Nest lost 197 ms and Sharp 41 ms at 100 Mbit/s with 40 ms response latency.

This change requests the latest document and the preferred history together when no usable cache exists. A latest version inside the range answers the request and cancels the history transfer. A miss, an invalid document or a failure continues with the history already in flight, and a history failure still defers to a satisfying latest document. Cached preferences keep their precedence.

## First-install results

All three LPM binaries share the parallel-writer-admission stack head. Times are median / nearest-rank p95 milliseconds with 24 samples per variant. The paired column is the median per-sample difference from the baseline, with the number of faster pairs.

### 100 Mbit/s, 40 ms response latency

| Fixture | Baseline | Sequential | Race | Race paired | Bun |
|---|---:|---:|---:|---:|---:|
| Native Sharp | 802.0 / 810.6 | 842.7 / 859.9 | 801.3 / 819.5 | +1.2 (11/24) | 742.5 |
| Nest | 506.8 / 528.6 | 701.0 / 715.2 | 501.2 / 517.8 | −6.8 (21/24) | 448.0 |
| Vite React | 1,912.5 / 1,929.3 | 1,737.8 / 1,744.8 | 1,713.6 / 1,728.6 | −200.2 (24/24) | 1,804.2 |
| T3 | 12,707.3 / 12,785.0 | 11,899.9 / 11,928.2 | 11,910.0 / 11,931.3 | −793.0 (24/24) | 12,803.0 |

### 1 Gbit/s, 30 ms response latency

| Fixture | Baseline | Sequential | Race | Race paired | Bun |
|---|---:|---:|---:|---:|---:|
| Native Sharp | 355.3 / 1,091.8 | 378.2 / 415.9 | 346.8 / 404.4 | −11.1 (13/24) | 283.5 |
| Nest | 379.8 / 420.5 | 496.2 / 534.2 | 380.8 / 426.7 | +3.3 (10/24) | 292.2 |
| Vite React | 657.0 / 679.6 | 632.0 / 651.3 | 608.1 / 626.7 | −48.7 (24/24) | 473.1 |
| T3 | 3,665.1 / 4,209.7 | 3,442.5 / 3,572.3 | 3,436.1 / 3,535.6 | −222.5 (23/24) | 3,593.1 |

The race removes the sequential regressions on Sharp and Nest in both profiles. It keeps the Vite and T3 transfer savings and beats the sequential design by 23–25 ms on Vite in 22–24 of 24 pairs. The baseline Sharp p95 in the fast profile comes from retained outliers.

### Zero latency

The unshaped replay answers every request immediately.

| Fixture | Baseline | Sequential | Race | Race paired | Bun |
|---|---:|---:|---:|---:|---:|
| Native Sharp | 105.8 / 109.7 | 105.2 / 110.2 | 106.6 / 128.6 | 0.0 (12/24) | 64.1 |
| Nest | 316.9 / 337.4 | 317.4 / 344.6 | 326.8 / 350.7 | +7.0 (7/24) | 276.0 |
| Vite React | 314.0 / 335.7 | 317.4 / 337.2 | 315.9 / 339.3 | +5.7 (9/24) | 247.1 |
| T3 | 1,898.7 / 2,120.2 | 1,752.8 / 2,007.8 | 1,809.0 / 2,046.0 | −95.4 (18/24) | 1,902.6 |

Without latency the history response is complete before cancellation reaches the server, so the race transfers what the baseline transfers plus the latest documents. On T3 it therefore trails the sequential design by 55.2 ms paired while remaining 95.4 ms faster than the baseline. The race path is limited to the `NpmDirect` route, which targets `registry.npmjs.org`; registries declared in `.npmrc` use the custom route and never race. Zero latency therefore does not describe a production path. These rows bound the cost of the extra requests.

Installs from a lockfile do not use this metadata path. Across the seven CI-cold cohorts, the race's paired difference from the baseline ranged from −20.5 to +1.1 ms with no consistent direction, and the sequential design's ranged from −3.7 to +7.5 ms.

## Metadata traffic

Replay-proxy records per first install. History megabytes are payload bytes scheduled by the proxy; cut short counts history responses that ended before their full payload.

| Profile | Fixture | Baseline history | Sequential history | Race history | Race latest requests | Race history cut short |
|---|---|---:|---:|---:|---:|---:|
| 100 Mbit/s, 40 ms | Vite React | 11.64 MB | 8.81 MB | 8.87 MB | 59 | 24.8 |
| 100 Mbit/s, 40 ms | T3 | 31.77 MB | 21.56 MB | 21.62 MB | 69 | 56.0 |
| 1 Gbit/s, 30 ms | Vite React | 11.64 MB | 8.81 MB | 9.08 MB | 59 | 16.0 |
| 1 Gbit/s, 30 ms | T3 | 31.82 MB | 21.55 MB | 21.91 MB | 69 | 48.7 |
| Zero latency | T3 | 33.77 MB | 23.56 MB | 33.87 MB | 69 | 0 |

With response latency, cancelled history transfers stop early and the race moves almost exactly the sequential design's bytes. The adjacent summary contains every fixture.

## Parity

Every LPM variant produced identical selected-package inventories and object content digests within each fixture, profile and state. All 1,824 scored installs succeeded: 1,368 LPM and 456 Bun.

## Method

The harness replays pinned HTTPS captures through a local proxy and makes no upstream requests while scoring. The shaped profiles pace response payloads through one shared round-robin budget and delay each response by the stated latency. They do not model packets, TCP setup, loss or congestion.

Each state seeds its caches and runs two unscored warm gates. The 24 scored rounds rotate four variants through eight balanced orders; every variant runs in every position three times. Scored installs run without timing instrumentation. Four instrumented diagnostic installs per LPM variant follow the scored rounds and are excluded from the tables.

| Variant | Source | Binary SHA-256 |
|---|---|---|
| Baseline | `28b6ae28c` | `aec138877faf3a19c6277c91d04ac0e81385eb4e7f3a5d27ecab1d7117faa36b` |
| Sequential | `3066da5ff` | `2234f484de93c88854ad3f4eee4bdb8839ef8185a05ddbdc793c66550b8c7697` |
| Race | `d193e6e5e` | `d5706b9dd23ba6af25034c98fae5cef1a4bf1a635f38e7350b167bda1a26847b` |
| Bun 1.4.2 | reference | `35d20dd0263e5c950194434b925454fdfa9ba6e4467da960410fa05b08a7a5b5` |

All LPM binaries use Rust 1.94.0 and the release profile with `--locked`. The later test-isolation commit changes only tests and test-only code, so the measured race binary matches the branch's production source. The host is an Apple M5 Pro on macOS 27.0 with Node v24.19.0. Builds, tests and profilers were stopped during scoring.

The fixtures and captures are the ones the sequential experiment used. Helper hashes: `pacer.mjs` `6c560fcc99f5dfe786c3d979d7d4d3dc9473374457f5549831a4962b1890a15a`, `replay-proxy.mjs` `364e8675d4bfff50692f6e47b8840f1c540323249ac8f679c21c8729f4d280e2`, `runner.mjs` `8ce827cf121ff4526a38dc227fc753599c128d0d1f6459d1d516c266d4278339`.

## Test isolation

Three existing tests failed intermittently under parallel `cargo test` on the stack head: 4 of 12 registry runs and 2 of 6 resolver runs. Each observed state that concurrent tests share:

- The unprofiled policy test reset and read the process-wide policy counters that every concurrent resolution also resets and advances. It now reads a test-only per-thread count and checks that the profiled path records on the same thread.
- Five resolver tests read `LPM_RESOLVER` without the module's environment lock, so a PubGrub-pinned test could switch their resolver arm mid-run. The npm-alias test failed deterministically under `LPM_RESOLVER=pubgrub`. They now hold the lock and pin the default arm.
- The cache serialization trace test used the only live dispatcher. tracing's single-dispatcher path then registered the shared callsite through another thread's empty dispatcher as never enabled. In a standalone program on the same tracing versions, the span was missing in 3 of 3 runs without a second dispatcher and in none of 3 runs with one. A second live dispatcher now keeps registration consulting every dispatcher.

After these changes, 20 consecutive full parallel runs of each crate passed.

The latest-tag hint workflows previously required zero `/latest` requests. Resolution may now race one latest document per package, so they accept at most one; hints add no request of their own, and exact requests still never fetch the latest document.

## Validation

All commands use Rust 1.94.0 with `--locked` on the final branch.

| Gate | Result |
|---|---|
| Workspace all-target Clippy with `-D warnings`, formatting, fancy-regex policy, workspace build | Passed |
| Workspace nextest excluding CLI and workflows | 6,829 passed, 10 skipped |
| Serial CLI unit tests | 5,326 passed, 10 ignored |
| CLI surface tests | 116 passed |
| Install workflow suites | 592 passed, 3 skipped |
| Remaining workflow suites, hermetic CLI | 3,259 passed, 7 skipped |

No dependency declarations changed.

## Limitations

These are local replay results on one host, not live-registry measurements. The shaped profiles approximate transfer pacing and response latency only. Nest's fast-profile difference (+3.3 ms, 10 of 24 faster pairs) is not a measured gain. Twenty-four samples per variant cannot characterize tails beyond the reported p95.

## Artifacts

The adjacent `-summary.json` contains every fixture, profile and state, the per-run traffic summary and the binary provenance. Raw rows, proxy event logs, instrumented diagnostics and harness copies remain under `performance-runs/20260924/race`.
