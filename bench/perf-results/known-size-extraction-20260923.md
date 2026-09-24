# Known-size file extraction

Large file-backed tarballs previously allocated an 8 MiB compressed prefix before switching to streaming extraction.
The store now reads the opened file handle's metadata and selects streaming directly for regular files larger than that limit.
Small files, exact-limit files, nonregular files, and metadata failures retain hybrid extraction.
Both callback modes use the same selection. Decoder, integrity, extraction limits, validation, and publication behavior remain intact.

## Memory attribution

A release DHAT diagnostic recorded a global tracked heap peak of 50.73 MiB.
Two decoded tar buffers occupied 34.07 MiB. One compressed prefix occupied 8 MiB.
Together these allocations accounted for 82.94% of that tracked peak.
Only 0.534 MiB remained live at exit. This does not establish a memory leak.
DHAT changes the allocator and scheduling. Its wall time and RSS are not production comparisons.

The production RSS gap includes allocator retention and allocations outside the tracked heap.
One diagnostic observed 59 allocator-using threads. Single runs with lower blocking-thread limits or immediate purging did not justify a policy change.

## SWC extraction microbenchmark

The fixture is the original 31,696,188-byte archive for `@next/swc-darwin-arm64@16.3.6`.
Its bytes match the captured registry integrity. Both preserved binaries use the same file and declared SRI.
Two warm-up rounds precede 24 scored alternating rounds. Source analysis is disabled.
The example measures verification, extraction, and publication. Process RSS comes from `/usr/bin/time -l`.

| Variant | Extraction median / p95 | Median peak RSS |
|---|---:|---:|
| Parent | 171.43 / 226.53 ms | 16.73 MiB |
| Candidate | 180.99 / 224.16 ms | 6.97 MiB |

The median of paired extraction differences is +0.795 ms. Each variant wins 12 pairs.
The aggregate medians differ by 9.56 ms, but this cohort does not establish a consistent extraction penalty.
No speed improvement is claimed. The approximately 9.77 MiB process RSS reduction is repeatable within this cohort.

## T3 CI-cold

The cohort contains 24 samples per variant with all six execution orders balanced.
Each sample retains a seeded lockfile and starts with empty package stores, caches, and installation state.
Both LPM variants share physical paths. Two deterministic warm gates precede scoring.
No builds or profilers ran during scoring. The registry remained live.

| Variant | Wall median / p95 | Peak RSS median / p95 |
|---|---:|---:|
| Parent | 1559.5 / 1617 ms | 213.89 / 238.72 MiB |
| Candidate | 1571 / 1659 ms | 206.74 / 224.72 MiB |
| Bun | 1524 / 1849 ms | 124.33 / 148.47 MiB |

The candidate saves 7.15 MiB median peak RSS. Wall median increases by 11.5 ms, or 0.74%.
This is a memory improvement, not a demonstrated speed improvement or tail-latency improvement.

## Four-fixture controls

The repository readiness harness ran one unscored warm-up and 12 scored samples for each fixture, variant, and state.
The scored matrix includes cold, warm, and up-to-date states. All 432 installs succeeded.
It includes built-in phase timing. Its absolute values are not directly comparable with the dedicated CI-cold harness.
All warm and up-to-date comparisons passed. The live Vite cold comparison regressed.

| Cold fixture | Parent median / p95 | Candidate median / p95 | Bun median / p95 |
|---|---:|---:|---:|
| T3 | 1900.5 / 2116 ms | 1896 / 2183 ms | 1793.5 / 1847 ms |
| Vite React | 631 / 752 ms | 707 / 1033 ms | 408 / 644 ms |
| Native Sharp | 316 / 511 ms | 302 / 464 ms | 236.5 / 273 ms |
| Nest | 340.5 / 854 ms | 335 / 447 ms | 296.5 / 527 ms |

Report percentiles use nearest rank. The harness verdict uses interpolation.
All original samples remain in the raw rows, including warm-up and unsuccessful comparison verdicts.

The frozen Vite capture contains 63 tarballs. None exceeds 8 MiB.
The largest archive is 4,080,074 bytes, so the new streaming route does not apply to these bytes.
The added metadata check can still execute. The capture alone does not explain the live timing difference.

The fixed-input Vite control uses the original ranges, npm-direct routing, and original HTTPS response bodies.
A loopback HTTP/2 proxy serves a pinned capture and refuses uncaptured requests during scoring.
All 63 original archives match registry SRI. The cohort contains 36 balanced rounds after warm gates.

| Variant | Vite wall median / p95 | Median peak RSS |
|---|---:|---:|
| Parent | 245 / 263 ms | 186.80 MiB |
| Candidate | 246 / 263 ms | 187.27 MiB |
| Bun | 173.5 / 183 ms | 142.73 MiB |

The live regression does not repeat with these fixed inputs. Its original cause remains unknown.
Both LPM variants produce identical lockfiles, selected-package inventories, and object-content digest maps across all 72 local samples.

A separate 24-round T3 CI-cold confirmation uses the same method as the pilot:

| Variant | Wall median / p95 | Peak RSS median / p95 |
|---|---:|---:|
| Parent | 1522.5 / 1682 ms | 216.84 / 240.48 MiB |
| Candidate | 1512.5 / 1637 ms | 212.22 / 233.83 MiB |
| Bun | 1412.5 / 1811 ms | 129.45 / 157.02 MiB |

The second cohort saves 4.62 MiB median peak RSS. The wall median is 10 ms lower.
The two cohorts support a modest RSS improvement with roughly level wall time. They do not establish a dependable speed or p95 improvement.
Within each CI-cold cohort, all LPM lockfiles and selected-package inventories match across variants.

## Validation

Rust 1.94.0 workspace build and all-target Clippy pass with zero warnings. Formatting passes.
The fast local gate passes 6,729 library tests, 5,278 serial CLI tests, and 116 CLI surface tests.
The relevant install gate passes 723 tests across 20 workflow targets. All 17 helper groups pass.
The store suite includes 360 tests, including new threshold, inspector, V3, permissions, and truncated-trailer cases.

The initial CLI unit run failed five self-update trust tests beneath the world-writable `/tmp` source parent.
The same binary reproduces the location-dependent failure and passes from the private workspace directory.
The complete serial CLI gate then passes from that directory through a Cargo test runner. No trust check was weakened.

Finding ledger: three received, three verified and resolved, zero rejected, zero blocked, zero pending.
The memory concept extends PR875. The user requested the cumulative native stack.
Timeline diagnostics are a separate concept and will measure the resulting extraction path.

## Reproduction and provenance

Parent commit: `2718e5e67ef68025596c10816d3937ff1372b179`.
The preserved parent binary predates report-only commits and has identical runtime source.
Parent binary SHA-256: `e47c97a0e3df43fa188d750b984e1facf88a9f7699ceb3bae2cb8e03967bf1ae`.
Candidate binary SHA-256: `332844f48cda8726d682a613009d906bc0ba430f01704f595c26b139523094f0`.
Both use Rust 1.94.0 and release settings on macOS arm64.

The extraction example accepts an archive path and declared SRI:

```sh
cargo build --release --locked -p lpm-store --example file-extraction
/usr/bin/time -l target/release/examples/file-extraction archive.tgz 'sha512-…'
```

Use separate Cargo targets for separate source worktrees. A reused target initially selected stale baseline example artifacts.
That binary was rejected before any microbenchmark. The scored parent example came from a fresh isolated build.

Local raw profiles, logs, binaries, fixture provenance, and drivers remain under `/tmp/lpm-next-install-costs`.
Public companion files retain the scored rows and summaries.
