# Cold object finalization

Extraction supplies a digest for each file. Object finalization still collected filesystem metadata with one stat operation per entry.
The macOS extraction path now reuses the existing bulk metadata reader. One 64 KiB buffer serves the traversal.
Shared hashing code consumes normalized metadata fields on all platforms.

The walker collects each complete directory before it changes hash state. After a bulk failure, the remaining walk uses the portable reader.
Symlinks use `symlink_metadata` and `read_link`. Missing and surplus extraction digests still fail.
Full filesystem verification and other platforms retain the portable path.
This change preserves the existing trust boundary. It does not add resistance to concurrent filesystem replacement.

## Frozen cold-store comparison

The fixture pins Next 16.3.6, React 19.3.0, and React DOM 19.3.0.
A loopback registry serves captured metadata and original tarball bytes. Only metadata tarball URLs change.
All 24 captured archives match registry SRI, covering 87,962,268 bytes. Scored runs cannot fetch uncaptured responses upstream.

Each sample restores a seeded lockfile and starts with empty installation state, caches, and package stores.
Both LPM binaries use the same physical project and store paths.
Two unscored warm gates precede 60 rounds with all six variant orders balanced.
This measures cold package stores with warmed local archive inputs, rather than public-registry network conditions.

Times below are median / nearest-rank p95 milliseconds. RSS is median peak MiB.

| Variant | Samples | Wall time | Peak RSS |
|---|---:|---:|---:|
| PR874 parent | 60 | 1,053.5 / 1,282 | 278.73 |
| Candidate | 60 | 1,020 / 1,272 | 276.81 |
| Bun | 60 | 930 / 1,160 | 183.01 |

The difference between medians is 33.5 ms. The median paired improvement is 10 ms; the candidate wins 35 of 60 rounds.
The cohort also contains a shared timing shift around round 26. All three variants become substantially faster later in the run.
The cause is unknown. Balanced orders help limit bias from timing drift, but the global median difference is not an isolated optimization estimate.
The end-to-end improvement remains suggestive. Neither wall time nor p95 improvement is established by this cohort alone.
The approximately 1.9 MiB RSS difference does not establish a material memory benefit.
All samples and outliers remain in the results.

All 180 selected-package inventories match. Both LPM variants produce identical lockfiles and content-digest maps across all 120 LPM samples.
Every scored install requests the same 22 tarballs. No frozen-registry request misses occurred.
Content-digest parity applies to LPM. Bun parity here covers package selection and original tarball inputs, not every installed file byte.

## Local attribution

Next contains 8,531 files and 696 directories.
Separate CLI diagnostics show the following median finalization intervals:

| Cohort | Diagnostics per LPM variant | Parent | Candidate |
|---|---:|---:|---:|
| Frozen registry | 8 | 31.5 ms | 25 ms |
| Live T3 CI-cold | 4 | 35 ms | 27.5 ms |

The `finalize_tree_integrity_ms` counter combines the tree walk with later integrity and snapshot sidecar writes.
The microbenchmark below isolates the tree walk.
These diagnostics run separately from the scored wall/RSS samples.
They show lower measured finalization time, consistent with the reduced metadata-query work.
Elapsed intervals include scheduling. They do not attribute the entire wall-time difference to finalization.

The prototype microbenchmark measured 32.992 → 21.636 ms over the retained Next tree.
Median process peak RSS changed from 9.258 to 9.117 MiB. Both digests and all statistics matched.
It used 20 alternating process samples per variant, with five finalizations per process.
File digests were prepared outside timing. The final CLI measurements above take precedence over the prototype result.

## Live and cached controls

The initial live T3 CI-cold cohort used 36 samples per variant:

| Variant | Wall time | Peak RSS |
|---|---:|---:|
| Parent | 1,583.5 / 1,627 | 222.85 |
| Candidate | 1,561.5 / 1,823 | 220.95 |
| Bun | 1,490 / 2,209 | 130.57 |

The candidate median improves, but its p95 regresses. This cohort remains part of the evidence.

A fixed 72-round confirmation did not repeat the p95 regression:

| Variant | Wall time | Peak RSS | Maximum wall time |
|---|---:|---:|---:|
| Parent | 1,585.5 / 1,780 | 222.61 | 5,730 |
| Candidate | 1,569.5 / 1,723 | 220.34 | 1,768 |
| Bun | 1,485.5 / 1,745 | 129.23 | 1,805 |

The median paired improvement is 11.5 ms, with the candidate faster in 44 of 72 rounds.
All 216 selected-package inventories and all 144 LPM lockfiles match in that confirmation.
Both live cohorts remain separate; the follow-up does not erase the earlier regression or establish dependable p95 improvement.

The cached-state controls use 36 samples per variant and state:

| T3 state | Parent | Candidate | Bun |
|---|---:|---:|---:|
| Fresh checkout, warm cache | 115 / 128 | 113 / 125 | 217.5 / 238 |
| CI warm | 103 / 115 | 103 / 115 | 203.5 / 228 |
| Installed, cache removed | 38 / 41 | 38 / 43 | 12 / 14 |
| Up to date | 38 / 40 | 38 / 39 | 12 / 15 |

The repository readiness harness also ran all four fixtures in cold, warm, and up-to-date modes.
One unscored gate preceded 12 scored samples. All installs succeeded.
Its comparison flagged Sharp and Nest cold tails. All warm and up-to-date comparisons passed.
The readiness harness includes built-in phase timing. The dedicated frozen and six-state wall/RSS samples run without that instrumentation.

| First-install fixture | Parent | Candidate | Bun |
|---|---:|---:|---:|
| T3 | 2,087 / 2,322 | 2,065.5 / 2,633 | 1,821 / 3,365 |
| Vite React | 753.5 / 985 | 760.5 / 882 | 514.5 / 1,526 |
| Native Sharp | 341 / 469 | 317 / 705 | 267.5 / 413 |
| Nest | 384 / 532 | 396.5 / 592 | 336.5 / 560 |

The readiness verdict uses interpolated percentiles. This report uses nearest-rank percentiles; with 12 samples, p95 equals the maximum.
Sharp's 705 ms candidate sample spent 603 ms in resolution. Nest's two slowest candidate samples spent 484–487 ms in resolution.
Those timings locate waiting but do not identify its cause. Overlapped HTTP intervals include runtime scheduling.

The fixed 36-sample Sharp/Nest confirmation produced these results:

| First-install fixture | Parent | Candidate | Bun |
|---|---:|---:|---:|
| Native Sharp | 382.5 / 620 | 340.5 / 649 | See failure below |
| Nest | 369 / 535 | 356.5 / 647 | 354 / 583 |

Sharp passed the harness's interpolated thresholds. Nest's p95 regression repeated, despite a lower median.
Bun's first Sharp sample failed with registry HTTP 502 for `semver` after 265 ms. It remains in the raw rows.
That failure invalidates treating the full Bun Sharp cohort as successful installs.
The cohort was not replaced, and no samples were removed.

The final check froze Nest metadata and tarballs while preserving its original manifest ranges and npm-direct routing.
A benchmark-only CONNECT proxy supports HTTP/2. The unchanged production binaries trust its ephemeral CA through isolated user configuration.
It does not change system DNS or certificate trust. Project-local TLS configuration was correctly rejected during the first preflight.
That failed preflight remains available. The accepted preflight uses a fresh isolated HOME and explicit npm user configuration.

The captured fixture contains 100 responses and 33 original archives. Metadata and tarball bodies have recorded SHA-256 values.
All archives match metadata SRI. Before every scored process, the proxy checks the stored bodies, metadata sidecars, and capture manifest.
The manifest SHA-256 is pinned outside the fixture directory and recorded in provenance.
Startup rejects a coordinated replacement of the body, metadata sidecar, and manifest that disagrees with this pin.
It rejects uncaptured requests, unexpected authorities, incorrect SNI, credential-bearing requests, and inherited proxy bypass settings.
The four diagnostic preflight installs each made 34 HTTP/2 metadata requests on npm-direct routes, with zero upstream fetches or misses.
The frozen Nest replay completed 72 balanced rounds:

| Variant | Wall time | Peak RSS | Maximum wall time |
|---|---:|---:|---:|
| Parent | 262 / 303 | 75.68 | 398 |
| Candidate | 257 / 285 | 75.35 | 301 |
| Bun | 194 / 246 | 43.02 | 336 |

The candidate is faster in 47 of 72 paired rounds. Its median paired improvement is 5 ms.
All 216 inventories select the same 33 packages. All 144 LPM lockfiles and content-digest maps match.
Every LPM sample makes the same 34 metadata and 33 tarball requests over HTTP/2.
Bun makes 33 metadata and 33 tarball requests over HTTP/1.1. No upstream requests, misses, or rejections occurred.

This replay does not reproduce the Nest tail increase under fixed inputs and local HTTP/2 transport.
It supports the small local improvement, but does not establish the cause of the two live-registry regressions.
The change is a macOS finalization optimization, with no claim of dependable public-registry p95 improvement.

The proxy captures identity-encoded payloads and preserves selected cache headers and original HTTPS URLs.
It precompresses metadata with gzip when the client accepts gzip. Both LPM binaries receive the same bytes and transport settings.
TLS termination, compression, and loopback response timing differ from the public registry; absolute times are specific to this controlled experiment.

## Correctness and measurement coverage

The initial unshipped prototype retried failed bulk calls and omitted the path from symlink-stat errors.
Both regression tests failed before the fixes.
Daybreak also found that parity tests could silently use portable fallback.
A test-only counter now requires successful bulk collection in each expected directory.
A forced-fallback mutation fails that assertion with zero directories instead of three.

Tests compare both digests and all statistics for executable files, hardlinks, Unicode names, empty directories, sidecars, and symlinks.
APFS rejects invalid UTF-8 filenames. A separate normalization test preserves raw name bytes without creating an unsupported filename.
Further cases cover missing and surplus digests, fallback after earlier digest consumption, unsupported entries, and symlink target mutation.
The targeted store suite passed all 355 tests.

The benchmark audit found one request-labeling defect, BM-1.
The original handler read the current phase after sending a response, so a concurrent control update could change its label.
The fix captures phase at request arrival. Two deterministic loopback tests independently fail before the fix and pass afterward.
They cover successful responses and frozen misses. The fix does not change response bytes or subprocess wall/RSS timing.

The original scored source is retained. All original sample groups have equal tarball multisets and non-overlapping labeled request intervals.
These checks support the comparison, but do not reconstruct control-transition timestamps that the original logger did not record.
The corrected handler and regression tests are included beside this report.

Final correctness and Daybreak reviews found no remaining production defects in the modified path.
The local gates passed: workspace build, workspace/all-target Clippy, formatting, 6,724 library tests, 5,278 CLI unit tests, and 116 CLI surface tests.
All 723 targeted install/store workflow tests passed. The optimized CLI build produced zero warnings.
Nextest marked one passing library test as leaky. Dependency policy passed with existing duplicate-dependency warnings.

All 17 helper checks passed after repeating the installer check.
Its first attempt failed before an assertion because the loopback server missed a three-second startup deadline.
The next invocation passed its assertions but encountered a shell-wrapper error. The final Python-driven invocation passed cleanly.
All attempts remain in the provenance.

The ledger includes the optimization, two unshipped prototype defects, one coverage issue, the benchmark-labeling defect, and a report-wording correction.
It also tracks four trust controls identified during the Nest replay design review and a failure to check rejected control responses.
The latter failed its regression before the fix. Every freeze and phase transition now requires a successful response before an install starts.
All six Nest proxy tests pass. Daybreak's final review confirms all four trust controls and the control-response fix.

Finding totals: 11 received, 11 verified and fixed, 0 rejected, 0 externally blocked, and 0 pending.

## Stack and reproduction

The parent is PR874 at `76504fd9065083c56dce54448ddc3450c32a509d`.
The source change is `fd41ed34a4d8904f544ab466562719f0f0552831`.
This concept depends on earlier extraction-digest and bulk-metadata support.
It does not require the no-op or metadata-allocation changes. Its placement after PR874 follows the requested cumulative native stack #863.

The host uses an Apple M5 Pro and macOS 27.0. Both LPM binaries use Rust 1.94.0 and the normal release profile.
Bun is version 1.4.2. Its resolved binary path and SHA-256 are recorded in provenance.
Raw artifacts and both LPM binaries remain at `/tmp/lpm-cold-local-cost`.
Scoring used monotonic subprocess timing and `/usr/bin/time -l`, with no concurrent builds, tests, or profilers.

The retained replay driver, runner, and regression test use the same filename prefix as this report.
Run `python3 bench/perf-results/cold-object-finalization-20260923-test-replay-phase.py` from the repository root to check request labeling.
The replay driver requires the retained frozen registry, fixture, and binaries under `/tmp/lpm-cold-local-cost`.
It requires a new output directory; it will not overwrite an existing scored cohort.

The npm-direct Nest replay sources and six regression tests are in `bench/scripts/cold-object-finalization-replay/`.
Run `node --test bench/scripts/cold-object-finalization-replay/proxy.test.mjs` to verify the harness controls.
Its raw inputs, outputs, pinned capture digest, and request logs remain at `/tmp/lpm-cold-nest-isolation`.
The ephemeral CA private keys were removed after each run. The parent process and system trust settings were unchanged.

The adjacent `-rows.jsonl`, `-summary.json`, `-provenance.json`, and `-ledger.json` files retain compact evidence for review.
They include all 1,800 scored rows, including the failed Bun sample. Raw source-file hashes identify the complete local artifacts.
