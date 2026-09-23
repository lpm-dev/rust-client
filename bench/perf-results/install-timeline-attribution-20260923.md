# Install startup and timeline attribution

## No-op result

The remaining no-op gap centers on the required live Node compatibility probe.
This investigation did not establish a safe, substantial startup optimization.
Caching arbitrary PATH shims by file metadata can return stale results after their environment or working directory changes.
The install continues to check the current runtime.

The diagnostic used 36 alternating rounds with prepared fixtures and retained every sample.
Times are external process wall time, with nearest-rank p95.

| Command | Median | p95 |
|---|---:|---:|
| LPM version | 7.25 ms | 9.18 ms |
| LPM help | 7.69 ms | 8.81 ms |
| Empty install | 9.25 ms | 11.74 ms |
| T3 LPM no-op | 32.09 ms | 33.14 ms |
| Node version | 21.38 ms | 22.55 ms |
| Bun version | 5.26 ms | 5.92 ms |
| T3 Bun no-op | 10.26 ms | 11.27 ms |

The separate phase trace assigns 23 ms to setup and zero to resolution, fetch, or linking.
A constant Node shim changes the median from 35.02 to 18.46 ms in a separate diagnostic.
That diagnostic also changes PATH and the runtime fingerprint. It is not a production optimization or a clean causal estimate.
The old 38/12 ms comparison used another harness. These absolute values must remain separate.

## Timeline contract

Set `LPM_INSTALL_TIMELINE_DIR` to collect an install or CI timeline.
The command writes an `install-<pid>-<attempt>.json` artifact after completion or a handled failure.
A startup return can produce an `incomplete` outcome. Export failure emits a warning without changing command status or JSON stdout.
The synchronous no-op fast lane does not initialize a subscriber and produces no artifact.

The common monotonic origin is `subscriber_initialized`, not process start.
Each span has an operation ID and optional parent ID. Events contain fixed names and allowlisted numeric fields.
The artifact omits package names, URLs, credentials, bodies, and paths.
Export writes a temporary file, flushes it, and publishes it without replacing an existing filename.
Handled write failures remove the temporary file. Abrupt process termination can leave a hidden temporary file, but no partial final artifact.
Files use mode 0600 on Unix. On Windows, files inherit the caller-selected directory ACL.
Windows output confidentiality depends on that directory ACL. No cross-platform user-only access guarantee is made.

The collector retains at most 50,000 records. Resolver correlation state retains at most 1,024 concurrent request entries.
The artifact reports dropped records, dropped correlations, open spans, and the export cutoff.
The correlation cap does not limit dependency resolution. Excess requests continue without retained correlation spans.
Detached work can remain incomplete at export. The collector does not wait for background cache writes.
Span closure marks the final reference drop, which can occur after worker completion.
Blocking operations therefore record enqueue, work start, work end, and await resume separately.

Registry hooks record request attempts, headers, retry backoff, body completion, and parsing.
Resolver hooks separate dispatch, task completion, observation, and ordered graph commit.
Extraction hooks cover input reads, decompression, decoder-consumer waiting, and tar materialization.
Store hooks separate tree walking, sidecar writes, integrity writes, and object publication.

## Interpretation

HTTP intervals include runtime scheduling. They are not pure network latency.
Streaming decode spans include nested compressed-input reads. Their residual is not automatically CPU time.
Pipelined materialization includes waiting for decoded buffers, which has its own span.
Materialization residual includes traversal, validation, hashing, and filesystem work.
Overlapping operations must not be added as if they ran sequentially.

The ordinary log filter excludes diagnostic events. Timeline capture remains independent of `RUST_LOG`.
Disabled field expressions do not execute, and the resolver allocates its correlation map only when capture is enabled.
Release comparisons must measure disabled overhead and enabled observer cost before interpreting small timing gaps.

## Validation

Collector tests cover filtering, numeric fields, parent selection, export cutoff, record limits, late events, and exclusive artifact creation.
A blocking-pool test separates work completion and caller resumption from the last span-reference drop.
Workflow tests cover success, command errors, startup errors, export failures, and JSON output preservation.
A mock registry exercises a 503 retry, blocking JSON parsing, and ordered graph commits under one trace.
Cache tests cover serialization-budget skips. Task ancestry and successful rename pairs have workflow assertions.

Rust 1.94.0 workspace build and all-target Clippy pass with zero warnings. Formatting and the Tracy feature check pass.
The final local gate passes 6,731 library tests, 5,290 serial CLI tests, 116 CLI surface tests, and 749 relevant workflow tests across 22 targets.
All 17 helper groups pass. The atomic-write inventory explicitly records the reviewed exporter.

The measurement review found five issues in local analysis and driver scripts.
Nonzero readiness verdicts now stop the driver even when every install succeeds.
Inline parsing no longer contributes to blocking-worker execution statistics.
Lost records or correlations disable interval attribution. Censored spans retain conservative observed duration lower bounds.
All replay preparation helpers pin the manifest from the actual capture directory and create their output parent before TLS setup.
Each correction has a failing reproduction and a passing regression check. The interpretation fixes preceded scored analysis. The fresh-output-directory fix preceded the Sharp control cohorts.

All report tables use nearest-rank p95. The readiness harness uses linear interpolation for its gate verdicts.

## Corrected-runtime controls

The final release binary uses source commit `3f717a981b6e792cab4be3c134c0103ccfbaa573`.
Its SHA-256 is `cb7faaad32c197be418588b2d8c9134933a53187d8d062e6d64f26a4c08e512a`.
The baseline is PR876, before the timeline changes.
The controls use 36 samples per variant, two warm gates, and all six execution-order permutations.
Each permutation occurs six times. Each install resets the same physical project and cache paths outside measurement.
The replay serves pinned original HTTP/2 responses. All scored runs make zero upstream requests.
No build, test, or profiler runs during scoring.

| Frozen fixture | Parent median / p95 | Timeline disabled | Timeline enabled |
|---|---:|---:|---:|
| Nest | 239 / 251 ms | 240 / 259 ms | 240 / 249 ms |
| Vite React | 251 / 283 ms | 248.5 / 298 ms | 255.5 / 280 ms |
| Native Sharp | 113 / 117 ms | 113 / 123 ms | 114.5 / 122 ms |

The paired median differences, parent to disabled, are +2.5 ms, -1 ms, and +0.5 ms.
These results show small observed disabled overhead for these inputs. They do not establish zero cost or production-wide equivalence.
Vite capture adds 5.5 ms at the paired median. It is slower in 23 pairs, faster in 10, and tied in three.

| Frozen fixture | Parent peak RSS median | Disabled | Enabled |
|---|---:|---:|---:|
| Nest | 76.08 MiB | 78.12 MiB | 77.96 MiB |
| Vite React | 183.67 MiB | 188.28 MiB | 187.61 MiB |
| Native Sharp | 56.58 MiB | 56.36 MiB | 57.20 MiB |

The paired enabled-minus-disabled RSS medians are +0.06, +1.81, and +0.69 MiB.
Aggregate medians and paired medians answer different questions. Neither supports a memory improvement from tracing.

The final live Nest diagnostic contains 36 enabled runs: 322.5 ms median, 465 ms p95, and 101.75 MiB median peak RSS.
The two enabled T3 CI-cold runs take 1550 and 1723 ms, with 230.98 MiB median peak RSS.
These enabled-only samples do not measure observer overhead. Two T3 samples cannot characterize tail latency.

The one-round readiness warmup completes all 36 installs but fails its performance comparison.
Nest takes 444 ms for the parent and 724 ms for the candidate. T3 peak RSS increases from 330.67 to 377.91 MiB.
The driver stops on that nonzero verdict. The separate continuation runs the original 12-round plan and retains the failed warmup unchanged.

The final readiness matrix completes all 432 installs and also fails the performance comparison.
The Sharp wall-time regression repeats. No performance-pass claim is made for this cohort.

| Live cold fixture | Parent median / p95 | Timeline disabled | Bun |
|---|---:|---:|---:|
| T3 | 1943 / 2078 ms | 1929.5 / 2193 ms | 1751.5 / 1960 ms |
| Vite React | 622.5 / 969 ms | 635.5 / 932 ms | 410 / 4928 ms |
| Native Sharp | 287 / 439 ms | 329 / 530 ms | 224 / 332 ms |
| Nest | 330 / 443 ms | 359.5 / 521 ms | 312 / 561 ms |

The Sharp paired median increases 68.5 ms. Its interpolated p95 increases from 425.8 to 529.45 ms.
All six candidate-first Sharp samples are slower than their paired parent samples. The other six pairs have mixed results.
The frozen control does not reproduce that increase, but does not explain it.
The successful 4928 ms Bun Vite sample remains in the data. No tail advantage is claimed from that outlier.

Two additional controls keep the same four fixtures, 12 rounds, environments, and AB/BA execution plan.
The first uses the identical PR876 binary under both labels. The second exchanges the parent and timeline binary labels.
Both controls complete 432 installs and retain their nonzero comparison verdicts.
The identical-binary control reports a Nest regression: 346.5 to 397 ms, with a 54.5 ms paired increase.
Thus, this live matrix can report a material regression without a code change.

| Sharp control | Baseline-label binary | Candidate-label binary | Baseline-label median | Candidate-label median | Paired candidate-minus-baseline |
|---|---|---|---:|---:|---:|
| Original | Parent | Timeline | 287 ms | 329 ms | +68.5 ms |
| Identical binary | Parent | Parent | 288 ms | 325 ms | +28 ms |
| Exchanged labels | Timeline | Parent | 279.5 ms | 334.5 ms | +57 ms |

The large Sharp penalty does not consistently follow the timeline binary.
The results are consistent with order or cohort confounding. The mechanism and any remaining code contribution are unresolved.
All original Sharp runs select the same 11 package identities, with equal request counts and metadata-byte totals.
Those totals do not prove byte-identical live responses. Normalized environments match, and each run uses an isolated cache.
Most observed delay occurs while metadata is pending, rather than during parsing or materialization.
The collector remains diagnostic tooling with measured overhead. These controls establish neither a cold-install speedup nor universal equivalence.

## Cold-tail attribution

All 146 corrected scored traces have zero lost records, lost correlations, open spans, and rootless tarball fetches.
The analyzer also follows each fetch's full parent chain to `install_pipeline`.
A synthetic regression rejects an indirectly orphaned fetch even when its immediate parent exists.
The frozen lockfiles, selected-package inventories, and installed-content digests match across all 108 runs for each fixture.
The earlier Vite traces remain excluded from ancestry-based attribution.

The live Nest intervals identify metadata ordering as the strongest next lead.
Each table entry summarizes the largest recorded interval in each of the 36 runs.

| Interval | Median of per-run maximum | Largest observed |
|---|---:|---:|
| Observed metadata to ordered commit | 39.290 ms | 156.530 ms |
| HTTP attempt to headers or error | 64.621 ms | 178.310 ms |
| Metadata dispatch wait | 0.086 ms | 9.689 ms |
| Metadata completion to resolver observation | 0.040 ms | 0.322 ms |
| Blocking-worker queue wait | 0.181 ms | 9.640 ms |
| Worker completion to async resume | 0.169 ms | 9.673 ms |
| Blocking metadata parse | 1.463 ms | 1.656 ms |

The local queue and resume maxima reach about 9.7 ms in one run. They are usually much smaller than metadata waiting.
These intervals overlap. Their sum is not removable wall time, and HTTP intervals do not identify a network cause.

The resolver assigns a deterministic request sequence and waits for the next sequence before metadata publication and parked-edge resumption.
The trace proves that a completed result waits. It does not connect that result to each child dependency discovered later.
Changing commit order also changes error order and the graph mutation schedule.
Current exact-target selection prevents the older "first compatible version wins" explanation from justifying every ordering barrier.

A controlled next experiment uses slow root `a` and fast root `b`, with child `c` only under `b`.
Pinned responses and server request times can show whether delaying `a` postpones the request for `c`.
If that cost is material, bounded metadata prefetch can be evaluated while graph mutation remains ordered.
That is an experiment proposal, not an established speedup.

## Earlier validation cohorts

The initial runtime candidate had binary SHA-256 `2049777b368098404b7d15abab47e2200180a3cb9b208926818b5c064c15eac3`.
Its four-fixture readiness matrix completed all 432 installs, but its Sharp cold wall comparison failed the regression gate.
Parent and candidate medians were 277.5 and 306.5 ms. Nearest-rank p95 values were 434 and 684 ms.
The paired median percentage difference was -1.09%, unlike the difference between aggregate medians. These statistics answer different questions.
A separate 36-round live Sharp confirmation measured 282.5 / 759 ms for the parent and 299 / 504 ms for the candidate.
This retained a higher candidate median, while the tail comparison reversed. The paired median increase was 1.5 ms; each variant won 18 pairs.
These samples do not establish a consistent 16.5 ms penalty. The cause remains unresolved.
The 36-round fixed-input Sharp control measured 105 / 115 ms for both disabled variants.
This controls local work for those inputs; it does not identify the cause of the live difference.

One successful Bun Nest sample took 106,186 ms. It remains in the raw results and determines that cohort's nearest-rank p95.
No LPM tail-latency advantage is claimed from this outlier.

These preliminary traces exposed a missing ancestry route in Vite.
The selected-package overlap dispatcher activates at 64 selected packages. Nest's 33-package graph did not activate it.
All 36 preliminary Vite traces contained 12–23 rootless fetch spans despite no lost records.
Four workflow regressions reproduced the defect in normal overlap, workspace sharing, post-policy fetching, and experimental resolution.
The corrected implementation carries explicit parent spans across dispatchers and child tasks, including the workspace request channel.
The tests require a real fetch through each route's marker and a complete ancestor chain to the install span.
Preliminary binaries, failed comparisons, and traces remain separate from the corrected-runtime results.

## Stack placement

The user requested a cumulative native GitHub stack. This concept extends PR876 and measures its extraction path.
The instrumentation can stand independently; it does not require a new extraction behavior for correctness.
The no-op investigation produced no source change and no separate optimization pull request.

Local evidence and preserved binaries remain under `/tmp/lpm-next-install-costs`.

## Finding ledger and evidence

The memory and timeline investigations received 24 findings: 23 verified and fixed, one rejected, zero externally blocked, and zero pending.
This timeline concept contains 21 of those findings: 20 fixed and one rejected. PR876 contains the other three fixes.
The rejected finding proposed a Windows user-only ACL guarantee that the documented contract does not make.

The adjacent `-ledger.json` records evidence, regression coverage, duplicate reports, and resolving commits.
The adjacent `-rows.jsonl`, `-summary.json`, and `-provenance.json` retain all cohorts, methods, binary hashes, and gate verdicts.
The `-traces.jsonl.gz` archive retains all 292 scored traces, including the earlier incomplete-ancestry Vite captures.
The `-tools.tar.gz` archive contains the exact experiment scripts and failing/passing measurement regressions.
Absolute paths in those scripts identify this run. Relocation requires path changes and the locally preserved registry captures.
The `-startup.json` artifact retains the separate no-op measurements.
