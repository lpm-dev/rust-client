# Child metadata lookahead investigation

The root-only prototype does not establish a repeatable production benefit. It is absent from compiled source and the optimization stack.
The source archive preserves the prototype, its tests, and the reproduction scripts.
The retained code correction repairs the replay server in PR875, where that server originated.

## Controlled overlap

The prototype admits one required exact child beneath a ready root while an earlier root delays deterministic graph updates.
A root can use a version range. The existing resolver selects its version.
The child response remains unparsed until authoritative demand. Existing demand has priority over the spare permit.
One command-wide admission and a 4 MiB body limit bound speculative work.
Policy, route, cache ownership, expiry, and generation checks remain in force.

A controlled fixture delays child C by 150 ms. Root B depends on C, and root A precedes B.
Each profile contains 12 alternating pairs after two warm gates.

| Root A delay | Baseline median | Prototype median |
|---|---:|---:|
| 0 ms | 201.027 ms | 199.955 ms |
| 150 ms | 351.225 ms | 198.487 ms |

Every install makes three metadata requests. Lockfile bytes and installed object digests match.
The delayed profile changes median peak RSS from 34.18 to 34.63 MiB.
This experiment establishes overlap under an imposed delay. It does not establish real-fixture savings.

## Frozen fixture results

The final candidate includes the inactive-dispatch guard. Each cohort balances all six execution orders and uses the same physical LPM paths.
Two successful warm gates precede scoring. Scored installs have no timeline or detailed timing flags.
Separate diagnostics check adoption and transport backoffs. Builds and tests remain stopped during scoring.

The proxy serves original captured response bytes and refuses uncaptured requests.
T3 and Sharp use a converted earlier capture with explicit scoped-path and Accept aliases.
Those aliases preserve the original response bodies. T3 selects Next 16.3.5, whereas the later live cohort selects newer registry data.
The two sources are separate experiments. Absolute frozen times are not live-registry estimates.

Times are median / nearest-rank p95 milliseconds.

| Fixture | Samples per variant | PR877 baseline | Prototype | Bun |
|---|---:|---:|---:|---:|
| T3 | 24 | 1758.5 / 1996 | 1622 / 1938 | 1560.5 / 1696 |
| Vite React | 24 | 271 / 292 | 268 / 292 | 181.5 / 194 |
| Native Sharp | 12 | 122.5 / 150 | 124 / 151 | 66.5 / 81 |
| Nest | 12 | 277 / 332 | 266 / 600 | 201.5 / 234 |

T3 improves 136.5 ms between aggregate medians. The paired median difference is -74.5 ms, with the prototype faster in 14 of 24 pairs.
An exploratory paired bootstrap gives a 95% interval of -274 to +53 ms.
The interval uses 10,000 resamples and seed 1940, without correction for multiple comparisons.
Thus, this cohort does not establish a reliable gain. The prior corrected T3 cohort also remains in the evidence.

| Fixture | Baseline median peak RSS | Prototype median peak RSS | Bun median peak RSS |
|---|---:|---:|---:|
| T3 | 334.09 MiB | 330.18 MiB | 467.21 MiB |
| Vite React | 182.23 MiB | 186.09 MiB | 145.69 MiB |
| Native Sharp | 55.73 MiB | 56.53 MiB | 38.39 MiB |
| Nest | 78.12 MiB | 77.38 MiB | 43.37 MiB |

These changes do not establish a useful memory reduction.
Fast local responses alter allocation overlap. These RSS values are not equivalent to live-registry RSS.

All final frozen LPM lockfiles, selected packages, object digests, and independently computed installed-file digests match.
Cross-manager selected packages and file contents also match. Bun file modes can differ, so that comparison excludes mode parity.
Every diagnostic has zero transport backoffs and zero dropped timeline records.
T3 adopts one lookahead in both diagnostics. The Vite, Sharp, and Nest diagnostic pairs show no activation.
Diagnostics cannot prove whether lookahead activated in each scored run.

## Live comparison

The repository readiness harness runs four fixtures in cold mode with both LPM binaries and Bun.
Two unscored rounds precede 12 scored rounds. The harness balances order and enables its standard detailed timing for both LPM variants.
All 144 scored installs succeed. The comparison verdict passes its regression limits.
A passing regression gate does not establish improvement.

| Fixture | Baseline median | Prototype median | Bun median |
|---|---:|---:|---:|
| T3 | 1978.5 ms | 1974.5 ms | 1850.5 ms |
| Vite React | 643.5 ms | 658.5 ms | 471.5 ms |
| Native Sharp | 322.5 ms | 286 ms | 204 ms |
| Nest | 342.5 ms | 350.5 ms | 286.5 ms |

T3 improves only 4 ms, or 0.2%. Its interpolated p95 increases from 2212.6 to 2311.65 ms.
Nearest-rank p95 is 2305 versus 2497 ms. With 12 samples, that percentile equals the maximum.
The large frozen median change does not repeat here.
Sharp cannot use this prototype's required-child path. Its apparent live improvement is not evidence for this optimization.

## Retained regressions and measurement defects

The earlier Vite control changed median wall time from 261.5 to 285 ms despite zero diagnostic activations.
A regression test showed that an ineligible hook still advanced ordinary request dispatch.
The guard now checks eligibility first. Its regression test passes, and the final Vite control is neutral.
The original timing regression remains in the raw rows. The scheduling defect does not prove its full timing cause.

Nest candidate sample 10 takes 600 ms, versus 272 ms for its paired baseline.
Both runs make the same 67 successful HTTP/2 requests with identical request and response-byte multisets.
The proxy activity interval grows from 37.069 to 124.864 ms. No response interval exceeds 2.215 ms.
The candidate has two server-idle intervals of 39.693 and 41.434 ms between request groups.
Its time log records 17,384 involuntary context switches, versus 5,680 for the paired baseline.
These observations establish delayed local progress, but do not identify its cause. No scored phase timeline exists for that sample.

The initial T3 replay also exposed the server-credit defect recorded as PROXY-6 in the PR875 ledger.
Node counts queued response data against its default 10 MB HTTP/2 session budget.
A paused 12 MiB tarball makes a concurrent metadata stream fail with `NGHTTP2_ENHANCE_YOUR_CALM` under that configuration.
The corrected proxy passes the same regression, including response-body checks.
The failed pilot cohorts remain intact and are excluded from optimization claims. This server correction is not an LPM speedup.

## Coverage and disposition

The prototype passes 17 focused registry tests, nine lookahead-related resolver tests, and 15 relevant workflow tests.
Those checks cover cache precedence, route and policy suppression, anonymous transport, bounded admission, expiry, invalidation, demand priority, and deterministic errors.
The final targeted Clippy checks pass. The guard release build has zero warnings.
An earlier workspace gate passes 6,749 library tests, 5,291 CLI unit tests, and 116 CLI surface tests.
The archive preserves red tests, corrected tests, and the full prototype source.

The investigation receives 12 reports for ten canonical findings, including two duplicate reports.
Eleven reports concern prototype behavior or test capture. Their fixes pass before the complete prototype is withdrawn.
One report concerns the retained replay-server correction in PR875. These are not twelve shipped product fixes.
All reports are resolved. The ledger has zero rejected, externally blocked, or pending findings.
A scoped tracing test also needed a second live dispatcher to capture concurrent first-call registration reliably.
Production uses a global subscriber, so that test failure does not establish a production telemetry defect.

Broader transitive range-child lookahead remains unimplemented research.
Nest's largest observed waits occur deeper in the graph, where children use ranges.
The current root-only admission frequently has little useful overlap.
A broader design needs authoritative preferred-metadata adoption, lane-specific permits, and measured demand selection before it merits an optimization PR.

## Reproduction and retained evidence

The baseline source is PR877 at `d53ddb1d81125c0bcc0ffbfabb95da063c98369f`.
The baseline binary SHA-256 is `cb7faaad32c197be418588b2d8c9134933a53187d8d062e6d64f26a4c08e512a`.
The final candidate SHA-256 is `90e09a2ae9afdfe61030d53b72675a9576baa7da95a083292c58b97efe4583d5`.
Both binaries use Rust 1.94.0 and the normal release profile.
Later source changes add only test coverage. The provenance checks that production source still matches the measured binary.

The adjacent summary and provenance files describe all cohorts and source hashes.
The compressed raw rows retain all 700 available rows, including controlled, warm-up, interrupted, and superseded runs.
The compact row file contains the eight main frozen cohorts and both live stages.
No run was replaced because of its timing result.
The source archive contains the rejected implementation, tests, and host-specific reproduction scripts.
Original response bodies, per-run files, binaries, and logs remain under `/tmp/lpm-metadata-lookahead` and the referenced capture directories.
