# Optional download and extraction overlap

This change starts eligible optional tarballs during dependency resolution and streams large speculative V2 archives during download.
Medium speculative archives use bounded file streaming to avoid whole-archive decode buffers.

Source commits: `28f9f014f` and `246b5d446`. Parent: `3c24d20ee` (PR #861).
The parent documentation changed after its binary was built; its executable code is unchanged.
Raw samples, binary hashes, runner sources, exclusions, and the finding ledger are in [the measurement file](optional-native-speculation-20260921.json).

## Final comparison

| Metric | Parent #861 | Candidate | Bun |
| --- | ---: | ---: | ---: |
| First-install median | 2,294.5 ms | 1,919.5 ms | 1,805 ms |
| First-install median peak RSS | 542.21 MiB | 465.57 MiB | 368.45 MiB |

First-install time decreased 16.34%, and peak RSS decreased 14.13%.
The candidate was faster in seven of eight pairs. The remaining median gap to Bun is 114.5 ms (6.34%).
Bun medians were 1,826.5 ms in the parent cohort and 1,805 ms in the candidate cohort.
Compare the paired run above; registry variation prevents treating an older 2,357 ms result as this run's baseline.

These are live-registry measurements on macOS 27 / Apple M5 Pro, Rust 1.94.0, and Bun 1.4.2.
The T3 first-install run used eight alternating parent/candidate pairs, with 16 Bun samples and one unscored warm gate per binary.
Each scored install had a fresh project, HOME, metadata cache, and package store. Bun execution order rotated.
Scored runs disabled LPM timing detail. No build, test, or other benchmark ran concurrently.
Peak RSS came from `/usr/bin/time -l`. Even-sized medians average the middle two values.
Small samples and registry variation limit conclusions about tail latency.
The final readiness warmup failed once on the parent with a response-body decode error.
That unscored run is preserved; the complete warmup was rerun before scoring.

| Metric | Parent #861 | Candidate | Bun |
| --- | ---: | ---: | ---: |
| CI-cold median | 1,643 ms | 1,637 ms | 1,517 ms |
| CI-cold median peak RSS | 226.20 MiB | 238.80 MiB | 135.77 MiB |

CI-cold time changed by -0.37%. RSS increased 12.59 MiB (5.57%) in this five-pair batch.
This run does not demonstrate a CI-cold memory improvement.

The CI-cold run used five alternating pairs after warm gates. Each manager first generated its own lockfile.
The harness then removed dependency caches, content stores, and node_modules before each measured install.

## Controlled overlap check

Median times were 1,002.59 ms for the parent, 603.69 ms for the candidate, and 545.31 ms for Bun.
Native tarballs overlapped pending metadata in 0/8 parent runs, 8/8 candidate runs, and 8/8 Bun runs.
Median peak RSS was 33.87, 33.93, and 8.07 MiB, respectively.

A local registry delayed one metadata response by 500 ms and the optional native tarball body by 400 ms.
The test used eight scored rounds after warm gates, alternating LPM binaries with isolated state.
This proves overlap under controlled conditions; it does not assign 400 ms of the live-registry result to a single package.
The workflow regression also holds metadata pending until the optional tarball starts.

## Broader install checks

| Fixture | Parent / candidate time | Parent / candidate RSS | Bun time / RSS |
| --- | ---: | ---: | ---: |
| vite-react | 1160 / 1116.5 ms | 285.61 / 280.33 MiB | 419 ms / 139.72 MiB |
| native-sharp | 573 / 518.5 ms | 72.41 / 70.30 MiB | 254 ms / 21.95 MiB |
| nest | 443.5 / 425.5 ms | 110.16 / 107.37 MiB | 270.5 ms / 37.65 MiB |
| t3 | 2367.5 / 1969.5 ms | 528.98 / 465.88 MiB | 2044.5 ms / 389.03 MiB |

All cold median-time and RSS checks passed. Warm and unchanged checks passed for all fixtures.
The initial Nest cold p95 check was inconclusive: 588.8 → 662.8 ms, while its median improved from 443.5 to 425.5 ms.
A targeted eight-pair repeat passed: median 423 → 413.5 ms, p95 458.05 → 469.75 ms, RSS 107.20 → 111.62 MiB.
Both batches are retained. The original matrix verdict remains `inconclusive`; the repeat did not reproduce a threshold breach.

The readiness matrix used eight adjacent, alternating pairs for cold, warm, and unchanged installs, plus Bun.
It enabled LPM timing instrumentation, so its numbers are separate from the plain T3 comparison.

## Selection and resource guarantees

Speculation uses canonical npm alias names, skips bundled packages, and checks platform and engine eligibility after version selection.
Incomplete libc metadata waits for hydration. Portable lockfile selection remains authoritative.
Existing omit-optional, firewall, policy-extension, custom-registry, integrity, and extraction-limit gates remain in force.

A shared, one-shot streaming lane remains reserved for archives declaring at least 64 MiB unpacked size.
Eligible lane losers spool the same HTTP response. V3 retains its file/CAS path.
V2 speculative files declaring at least 8 MiB unpacked size use bounded streaming after download.
The declaration selects an implementation; it never replaces extraction safety limits.
File streaming rehashes compressed content and can extract before discovering a late canonical-store hit.
The warm-install checks measure this tradeoff.

Cancellation now retains package locks, extraction permits, temporary archives, and spool reservations until their blocking workers finish.
Three additional failing regressions proved premature resource release before these ownership fixes.

All 16 scored final LPM graphs match the original 95-package graph.
The SHA-256 of sorted `(name, version)` pairs is `e59db409cad0da216fb25ae2f235a6e8305d7f19332a17b8ef0905d9724b55c4`.

Final diagnostics show Next using the live streaming lane in all three runs.
Resolve/fetch/link times were 1,508/241/122 ms, 1,637/4/221 ms, and 1,816/4/226 ms.
Resolution remains the largest phase; most tarball work now overlaps it.

## Rejected experiments

Optional downloads alone did not improve the eight-pair run: 2,412 → 2,438 ms and 530.14 → 546.98 MiB.
Strict size-weighted file extraction also failed its memory goal: 2,498 → 2,407 ms and 526.09 → 542.13 MiB. It was removed.
One Bun attempt took 120,025 ms. A retry briefly overlapped the original run; all affected pairs were excluded and rerun serially.
The excluded attempts remain in the measurement file.

Live streaming then improved first-install medians from 2,760.5 to 2,121 ms, with Bun at 1,861 ms.
However, native Sharp peak RSS rose from 71.24 to 96.95 MiB in the readiness matrix.
Bounded streaming of medium files corrected that regression before publication.
The final targeted Sharp check measured 69.67 → 71.63 MiB and 764 → 626.5 ms.

Five metadata-memory proposals were rejected for this measured workload. Their cost attribution or net memory benefit was unproven.
The ledger records the evidence and distinguishes these proposals from implemented fixes.

## Blocked-script metadata timing

The earlier 39 ms `blocked_metadata_ms` phase was best-effort registry enrichment for denied lifecycle scripts.
It records publication dates and behavior tags for later `approve-scripts` decisions.
The trace contains one network RPC (28 ms), alongside metadata-cache work.
The default lifecycle policy denies scripts. Release-age, firewall, source scanning, and policy-extension settings do not control this enrichment.
Its failure does not fail installation. Calling it a malware blocklist or firewall request was incorrect.

## Validation and findings

The final source passed the Rust 1.94.0 workspace build and all-target Clippy with zero warnings, plus formatting.
The fast gate passed 6,587 non-CLI tests, 5,250 CLI unit tests, and 116 CLI binary tests.
Targeted workflows passed 79 install tests, 27 tarball/credentials/health tests, 10 interruption/publish tests, and the causal speculation test.
The installer, npm-wrapper, release-artifact, and benchmark-helper checks also passed.

Findings: 18 received, 12 verified and fixed, six rejected with recorded evidence, zero externally blocked, and zero pending.
