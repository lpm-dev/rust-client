# Metadata cache allocation bounds and cold-install measurements

The cache changes enforce the allocation budget before serialization and preserve cache mutation order.
The measurements do not establish parity with Bun or a general performance improvement.
The cache changes remain useful for allocation limits, readable fallback entries, and mutation ordering.
The live-registry comparison flags slower tails in two fixtures. This report retains those failures.

## Cache behavior

The serializer reserves the shared 128 MiB budget before each allocation.
The buffer remains contiguous. Before growth, the budget covers both the old allocation and its replacement.
The old reservation ends after reallocation. The remaining reservation stays with the buffer through the queued write.
The budget applies to serialized output buffers, not all cache or process allocations.
The serialized file limit remains 100 MiB. A smaller entry can still be skipped if its growth exceeds the shared budget. Budget exhaustion skips the best-effort write without a second encoding attempt.

A genuine MessagePack encoding failure can use JSON after the reserved `0xc1` marker.
Fresh, stale, and 304 cache readers recognize that marker. Earlier readers safely treat tagged JSON entries as misses.
Ordinary MessagePack entries retain their existing format.

A mutation revision precedes serialization. Older serializers cannot replace newer entries or restore entries after invalidation.
An older allocation failure cannot cancel a newer queued write.

## Final candidate measurements

The baseline uses current PR #862 at `80ab5a937`. The candidate uses `8c2cc9738`.
The candidate excludes the latest-document, extraction-prefix, and chunk-cache prototypes.

Plain T3 installs used eight alternating pairs without timing instrumentation.

| Metric | Current #862 | Cache candidate | Bun, parent / candidate cohorts |
| --- | ---: | ---: | ---: |
| First-install median | 2356 ms | 2211.5 ms | 1817 / 1845.5 ms |
| First-install median peak RSS | 469.42 MiB | 460.61 MiB | 380.98 / 380.79 MiB |
| CI-cold median | 1626.5 ms | 1643 ms | 1521 / 1593 ms |
| CI-cold median peak RSS | 241.32 MiB | 265.74 MiB | 128.10 / 127.43 MiB |

The CI-cold run stopped during the fourth scored variant. Six completed rows remained intact.
The resumed run retained those rows, added unscored warmups, and completed the original eight-pair sequence.
The incomplete attempt remains on disk. It does not contribute a scored sample.

The instrumented readiness matrix used eight pairs per fixture and mode.

| Cold fixture | Parent / candidate median | Parent / candidate peak RSS | Bun median |
| --- | ---: | ---: | ---: |
| T3 | 2546.5 / 2478.5 ms | 456.16 / 467.48 MiB | 1719.5 ms |
| Vite React | 1432 / 1356.5 ms | 272.93 / 273.63 MiB | 525 ms |
| Native Sharp | 622 / 628.5 ms | 71.21 / 69.66 MiB | 259.5 ms |
| Nest | 549.5 / 554.5 ms | 111.02 / 110.09 MiB | 327 ms |

The overall readiness verdict is `regression`.
Nest cold p95 increased from 731.35 to 1983.45 ms. Vite cold p95 increased 24.92%.
The slow Nest candidate spent 2375 ms awaiting one exact `tslib` response.
The slow Vite candidate spent 1629 ms awaiting one exact Rollup response.
Those observations locate waiting, but do not establish an external-network cause. Runtime scheduling contributes to HTTP wall timers.
T3 cumulative cache serialization and dispatch increased from 36.5 to 42 ms at the median.
The local cache probe also shows overhead. The candidate does not demonstrate a general RSS reduction.

The retained tradeoff is correctness: allocation admission precedes serialization, and older writes cannot defeat newer mutations.
These guarantees matter under large or concurrent metadata workloads even when typical fixture RSS does not improve.
No install-speed claim relies on accepting or excluding the slow samples.

## Historical PR #862 comparison

The original PR #862 report measured 1919.5 ms with source `246b5d446` and binary SHA-256 starting `5d953bbc`.
Current #862 uses `80ab5a937`, after resolver correctness corrections.
The benchmark declaration, script policy, Bun version, and timing settings match.
However, two TanStack selections advanced from 5.103.1 to 5.103.2 between the historical and current cohorts.

A separate replay used all three preserved binaries, eight rounds each, and Bun controls after unscored warmups.
Six order permutations plus two opposite orders gave every binary pair four runs in each relative order.

| Binary | Median first install | Median peak RSS | Bun control median |
| --- | ---: | ---: | ---: |
| Original #862 | 2368 ms | 459.17 MiB | 1828.5 ms |
| Current #862 | 2356.5 ms | 471.13 MiB | 1871 ms |
| Cache candidate | 2435.5 ms | 462.59 MiB | 1886 ms |

The exact original binary no longer reproduced its historical 1919.5 ms median in this run.
Current #862 was faster than the original in four of eight rounds.
All 24 replay installs selected identical packages and versions, with matching reported peer, override, patch, and blocked-script metadata.
These results do not establish a source regression from the intervening corrections.
They also do not establish the cause of the historical timing change.
The original and current traces retain identical request counts and graph-work counts. The extra hydration corrections do not activate for T3.
The cache candidate did not repeat its earlier lower median. No confirmed speed improvement is claimed for this cache concept.

## Rejected metadata experiment

A guarded latest-document path reduced metadata from about 68.4 MB to 17.5 MB.
However, both implementations increased cold-install time across all four fixtures.
The first implementation used eight alternating pairs. The eager-fallback revision used four pairs.

| Fixture | Original baseline | Latest-document prototype | Eager baseline | Eager prototype |
| --- | ---: | ---: | ---: | ---: |
| T3 | 2282 ms | 2434 ms | 2283.5 ms | 2683 ms |
| Vite React | 1298 ms | 1876 ms | 1390.5 ms | 1739 ms |
| Nest | 473 ms | 954.5 ms | 604.5 ms | 926.5 ms |
| Native Sharp | 501.5 ms | 746 ms | 722.5 ms | 763.5 ms |

Observed latest responses reported `CF-Cache-Status: DYNAMIC`, while package histories reported `HIT`.
That observation alone does not establish the cause of the regression. Neither prototype is part of the shipping stack.

The investigation found existing resolver faults. PR #861 contains the corrections for exact overrides, incomplete peer histories, workspace fallback, and speculative selection.
Each regression failed before its correction.

## Rejected extraction experiment

The extractor prototype capped the compressed prefix and released it after consumption.
It also streamed large verified files without the initial prefix allocation.
A controlled two-archive probe reduced RSS from 30.98 to 7.41 MiB. Median time changed from 31.72 to 30.86 ms.
That probe used two 12 MiB archives and the System allocator.

The install results did not support acceptance.
Across 16 native-Sharp cold pairs, median time increased from 631.5 to 768.5 ms. The existing comparator reported a regression.
Plain T3 RSS increased from 452.45 to 478.45 MiB in eight pairs.
The Nest confirmation also flagged a tail regression: p95 increased from 601.5 to 759.45 ms. Its pooled comparison passed.
CI-cold RSS also remained inconclusive. The prototype is excluded from the shipping stack.
The cache branch uses #862 directly as its parent.

## Cache encoding cost

A local HTTP server supplied the same 22,173,595-byte history in each probe.
The public registry client fetched, decoded, serialized, and flushed the cache entry.
The fixture contains 8,192 versions with 64 dependencies each. The probes use the System allocator.

Eight alternating samples per binary produced these medians:

| Implementation | Time | Peak RSS |
| --- | ---: | ---: |
| Original contiguous writer | 72.660 ms | 166.09 MiB |
| Initial chunk writer | 83.126 ms | 166.32 MiB |
| Inline chunk writer | 77.880 ms | 166.23 MiB |

Inlining removed about half the added encoding cost. This implementation still took 5.22 ms longer in that probe.
This probe did not show a process RSS improvement.

Earlier live T3 traces also recorded additional cache work: cumulative serialization and dispatch increased from 35.5 to 51 ms.
Both sides of the earlier cache comparison contained the extraction prototype. The only difference between those binaries was the cache change.
Their pooled T3 p95 increased from 2643 to 3036.75 ms, a 14.90% regression.
The Nest confirmation also flagged a tail regression: p95 increased from 654.25 to 728 ms. Its pooled comparison passed.
Those failures remain in the raw data. The final shipping comparison uses the parent without the extraction prototype.
This branch change motivates a new comparison. It does not establish that extraction caused the earlier incremental cache regression.
The next comparison removed extraction from both sides. T3 median time still increased from 2503.5 to 2662.5 ms.
Its p95 increased 13.09%. This result also failed the comparator, so the chunk representation is excluded.
One Vite baseline took 27966 ms, mostly in resolution. That sample remains in the data.

The final implementation uses a contiguous reserved buffer. A separate eight-pair local probe measured 71.572 ms before and 72.942 ms after.
RSS was 166.09 and 166.26 MiB. These samples do not establish a memory improvement in that probe.

HTTP wall timers include runtime scheduling delays. The data cannot assign every slow response to external network variation.

## Link concurrency experiment

Six alternating CI-cold samples used each setting: default, one task, and four tasks.
The runner forwarded `LPM_V2_LINK_TASKS` and recorded its value in every run plan.
All three settings measured 1657.5 ms at the median.
Their RSS medians were 226.51, 228.74, and 238.66 MiB respectively. The default remains unchanged.

## Method and limits

The host was an Apple M5 Pro with 48 GiB RAM, Darwin 27 arm64, and Bun 1.4.2.
LPM used Rust 1.94.0, release optimization, fat LTO, and one codegen unit.
Each comparison preserved its binaries and used equal sample counts, an unscored warm round, and alternating execution order.
No local build, test, or other benchmark overlapped scored measurements.

Each run used an isolated project, HOME, cache, and store. Both managers denied lifecycle scripts.
LPM used direct npm, release-age zero, firewall off, source scanning off, and no policy extensions.
Readiness runs included JSON timing traces. Plain first-install and CI-cold runs omitted timing instrumentation.
The final tables use midpoint medians. Eight samples do not support a strong tail-latency claim.

The live registry remains an uncontrolled input. Original and confirmation cohorts remain separate in the data, with pooled comparisons where appropriate.
The package-selection comparison covers reported packages, peer diagnostics, overrides, patches, and blocked-script metadata.
It does not cover graph edges absent from the JSON output.

## Validation

Every source bug had a failing regression before its correction.
Coverage includes initial budget admission, bounded growth, file limits, short writes, encoding fallback, invalidation, and write ordering.
The Rust 1.94.0 workspace build, all-target clippy, formatting, required fast gates, and relevant workflow gates passed.

Initial local gates exposed shared temporary fixture names, sandbox path assumptions, ownership assumptions, and tar link-name limits.
Independent short native macOS temporary directories resolved those environment failures.
Local logs retain the failures and successful reruns. The data file records their summaries. No unrelated product workaround was added.

## Further research

Three read-only investigations found no additional demonstrated correctness defect.
They identified seven optimization hypotheses and one low-priority cache-probe lead.
These are experiments to evaluate, not verified savings or unresolved defects in the cache implementation.

| Area | Observed evidence | Experiment and constraints |
| --- | --- | --- |
| Metadata lookahead | Ordered commits delay child discovery behind earlier requests. | Start bounded child lookups from ready metadata. Preserve deterministic graph mutation, routes, auth, policies, and portable lockfiles. |
| Metadata CPU work | Earlier T3 traces contain 37.5 ms cache work and 74 ms projection, cumulatively. | Move large work off async workers without cloning histories or extending unbounded lifetimes. These totals are not wall savings. |
| Materialization overlap | Candidate T3 waits 144 ms for link population; final wiring takes 6 ms. | Prepare bounded private package copies during resolution. Preserve authoritative identity, peers, patches, and cancellation cleanup. |
| Allocator attribution | System-allocator extraction micro results did not predict production RSS. | Compare the existing no-mimalloc feature with production mimalloc. Use DHAT for allocation attribution only. |
| Blocked metadata reuse | T3 enrichment takes 51.5 ms and decodes three esbuild versions separately. | Share one document per canonical package and complete route. Preserve version-specific integrity checks and output entries. |
| First-use signing secret | Cold build-state writes take 9.5–14 ms across fixtures; warm writes round to zero. | Attribute durable secret creation before considering earlier initialization. Preserve locks, permissions, synchronization, and authentication. |
| Installed manifest reuse | Lifecycle preparation reads some materialized manifests more than once. | Reuse validated snapshots within one preparation phase. Preserve post-patch bytes and recapture after script execution. |

Repeated cold cache probes have little measured cost in these traces. They remain lower priority than the listed experiments.
Removing destination tree validation is unsafe. The snapshot describes destination metadata, and macOS already uses bulk attribute reads.
Lockfile serialization takes approximately 0–1 ms at the median and is low priority.

Blocked metadata remains lifecycle approval enrichment. Release-age, firewall, scanning, and extension settings do not disable it.
All measured fixtures returned empty enrichment fields, but populated enrichment is part of the supported approval-state contract.

## Findings and stack

This investigation received 23 findings: 10 verified and fixed, 13 rejected with evidence, zero externally blocked, and zero pending.
The data file contains the ledger and maps resolver corrections to PR #861.
Research hypotheses are listed separately because their proposed benefits remain unmeasured.

PR #862 depends on #861 for early metadata publication and request scheduling.
The cache concept is independently useful. It follows #862 in the cumulative native stack requested by the user.
No merge or automatic merge is authorized.
