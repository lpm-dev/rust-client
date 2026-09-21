# Cold resolver metadata measurements

The changes reduce metadata storage and remove avoidable scheduling delays. They do not establish parity with Bun on cold first installs.

Source commit: `1f28499c04c924ca100300f89895136d42d542df`. Baseline: `212010591d0ef30b53505ffc2d1d0bdd138cc00d`.
Raw samples, binary hashes, diagnostic counters, and microbenchmark sources are in [the accompanying JSON file](cold-resolver-metadata-20260921.json).

## Changes

- Distinct exact versions can fetch concurrently. Identical requests share work. Graph commits retain deterministic ordering.
- Ready metadata can start tarball speculation before its graph commit. Partial snapshots preserve known versions and uncovered requests.
- Exact requests share successful fallback histories. Failed fallbacks remain retryable, and waiting tasks retain admission permits.
- Equivalent snapshots share the existing history allocation. Version membership checks use the existing descending order.
- Two rarely populated metadata fields use boxed storage. Pending cache writes reserve their allocated capacity.

The default limits remain eight package histories and 32 exact-version documents. Registry routes and portable lockfile behavior remain intact.

## Final install comparison

The final T3 comparison used eight baseline/candidate pairs and 16 Bun samples.

| Metric | Baseline LPM | Final LPM | Bun |
| --- | ---: | ---: | ---: |
| First-install median | 2,460.5 ms | 2,357 ms | 1,863.5 ms |
| First-install peak-RSS median | 542.26 MiB | 553.34 MiB | 383.64 MiB |

The latest time difference is -4.21%, while peak RSS increased 2.04% in this batch.
Earlier batches showed different directions. These measurements do not establish a reliable end-to-end speed or memory improvement.
The final LPM median remains 493.5 ms behind Bun.
The isolated deserialization RSS improvement is repeatable. a whole-install peak-RSS improvement remains unproven.

The eight-round readiness matrix produced these cold-install medians. LPM timing instrumentation was enabled.

| Fixture | LPM before/after time | LPM before/after RSS | Bun time/RSS |
| --- | ---: | ---: | ---: |
| vite-react | 1256.5/1284.5 ms | 301.59/278.48 MiB | 437 ms/138.27 MiB |
| native-sharp | 606.5/733 ms | 70.20/71.55 MiB | 191 ms/21.50 MiB |
| nest | 433/430 ms | 112.68/109.59 MiB | 300 ms/38.41 MiB |
| t3 | 2464/2486.5 ms | 523.19/519.64 MiB | 1872.5 ms/383.02 MiB |

Warm and unchanged installs passed the readiness thresholds for every fixture.
The separate five-round cold-lockfile check also passed for every fixture.
T3 CI-cold median decreased from 1,711 to 1,658 ms. peak RSS median decreased from 251.25 to 239.53 MiB.
The native-Sharp cold matrix flagged a time regression, discussed below.

## Method and limitations

The host was an Apple M5 Pro with 48 GiB RAM, Darwin 27 arm64, Node 24.19.0, and Bun 1.4.2.
LPM used Rust 1.94.0, release optimization, fat LTO, and one codegen unit.
Only LPM and Bun were benchmarked. Separate release binaries preserve the baseline and each candidate.

The paired T3 runs used isolated projects, HOME, caches, and stores. Each binary received an unscored warm gate.
Scored runs alternated baseline/candidate order and rotated manager order. Timing traces ran separately from scored T3 installs.
All tables use conventional midpoint medians. No strong p95 claim is made from eight samples.
No build or test ran during scored benchmarks.

The readiness harness measured Vite React, native Sharp, Nest, and T3 with cold, warm, and unchanged installations.
Its LPM runs include timing instrumentation. Its CI-cold mode currently supports LPM only. that check ran separately.
The initial six-state T3 comparison also included Bun with cold lockfile installs.
Its first-install medians were 2,393.5 ms before, 2,356 ms after, and 1,862 ms for Bun.
Its CI-cold medians were 1,618 ms before, 1,593.5 ms after, and 1,605.5 ms for Bun.
Fresh-checkout warm-cache RSS decreased from 242.45 to 227.06 MiB. median time stayed near 216 ms.
These initial samples precede the final fallback retry and merge fixes. They remain separate from final-binary results.

Live-registry samples include network and CDN variation. The first 32-slot comparison improved first-install median by 1.6%.
A second eight-round batch regressed by 15.1%. The original five-round readiness comparison was effectively flat for T3.
These inconsistent outcomes prevent a reliable first-install speed claim.

The initial native-Sharp readiness median regressed from 564 to 737 ms. All installations succeeded.
Its traces retained the same nine completed speculative packages and two remaining fetches.
Header waits and streamed-body durations varied substantially. The final matrix also flagged Sharp: 606.5 ms before and 733 ms after.
A separate eight-round live repeat passed: 602.5 ms before and 571 ms after.
The pooled 16 final pairs measured 602.5 and 594.5 ms. The evidence does not establish a repeatable code regression.
Several slow samples spent about 700 ms awaiting individual npm version documents. Both binaries made the same 30 metadata requests.
An attempted local replay received zero requests because its override is debug-only. Those repeat samples are therefore labeled live, not controlled.
The JSON retains the initial regression as well as the repeat measurements.

## Focused measurements

Each probe used the same captured Next history with 3,945 versions and eight alternating scored rounds after warm gates.
Peak RSS came from `/usr/bin/time -l`. The JSON includes each probe source and the fixture hash.

| Probe | Before | After | Change |
| --- | ---: | ---: | ---: |
| 30 JSON deserializations | 2,323.24 ms | 2,274.91 ms | -2.08% |
| Deserialization process peak RSS | 145.38 MiB | 140.86 MiB | -3.11% |
| 20 full/partial/full merge sequences | 925.50 ms | 430.47 ms | -53.49% |
| Merge process peak RSS | 140.55 MiB | 140.61 MiB | Effectively unchanged |

`VersionMetadata` decreased from 1,296 to 1,064 bytes. The two optional fields decreased from 248 to 16 bytes.
The merge fast path still allocates temporary manifests for comparison. Initial JSON parsing sets the process RSS peak in that probe.
No claim translates these microbenchmark gains directly into install milliseconds.

## Diagnostics and rejected experiments

The original and 32-slot candidate traces requested 69 package histories and 151 exact documents for 174 package names.
They transferred 68,399,045 decoded bytes and parsed 34,394 versions. Exact documents contributed only 298,793 bytes.
All six original/candidate traces installed the same 95 name/version pairs.
All 16 final readiness T3 traces matched that same graph.
Its SHA-256 is `e59db409cad0da216fb25ae2f235a6e8305d7f19332a17b8ef0905d9724b55c4` for sorted JSON name/version pairs.
The canonical-name duplicate counter includes different requested versions. it does not prove duplicate HTTP requests.
Release-age processing, firewall, source scanning, and policy extensions recorded zero elapsed milliseconds.
The separate blocked-script metadata enrichment still consumed 39 ms in the original trace.
It makes a best-effort registry lookup for publication dates and behavior tags used by `approve-scripts`.
The default lifecycle-script policy is `deny`. The four disabled settings do not control this enrichment.
Lookup failures do not fail the install. This is not a malware-blocklist or firewall check.

The 64-slot trial reduced cumulative semaphore waiting from roughly 17.7 seconds to 2.1 seconds in diagnostic runs.
Those totals overlap across requests. They are not elapsed install time.
In the rotating eight-round comparison, baseline/32-slot/64-slot first-install medians were 2,274/2,616.5/2,343 ms.
Peak RSS medians were 548.34/537.45/543.73 MiB. The 64-slot default was rejected because total-time benefit was unproven.

A blanket package-history route trial increased metadata to 117,352,041 bytes and 82,838 versions.
Its three process RSS samples reached 587–617 MiB. That route was reverted.
Selective history projection still requires the larger transfer and transient decoding. It was not adopted without supporting measurements.

The Accept-header probe also failed compatibility checks. Scoped exact URLs returned HTTP 406 for install-v1 JSON.
Adding a JSON fallback retained dynamic responses. Unscoped cache warmth changed independently of the header.
No header change was retained.

## Validation

Rust 1.94.0 release and workspace builds completed without warnings. All-target workspace clippy and formatting passed.
The required fast gates passed 6,585 non-CLI tests, 5,232 CLI unit tests, and 116 CLI binary tests.
Targeted install, archive, credential, health, interruption, and publish checks passed another 106 tests.
The CI helper, installer, benchmark-harness, npm-wrapper, pack, and release-artifact checks also passed.
Linux, Windows, musl, and experimental HTTP/3 coverage runs in the concept PR.
Merge requires separate user approval.

## Finding ledger

There are 22 recorded reports and experiments, representing 20 canonical findings: 13 verified and fixed, seven rejected, zero externally blocked, zero pending.
`H1` duplicates `M1`/`M2`. The memory researcher's `M3` duplicates `ML-V5`.
Repeated exact-plus-range fallback reports map to `ML-V2`.

The original verified rows use source commit `1f28499c04c924ca100300f89895136d42d542df`. Their PR state is the concept branch submitted with this report. current CI status belongs to the PR checks.
Rejected rows require no resolving commit. No separate finding PRs were created.

| ID | Source | Category | Location and claim | Evidence | Coverage | Disposition | Commit | PR status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| ML-R1 | Metadata researcher | Performance | Exact endpoint replacement with whole histories | Trial transferred 72% more metadata and reached 587–617 MiB RSS | Preserved trial binary and samples | Rejected | — | Not applicable |
| ML-R2 | Metadata researcher | Performance | `greedy/fused.rs`: canonical tracking serialized distinct exact versions | Gated response test failed before request-specific keys | `fusion_fetches_distinct_exact_versions_concurrently` | Verified | `1f28499c0` | Open concept PR; merge unapproved |
| ML-R3 | Metadata researcher | Performance | `greedy/fused.rs`: ordered commits delayed ready speculation | Ready package arrived after the deliberately delayed package before the fix | `fusion_dispatches_ready_tarball_metadata_before_earlier_slow_metadata` | Verified | `1f28499c0` | Open concept PR; merge unapproved |
| ML-V1 | Metadata researcher and primary | Correctness | `install/fetch.rs`: partial snapshots erased history or discarded uncovered work | Dispatcher regressions reproduced both losses | History, disjoint snapshot, delayed exact/range tests | Verified | `1f28499c0` | Open concept PR; merge unapproved |
| ML-V2 | Metadata researcher and primary | Performance | `greedy/fused.rs`: distinct exact misses repeated fallback histories | No-store test observed two histories instead of one | `fusion_exact_versions_share_one_packument_when_version_endpoints_are_missing` | Verified | `1f28499c0` | Open concept PR; merge unapproved |
| ML-V3 | Metadata researcher | Performance | `greedy/fused.rs`: early permit release expanded waiting tasks | Regression observed 16 tasks against an eight-task bound | `exact_document_fallback_waiters_keep_task_admission_bounded` | Verified | `1f28499c0` | Open concept PR; merge unapproved |
| ML-V4 | Metadata researcher | Correctness | `install/fetch.rs`: partial guard rejected covered distribution tags | Beta-tag test dispatched zero tasks before the parser fix | `speculation_dispatches_a_covered_dist_tag_from_partial_metadata` | Verified | `1f28499c0` | Open concept PR; merge unapproved |
| M1 | Memory researcher | Performance | `types.rs`: absent ecosystem/publisher fields enlarged every version | Layout decreased by 232 bytes per version. measured parse probe | Layout and populated JSON/named-MessagePack roundtrip tests | Verified | `1f28499c0` | Open concept PR; merge unapproved |
| M2 | Memory researcher | Correctness | `client/cache.rs`: queued-write budget counted length, not capacity | A 4 KiB allocation incorrectly fit a 1 KiB budget | `queued_metadata_cache_write_budget_covers_spare_buffer_capacity` | Verified | `1f28499c0` | Open concept PR; merge unapproved |
| R1 | Memory researcher | Correctness | Skip optional metadata for other platforms | Portable lockfile graph is captured before host filtering | Traced `install/resolve/online.rs` | Rejected: would break portable lockfiles | — | Not applicable |
| R2 | Memory researcher | Performance | Remove command-cache clones from ordinary first installs | That command cache is inactive in this case | Traced cache initialization | Rejected: inactive path | — | Not applicable |
| R3 | Memory researcher | Performance | Replace shared registry representation with resolver-only decoding | Shared caches and non-resolver consumers require broader metadata contracts | Traced transport, cache, and projection consumers | Rejected: no independent defect established | — | Not applicable |
| R4 | Memory researcher | Performance | Replace persisted MessagePack with raw JSON | Production reader accepts named MessagePack. JSON fallback is test-only | Traced cache reader | Rejected: incompatible cache contract | — | Not applicable |
| ML-R4 | Primary | Performance | Double exact admission from 32 to 64 | Queue waiting decreased. rotating end-to-end comparison did not establish benefit | Bounded admission tests and eight-round trial | Rejected. restored 32 | — | Not applicable |
| ML-R5 | Primary and metadata researcher | Performance | Change exact-document Accept header for CDN caching | Scoped URLs returned 406. fallback remained dynamic | Recorded repeated HTTP probes | Rejected | — | Not applicable |
| ML-V5 | Both researchers | Correctness | `greedy/fused.rs`: failed fallback poisoned later requests | Malformed first response remained cached despite a healthy later response | `failed_packument_fallback_does_not_poison_later_exact_requests` | Verified | `1f28499c0` | Open concept PR; merge unapproved |
| ML-V6 | Metadata researcher | Performance | `provider/cache.rs`: overlapping snapshots rebuilt shared histories and scanned equal sets quadratically | Sharing regression failed. merge probe improved 53.49%. process RSS unchanged | Sharing, changed facts, tags, release times, and provenance tests | Verified | `1f28499c0` | Open concept PR; merge unapproved |
| ML-V7 | Metadata researcher and primary | Correctness | `greedy/fused.rs`: exact documents and partial cache hits hid override targets | Cold and cached exact2.0→override1.0 tests both selected2.0 before hydration | `exact_metadata_requests_preserve_override_targets_outside_the_requested_version`; `partial_exact_cache_hydrates_history_before_selecting_an_override` | Verified | `4f703c4c1` | Open concept PR; merge unapproved |
| ML-V8 | Metadata researcher | Correctness | `greedy/fused.rs`: cached exact documents hid older required peers | Alias pinned to shared2 plus consumer peer^1 raised PeerConflict despite available shared1 | `exact_alias_metadata_hydrates_history_for_an_older_required_peer` | Verified | `bd07bde4c` | Open concept PR; merge unapproved |
| ML-V9 | Metadata researcher | Performance | `install/fetch.rs`: speculation chose the highest version instead of a satisfying latest tag | Full history latest2.1 plus version2.9 selected2.9 before the fix | `speculative_picker_prefers_a_satisfying_latest_over_a_higher_version` | Verified | `bd07bde4c` | Open concept PR; merge unapproved |

The override correction predates this stack (introduced by the exact-document path in #638). It is included on this owning metadata branch so every later member inherits it. The benchmark datasets above remain measurements of their recorded binaries; this correction only requires extra history for override-targeted packages. Both regressions pass after the fix.



The peer and speculative-selection corrections also predate this stack. Each test failed before its fix. Peer resolution now hydrates incomplete history, and speculation follows the resolver's satisfying-latest preference. Recorded benchmarks above retain their original binary identities; the subsequent extraction/cache report measures the corrected ancestry.

Cache follow-up review corrected the earlier R4 reader assessment: the production writer had a JSON fallback that the production reader could not decode. The separate bounded-cache concept adds an unambiguous format marker and reader coverage; it does not replace ordinary MessagePack entries with JSON.
