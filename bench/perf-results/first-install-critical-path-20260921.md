# First-install metadata and extraction measurements

The candidate reduces first-install medians across all four fixtures. T3 improves by 228 ms, but remains 284.5 ms slower than Bun. The largest improvements occur in Vite React and native Sharp. These results support the combined change, with the memory and tail limits below.

**Cold installs, eight samples per entry.** Each cell shows median milliseconds / median peak RSS in MiB.

| Fixture | Shipping baseline | Previous candidate | Candidate | Bun |
|---|---:|---:|---:|---:|
| T3 | 2335.5 / 472.02 | 2159 / 442.90 | 2107.5 / 441.66 | 1823 / 401.29 |
| Vite React | 1392.5 / 280.51 | 801 / 272.27 | 615.5 / 292.10 | 504 / 136.51 |
| Native Sharp | 941 / 71.31 | 316 / 72.26 | 313.5 / 75.78 | 266 / 21.22 |
| Nest | 484.5 / 109.54 | 398.5 / 104.61 | 395.5 / 109.98 | 298 / 37.76 |

The shipping-to-candidate median reductions are 9.8%, 55.8%, 66.7%, and 18.4%, respectively. They include all implementation changes in this concept. They do not measure the canonical cache alone.

The previous candidate contains the earlier projection, selected-history, lifecycle, and extraction changes. The candidate adds bounded canonical history reuse and two failed-attempt timing corrections. T3 improves in five of eight paired samples, with a paired median change of −20 ms. Vite improves in all eight pairs, with a paired median change of −167.5 ms. Sharp and Nest have paired median changes of +1.5 ms and −2 ms.

Vite peak RSS increases by 19.84 MiB from the previous candidate and 11.59 MiB from the shipping baseline. This tradeoff accompanies a 185.5 ms incremental median improvement. The raw cache retains at most 8 MiB of body capacity. Concurrent work and allocator behavior also affect process RSS. The measurement does not attribute the entire RSS increase to retained cache bodies. T3 peak RSS decreases by 30.36 MiB from shipping, but Bun remains lower in every cold fixture.

**What changed.** Broad ranges project authoritative latest and newest-stable records without constructing every historical manifest. Complete-history fallback remains available for other ranges and policy requirements. Exact versions first use a capped canonical history response, then fall back to an exact document. Small canonical histories can serve several version selections from one immutable body.

The canonical cache bounds body capacity, entry count, validator size, and flight count. It preserves original expiry, origin and TLS isolation, conditional-response semantics, and invalidation generations. Cache admission never waits for memory. Each reused version still passes identity and field checks.

Lifecycle enrichment groups versions by package and source. Selected histories retain publication timestamps so later enrichment can reuse them. Extraction releases owned compressed buffers after use. Forced spool extraction reuses the downloader's SHA-512 digest while preserving archive, size, declared-integrity, and publication checks. Speculative timings now expose work that previously appeared only as a consumer wait.

**Metadata evidence.** T3 has 231 logical metadata requests in both the previous and candidate runs. Returned HTTP responses decrease from 231 to a median of 193. This count excludes attempts that return no response. All observed responses use HTTP/2. Detailed resolver calls remain 221.

Decoded metadata bodies decrease from 175,172,924 to a median of 167,333,435 bytes (−4.48%). This is decoded input volume, not compressed wire volume. The ten capped-history fallbacks consume identical reported bytes in both binaries. The two timing corrections therefore do not explain this difference. Resolver manifest waiting decreases from a median of 1336.31 to 1241.16 ms. Overlapping intervals cannot be added to predict total wall time.

**Remaining T3 delay.** Next still requires a 25,557,776-byte decoded history in every candidate sample. Median Next dispatch does not improve: 361.5 ms for the previous candidate and 384 ms for the candidate. The canonical cache mainly removes other repeated requests.

Two candidate cold samples take 2601 and 2390 ms. Next metadata finishes at 725 and 645 ms, and its speculative download starts immediately afterward. The body-read intervals take 523 and 453 ms, versus 212 and 197 ms in the paired previous samples. These intervals locate the delay. They do not distinguish transport, runtime scheduling, or backpressure.

Earlier paired cold/CI traces put the additional Next start delay near 349 ms. Next task-duration differences were much smaller in that separate cohort. This explains why a lockfile avoids substantial critical-path metadata delay. It does not prove that all remaining wall-time differences have one cause.

**CI-cold, eight samples per entry.** Each cell shows median milliseconds / median peak RSS in MiB.

| Fixture | Shipping baseline | Previous candidate | Candidate | Bun |
|---|---:|---:|---:|---:|
| T3 | 1780.5 / 254.53 | 1789 / 246.16 | 1728 / 255.89 | 1564 / 146.46 |
| Vite React | 312 / 111.16 | 309 / 106.49 | 312.5 / 107.07 | 199.5 / 51.12 |
| Native Sharp | 174.5 / 46.04 | 172.5 / 46.30 | 166 / 45.92 | 141 / 16.03 |
| Nest | 319.5 / 67.73 | 333 / 66.31 | 323.5 / 65.15 | 233.5 / 25.62 |

T3 CI-cold p95 increases from 1834.4 to 2100.15 ms against shipping. Its slowest candidate sample takes 2251 ms, including 2058 ms in fetch. The Next streaming interval accounts for most of the increase. That interval includes input transfer and extraction.

Vite CI-cold p95 increases from 326.45 to 430.85 ms. Its slowest candidate sample takes 476 ms, including 401 ms in fetch. The limiting package spends 104 ms in queue, 292 ms in download, and 1 ms in extraction. Final linking does not explain the increase.

Bun T3 CI-cold includes a successful 237,284 ms sample. Its cause is unknown. The dataset retains it. Eight samples and this outlier do not support a comparative tail-latency claim.

The targeted CI-cold repeat used the same four binaries, two fixtures, balanced eight-sample order, and a separate preliminary pass. All 64 scored installs and their 64 seed installs succeeded. All 16 preliminary installs also succeeded. The large candidate tail samples did not recur.

| CI-cold repeat | Shipping median / p95 | Previous median / p95 | Candidate median / p95 | Bun median / p95 |
|---|---:|---:|---:|---:|
| T3 | 1697 / 1725.2 | 1732 / 1783.85 | 1719 / 1792.4 | 1551 / 1800.9 |
| Vite React | 298.5 / 313.8 | 296 / 316.1 | 300 / 315.75 | 195.5 / 307.3 |

T3 is 22 ms slower than shipping by median in this repeat (+1.3%). Its paired median difference is +39 ms, with one of eight wins. Candidate and previous medians differ by −13 ms. Vite differs from shipping by +1.5 ms. The repeat supports small CI-cold differences, but does not prove that tails cannot regress. Both cohorts remain in the dataset.

The combined change is accepted for its cold-install gains, with the Vite RSS increase and small repeated T3 CI-cold cost explicit. It is not a claim of Bun parity or universally lower latency.

Cold p95 values also remain explicit:

| Fixture | Shipping baseline | Previous candidate | Candidate | Bun |
|---|---:|---:|---:|---:|
| T3 | 2496.2 | 2288.6 | 2527.15 | 1980.9 |
| Vite React | 1480.05 | 919.7 | 716.75 | 549.8 |
| Native Sharp | 1078.95 | 473.15 | 494.45 | 368.35 |
| Nest | 622.9 | 552.15 | 513.3 | 415.9 |

Warm and up-to-date LPM medians remain within 1.5 ms of shipping across all fixtures. These short operations do not establish a material regression.

**Method and provenance.** The main run contains 512 successful scored installs and 64 successful preliminary warm-up installs. It uses four fixtures, four modes, four entries, and eight scored samples per cell. Each entry occupies every position twice. Each pair runs in both relative orders four times. Builds and tests did not run during scoring.

The runner uses isolated project, HOME, store, and cache directories. Cold installs start without a lockfile or dependency cache. CI-cold preserves the generated lockfile and clears dependency state. Warm installs retain cache and recreate the installation. Up-to-date installs retain the installation. A preliminary pass warms shared runtime and registry paths without reusing package caches in scored cold installs. The registry remains live, so order balance cannot freeze upstream inputs.

The host uses macOS arm64, Rust 1.94.0, Node 26.5.0, and Bun 1.4.2. The route is direct npm. Firewall, source scanning, policy extensions, and release-age policy are disabled. Lifecycle script approval remains a separate contract. `blocked_metadata_ms` records approval-state enrichment, not firewall or release-age processing. This work can remain enabled under those defaults.

The runner measures wall time with `process.hrtime` around `spawnSync`. `/usr/bin/time -l` supplies peak RSS. Wall measurements exceed the rounded `time` output by 1–11 ms. Percentiles use linear interpolation. A successful runner exit establishes execution only: `--allow-inconclusive` does not establish performance acceptance.

The shipping binary comes from `8c2cc97384a148b289a1099c4de27a5b4421615d`. Its Cargo files and crates match parent `d33294587cd3c854edb8d8f265522438d664e82b`. The candidate binary matches the archived source hashes in [provenance.json](first-install-critical-path-20260921-provenance.json). A later `to_json`→`into_json` method rename and harness edits are excluded from that binary. Local gates passed on the renamed source. No deadline or transport experiment is enabled in the candidate.

Previous and candidate locks are byte-identical in all 32 comparisons. Shipping and candidate locks differ only through added publication timestamps. Bun and LPM share all package identities and integrities, with four additional WASM identities in Bun's T3 lock. These are retained locks after the four-mode sequence, not separate snapshots from each phase. Earlier installed-artifact checks also matched target versions and integrities.

Historical PR #862 reported 1919.5 ms at an earlier source snapshot. Later replay measured its preserved binary at 2368 ms and its corrected binary at 2356.5 ms. That replay changed two TanStack versions relative to the historical cohort. These independent cohorts cannot form a continuous improvement curve or establish the cause of their timing differences.

**Rejected experiments.** Body deadlines improved one setting but lost publication timestamps in fallback cases. Identity encoding, transport-pool isolation, higher metadata concurrency, lighter streaming admission, and disabled direct streaming regressed relevant fixtures. Allocator purge changes showed no consistent benefit. These variants are absent from the candidate.

The buffer-lifetime microbenchmarks did not establish a wall-time or peak-RSS improvement. Known-SHA512 spool extraction reduced median time from 804.55 to 783.27 ms for the saved large archive. A 12 MiB archive improved from 17.07 to 10.66 ms. Peak RSS remained unchanged. This saves hashing CPU, not a file-read pass, and does not change Next's live streaming lane.

**Validation and scope.** Rust 1.94.0 workspace build and all-target Clippy passed with zero warnings. The fast PR gate passed: 6670 library/integration tests, 5256 CLI unit tests, and 116 CLI surface tests. Targeted install and policy workflow groups passed 357 and 152 tests. Registry tests passed 642 cases. Recovery, provenance, dependency-policy, shell, npm-wrapper, and benchmark-runner checks also passed. Heavy main/release gates were not required for this unmerged PR.

This concept extends the selected-metadata and speculative extraction paths from the existing stack. It depends on #864's bounded typed caches, #862's extraction ownership, and #861's request-specific metadata scheduling. The new PR belongs after #864. No parent source or unrelated workspace edits are included.

The adjacent `first-install-critical-path-20260921-*` files contain sanitized rows, summaries, binary/source hashes, local gate records, and the finding ledger. Full local traces and preserved binaries remain under `/tmp/lpm-critical-path`. Local paths and command output are excluded from the public rows.

The [finding ledger](first-install-critical-path-20260921-ledger.json) contains 62 reports: 60 unique findings and two mapped duplicates. Of the unique findings, 37 are resolved and 23 are rejected with evidence. None are externally blocked or pending. Two resolved findings concern withdrawn prototype bugs. They do not count as shipped-baseline performance improvements.
