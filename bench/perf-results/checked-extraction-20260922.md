# Checked extraction and file-creation measurements

This change corrects extraction, permission, and rollback behavior when output paths change during extraction.
The Linux directory-open path also reduces extraction work. The macOS install comparison does not establish a performance improvement.

Open file handles now remain valid through writes and executable permission updates.
Rollback checks recorded file identities before it removes completed or partial files.
Parent and root identity checks reject replaced directories and retargeted root aliases.
Inspector callbacks can still replace an output with a cache hardlink, as V3 requires.

When source analysis is disabled and V3 CAS ingestion is absent, the store uses extraction without callbacks.
This route retains file digests, archive limits, integrity checks, final directory checks, and rollback protection.

Linux uses `openat2` with `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS` for known directories.
Unsupported syscall or flag errors use the checked component walker. The same fallback handles `EPERM` from syscall filters.
Path rejection and `EAGAIN` errors propagate. They do not trigger fallback.
Apple systems use `O_NOFOLLOW_ANY` when available. Other systems retain checked traversal.

All install comparisons use the parent from PR #866, the candidate, and Bun 1.4.2 on macOS arm64.
Each cell has six scored samples after a separate warm gate. Program order and pair order are balanced.
First install has no lockfile or local package cache. CI-cold retains the lockfile and removes the local package cache.
The benchmark disables lifecycle execution, firewall checks, source analysis, release-age enforcement, and policy extensions.
The registry is live. The report does not compare these medians with historical cohorts.

| Fixture | Mode | Parent ms | Candidate ms | Bun ms | Paired candidate delta ms |
| --- | --- | ---: | ---: | ---: | ---: |
| t3 | cold | 2141.5 | 2283 | 1905.5 | +94 |
| t3 | ci-cold | 1777 | 1778 | 1562.5 | -0.5 |
| vite-react | cold | 589.5 | 644.5 | 392.5 | +40.5 |
| vite-react | ci-cold | 299 | 292 | 194 | -2 |
| native-sharp | cold | 341.5 | 268 | 249.5 | -96.5 |
| native-sharp | ci-cold | 164 | 161 | 127.5 | -1 |
| nest | cold | 391.5 | 357.5 | 368 | -35 |
| nest | ci-cold | 332.5 | 332.5 | 235.5 | +1 |

Negative paired deltas favor the candidate. Separate column medians need not equal the median paired difference.

T3 first-install wall time increased by 141.5 ms between medians. Its CI-cold median changed by 1 ms.
The smaller fixtures have mixed first-install results. Their CI-cold medians are approximately unchanged.
All 144 installs succeeded. The 24 LPM lockfile pairs are byte-identical.
The LPM manifest inventories match, and critical native artifacts match Bun.
The artifact check covers Next, SWC, Sharp, esbuild, and Biome where present.
Bun retains four additional WASM-only package names in the portable lockfile comparison.
One Bun T3 first-install sample took 118,089 ms. The report retains this sample and makes no tail-latency claim.

| Fixture | Mode | Parent peak RSS MiB | Candidate peak RSS MiB | Bun peak RSS MiB |
| --- | --- | ---: | ---: | ---: |
| t3 | cold | 329.41 | 325.73 | 393.95 |
| t3 | ci-cold | 225.62 | 225.74 | 127.95 |
| vite-react | cold | 197.96 | 202.06 | 140.83 |
| vite-react | ci-cold | 88.12 | 90.08 | 52.30 |
| native-sharp | cold | 61.79 | 59.60 | 21.88 |
| native-sharp | ci-cold | 41.85 | 41.27 | 14.51 |
| nest | cold | 102.48 | 98.02 | 37.73 |
| nest | ci-cold | 57.67 | 56.95 | 26.18 |

The RSS columns show the median process peak. The candidate does not establish a general memory improvement.

The extraction microbenchmark uses the same frozen Next archive and fresh output directories.
Each program and root shape has six scored samples after a separate warm round.
Root-shape order rotates. The deep and long roots have equal byte lengths, with different component counts.

| macOS root | Parent ms | Candidate with inspector ms | Candidate without callback ms |
| --- | ---: | ---: | ---: |
| shallow | 828.09 | 905.61 | 864.65 |
| deep | 950.84 | 1018.73 | 973.01 |
| long | 985.20 | 1044.96 | 983.07 |

Candidate microbenchmark RSS is 10.4–10.5 MiB, versus 9.5–9.7 MiB for the parent.
The identity vector removes the additional pathname map from an intermediate implementation. It does not remove the cost of identity records.

The instrumented macOS probe attributes most extra long-root time to file creation: 283 ms shallow, 383 ms deep, and 378 ms long.
Read/write/hash takes 362–366 ms. This stage includes streaming decompression.
Final directory checks take 1.9–2.1 ms. The measurements do not identify a Darwin kernel hook as the cause.
The fresh-file `O_EXCL` experiment showed no consistent material improvement. Production keeps the existing creation semantics.

| Native Linux root | Checked walker ms | `openat2` ms | Reduction |
| --- | ---: | ---: | ---: |
| shallow | 428.73 | 411.44 | 4.0% |
| deep | 429.07 | 411.05 | 4.2% |
| long | 429.41 | 413.51 | 3.7% |

The native Linux experiment preserves dependency versions and uses the system allocator on both sides.
Peak RSS remains approximately 4.2 MiB. Separate syscall tracing reduces open calls from 43,933 to 19,894.
The counts include file opens and library startup. Traced timings are excluded from performance measurements.
No Linux end-to-end install improvement is claimed. The macOS install binary predates only Linux-specific code, tests, and documentation changes.

Local checks passed: workspace build, formatting, and workspace Clippy with warnings denied.
The test gates passed 6,697 library tests, 5,263 CLI unit tests, 116 CLI integration tests, and 479 relevant workflow tests.
Extractor tests passed 92 cases on macOS and 95 on native Linux. Store tests passed 21 targeted cases.
The portable replacement tests also run in Windows CI. Windows runtime validation remains a PR check.

The findings ledger contains 21 entries: 16 resolved, 5 rejected with evidence, 0 externally blocked, and 0 pending.
The resolved entries comprise 11 correctness findings and 5 performance or measurement findings.
The rejected entries include unsupported causal diagnoses. Rejection does not prove every proposed mechanism impossible.

This concept depends on the streaming store paths and extraction records in the existing install stack.
It retains reproduced correctness fixes despite the macOS microbenchmark cost. The first-install performance gap remains unresolved.

Raw measurements: [checked-extraction-20260922-installs.jsonl](checked-extraction-20260922-installs.jsonl), [checked-extraction-20260922-measurements.json](checked-extraction-20260922-measurements.json).
Checks and ledger: [checked-extraction-20260922-local-gates.json](checked-extraction-20260922-local-gates.json), [checked-extraction-20260922-ledger.json](checked-extraction-20260922-ledger.json).
Provenance: [checked-extraction-20260922-provenance.json](checked-extraction-20260922-provenance.json).
