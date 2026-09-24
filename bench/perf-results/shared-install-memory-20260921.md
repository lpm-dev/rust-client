# Shared install memory measurements

The candidate lowers cold-install peak RSS across all four fixtures. T3 decreases by 98.79 MiB and Vite React by 86.19 MiB. Wall-time results remain mixed. This change primarily improves memory use.

Each table cell shows median milliseconds / median peak RSS in MiB. Every entry has eight scored samples.

**Cold install**

| Fixture | Parent | Candidate | Parent, two workers | Bun |
|---|---:|---:|---:|---:|
| T3 | 2112 / 424.12 | 2102 / 325.33 | 2185 / 323.67 | 1814 / 405.70 |
| Vite React | 638.5 / 281.77 | 580.5 / 195.58 | 654.5 / 210.04 | 458 / 140.27 |
| Native Sharp | 291.5 / 74.62 | 275 / 61.61 | 277.5 / 61.91 | 216 / 21.41 |
| Nest | 361.5 / 109.67 | 379.5 / 98.01 | 357 / 104.55 | 305.5 / 37.97 |

Cold medians change by -10 ms for T3, -58 ms for Vite, -16.5 ms for Sharp, and +18 ms for Nest. Paired median changes are -2, -37.5, -12.5, and -8.5 ms. These statistics answer different questions. They do not establish a uniform speed improvement.

Candidate RSS decreases in 31 of 32 cold pairs. Median paired savings are 96.83 MiB for T3, 82.96 MiB for Vite, 12.20 MiB for Sharp, and 11.80 MiB for Nest. T3 uses less memory than Bun in this cohort. Bun still uses less memory in the other fixtures.

**CI-cold install**

| Fixture | Parent | Candidate | Parent, two workers | Bun |
|---|---:|---:|---:|---:|
| T3 | 1744 / 224.02 | 1739.5 / 213.66 | 1762 / 218.05 | 1636.5 / 145.52 |
| Vite React | 304.5 / 107.67 | 310 / 90.34 | 305.5 / 90.01 | 195.5 / 52.77 |
| Native Sharp | 158 / 46.61 | 157 / 41.92 | 158 / 41.89 | 124 / 15.37 |
| Nest | 324.5 / 65.04 | 318.5 / 57.85 | 321 / 58.01 | 231 / 26.18 |

The largest CI-cold median increase is Vite at 5.5 ms (1.8%). Candidate RSS decreases in 29 of 32 pairs. T3 saves a median 10.36 MiB by aggregate medians and 19.01 MiB by paired differences.

Warm wall medians change by -0.5 to -2 ms. Up-to-date medians change by -2 to +0.5 ms. These small differences do not establish a material performance change.

**Tail samples and repeat**

Nest cold median time increases from 361.5 to 379.5 ms in the main cohort. The candidate wins five of eight pairs. Sharp cold p95 increases from 375 to 397.3 ms. Sharp CI-cold p95 increases from 162.6 to 182.4 ms. All outliers remain in the data.

A separate repeat covers Sharp and Nest with the same four entries, balanced order, and eight samples. Each cell again shows median time / median peak RSS.

Cold repeat:

| Fixture | Parent | Candidate | Parent, two workers | Bun |
|---|---:|---:|---:|---:|
| Native Sharp | 267.5 / 74.48 | 266 / 61.30 | 295.5 / 60.57 | 240 / 23.20 |
| Nest | 382.5 / 107.05 | 357.5 / 101.80 | 360.5 / 104.35 | 272.5 / 37.55 |

CI-cold repeat:

| Fixture | Parent | Candidate | Parent, two workers | Bun |
|---|---:|---:|---:|---:|
| Native Sharp | 159.5 / 46.23 | 159.5 / 42.01 | 160.5 / 42.27 | 126 / 16.98 |
| Nest | 320.5 / 65.60 | 318.5 / 58.04 | 315.5 / 57.70 | 228.5 / 26.16 |

The repeat does not reproduce the Nest median regression. Sharp CI-cold medians are equal. The two cohorts remain separate. Eight samples per entry do not establish tail-latency guarantees.

**Implementation**

Confirmed standalone JavaScript installs use at most two Tokio workers. Workspaces, global installs, package-addition installs, and other commands retain the existing worker count. Uncertain project discovery also retains that count. Any present `TOKIO_WORKER_THREADS` value bypasses the policy and retains native Tokio interpretation.

CLI parsing stays on the existing 64 MiB thread. Both the main async thread and runtime workers retain their existing stack sizes. The blocking-pool override remains available. Runtime creation now follows CLI parsing. Help and parser errors can therefore exit before Tokio validates an invalid environment override.

The extractor stores its EOF probe in a separate one-byte buffer. It no longer appends that probe to a full compressed prefix. The old append doubled an 8 MiB prefix to 16 MiB. Buffer growth also respects non-power-of-two limits. Prefix release, byte order, digest checks, gzip completion, and path checks remain intact.

The parent-with-two-workers entry helps separate the changes. Worker reduction explains the main cold RSS improvement. Candidate-versus-two-worker RSS differences are mixed, so this cohort does not isolate a consistent process-RSS benefit from the prefix fix. Allocation regressions demonstrate that fix directly.

An earlier worker experiment used the same parent executable for default, four-worker, and two-worker variants, plus Bun. All 256 scored installs succeeded. Two workers lowered cold RSS in all 32 pairs and CI-cold RSS in 31 of 32 pairs. Wall-time effects were mixed. The final policy also excludes workspaces after a separate regression probe.

The broad workspace cap increased independent cold median time from 957.46 to 1016.40 ms. Up-to-date time increased from 101.45 to 109.43 ms. A failing classification test preceded the scope correction. In the final repeat, independent cold medians were 937.67 and 972.40 ms, with a paired median change of -9 ms. Shared cold medians were 1403.32 and 1406.80 ms. Their paired median change was +2.45 ms. Both up-to-date medians improved. The consistent broad-cap regression did not recur.

**Remaining costs**

T3 candidate resolution takes a median 1127.5 ms. Next still requires a 25,557,776-byte decoded history. Its selected record starts 99.91% through that response. Earlier parsing alone cannot select that record substantially earlier.

The Next task takes approximately 1536 ms in cold installs and 1534.5 ms in CI-cold installs. Its streaming interval includes transfer and extraction. Those operations overlap, so their timers cannot isolate pure network or filesystem costs. Earlier package discovery remains valuable because it advances this large task.

T3 also waits a median 106.5 ms for package entries after fetch. Final links and binary shims take about 6 ms. A frozen Next extraction probe took 776.23 ms at a shallow root and 918.80 ms with twelve additional directory levels. This establishes path-depth sensitivity. It does not prove that a directory-descriptor implementation saves 143 ms in production. Any replacement must preserve symlink checks, duplicate-file isolation, and file-descriptor limits.

The small-archive probe covers 166 frozen archives and about 9.6 MiB of compressed input. Serial file-based extraction takes 650.18 ms, versus 610.20 ms from bytes. Most small archives overlap metadata work. The 40 ms corpus difference is not an install saving. No new memory-buffered download path ships here.

Larger HTTP/2 windows reduce a metadata-only probe median from 231.76 to 213.59 ms. Six of eight pairs improve. Every decoded body hash matches across the probe. This result does not establish install savings or prove a flow-control stall. Transport defaults remain unchanged.

Warm trust-index rebuilds take 3.74 ms for T3, 2.18 ms for Vite, 0.45 ms for Sharp, and 1.18 ms for Nest. These component costs do not justify a trust-path rewrite in this concept.

The candidate retains lifecycle approval behavior. T3 blocked-script metadata enrichment takes a median 10 ms, with zero blocked-set RPCs and two metadata cache hits. Firewall, release-age, source scanning, and policy extensions remain disabled in this benchmark. Lifecycle enrichment is a separate contract.

DHAT attributes the earlier T3 cold heap peak mainly to metadata buffers and Brotli decoder rings. The CI-cold profile contains two amplified compressed prefixes. These profiles use a different allocator from production. Their tracked heap peaks cannot be subtracted from production RSS, and they do not establish a leak.

**Method and correctness**

The main cohort contains 512 successful scored installs and 64 preliminary installs. The targeted repeat contains 128 successful scored installs and 16 preliminary installs. Cold, CI-cold, warm, and up-to-date states use the committed readiness runner. Only LPM and Bun participate. Builds, tests, profiling, and other benchmark processes do not run during scored installs.

The host is an Apple M5 Pro with 18 logical CPUs and 48 GiB RAM. It runs macOS 27.0, Rust 1.94.0, Node 26.5.0, and Bun 1.4.2. The route is direct npm. The registry remains live. These results are not comparable to historical PR medians as a continuous improvement series.

Each entry occupies each position twice. Each pair runs in both relative orders four times. Projects, HOME directories, stores, and caches are isolated. Preliminary installs warm shared runtime and registry paths without reusing dependency state in scored cold installs. All three LPM entries use equivalent shell wrappers. Bun runs directly. LPM wall measurements therefore include the small wrapper overhead.

The runner measures elapsed time with `process.hrtime` around `spawnSync`. `/usr/bin/time -l` supplies peak RSS. Percentiles use linear interpolation. No samples are removed. A successful runner exit with `--allow-inconclusive` does not establish performance acceptance.

All 48 retained lock triples are byte-identical across the three LPM entries. Selected identities remain stable within each main fixture. Installed package manifests and critical files match across LPM entries. Critical Next, SWC, Sharp, esbuild, and Biome files also match Bun. Bun retains four additional WASM identities in its T3 lock, as before this change. These checks use the retained projects after each mode sequence.

Rust 1.94.0 workspace build, all-target Clippy, and formatting pass with zero warnings. The fast gate passes 6676 library tests, 5263 CLI unit tests, and 116 CLI integration tests. The relevant workflow groups pass 477 tests. Two additional standalone cancellation and metadata-failure tests also pass. Seventeen shell, benchmark-runner, and npm checks pass. The extractor and runtime reviews report no unresolved findings.

The finding ledger contains 27 reports mapped to 25 unique research leads. Four findings are reproduced and fixed, including the withdrawn broad workspace policy. Twenty-one proposals or causal claims are rejected for this concept. Their measured observations remain explicit. None are externally blocked or pending.

This concept depends on the prefix-release machinery and pipeline baseline in PR #865. It belongs after #865 in native stack #863. Parent branches and unrelated workspace edits are unchanged. The adjacent data files record sanitized rows, summaries, experiments, provenance, checks, and the finding ledger.
