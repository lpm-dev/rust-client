T3 first-install median decreased from **1,978 ms to 1,872.5 ms** against the PR867 baseline, a **5.3% improvement**. Bun measured **1,923.5 ms** in this cohort. T3 CI-cold median decreased from **1,642.5 ms to 1,580.5 ms**, a **3.8% improvement**. The candidate beat the baseline in all six paired T3 rounds for both modes.

This change trades memory for speed. Median T3 peak RSS increased by **14.6 MiB** on first install and **11.6 MiB** on CI-cold. The results establish a gain on this host and workload. They do not establish a universal advantage over Bun.

The extractor now overlaps gzip decoding with filesystem extraction for streamed V2 objects with a declared unpacked size of at least 8 MiB. A scoped worker uses three reusable 256 KiB buffers. The consumer retains the existing file checks and digest calculation. One reusable 64 KiB copy buffer also coalesces reads before writes and hash updates.

The store joins the decoder, drains the same compressed hashing reader, and checks integrity before object publication or reuse. Failure cancels pending network reads before the worker joins. Source inspection retains its sequential callback path. Existing APIs still accept readers without `Send`.

The concept depends on PR867's checked file-handle extraction and the earlier streamed V2 pipeline. Its parent is `56bbf4e5a7afef9996b726e992fd0a44ec96b3e2`. The source commit is `df373bb317c035f869e0321e8695db249518e651`.

All wall times in the next table are medians in milliseconds. Each cell contains six scored samples.

| Fixture | Mode | Baseline | Candidate | Bun |
|---|---|---:|---:|---:|
| T3 | First install | 1,978 | 1,872.5 | 1,923.5 |
| T3 | CI-cold | 1,642.5 | 1,580.5 | 1,513 |
| Vite React | First install | 656 | 572.5 | 452 |
| Vite React | CI-cold | 281.5 | 284 | 185.5 |
| Native Sharp | First install | 284 | 272 | 196.5 |
| Native Sharp | CI-cold | 152 | 150.5 | 121.5 |
| Nest | First install | 352.5 | 335 | 270.5 |
| Nest | CI-cold | 306.5 | 307 | 221.5 |

The smaller fixtures also used the live registry. Their first-install changes include resolver variation, so the table does not attribute every improvement to extraction.

Median peak RSS, in MiB:

| Fixture | Mode | Baseline | Candidate | Bun |
|---|---|---:|---:|---:|
| T3 | First install | 326.4 | 341.0 | 383.4 |
| T3 | CI-cold | 220.5 | 232.1 | 125.4 |
| Vite React | First install | 209.1 | 206.1 | 133.2 |
| Vite React | CI-cold | 92.8 | 92.5 | 52.0 |
| Native Sharp | First install | 59.9 | 59.7 | 21.4 |
| Native Sharp | CI-cold | 41.2 | 42.9 | 14.4 |
| Nest | First install | 100.6 | 100.6 | 38.1 |
| Nest | CI-cold | 57.0 | 58.8 | 26.7 |

The frozen extraction benchmark used the official Next 16.3.6 archive, with an independent SHA-512 check. Its compressed size was 41,747,455 bytes. The destination path shape stayed fixed across variants. One warm round preceded six scored rounds with balanced variant order.

| Extractor | Median time | Median peak RSS |
|---|---:|---:|
| Baseline | 791.261 ms | 10,960,896 bytes |
| Candidate, sequential decoder | 763.792 ms | 11,108,352 bytes |
| Candidate, parallel decoder | 636.131 ms | 11,894,784 bytes |

The combined extraction improvement was **19.6%**, with approximately **0.89 MiB** more peak RSS in the isolated process. All 8,531 output files matched in content and permissions. The sequential comparison measures the copy-buffer change separately. It does not establish a separate install-level gain.

The main install cohort contained **144 scored installs**, all successful. The host used macOS 27.0 on ARM64, 48 GiB RAM, Rust 1.94.0, and Bun 1.4.2. Builds and tests stopped before measurement. The harness rotated manager order and used separate cold, CI-cold, warm, and up-to-date warm gates.

Cold mode starts without a lockfile or manager cache. CI-cold retains the generated lockfile and removes the installed tree and manager cache. Lifecycle scripts were disabled for both managers. LPM used V2, direct registry access, release age zero, firewall off, source analysis off, and no policy extensions. The benchmark used only LPM and Bun.

The repository readiness harness supplied timing and peak RSS. A local harness copy retained lockfiles and package inventories after measurement, before cleanup. This addition changed neither timing nor execution order. The provenance artifact contains the retention patch, commands, hashes, and microbenchmark source.

All 72 scored package inventories matched within each fixture across the three variants. Full warm payload comparisons also matched package bytes and directories. Baseline and candidate permissions matched. Bun's bin permission differences remain recorded in the parity artifact.

| Fixture | Packages | Regular files | Payload bytes |
|---|---:|---:|---:|
| T3 | 95 | 17,846 | 441,695,827 |
| Vite React | 63 | 2,222 | 35,011,496 |
| Native Sharp | 11 | 130 | 16,562,326 |
| Nest | 33 | 3,376 | 7,831,945 |

Installed-version parity does not prove identical live metadata histories or HTTP behavior. The frozen archive provides the controlled extraction comparison.

All outliers remain in the results. Sharp candidate CI-cold round four took **359 ms**, including **274 ms** inside streamed extraction. Its header time was 40 ms, and its extraction permit wait was zero. These counters combine input waiting and extraction, so they do not identify the cause.

A separate Sharp follow-up used one warm gate and twelve scored rounds per variant, for 72 additional successful installs. Candidate CI-cold median was **156 ms**, versus **156.5 ms** for the baseline and **121.5 ms** for Bun. Candidate samples ranged from 152 to 182 ms. The baseline had a 498 ms sample, with 384 ms before streamed response headers. That different interval does not explain the original candidate outlier. All 36 follow-up package inventories matched the main cohort.

Nest candidate first-install round six took **533 ms**, including **430 ms** in resolution. Bun T3 first-install round five took **2,322 ms**. Six main-cohort samples do not support strong tail-latency claims. The Sharp follow-up is separate and does not replace any main-cohort sample.

Earlier diagnostic runs separated Next's metadata, input, decoder, filesystem, and linker intervals. They used three samples per mode and a temporary instrumented CLI. Production source contains none of that instrumentation. Frozen microbenchmarks found negligible diagnostic overhead, but the live overhead is not precisely established.

| Diagnostic interval | Cold median | CI-cold median |
|---|---:|---:|
| Next extraction worker | ~1,491 ms | ~1,483 ms |
| Input-read waits, included in extraction | ~324 ms | ~216 ms |
| File creation | ~426 ms | ~454 ms |
| File writes | ~158 ms | ~166 ms |
| File acceptance and close | ~120 ms | ~110 ms |
| Parent preparation | ~90 ms | ~106 ms |
| Next materialization | ~75 ms | ~81 ms |
| Destination metadata scan | ~30 ms | ~30 ms |

Next's cold metadata fetch took about 352 ms before the selected document became available. Worker queue and async resume delays were each less than 1 ms. Input-read waits include runtime and bridge scheduling. They are not pure network time. Nested counters overlap and cannot be added as separate wall costs.

The different installation layouts required different filesystem work. Next's ten dependency symlinks took about 0.47 ms. Across all 95 package tasks, 113 dependency symlinks summed to 20.9 ms cold and 8.6 ms CI-cold. Snapshot writes summed to 740 ms cold and 20 ms CI-cold. These concurrent elapsed intervals include contention and scheduling, so they do not directly measure install wall time.

Those measurements support the decoder overlap change. They do not prove a separate snapshot-contention or directory-handle-cache improvement. The report also preserves destination metadata checks, because source metadata cannot establish the cloned destination state. The local Bun source checkout was version 1.4.0, so source observations do not describe measured Bun 1.4.2 by assumption.

Local checks passed on the final source with zero build or Clippy warnings. The fast workspace gate passed 6,711 library tests, 5,266 CLI unit tests, and 116 CLI binary tests. Relevant install workflows passed 479 tests. Targeted extractor, store, and fetch suites passed 100, 348, and 26 tests. These targeted counts overlap the larger gate counts. Seventeen helper checks and the release build also passed.

Regression coverage includes short reads, duplicate entries, truncated trailers, CRC failures, compressed and decompressed limits, late input failures, object reuse, and private staging cleanup. It also covers producer panic, consumer panic, blocked buffer capacity, and an actual stalled HTTP response. Two regressions failed before their fixes: repeated polling after cancelled-stream EOF, and changed staging setup order.

The finding ledger contains **4 findings received, 4 verified and fixed, 0 rejected, 0 externally blocked, and 0 pending**. The research reconciliation records measurement observations, preserved constraints, and unmeasured alternatives separately. The production review found no additional concrete correctness defect.

Artifacts:

- [All measured install samples](streaming-materialization-20260923-installs.jsonl)
- [Wall and RSS summaries](streaming-materialization-20260923-summary.json)
- [Frozen extraction samples](streaming-materialization-20260923-micro.json)
- [Source, binary, and reproduction provenance](streaming-materialization-20260923-provenance.json)
- [Package and payload parity](streaming-materialization-20260923-parity.json)
- [Diagnostic intervals and retained outlier traces](streaming-materialization-20260923-diagnostics.json)
- [Local gate results](streaming-materialization-20260923-gates.json)
- [Finding ledger and research reconciliation](streaming-materialization-20260923-ledger.json)

The full local logs and preserved binaries remain under `/tmp/lpm-next-materialization`. The early diagnostic standalone probe was overwritten before preservation. Its command, hash, and instrumentation source remain. The diagnostic CLI and all optimization baselines and candidates remain available.
