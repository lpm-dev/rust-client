# Large files during parallel extraction

When a package has enough files, extraction hands them to two writer threads. A file over 256 KB is too large to buffer for them, so the extracting thread writes it itself. Before this change it first waited for every queued file to finish, and the writers stayed idle while it wrote. It now writes the large file while the writers finish their queue, and queues the finished file so it is still accepted in archive order. next@16.3.6 extracts in 416 ms instead of 446 ms. In installs the effect is small, because the package's download paces its extraction.

## Where the extraction of `next` went

`next@16.3.6` has 8,531 files in 651 directories; 115 of them are over 256 KB (124 MB). One instrumented extraction each, before and after this change (ms):

| | Before | After |
|---|---:|---:|
| Extraction, total | 441.1 | 415.9 |
| Extracting thread: opening each file's directory | 74.0 | 72.5 |
| Extracting thread: writing files over 256 KB | not separable | 106.2 |
| Extracting thread: accepting finished files (identity check and close) | 83.5 | 92.1 |
| Extracting thread: waiting for writer capacity | 96.6 | 106.0 |
| Both writers, busy (sum) | 579.4 | 599.3 |

Before the change, waiting for the queue to drain before each file over 256 KB took 61 ms in total in a separate run; the table's wait row doesn't include it. After the change, the extracting thread and the two writers are about equally busy, so removing more work from one side moves the wait to the other.

## Results

**Extraction alone.** `next@16.3.6` extracted through the pipelined file API with two writers, variants rotated over 8 rounds of 3 runs (ms):

| Variant | Median | p10 | p90 | vs before |
|---|---:|---:|---:|---:|
| Before | 445.8 | 440.7 | 455.7 | |
| This change | 415.6 | 412.2 | 447.9 | −30.1 |

**Installs.** Release builds of #899 and this change, and Bun, installed each fixture from a frozen HTTPS replay of its registry traffic on one machine, in balanced order. Values are median / nearest-rank p95 in ms; the paired difference is the median over the pairs, with the number of pairs in which this change was faster.

| Fixture | State | #899 | This change | Paired | Bun |
|---|---|---:|---:|---:|---:|
| T3 | First install (24 pairs) | 1,177.0 / 1,231.8 | 1,168.8 / 1,207.6 | −15.4 (16/24) | |
| T3 | CI cold (24 pairs) | 1,103.4 / 1,125.7 | 1,107.5 / 1,174.8 | +5.5 (10/24) | |
| T3 | First install (12 pairs) | 1,187.7 / 1,319.7 | 1,179.2 / 1,319.1 | −9.2 (7/12) | 1,349.3 / 1,421.4 |
| T3 | CI cold (12 pairs) | 1,115.9 / 1,162.7 | 1,093.8 / 1,140.7 | −14.8 (8/12) | 1,352.4 / 1,436.8 |
| nest | First install | 216.6 / 238.1 | 213.3 / 218.2 | −2.9 (11/16) | 194.6 / 197.9 |
| nest | CI cold | 196.0 / 213.1 | 192.5 / 201.9 | −3.8 (12/16) | 192.7 / 225.0 |
| vite-react | First install | 232.5 / 250.4 | 234.3 / 247.7 | +0.2 (8/16) | 183.9 / 192.7 |
| vite-react | CI cold | 189.4 / 220.0 | 185.5 / 195.1 | −2.5 (9/16) | 158.8 / 170.8 |

- **T3.** `next` streams from the network into extraction, and the download paces it. First installs gain up to 15 ms; CI-cold installs are within noise.
- **nest.** `rxjs` has three files over 256 KB: 3–4 ms.
- **vite-react** has no package with writers and files over 256 KB, and is unchanged.

## Measured and not adopted

- **Larger files for the writers.** Letting files up to 1, 2, 4 or 8 MB go to the writers (with a pending budget of 4, 8, 8 or 16 MB) extracted `next` in 411.9–414.0 ms, 2–4 ms better than this change, while buffering up to four times as much. The writers were already as busy as the extracting thread.
- **Keeping directory handles open.** Opening each file's directory costs the extracting thread 72 ms on `next`, because its archive order changes directory on 8,199 of 8,531 files. A least-recently-used cache of open directory handles would serve 55% of those opens with 64 handles and 67% with 128, holding that many descriptors per extraction. With the writers as busy as the extracting thread, and the download pacing it in installs, it was not built.

## Limitations

All runs used one Apple Silicon machine (18 cores) with APFS, and registry traffic was replayed from local captures. Extraction timings come from one instrumented run per build.

## Artifacts

The adjacent `-summary.json` holds every scored install, the isolated extraction results, the attribution and the directory reuse figures. The `-tools.tar.gz` archive contains the extraction benchmark crate and its driver, the instrumentation patches, the harness scripts and the summary scripts.
