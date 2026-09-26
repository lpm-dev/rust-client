# Parallel file creation during extraction

Large packages extracted mostly on one thread. The writer pool only filled files that the coordinating thread had already created, and it waited for each batch of 64 to finish completely before admitting more. Now the writers create the files, and the pool accepts finished entries continuously in archive order. On its own, T3's `next` tarball (8,531 files) extracts in 465 ms instead of 582 ms. T3 first installs and CI-cold installs are about 60 ms faster in the frozen-registry harness.

## Where the time went

A sampling profile of `next` extracting on its own showed:

- **The coordinating thread did the creating.** It spent 365 of 580 ms in `openat(O_CREAT)`, creating every file one after another. The two writers were idle most of the time, because they only wrote contents into files that already existed.
- **The pool ran stop-and-wait.** After moving creation into the writers, a second profile showed the coordinating thread waiting 148 ms in the pool's drain. The pool filled a window of 64 files, waited until all 64 finished, and only then accepted them and admitted more. So the writers sat idle while each batch was accepted, and the coordinating thread sat idle while the batch finished.

## The change

**Writers create files.** For each small file, the coordinating thread now hands the pool a creation request: the verified parent directory handle, the leaf name and the path for errors. The worker opens it with `O_CREAT | O_NOFOLLOW` relative to that handle, writes it, hashes it and sets its mode. Directory preparation, duplicate paths and files over 256 KB stay on the coordinating thread, as before.

Creation stays relative to the pinned directory handle, so doing it later on another thread adds no path lookup. A new test plants a symlink at the name between submission and creation. The worker does not follow it, and the extraction fails with the path-traversal error.

**Continuous, ordered acceptance.** The pool keeps its bounds of 64 entries and 4 MB. It accepts completed entries from the front, in archive order, as they finish, and when the window is full it waits only for the oldest entry. Record order is unchanged. The earliest failure by archive order still wins. Completed entries behind a failure are rolled back by their existing drop guard. A new test shows that the entry after a full window is admitted while every later write is still blocked.

## Results

### Extraction on its own

Measured on this Mac through the pipelined file-extraction API; medians of 9 runs.

T3's `next@16.3.6` tarball, 8,531 files, with 2 writers:

| Round | #892 | This change |
|---|---:|---:|
| 1 | 580 ms | 462 ms |
| 2 | 583 ms | 469 ms |
| 3 | 582 ms | 463 ms |

Writer counts on `next@16.0.7`, 7,399 files, two rounds of 7 runs each:

| Writers | #892 | This change |
|---|---:|---:|
| 2 | 487–504 ms | 382–388 ms |
| 4 | 490–511 ms | 345–347 ms |
| 8 | 483–499 ms | 401–402 ms |

With the old pool, adding writers changed nothing, because creation was serial.

### T3 installs in the frozen-registry harness

The harness replays a frozen HTTPS capture of the registry locally, with balanced ordering and 16 samples per variant. Values are median / nearest-rank p95 in ms, and the paired difference is the median over the same samples:

| State | #892 | 2 writers (shipped) | 4 writers |
|---|---:|---:|---:|
| First install | 1,539 / 1,720 | 1,469 / 1,669, paired −67 (13/16) | 1,506 / 1,635, paired −38 (12/16) |
| CI cold | 1,449 / 1,519 | 1,376 / 1,815, paired −61 (13/16) | 1,417 / 1,574, paired −63 (14/16) |

In the traced runs, `next`'s extraction inside a CI-cold install took about 1,190 ms with #892 and 743–1,159 ms with this change.

An earlier 12-sample run with 4 writers measured first installs at a paired −59 ms (8/12) and CI-cold at +25 ms (5/12). Samples vary by about 100 ms, so only the 16-sample runs are used above.

## Measured and not adopted

- **Four writers by default.** They were faster than two on their own (345 against 385 ms) but no better inside an install, where many packages extract at once, and they cost more CPU on smaller machines. The default stays at two, and `LPM_INTERNAL_EXTRACT_WRITERS` still overrides it.
- **Closing accepted files on the writers.** The coordinating thread spends about 80 ms closing descriptors after acceptance. Moving that work to the writers saved only 10 ms, and the files waiting in the queue to be closed would fall outside the per-pool descriptor budget.

## Limitations

The harness replays locally over TLS. It does not model internet bandwidth, which bounds large downloads on slower links. The standalone measurements read the tarball from disk.

## Artifacts

The adjacent `-summary.json` holds the numbers in this report. The `-tools.tar.gz` archive contains the extraction benchmark source, the harness drivers and the raw harness rows.
