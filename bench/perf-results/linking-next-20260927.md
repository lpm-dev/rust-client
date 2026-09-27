# Linking `next` after extraction

After a package is extracted into the store, its link directory is created as a copy-on-write clone of the store object. For `next@16.3.6` (8,534 files in 697 directories), that link step runs last in a T3 install and was estimated at 128–131 ms. This report investigates it. No change is adopted: the clone is already the cheapest way to create the link directory, and the link step waits on `next`'s own extraction, which is bound by file-system contention with the other extractions.

## The link step

Timed inside T3 installs, `next`'s link step is a whole-tree `clonefile()` followed by a walk that stats the cloned tree for its snapshot (ms):

| State | Clone | Snapshot walk | Total |
|---|---:|---:|---:|
| First install (6 runs) | 92–125 | 14–31 | 108–158 |
| CI cold (6 runs) | 81–94 | 14–19 | 97–114 |

- **The clone.** Cloning `next`'s store object on its own, with each strategy run 7 times in rotation (median ms):

  | Strategy | Median |
  |---|---:|
  | One `clonefile()` of the tree (current) | 89.7 |
  | Clone each file separately, 1 / 4 / 8 threads | 870.3 / 517.2 / 482.1 |
  | Clone subtrees in parallel, depth 3, 4 / 8 threads | 140.9 / 137.7 |
  | Clone subtrees in parallel, depth 4 / 5, 8 threads | 263.1 / 380.3 |

  APFS serializes clone operations, and each separate call costs about 100 µs, so splitting the work is slower. A tree whose files were just written cloned in 60.5 ms, and the same tree after a flush in 81.0 ms, so the clone does not wait for pending writes either.
- **The snapshot walk.** The link snapshot records each entry's mode, size, modification time and change time. A clone creates new inodes with a new change time, so the snapshot can't be copied from the store object; it has to stat the link directory.

## What the link step waits for

The link step starts as soon as `next`'s fetch task ends. In T3's CI-cold install, timed from the start of the install (medians of 6 runs, ms):

| Event | Time |
|---|---:|
| `next`'s fetch task starts | 21 |
| `next`'s streamed download and extraction | 916 |
| `next`'s fetch task ends, the install's last | 1,007 |
| `next`'s link step ends | 1,114 |
| Link phase ends | 1,121 |

While `next` extracted, the other packages spent 1,990 ms extracting in total. Counters on the extraction's threads show where `next`'s time went (ms):

| `next`'s extraction | Alone, from a file | In the install (6 runs) |
|---|---:|---:|
| Total | 416 | 819–919 |
| Extracting thread: opening each file's directory | 72 | 155–189 |
| Extracting thread: accepting written files (identity check, close) | 92 | 220–283 |
| Extracting thread: writing files over 256 KB | 106 | 176–203 |
| Extracting thread: waiting for writer capacity | 106 | 161–197 |
| Decoder: waiting for the extracting thread | — | 541–651 |
| Decoder: reading the download | — | 39–42 |

The download and the decoder keep up. The extracting thread's file-system calls run 2–2.7 times slower than alone, because the other extractions contend for the same file system.

## Measured and not adopted

**Fewer extraction permits.** T3 CI cold, 8 runs each (medians; ms from the start of the install):

| Permits | Wall | `next` extracted in | `next` ends | Last fetch ends | Link phase ends |
|---:|---:|---:|---:|---:|---:|
| 4 (current) | 1,108.3 | 884 | 975 | 975 | 1,083 |
| 3 | 1,096.7 | 790 | 913 | 1,046 | 1,069 |
| 2 | 1,137.1 | 602 | 728 | 1,101 | 1,109 |

`next` extracts faster with fewer concurrent extractions, and every other package finishes later by about as much.

**More writers for the streamed package.** Writers for `next` only, T3 CI cold, 8 runs each:

| Writers | Paired wall vs 2 | `next` extracted in | `next` ends | Last fetch ends |
|---:|---:|---:|---:|---:|
| 2 (current) | | 896 | 976 | 976 |
| 3 | +9.3 (2/8) | 886 | 987 | 1,007 |
| 4 | +15.8 (2/8) | 890 | 1,002 | 1,081 |
| 6 | +51.4 (2/8) | 920 | 1,026 | 1,070 |

**Keeping directory handles open.** `next`'s archive changes directory on 8,198 of 8,531 files. A cache of open directory handles, up to 512 per extraction, would serve 90% of the reopens (78% with 256, 67% with 128). Each revisit still has to prove its path hasn't changed. On macOS, one `fstatat` that refuses symlinks anywhere in the path does that in 0.54 µs, against 2.0 µs for today's reopen. The cache was built with that check and a shared descriptor budget:

- **Alone:** `next` extracted in 432.1 ms against 431.7 ms (24 runs each).
- **In T3's CI-cold install:** directory preparation fell from 169.7 to 138.1 ms and waiting for writer capacity rose from 169.4 to 185.7 ms, so `next`'s extraction went from 873.2 to 864.7 ms (8 runs each).
- **Install walls:** T3 −9.1 ms (9/12) on first install and −27.2 ms (8/12) on CI cold; nest −4.1 (13/16) and +0.0 (8/16); vite-react +1.7 and +2.5 (6/16). All within noise.

The time saved on the extracting thread went to waiting for the writers.

## What remains

Each extracted file costs a fixed set of file-system operations:

- **Extraction:** creating it, writing it, checking its identity on the writer, closing it, and checking its identity again when it's accepted.
- **Linking:** cloning it into the link directory, then stat-ing it for the snapshot.

With several packages extracting at once, the total of these operations sets T3's install time, and moving them between threads doesn't change it. Removing any of the identity checks would change the guarantees of checked extraction, and none were removed here.

## Limitations

All runs used one Apple Silicon machine (18 cores) with APFS. Registry traffic was replayed from local captures. The first-install trace didn't record `next`'s fetch task, so the timeline uses CI-cold installs. Counters and traces came from instrumented builds.

## Artifacts

The adjacent `-summary.json` holds the install comparisons, the timelines and counters of every traced run, `next`'s link-step timings and the isolated measurements. The `-tools.tar.gz` archive contains the clone and lookup benchmarks, the timeline script, the instrumentation patches (fetch, link and tail traces, extraction counters, the directory cache) and the harness scripts.
