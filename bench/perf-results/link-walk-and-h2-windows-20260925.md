# Link metadata walk and HTTP/2 window evaluation

This investigation examined two fixed costs: Next's link step and the HTTP/2 flow-control windows. The link step now reads tree metadata in parallel. The directory clone and the HTTP/2 windows remain unchanged because the measured alternatives were slower on the workloads that matter.

## Link step

On the PR887 stack head, a T3 CI-cold install spent 94 ms linking Next: 68 ms in one whole-directory `clonefile` and 26 ms in the tree metadata digest of the clone. CI-warm reuses every link entry; Next's 34 ms there is the reuse check, which recomputes the same digest. The clone runs only when an entry is created.

### Splitting the clone

Next's tree has 8,531 files in 697 directories. Splitting the clone into subtrees on 1–8 threads was slower in every configuration. Each `clonefile` call has a large fixed cost, and concurrent calls scale poorly.

| Clone of Next's tree | Median |
|---|---:|
| One directory clone | 79.8 ms |
| 931 subtree clones, best of 1/2/4/8 threads | 121.0 ms |
| 3,915 subtree clones, best | 250.0 ms |
| 8,531 file clones, best | 430.8 ms |

The clone is unchanged.

### Parallel metadata walk

The digest hashes one record per entry in depth-first order with sorted names; directory reads dominate its cost. Helper threads now read directories concurrently once 16 are waiting, and the caller hashes the collected entries in the original order. The digest and the first reported error are unchanged; small trees never start helpers. The walk serves link reuse checks, the snapshot after a clone and object reuse checks.

| Walk of Next's tree, isolated | Median |
|---|---:|
| Sequential portable | 23.1 ms |
| Bulk, one thread (previous path) | 14.6 ms |
| Bulk, two threads | 10.7 ms |
| Bulk, four threads | 7.7 ms |
| Bulk, eight threads | 8.1 ms |

Four threads include the caller. Eight threads add no benefit.

### Installs

Warm installs alternate the PR887 binary and the parallel walk for 24 balanced rounds after two unscored gates per variant. Both share one store; HOME is isolated without an `.npmrc`. Times are median / nearest-rank p95 milliseconds.

| State | PR887 | Parallel walk | Paired | Next reuse check |
|---|---:|---:|---:|---:|
| CI-warm | 82.8 / 86.1 | 75.5 / 79.5 | −6.9 (18/24) | 32 → 22–24 |
| Fresh checkout, warm cache | 93.6 / 100.3 | 88.6 / 89.9 | −5.1 (24/24) | 31–32 → 21–22 |

With one link worker, Next's reuse check measures 19 ms before and 10 ms after. With the default four workers, concurrent reuse checks add about 9 ms to both. After the change, the warm link phase is bounded by the other 94 packages' checks rather than Next's.

In three live-registry CI-cold installs per variant, Next's post-clone snapshot took 23–24 ms before and 13–15 ms after; the clone took 71–85 ms in both.

The parallel binary reused all 95 link entries written by the PR887 binary, and the PR887 binary reused all 95 entries written by the parallel binary.

## HTTP/2 windows

The client uses hyper's defaults: a 2 MiB stream window and a 5 MiB connection window. Enabling adaptive windows resets both to 64 KiB and grows them from BDP pings up to 16 MiB. Operating systems cap one TCP receive buffer at 4 MiB by default on macOS and 6 MiB on Ubuntu.

Two Linux containers exchanged HTTP/2 over a Docker network. Each side's `eth0` applied the one-way delay and 1 Gbit/s pacing through netem, with a queue of about twice the bandwidth-delay product and segmentation offload disabled. The client's TCP receive buffer was capped at 4 or 6 MiB. Client and server used the workspace's reqwest 0.12.28, hyper 1.10.1 and h2 0.4.16 over prior-knowledge HTTP/2; TLS does not change flow control. Each cell ran five repetitions. Retransmissions were zero at every nonzero latency.

The workloads were one 42 MB download and an install-like mix on one connection: 40 × 50 KB, 10 × 1 MB and 2 × 35 MB started together. Times are median milliseconds, as single download / mix completion.

| TCP cap, RTT | Default | Adaptive | 8 / 16 MiB | 16 / 32 MiB |
|---|---:|---:|---:|---:|
| 4 MiB, 0 ms | 397 / 745 | 493 / 819 | 468 / 780 | 409 / 728 |
| 4 MiB, 20 ms | 1,126 / 1,015 | 845 / 1,175 | 776 / 1,092 | 829 / 1,227 |
| 4 MiB, 50 ms | 2,646 / 2,752 | 3,011 / 3,353 | 3,264 / 3,945 | 2,684 / 4,180 |
| 4 MiB, 100 ms | 4,079 / 4,764 | 3,466 / 4,428 | 2,678 / 5,834 | 3,528 / 6,886 |
| 6 MiB, 0 ms | 395 / 707 | 476 / 811 | 447 / 722 | 373 / 748 |
| 6 MiB, 20 ms | 957 / 1,439 | 995 / 1,160 | 839 / 1,311 | 605 / 1,097 |
| 6 MiB, 50 ms | 3,420 / 3,629 | 1,399 / 3,068 | 2,440 / 2,453 | 2,115 / 2,273 |
| 6 MiB, 100 ms | 3,948 / 3,881 | 2,697 / 4,789 | 2,951 / 4,191 | 2,997 / 4,086 |

Larger windows often speed up a lone large download but slow the mix under a 4 MiB TCP cap at 50 and 100 ms, where the server can queue large-stream data ahead of small responses inside the one TCP connection. Adaptive windows also slow a lone download at zero latency, 493 against 397 ms. No configuration improved the mix consistently, so the defaults remain.

### Large bodies on a second connection

A follow-up kept default windows and moved the two 35 MB bodies to a second connection.

| TCP cap, RTT | Mix completion, one connection | Two connections | Small bodies done, one → two |
|---|---:|---:|---:|
| 4 MiB, 50 ms | 3,932 | 2,241 | 1,137 → 990 |
| 4 MiB, 100 ms | 4,532 | 3,501 | 1,425 → 1,269 |
| 6 MiB, 100 ms | 4,098 | 3,279 | 1,701 → 1,164 |

Every two-connection repetition at 100 ms and a 4 MiB cap finished before the fastest single-connection repetition. This design needs its own implementation and end-to-end evaluation, including low-latency cost and connection setup, before it can change the client.

## Limitations

The clone and walk measurements come from one Apple M5 Pro on macOS 27.0 with APFS. The HTTP/2 containers ran under OrbStack's Linux kernel, whose netem approximates a paced link; it does not model the real registry's CDN behavior. The CI-cold link timings use three live-registry installs per variant and describe the link phase only.

## Artifacts

The adjacent `-summary.json` holds every measurement in this report. The `-tools.tar.gz` archive contains the clone and walk microbenchmark, the netem client, server and drivers, the warm-install driver, and the raw rows. Absolute paths in those scripts identify this run.
