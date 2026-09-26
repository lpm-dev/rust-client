# Oversized exact-version histories

On the npm route, an exact version is selected from the package's full history when that history fits in 4 MiB, and read from the version document otherwise. A history over the cap was read up to the cap on every lookup and then discarded. Ten of T3's exact dependencies (`@next/swc-*`, `@next/env`, `@tailwindcss/oxide`) have 4.8–7.7 MB histories, so every cold or expired T3 install decoded 42 MB it could not use. The first lookup now records that a history is too large, and later lookups go straight to the version document. With an expired cache against the live registry, T3's install takes 619 ms instead of 787 ms.

## The change

- **Detection.** A history counts as oversized only when its declared or streamed length exceeds the cap; parse errors and other failures do not.
- **Memory.** The command's client remembers oversized histories (up to 4,096 packages), and cache invalidation keeps them: a history's size does not depend on the entries invalidated.
- **Disk.** A marker beside the metadata cache records the cap and the time of the observation. Later commands honor it for a week, and ignore it if it was written under a smaller cap than today's. A history that shrinks is therefore read again within a week.
- **Reporting.** `install --timing` reports `oversized_history_count` and `oversized_history_skip_count` under `npm_direct_version_documents`.

Exact versions answered from a fresh cache never read a history, so fresh-cache states are unaffected.

## Results

Release builds of #894 (c398505e1) and this change installed T3 against registry.npmjs.org on one machine. The store held every tarball, so the runs differ only in metadata. Runs alternated between the builds; values are median / nearest-rank p95 in ms, and the paired difference is the median over the pairs.

**First install.** With an empty metadata cache, this change found the 10 oversized histories and decoded 41,965,784 bytes of exact-version documents, as #894 does. That cache, markers included, is the snapshot for the next measurement.

**Expired cache.** Before each run the snapshot was restored with every entry expired, and the lockfile, `node_modules` and `.lpm` were removed. 12 paired runs:

| | #894 | This change | Paired |
|---|---:|---:|---:|
| Total | 787.0 / 1,156 | 619.0 / 981 | −161.0 (11/12) |
| Resolve | 722.5 / 1,083 | 555.0 / 915 | −173.5 |
| Exact-version document bodies | 41,965,784 B | 22,744 B | |

Both builds revalidated the other 211 documents with a 304. An earlier round of 8 pairs measured −63 ms (5/8); midway through it, a package history changed on the registry and both builds downloaded 37 MB more in each later run.

**Cold metadata.** With an empty metadata cache, the first lookup still reads each oversized history once. Two rounds measured +48 ms (3/6) and −57 ms (8/10): no consistent direction.

## Limitations

Registry latency varied by about ±100 ms between runs. Body sizes are decoded bytes; the histories travel compressed. All runs used one Apple Silicon machine (18 cores).

## Artifacts

The adjacent `-summary.json` holds every run. The `-tools.tar.gz` archive contains the A/B driver, the environment wrapper and the summary script.
