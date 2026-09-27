# Scripted-package scan after linking

A fresh install records registry metadata (publish time and behavioral tags) for each package with install scripts. To find those packages it reads every linked package's manifest, one at a time. On a first install each of those reads is the first since linking created the package's directories, and it cost about 100 µs: 10–11 ms of the tail on vite-react and T3. The manifests are now read in parallel. vite-react's first install is 7 ms faster; the gain grows with the number of packages.

## Where the tail went

Step marks in the install tail, first installs, medians of 8 runs per build (ms):

| Step | vite-react #897 | vite-react this change | T3 #897 | T3 this change |
|---|---:|---:|---:|---:|
| Store baseline index and patches | 3.33 | 3.33 | 5.31 | 5.29 |
| Scripted-package scan and blocked-set metadata | 10.87 | 4.56 | 10.48 | 2.87 |
| Trust check | 1.15 | 1.22 | 0.63 | 0.65 |
| Blocked-set capture | 1.16 | 0.94 | 1.91 | 1.55 |
| Lockfile write | 1.27 | 1.24 | 2.29 | 2.31 |
| Other steps | 0.13 | 0.13 | 0.16 | 0.17 |
| **Tail, total** | **19.51** | **11.56** | **20.84** | **12.90** |

Each value is the median of its own row, so a column need not add up to its total.

- **The scan, not the registry.** The metadata step makes no request on the npm route: the resolver's cache of each selected version's history already holds it (`timing.detail.metadata`, purpose `blocked_set`: 0 requests, 1 cache hit on vite-react).
- **The first read, not the parsing.** Timed twice in a row within one install, the serial scan took 7.6–11.2 ms the first time, of which 0.3–0.9 ms was JSON parsing, and 0.9–2.1 ms the second time.
- **The later reads were already parallel.** The blocked-set capture that follows reads the same manifests with a parallel walk, and was cheap because the scan had just read them.

## The change

The scan reads the manifests on the parallel worker pool that the blocked-set capture already uses, and keeps the packages in install order.

## Results

Release builds of #897 (08ac29e1e) and this change, and Bun, installed each fixture from a frozen HTTPS replay of its registry traffic on one machine. Runs rotated between variants in balanced order. Values are median / nearest-rank p95 in ms; the paired difference is the median over the pairs, with the number of pairs in which this change was faster.

| Fixture | State | #897 | This change | Paired | Bun |
|---|---|---:|---:|---:|---:|
| vite-react | First install (32 pairs) | 243.2 / 252.7 | 237.1 / 245.7 | −7.2 (24/32) | |
| vite-react | First install | 237.1 / 245.4 | 233.2 / 242.1 | −4.1 (14/16) | 186.1 / 197.7 |
| vite-react | Fresh checkout | 40.4 / 48.9 | 40.9 / 44.1 | −0.1 (10/16) | 34.5 / 44.6 |
| vite-react | CI cold | 189.5 / 207.4 | 187.3 / 204.0 | −0.4 (9/16) | 160.9 / 285.3 |
| nest | First install | 219.9 / 227.2 | 217.8 / 229.0 | −2.8 (12/16) | 195.2 / 203.5 |
| nest | Fresh checkout | 27.6 / 30.0 | 27.6 / 31.5 | +0.1 (8/16) | 32.9 / 39.3 |
| nest | CI cold | 194.3 / 202.4 | 196.5 / 209.5 | +2.4 (7/16) | 193.2 / 214.8 |
| native-sharp | First install (32 pairs) | 90.3 / 97.1 | 89.0 / 92.6 | −1.2 (26/32) | |
| native-sharp | First install | 90.9 / 94.6 | 86.8 / 93.9 | −4.2 (12/16) | 62.7 / 64.4 |
| native-sharp | Fresh checkout | 18.4 / 19.9 | 18.5 / 25.7 | +0.1 (5/16) | 9.6 / 11.4 |
| native-sharp | CI cold | 57.5 / 66.0 | 56.7 / 59.5 | −0.9 (11/16) | 50.1 / 52.8 |
| T3 | First install (12 pairs) | 1,232.8 / 1,287.8 | 1,212.9 / 1,269.9 | −23.9 (7/12) | 1,401.7 / 1,447.7 |
| T3 | Fresh checkout (12 pairs) | 77.8 / 186.9 | 74.8 / 81.1 | −2.8 (10/12) | 207.8 / 216.6 |
| T3 | CI cold (12 pairs) | 1,152.8 / 1,622.9 | 1,154.5 / 1,214.0 | +9.5 (4/12) | 1,399.9 / 1,632.8 |

The gain follows the package count: vite-react has 63 packages, native-sharp 13. On a fresh checkout the linked directories already exist in the store, and a CI install reuses the metadata its lockfile's last install recorded, so neither runs the slow first read; those rows are within noise. T3's first installs vary by more than the change.

## Measured and not adopted

**Fetching the metadata while linking.** Before the scan was found, the metadata fetch was started as soon as the fetch phase ended, for the packages whose stored objects declare install scripts, so it would overlap linking:

| Fixture | First install, paired |
|---|---:|
| vite-react | +2.5 (6/16) |
| native-sharp | −2.7 (11/16) |
| nest | +2.9 (6/16) |
| T3 | +19.1 (5/12) |

The prefetch finished 3–6 ms after it started and the tail never waited for it, but the metadata came from the resolver's cache in about 1 ms, so there was nothing to hide. The scan it left in place was the cost.

**Extraction admission.** Extraction takes one of four permits. On vite-react's CI install, packages waited up to 114 ms for one.

- **Queue order.** Per-package traces of every fetch task, replayed in a simulator against the same four permits, predicted at most 1–3 ms from admitting the largest or most-files package first. On nest, native-sharp and T3 the install's last package is the streamed one, which no admission order moves.
- **Skipping the queue for small packages.** The simulator predicted 20–25 ms on vite-react from letting packages under 64 KB extract without a permit, but it cannot see disk contention. Measured on release builds, 12 pairs per state, CI cold:

  | Fixture | Under 64 KB bypass | Under 256 KB bypass |
  |---|---:|---:|
  | vite-react | +10.9 (3/12) | +26.8 (2/12) |
  | nest | +7.4 (4/12) | +8.7 (1/12) |
  | native-sharp | +2.4 (3/12) | +3.4 (3/12) |

  More concurrent extraction costs more than the waits it saves, as with 8 or 16 permits. T3's first install measured −40 and −109 ms on a loaded machine; that result was not reproduced.

## Limitations

All runs used one Apple Silicon machine (18 cores) with APFS. Registry traffic was replayed from local captures. On a route without the public npm history cache, such as a private registry, the blocked-set metadata may be requested from the registry after linking; that case was not measured.

## Artifacts

The adjacent `-summary.json` holds every scored run, the step marks of each traced run and the scan passes. The `-tools.tar.gz` archive contains the harness runner and A/B scripts, the replay proxy and TLS helper, the summary scripts, and the diagnostic patches used for the step marks, the scan passes and the prefetch.
