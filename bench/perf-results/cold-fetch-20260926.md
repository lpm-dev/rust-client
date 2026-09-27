# Cold installs of small projects

Against #895, cold installs of three small fixtures spent time in places that did not depend on the network: a package extracted serially on the critical path, `node --version` run before any download started, and a signing secret created and synced at the end of a first install. This change removes each from the critical path. nest's CI install is 50 ms faster and within 2 ms of Bun's; first installs are 14–25 ms faster on all three fixtures.

## The changes

- **Every streamed package gets the parallel file writers.** An install streams one package, its largest, from the network into extraction. It used the pipelined extractor (gzip decoding on its own thread, parallel file writers) only when it unpacked to 8 MiB or more. nest's rxjs (2,277 files, 4.5 MB) extracted serially and set the length of nest's CI install.
- **The engine check runs during the fetch when it cannot change it.** The first dependency engine check runs `node --version`, about 10 ms. When no decision can remove a package and the fetch writes only to the virtual store, the check now runs alongside the downloads. A mismatch still fails before the project changes, and stops the downloads rather than waiting for them.
- **Downloads start while Node is probed.** Under engine-strict, a mismatch skips an optional package that declares `engines.node`, so the check settles the fetch plan first. A lockfile install now downloads the packages without an engine requirement during the probe, under the conditions that already allow prefetching during resolution.
- **The fetch overlap streams the install's largest download** when that package is one of its own, and skips stored and foreign-platform packages without starting a task.
- **The build-state signing secret is created in the background.** On a fresh LPM home, creating it (a write, a file sync and a directory sync) delayed the end of the first install by 16–19 ms.

## Results

Release builds of #895 (5ea1b5e11) and this change, and Bun, installed each fixture from a frozen HTTPS replay of its registry traffic on one machine. No request reached the upstream registry while runs were scored, and every archived tarball matched its integrity before and after scoring. Runs rotated between variants in balanced order. Values are median / nearest-rank p95 in ms over 16 runs; the paired difference is the median over the pairs, with the number of pairs in which this change was faster.

The six states are those of the research harness: *first install* (nothing cached), *CI cold* (lockfile only), *CI warm* (lockfile and warm store), *fresh checkout* (warm store, no lockfile), and the two no-op states.

**nest** (33 tarballs):

| State | #895 | This change | Paired | Bun |
|---|---:|---:|---:|---:|
| CI cold | 243.0 / 251.3 | 195.2 / 204.2 | −50.3 (16/16) | 191.8 / 217.7 |
| First install | 231.5 / 262.7 | 209.4 / 217.3 | −21.2 (16/16) | 191.7 / 202.2 |
| Fresh checkout | 43.1 / 47.8 | 35.4 / 38.6 | −7.1 (16/16) | 34.1 / 42.3 |
| CI warm | 37.4 / 42.3 | 31.6 / 32.3 | −5.9 (16/16) | 38.0 / 43.4 |

**vite-react** (63 tarballs). The 16-run pass for this fixture was disturbed (p95 above 500 ms for both LPM builds in CI cold); the three lockfile and fresh-checkout states come from a separate 32-run pass:

| State | #895 | This change | Paired | Bun |
|---|---:|---:|---:|---:|
| CI cold | 194.9 / 225.3 | 182.2 / 198.2 | −13.1 (27/32) | 150.8 / 159.2 |
| First install | 262.8 / 294.8 | 236.5 / 259.0 | −24.6 (16/16) | 198.5 / 322.7 |
| Fresh checkout | 52.5 / 67.2 | 52.0 / 57.8 | −0.5 (19/32) | 35.0 / 46.9 |
| CI warm | 44.8 / 48.4 | 45.0 / 56.6 | +0.5 (12/32) | 32.0 / 41.0 |

**native-sharp** (13 tarballs):

| State | #895 | This change | Paired | Bun |
|---|---:|---:|---:|---:|
| CI cold | 73.8 / 76.1 | 58.9 / 66.7 | −14.3 (16/16) | 52.7 / 76.0 |
| First install | 104.3 / 115.2 | 89.9 / 108.9 | −14.3 (15/16) | 64.0 / 67.3 |
| Fresh checkout | 31.4 / 37.3 | 31.8 / 36.8 | −0.0 (9/16) | 10.0 / 11.4 |
| CI warm | 29.2 / 30.9 | 29.2 / 31.0 | +0.0 (8/16) | 8.9 / 9.6 |

In the two no-op states every paired difference is within ±0.4 ms: those installs return before any code this change touches.

## Measured and not adopted

- **More extraction permits.** 8 and 16 permits instead of 4 made vite-react's CI install slower (+13.2 and +27.6 ms, 0/12 pairs faster).
- **More file writers for rxjs.** With 0, 2 and 4 writers rxjs extracted in 165–188 ms; the gain came from the pipelined decoder.
- **Streaming the overlap's own largest package.** vite-react's largest download, `@esbuild/darwin-arm64`, declares engines and so downloads in the fetch phase. An overlap that took the streaming lane for its own, smaller largest package left esbuild without it and cut vite-react's CI gain from 13 ms to 6.5 ms. The overlap now streams only the install's largest download.
- **Validating stored objects in the overlap.** The overlap first checked each package with the store's reuse validation, which the fetch phase repeats; on warm lockfile installs this cost vite-react about 1 ms (2/16 pairs faster). It now checks only that the object exists.

## What remains

From `--timing` diagnostics of this change's runs:

- **Node's version, on warm lockfile installs.** `node --version` takes 10–15 ms. On a CI-warm project with no install hash it is the main difference from Bun: 14 of native-sharp's 17 ms of timed install work and 13 of vite-react's 29. On cold installs it now overlaps the downloads. The install hash already remembers the version per project; remembering it per Node binary, keyed by the same identity, would cover new checkouts.
- **Extraction queueing on vite-react.** In its CI install, one package waited 114 ms for one of the four extraction permits. More permits were slower (above); ordering the queue by size is untested.
- **Resolution on first installs.** 22–24 ms on nest and native-sharp and 86 ms on vite-react, against the replayed registry.
- **Process start and exit.** About 9 ms pass before an install's timer starts and 2.5 ms after it ends; `lpm --version` takes 5.6 ms, Bun's 3.1 ms.

## Limitations

All runs used one Apple Silicon machine (18 cores) with APFS. Registry traffic was replayed from local captures, so network latency is not represented. Bun was run with `--ignore-scripts`.

## Artifacts

The adjacent `-summary.json` holds every scored run. The `-tools.tar.gz` archive contains the A/B driver (`run-ab.mjs`), the harness runner, the replay proxy and TLS helper, and the summary script.
