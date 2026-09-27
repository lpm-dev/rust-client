# Open-file limit at startup

macOS starts a process with a soft limit of 256 open files and, usually, no hard limit. That is what `lpm` gets when it runs from Terminal. Extraction sizes its parallel file writers from the soft limit, and at 256 it starts none, so every package extracted on one thread. `lpm` now raises its soft limit to the hard limit at startup, as Node, Bun and Go do. From a soft limit of 256, T3's installs are 118–128 ms faster and nest's 35 ms, and they now match installs started with a raised limit.

## Why earlier measurements missed it

The benchmark harness starts each install from Node, and Node raises its own soft limit to the maximum at startup, so its children inherit a high limit. Every earlier report in this series measured `lpm` with that raised limit, and so does any `lpm` started from VS Code's terminal.

Measured before this change, with the #898 build started under the harness's limit and under `ulimit -n 256` (median ms, paired difference, pairs faster at 256):

| Fixture | State | Raised limit | 256 | Paired |
|---|---|---:|---:|---:|
| T3 | First install | 1,192.2 | 1,311.5 | +118.8 (1/12) |
| T3 | CI cold | 1,138.6 | 1,269.0 | +140.2 (0/12) |
| nest | First install | 223.0 | 256.1 | +33.9 (0/12) |
| nest | CI cold | 198.1 | 232.6 | +34.8 (0/12) |
| vite-react | First install | 240.6 | 250.5 | +10.3 (1/12) |
| vite-react | CI cold | 191.7 | 189.1 | −2.3 (8/12) |

## The change

- **At startup,** `lpm` raises its soft limit on open files to the hard limit. On macOS it also caps the soft limit at `kern.maxfilesperproc`, the most macOS accepts, since the hard limit there is usually unlimited. A failure leaves the limit unchanged.
- **Children inherit the raised limit,** as they do under npm and Bun. Sandboxed scripts keep the sandbox's own cap of 4,096.
- **Windows** has no such limit and is unchanged.

## Results

Release builds of #898 and this change installed each fixture from a frozen HTTPS replay of its registry traffic on one machine, each started from a shell that set the soft limit to 256 and left the hard limit unlimited. The same build of this change also ran with the harness's raised limit, and Bun ran as a reference. Runs rotated between variants in balanced order; 16 pairs per state, 12 for T3. Values are median / nearest-rank p95 in ms. The paired difference is the median over the pairs, with the number of pairs in which the second variant was faster.

| Fixture | State | #898 at 256 | This change at 256 | Paired | This change, raised limit | At 256 vs raised | Bun |
|---|---|---:|---:|---:|---:|---:|---:|
| T3 | First install | 1,329.2 / 1,546.0 | 1,215.5 / 1,447.3 | −117.7 (12/12) | 1,232.5 / 1,441.9 | −16.5 (8/12) | 1,409.2 / 1,737.8 |
| T3 | Fresh checkout | 80.9 / 189.7 | 79.0 / 110.1 | −1.4 (8/12) | 79.6 / 84.6 | −0.0 (6/12) | 210.7 / 304.3 |
| T3 | CI cold | 1,323.0 / 1,504.0 | 1,189.3 / 1,365.7 | −128.4 (12/12) | 1,164.5 / 1,361.9 | +15.0 (3/12) | 1,422.6 / 1,631.3 |
| nest | First install | 257.9 / 267.3 | 222.8 / 240.7 | −34.5 (16/16) | 224.7 / 237.4 | −2.1 (10/16) | 198.9 / 223.7 |
| nest | Fresh checkout | 30.4 / 33.8 | 30.6 / 31.9 | +0.1 (7/16) | 30.5 / 32.6 | +0.0 (8/16) | 33.8 / 41.7 |
| nest | CI cold | 232.5 / 248.3 | 197.1 / 203.3 | −35.1 (16/16) | 200.3 / 207.9 | −4.5 (11/16) | 195.7 / 218.6 |
| vite-react | First install | 252.5 / 259.3 | 241.5 / 253.2 | −9.7 (13/16) | 241.5 / 261.2 | +1.3 (5/16) | 185.1 / 196.4 |
| vite-react | Fresh checkout | 44.8 / 52.7 | 44.3 / 51.3 | +0.1 (8/16) | 46.4 / 48.7 | −1.2 (10/16) | 35.8 / 39.8 |
| vite-react | CI cold | 192.0 / 221.0 | 194.4 / 201.6 | +0.4 (8/16) | 193.0 / 200.3 | +1.0 (7/16) | 168.0 / 185.7 |
| native-sharp | First install | 91.5 / 97.5 | 92.2 / 97.2 | +0.3 (7/16) | 92.3 / 132.1 | +0.4 (7/16) | 63.4 / 66.6 |
| native-sharp | Fresh checkout | 21.6 / 22.9 | 21.8 / 24.0 | +0.1 (6/16) | 21.8 / 23.2 | −0.1 (9/16) | 9.9 / 11.1 |
| native-sharp | CI cold | 60.4 / 62.3 | 60.3 / 64.6 | +0.4 (8/16) | 60.3 / 64.2 | −0.3 (9/16) | 51.2 / 53.3 |

- **The gain follows the packages with many files.** The writers start only after a package's first 256 files. T3's `next` has 8,531 files and nest's `rxjs` 2,277; native-sharp has no package that large.
- **At 256 and at the raised limit, this change is within noise** in every state, so an install from Terminal now behaves like the ones measured in earlier reports.
- **Fresh checkouts don't extract,** and are unchanged.

## Limitations

All runs used one Apple Silicon machine (18 cores) with APFS, and the registry traffic was replayed from local captures. On Linux the usual default soft limit is 1,024, which already allows three of extraction's four writer pools; the change was not measured there.

## Artifacts

The adjacent `-summary.json` holds every scored run, both comparisons and the measurement before the change. The `-tools.tar.gz` archive contains the harness runner and A/B scripts, the replay proxy and TLS helper, the limit wrappers and the summary scripts.
