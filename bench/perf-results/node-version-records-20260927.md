# Recorded Node versions

Installs, `lpm run`, `lpm dev` and tool commands run `node --version` to check `engines.node`, and each probe takes 10–15 ms. The install hash kept the result per project, so a new checkout, a CI job with a warm cache and every script run probed again. The versions that real Node binaries report are now recorded in the LPM home, keyed by the fingerprint the install hash already uses. On warm lockfile installs, native-sharp and vite-react are 12–13 ms faster and nest about 6 ms; `lpm run` in a project with `engines.node` takes 13 ms instead of 27.

## The change

- **What is recorded.** After a probe, the version of a real Node binary is written under `cache/metadata/node-versions` in the LPM home, named by the executable's fingerprint: its canonical path, device, inode, size, modification time and mode, plus the version files and version-manager settings that could select another version. A later command with the same fingerprint uses the recorded version instead of probing.
- **What is not.** Launchers, such as version-manager shims, report the version they select and are still probed every time. A record that is missing, unreadable or not a valid version is ignored.
- **Refreshing.** `lpm install --force` probes again and replaces the record. `lpm cache clean metadata` removes all records.
- **Off the critical path.** The record is written on a background thread and joined when the command's Node resolver is dropped. Written inline, the record cost native-sharp's CI-cold install 2.8 ms (2/16 pairs faster): with an empty cache, it creates three directories and a file on the path to the first download.

## Results

Release builds of #896 (dde46b502) and this change, and Bun, installed each fixture from a frozen HTTPS replay of its registry traffic on one machine, 16 balanced pairs per state. The system Node was a real Mach-O binary installed by `n`. Values are median / nearest-rank p95 in ms; the paired difference is the median over the pairs, with the number of pairs in which this change was faster.

| Fixture | State | #896 | This change | Paired | Bun |
|---|---|---:|---:|---:|---:|
| nest | Fresh checkout | 35.0 / 38.0 | 28.9 / 34.8 | −6.0 (16/16) | 33.8 / 39.8 |
| nest | CI warm | 31.9 / 36.1 | 25.2 / 35.2 | −6.5 (14/16) | 31.8 / 34.7 |
| vite-react | Fresh checkout | 54.4 / 58.5 | 46.1 / 63.3 | −6.7 (13/16) | 46.5 / 123.1 |
| vite-react | CI warm | 46.1 / 63.3 | 33.5 / 44.3 | −12.7 (16/16) | 40.1 / 113.9 |
| native-sharp | Fresh checkout | 33.5 / 38.9 | 21.3 / 26.0 | −12.3 (16/16) | 11.9 / 18.8 |
| native-sharp | CI warm | 32.1 / 40.7 | 18.3 / 22.1 | −12.8 (16/16) | 10.8 / 15.6 |

The states without a reusable record are unchanged. CI-cold installs start with an empty cache: nest +0.8 (7/16), native-sharp +0.1 (7/16), and vite-react −0.6 in a separate 32-pair run (16/32; +2.1 in a 16-pair run whose p95 exceeded 270 ms for all three tools). Up-to-date installs already reused the install hash's version: every fixture within ±0.2 ms.

**`lpm run`.** A project declaring `engines.node` with a script that does not start Node, run 30 times per build in alternating order after one warm-up run:

| Median, ms | #896 | This change | Paired |
|---|---:|---:|---:|
| `lpm run` | 27.4 | 13.1 | −14.4 (30/30) |

## Limitations

All runs used one Apple Silicon machine (18 cores) with APFS. The fixtures' registry traffic was replayed locally. Version managers that install shims rather than binaries (volta, asdf, mise) gain nothing, by design.

## Artifacts

The adjacent `-summary.json` holds every scored run. The `-tools.tar.gz` archive contains the A/B driver (`run-ab.mjs`), the harness runner, the replay proxy and TLS helper, the `lpm run` benchmark (`runbench.py`) and the summary script.
