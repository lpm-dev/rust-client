# Parse the lockfile once

A single install read `lpm.lock` from several independent phases, and each read parsed and validated the whole file again. An up-to-date T3 install parsed it twice, and a warm install five times. Warm installs also indexed the installed tree twice. This change parses each distinct lockfile text once per process and builds the index once per install. T3 warm installs are 10.6 ms faster, and up-to-date installs 1.4 ms.

## Where the time went

Sampling profiles of T3, whose `lpm.lock` is 206 KB, showed:

- **Up to date:** the install-state check parsed the lockfile only to learn its path, and the lockfile fast path parsed it again.
- **Warm installs:** validation, drift detection, plan selection, the fast path and the install-hash write each parsed it.
- **Index builds:** the store baseline index was built once before patching and again for the script-trust check, which walks every package's link metadata.

Unit costs on that lockfile, median:

| Operation | Time |
|---|---:|
| Read the file | 36 µs |
| Compare its text | 6 µs |
| Parse and validate | 1.52 ms |
| Clone a parsed lockfile | 32 µs |
| Serialize with `to_toml` | 1.44 ms |

## The change

**A process-wide parse cache in `lpm-lockfile`.** `Lockfile::from_toml` looks up the exact text among the four most recently parsed texts and returns a clone of the stored result. It parses only on a miss. Parsing and validating depend on nothing but the text, so keying by the full text needs no invalidation: an edited file is always parsed afresh. Failed parses are not kept. New `from_toml_shared` and `read_shared` return the shared value without cloning, and the install's shared-read fallbacks use them.

Seeding the cache when LPM writes a lockfile was considered and left out. It would be valid only if parsing the written text always reproduced the in-memory value, and the code does not guarantee that round trip.

**One baseline index per install.** The script-trust check now reuses the index the install built for patching. It rebuilds the index only when an applied patch refreshed the links, because refreshed links can replace the recorded entries. This covers the online and offline install paths.

**Counters.** Timing detail (`LPM_TIMING_DETAIL`) reports `lockfile.parse_count` and `lockfile.reuse_count`, and full installs report `tail.baseline_index_build_count`.

On T3 with `CI` set:

- **Up-to-date install:** 1 parse and 1 reuse, down from 2 parses.
- **Warm install:** 1 parse and 4 reuses, down from 5 parses. The reported counters cover the first four reads, because the install-hash write comes after the report. It builds 1 index instead of 2.

## Results

Release builds of #891 and this change, with `CI` set so every run takes the install pipeline. Each project was installed once from the live registry, then copied per variant. Runs alternate between the two builds, 40 pairs for up-to-date states and 30 otherwise. The table shows wall-clock medians in milliseconds, with the paired median difference and how many rounds this change won. A browser was running, so the internal totals from `--timing` are also given.

| State | #891 | This change | Paired | Internal total |
|---|---:|---:|---:|---:|
| T3 up to date | 13.1 | 11.7 | −1.4 (40/40) | 4 → 3 |
| T3 package cache removed | 13.3 | 11.9 | −1.5 (40/40) | 4 → 3 |
| T3 `node_modules` removed, `.lpm` kept | 65.0 | 54.1 | −10.7 (29/30) | 50 → 40 |
| T3 CI-warm (`node_modules` and `.lpm` removed) | 78.3 | 67.5 | −10.6 (30/30) | 62 → 53.5 |
| vite-react CI-warm | 45.8 | 40.6 | −5.3 (29/30) | 33 → 28 |
| T3 fresh checkout, 24 pairs | 87.0 | 84.2 | −4.0 (22/24) | 70.5 → 67.5 |

The saving grows with the lockfile, since each avoided parse costs time proportional to its size.

## Not changed

A warm install still serializes the lockfile once with `to_toml` for the install hash. The hash is taken over the normalized projection, so formatting-only edits keep an install up to date, and reusing the raw text would change that behavior.

Upgrading `toml` from 0.8 to 0.9 parses the same file about 40% faster. It is a separate change.

## Artifacts

The adjacent `-summary.json` holds the medians, and the `-tools.tar.gz` archive contains the benchmark scripts and raw paired samples.
