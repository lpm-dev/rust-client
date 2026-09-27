# Start-up, exit and lockfile parsing

In the no-op install states, `lpm` trails Bun by 2.5–5 ms on every fixture. This report attributes that time and makes two changes:

- **The update-check lookup runs during the command.** After every command, the update banner looked up the account's home directory, which on macOS takes about a millisecond. The lookup now starts when the command starts. `lpm run` with nothing to do takes 0.68 ms less.
- **TOML is parsed with toml 1.** Lockfiles parse about twice as fast, and up-to-date installs of T3 and vite-react are up to 1 ms faster. toml 1 writes the lockfiles byte for byte as toml 0.8 did.

## Where a no-op install goes

Markers in the #900 build, timed from process creation, in the harness's up-to-date state (medians of 16 runs, ms):

| Step | nest | vite-react | T3 |
|---|---:|---:|---:|
| Process creation to `main` (spawn, dyld, frameworks) | 5.52 | 5.90 | 5.83 |
| Color setup, thread start and argument parsing | 0.62 | 0.64 | 0.63 |
| Runtime and dispatch | 0.40 | 0.42 | 0.43 |
| Install setup | 0.73 | 0.81 | 0.87 |
| Install-state check, including Node's identity | 0.79 | 1.47 | 2.31 |
| Lockfile parse and package list | 0.42 | 0.52 | 0.70 |
| Rest of the command | 0.26 | 0.25 | 0.26 |
| `main` returning to the harness seeing the exit | 1.78 | 2.17 | 2.10 |
| **Wall, median** | **10.47** | **12.20** | **13.19** |

Each value is the median of its own row, so a column need not add up to its wall time.

The harness disables the update check. A CPU profile of 200 no-op nest installs (samply at 20 kHz, idle threads excluded) put about 4 ms of CPU in each run:

| Work | CPU per run, ms |
|---|---:|
| Install-state check: reading and hashing the manifest and lockfile | 0.68 |
| Node's identity for the dependency engine key | 0.67 |
| Parsing `lpm.lock` | 0.51 |
| Reading `package.json` | 0.43 |
| Workspace discovery (directory reads, canonicalization) | 0.44 |
| dyld | 0.32 |
| The allocator's collection at exit | 0.08 |

## The changes

- **Update check.** The banner reads its cache from the account home, which comes from the user database rather than `$HOME`. Resolving it now starts on a thread when a command starts, and the command joins it at the end. The cache file and the clock are still read at the end, so a long command such as `lpm dev` sees the cache as it is then. `lpm self-update` starts it too and reads the cache it just wrote; `internal-update-check`, which exits without a banner, doesn't start the thread.
- **toml 1.** `toml` moves from 0.8 to 1.1 and `toml_edit` from 0.22 to 0.25, the version the tree already pulls in for tests and proc macros. One TOML parser remains, and the binary is 165 KB smaller.
- **toml 1 compatibility.** toml 1 parses a string into `toml::Value` as a single value rather than a document, so reading a file that way failed. The port overrides that `lpm dev` saves are now read with `toml::from_str`. The self-update check of Cargo's install records builds its deserializer with `Deserializer::parse`. Three port-override tests caught the first.

## Results

**Lockfile parsing.** Each lockfile was parsed into LPM's lockfile model 100 times, bypassing the in-process parse cache (medians, ms). Written back out, every one is identical between toml 0.8 and toml 1.

| Lockfile | Size | toml 0.8 | toml 1 |
|---|---:|---:|---:|
| T3 | 206 KB | 1.454 | 0.795 |
| vite-react | 103 KB | 0.675 | 0.361 |
| complex-workspace-portable (test fixture) | 69 KB | 0.411 | 0.218 |
| native-sharp | 27 KB | 0.179 | 0.090 |
| nest | 27 KB | 0.174 | 0.087 |

**No-op installs.** Release builds of #900 and this change, and Bun, from a frozen HTTPS replay of each fixture's registry traffic, 16 balanced pairs per state; the harness disables the update check. Median / nearest-rank p95 in ms; the paired difference is the median over the pairs, with the number of pairs in which this change was faster.

| Fixture | State | #900 | This change | Paired | Bun |
|---|---|---:|---:|---:|---:|
| T3 | Up to date | 15.59 / 17.05 | 14.49 / 19.01 | −0.99 (12/16) | 11.30 / 13.67 |
| T3 | Installed, cache gone | 15.76 / 17.83 | 14.64 / 16.78 | −1.08 (13/16) | 12.03 / 14.84 |
| vite-react | Up to date | 13.14 / 14.12 | 12.78 / 14.94 | −0.38 (12/16) | 9.46 / 11.07 |
| vite-react | Installed, cache gone | 13.44 / 15.42 | 12.87 / 13.16 | −0.63 (16/16) | 9.40 / 11.61 |
| nest | Up to date | 11.62 / 12.65 | 11.28 / 12.62 | −0.30 (11/16) | 6.87 / 7.25 |
| nest | Installed, cache gone | 11.56 / 13.17 | 11.44 / 12.53 | −0.13 (12/16) | 7.16 / 7.84 |
| native-sharp | Up to date | 11.80 / 13.55 | 11.66 / 18.60 | −0.11 (9/16) | 6.60 / 6.94 |
| native-sharp | Installed, cache gone | 11.87 / 15.71 | 11.80 / 16.98 | −0.18 (11/16) | 6.65 / 14.33 |

The gain follows the lockfile's size. CI-warm and fresh-checkout installs, which also parse the lockfile, moved by −0.6 to −1.0 ms on T3 and by −0.9 and +0.9 ms on vite-react, within their noise.

**Update check.** Commands run from a shell in the nest project, with a fresh update cache (no background refresh), alternating the two builds for 300 rounds each (medians, ms):

| Command | Update check | #900 | This change | Paired |
|---|---|---:|---:|---:|
| `lpm run noop` | on | 9.30 | 8.63 | −0.68 (292/300) |
| `lpm store path` | on | 6.72 | 6.80 | +0.06 (133/300) |
| `lpm --version` | on | 4.94 | 4.94 | +0.00 (148/300) |
| `lpm run noop` | off | 8.51 | 8.51 | +0.01 (148/300) |
| `lpm store path` | off | 5.86 | 5.90 | +0.00 (148/300) |
| `lpm --version` | off | 4.25 | 4.24 | −0.02 (166/300) |

`lpm store path` ends before the lookup does, so it waits for it as before. `--version` prints its notice at once and keeps the synchronous lookup.

## Measured and not adopted

- **Loading the system frameworks on demand.** The binary links CoreFoundation, Security, CoreServices, LocalAuthentication, Foundation and the Objective-C runtime, and dyld loads and initializes them all at launch. An empty C program takes 0.93 ms and 11.8 million instructions; linked against the same libraries, 1.8 ms and 25.3 million, most of it CoreFoundation. `lpm` reaches `main` 4.8 ms after process creation, against 2.4 ms for that C program. CoreFoundation comes in through chrono's local time zone, the keychain (keyring, security-framework), certificate trust, Touch ID and FSEvents. Avoiding it at launch means loading each of those on demand, a change across several crates, so it is not part of this change.
- **The allocator's collection at exit.** 0.08 ms of CPU per run.

## What remains

On a no-op install, computing Node's identity (0.67 ms of CPU), reading `package.json` into the full model (0.43 ms) and workspace discovery (0.44 ms) are the largest remaining steps inside the command.

## Limitations

All runs used one Apple Silicon machine (18 cores) with APFS. The no-op installs came from the harness, whose Node parent raises the open-file limit and which disables the update check; the command timings came from a shell. Lockfile parse timings exclude reading the file.

## Artifacts

The adjacent `-summary.json` holds the scored installs, the paired command timings, every marker run, the framework measurements and the parse comparison. The `-tools.tar.gz` archive contains the marker patch, the samply loop driver and aggregation script, the lockfile comparison crate, the paired timing script, the framework test programs and the harness scripts.
