# Source analysis precision report

## Result

The scan covered 1,000 frozen npm package versions. It executed no package code.
Normal audit and install output now separates API capabilities from security findings.
Explicit capability policies keep their existing severity levels.

The review covered all 132 baseline high source package/rule pairs and 16 added pairs.
It found 10 unsupported matches across nine packages.
Those matches came from local functions, method declarations, or a closed bundled loader.

The candidate also removed 12 shell tags inferred from imports or unrelated aliases.
Those removals are not proof that the packages cannot run a shell.
Runtime options and downstream helpers can select a shell, especially in Execa, Tinyexec, Foreground Child, and Open.

| Capability | Baseline packages | Candidate packages |
| --- | ---: | ---: |
| Child processes | 41 | 33 |
| Shell execution | 17 | 11 |
| Dynamic module loading | 52 | 60 |
| Runtime code generation or evaluation | 22 | 22 |
| Critical obfuscation or protestware | 0 | 0 |

The candidate adds six shell detections and 10 dynamic loader detections.
Examples include explicit shell calls in Esbuild, Rollup, Webpack, and Detect Libc.
Computed imports in Sharp, Lightning CSS, and Regexpu Core also remain visible.
All other source, supply-chain, and manifest tag counts are unchanged.
Overall, 37 packages have changed tags.

The 126 remaining high source capabilities retain their policy severity.
They no longer contribute to security warning counts. This presentation change is separate from detector accuracy.
The review does not assign benign or malicious verdicts to whole packages.

## Reproduction and review data

- [Frozen package manifest](top-1000.json): ranking source, exact versions, archive URLs, and integrity digests.
- [Package comparisons](results.jsonl): tags and coverage for every package, with additions and removals.
- [Aggregate counts](results.summary.json): machine-readable totals.
- [Reviewed findings](reviewed-findings.json): all 148 high source package/rule pairs, with source evidence and review reasons.
- [Instructions and JSON migration](README.md): reproduction commands, output fields, and limits.
- [Finding ledger](findings.md): regression coverage and resolution commits.

The manifest SHA-256 is `2d0bb511bd6c5c90f2d65e6bfb3ef280b1bb7712afcec4c2746f503bd8043ed6`.
The ranking uses the June 8, 2026 npm-high-impact snapshot.
Package versions were frozen from npm metadata on September 15, 2026.
This is not a current download ranking.

## Coverage

All 1,000 archives passed integrity verification and extraction.
Both scanners inspected 25,730 source files and 137,346,796 bytes.
Neither scanner increased the scan limits or removed directory exclusions.

Both runs report 997 packages complete within the configured scan rules.
Fifty-five packages have no eligible source files, including declaration-only packages.
Three packages report partial coverage:

| Package | Coverage limit |
| --- | --- |
| `jsdom` | Oversized source sampling and incomplete syntax parsing |
| `tiny-invariant` | Incomplete syntax parsing |
| `istanbul-reports` | Incomplete syntax parsing |

Complete coverage means the configured scan completed. It does not prove that every behavior was detected.
Source samples, generated code, custom wrappers, and values passed between modules remain limits of static analysis.

## Tuning and validation

A deterministic package-family split assigned 769 packages to tuning and 231 to validation.
Scopes and selected related names stayed together. Embedded dependencies can still cross the split.

The first validation candidate missed a `createRequire` assignment after variable declaration in `import-in-the-middle`.
A failing regression test reproduced this miss. Bounded assignment propagation restored the detection.
The final validation scan is therefore a rerun after a validation-driven correction.
It is not an independent estimate of final accuracy.

A final code review also found that execution-library helpers could produce process tags.
Regression tests now distinguish Execa's `parseCommand` and ShellJS's `which` from execution APIs.
The correction preserves Execa entry points and ShellJS `exec`.
Fixed string expressions such as `require('u' + 'rl')` also remain static.

Twelve permanent source controls cover benign syntax, execution capabilities, and synthetic threat patterns.
They include obfuscation and locale-dependent termination. Existing source and policy tests remain active.
These controls cannot establish recall for arbitrary malicious packages.

## Performance

Measurements used preserved release binaries on an Apple M5 Pro with 48 GiB RAM and macOS 26.6.2.
Both binaries used Rust 1.94.0 and the same build flags. No Cargo build or test ran during measurement.
The [measurement data](performance.json) records binary hashes, individual samples, and comparison thresholds.

The source benchmark scanned all 1,000 packages with four Rayon threads.
Each binary received two warmups and seven measured runs. The execution order alternated.
Median scanner time was 1.801 seconds for the baseline and 1.799 seconds for the candidate.
Median process wall time was 1.849 and 1.839 seconds.
These results show similar warm scan time, with variation between runs.

Median peak resident memory increased from 67.5 to 82.2 MiB, about 14.6 MiB or 21.7%.
This cost includes semantic bindings and source evidence. The precision and evidence improvements justify that measured increase.
The baseline binary had no evidence instrumentation. A separate comparison confirmed that instrumentation preserved all baseline tags and coverage.

The install benchmark used `run-install-readiness.mjs`, with seven alternating pairs per configuration and install state.
Each pair used isolated project, home, store, and cache directories. Cold installs seeded each corresponding warm and already-current state.
The fixture contained frozen local archives of Prettier, Core JS, Commander, JSON5, and Diff, without runtime dependencies.
Core JS's postinstall script remained blocked in all 56 cold and warm installs. The other 28 runs exited as already current.

| Source scan | Install state | Baseline median | Candidate median | Baseline peak RSS | Candidate peak RSS |
| --- | --- | ---: | ---: | ---: | ---: |
| Enabled | Cold | 702 ms | 737 ms | 81.8 MiB | 88.1 MiB |
| Enabled | Warm | 57 ms | 56 ms | 35.2 MiB | 35.1 MiB |
| Enabled | Already current | 29 ms | 28 ms | 22.3 MiB | 22.3 MiB |
| Disabled | Cold | 529 ms | 528 ms | 54.2 MiB | 55.8 MiB |
| Disabled | Warm | 55 ms | 56 ms | 35.1 MiB | 35.1 MiB |
| Disabled | Already current | 30 ms | 29 ms | 22.3 MiB | 22.3 MiB |

Peak RSS values are medians of each process's maximum resident memory.
With source analysis enabled, the cold median increased by 35 ms, or 5.0%.
The harness passed its existing combined percentage and absolute thresholds for wall time and memory.
This result does not establish an install speed improvement.

Cold installs still contacted npm for lifecycle metadata, despite the local archives. Cold wall times therefore include network variation.
Their baseline and candidate p95 values were 1,408 and 1,368 ms with source analysis enabled.
Cold means an empty LPM store, not an empty operating-system page cache.
Local archive analysis occurs during setup, so the fetch-stage scan counter cannot isolate its duration.
A separate diagnostic run confirmed five analysis sidecars when enabled and none when disabled.

## Validation checks

The final macOS workspace gate passed all 14,347 selected tests. It skipped 26 tests under the repository's default filter.
Workspace builds and Clippy completed with zero warnings on Rust 1.94.0.
The corpus helper suite passed all 11 tests. Formatting, dependency policy, and CI helper checks also passed.

The tests cover source evidence, cache and scanner parity, human and JSON output, and explicit capability policies.
Every verified detector correction started with a failing regression test.
Earlier runs exposed unrelated timing failures under build load. The final complete workspace run passed those tests without source changes.

## Recommendation

Keep capabilities separate from security warnings, with explicit policies for teams that restrict APIs.
Require source evidence and a failing regression before changing a detector.
Avoid package-name allowlists and blanket suppression of minified output.

Keep this frozen corpus as a regression set. Use fresh packages for the next independent validation set.
Report coverage gaps and review uncertainty alongside tag counts.
A download ranking alone cannot establish a false-positive rate or prove that a package is safe.
