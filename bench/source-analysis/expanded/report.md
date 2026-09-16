# Expanded source-analysis validation

## Result

This study scanned 12,000 distinct npm package names and five historical compromised versions without executing package code.
It includes the original 1,000 packages, 9,000 additional packages, and a replacement independent validation set of 2,000 packages.

The detector removes a confirmed critical false positive in `js-beautify@2.0.3` and distinguishes local methods and classes from runtime evaluators.
It also recognizes evaluator aliases, indirect calls, and supported Node VM APIs.
Normal API capabilities remain separate from security warnings. Explicit capability policies retain their severity rules.

| Dataset | Packages | Baseline eval capability | Final eval capability | Baseline critical source alerts | Final critical source alerts |
| --- | ---: | ---: | ---: | ---: | ---: |
| Original regression corpus | 1,000 | 22 | 46 | 0 | 0 |
| Expanded corpus, including initial validation | 9,000 | 337 | 583 | 1 | 0 |
| Fresh independent validation | 2,000 | 124 | 167 | 0 | 0 |
| Historical compromised controls | 5 | 0 | 0 | 2 | 2 |

The added capabilities often describe legitimate polyfills, template compilers, development tools, or shipped test code.
For example, `Function('return this')` still generates code, even when its body is constant.
An added capability is not evidence of a malicious package.
Explicit capability policies can now reject evaluator aliases or VM use that the previous detector missed.
Cached source results refresh under schema version 8.

Nine implementation and acquisition findings were verified and fixed. None remain pending.
The [finding ledger](findings.md) records evidence, regression tests, and resolution commits.

## Validation protocol

The original expansion reserved 2,000 packages from 1,333 families before examining scanner results.
Those families did not overlap the 7,000 tuning packages or the original corpus.
The [initial freeze](initial-freeze.json) records the candidate binary and source hashes.

Initial validation exposed a critical false positive in `js-beautify`.
Its decoder tests contain quoted obfuscator examples. The old detector counted those names as executable obfuscation evidence.
A failing regression reproduced the warning. The correction uses executable syntax positions while retaining encoded-string signals.

That correction makes the initial validation set tuning evidence.
To preserve independent validation, the study reserved another 2,000 packages from families absent from all first 10,000 packages.
The [final freeze](final-freeze.json) precedes both scans of this fresh set.
No detector changes followed those scans.

Fresh validation added 43 supported evaluator capabilities, removed no evaluator capabilities, and produced no critical source alerts.
Two informational obfuscation tags disappeared where quoted or embedded code supplied decoder patterns.
Those removals do not prove that the embedded code cannot execute later.

The family split reduces related-package overlap. Bundled third-party code can still cross dataset boundaries.
Popularity does not label a package benign, and these results do not establish a population false-positive rate.

## Reviewed changes

Review covered all 332 changed package result rows and all critical alerts. Coverage measurements record the remaining scan gaps.
It did not establish ground-truth labels for every unchanged finding or inspect every source file manually.

Five packages lost evaluator matches supported only by local methods or classes: `effect`, `math-expression-evaluator`, `pprof-format`, `@launchdarkly/js-sdk-common`, and `@pulumi/aws`.
Three further removals involve delegation or browser callbacks: `@wdio/local-runner`, `react-virtualized`, and `expect-playwright`.
These three are not confirmed examples of packages without evaluation capability.

`@wdio/repl` retains its tag through `vm.runInContext`.
`whatwg-url` retains conservative evidence for an unresolved object's `eval` call.
Fengari Interop retains its tag, with evidence pointing to an actual `Function(...)` call instead of a borrowed generic `apply` helper.

The quoted-example correction removes the critical warning in `js-beautify`. Informational patterns remain.
It also removes informational obfuscation tags from embedded code in `@effect/platform`, `react-error-overlay`, `express-graphql`, and `heic2any`.
The scanner does not recursively analyze arbitrary strings as programs.

See [reviewed changes](reviewed-changes.json) for bounded evidence and review reasons.

## Historical and synthetic controls

The historical controls pin five incident samples from a specific DataDog archive commit.
The acquisition harness verifies archive hashes, package identities, paths, file types, and size limits.
Samples stay outside public source control and are never executed.

| Historical version | Critical source result | Limit |
| --- | --- | --- |
| `debug@4.4.2` | Obfuscation retained | A heuristic warning does not identify the full attack. |
| `node-ipc@12.0.1` | Obfuscation retained | A heuristic warning does not identify the full attack. |
| `@solana/web3.js@1.95.7` | No critical source warning | Capabilities and informational tags do not identify the compromise. |
| `xrpl@4.2.1` | No critical source warning | Capabilities and informational tags do not identify the compromise. |
| `@ctrl/tinycolor@4.1.1` | No critical source warning | Oversized source is sampled; coverage is partial. |

Every historical tag is unchanged from the baseline.
This small, deliberately selected set is not a malware recall estimate.
It demonstrates why a clean source scan cannot prove package safety.

The permanent source control corpus grew from 12 to 50 cases.
It covers benign lookalikes, evaluator aliases, VM APIs, receiver mutation, borrowed invocation helpers, quoted examples, obfuscation, and protestware patterns.
An installation workflow test checks cache refresh, audit JSON, capability evidence, and explicit policy exits together.

## Coverage and skipped files

Both scanners report identical coverage for every package.
Scan limits and directory exclusions are unchanged.

| Dataset | Fully scanned files | Scanned bytes | Unparsed files | Packages with partial coverage | Packages with no fully scanned source |
| --- | ---: | ---: | ---: | ---: | ---: |
| Original 1,000 | 25,730 | 137,346,796 | 9 | 3 | 55 |
| Expanded 9,000 | 291,225 | 2,531,729,633 | 1,625 | 188 | 802 |
| Fresh validation 2,000 | 96,140 | 751,215,600 | 383 | 63 | 69 |

There were no package acquisition failures after resolving the case-sensitive extraction requirement and no reported source input/read gaps.
Unparsed source retains conservative pattern matching. Unsupported syntax prevents complete parser coverage.
Oversized sources receive bounded samples. File and byte limits also produce partial coverage.

The expanded archives contain 799,852 regular files, of which 326,675 meet the source-file selection rules.
The fresh validation archives contain 308,099 regular files, of which 121,626 meet those rules.
Maps, declaration files, other extensions, hidden paths, and excluded directories account for the remaining files.
Eligible files that are not fully scanned include oversized sampled files and files beyond package limits.
They must not be counted as fully inspected or merged with parser failures.

[File inventory](file-inventory.json) gives exclusion counts.
[Coverage details](coverage.json) list every partial package and its recorded oversized-file evidence.
Evidence lists are bounded and do not enumerate every skipped or sampled file.

## Reproducibility

- [Expanded manifest](../expanded-9000.json): exact versions and integrity digests for the additional 9,000 packages.
- [Fresh validation manifest](../fresh-validation-2000.json): 2,000 packages from previously unseen families.
- [Historical manifest](../historical-controls.json): pinned archive hashes and incident provenance.
- [Expanded comparison](expanded-results.jsonl), [original regression comparison](original-results.jsonl), and [independent validation comparison](validation-results.jsonl).
- [Initial validation comparison](initial-validation-results.jsonl): preserves the result that exposed the false positive.
- [Historical comparison](historical-results.jsonl), [aggregate counts](summary.json), and [validation protocol](validation-protocol.json).

The baseline is main commit `32e483d0`. The final detector is frozen at `9689df6d`, using Rust 1.94.0.
The ranking remains the June 8, 2026 npm-high-impact snapshot; versions were resolved on September 16, 2026.
This is not a current download ranking.

The expansion covers available ranks 1,001–10,005 and records five metadata 404 replacements.
Fresh validation selects ranks 10,008–13,680 after excluding all previously seen families; its manifest records six unavailable metadata entries.
Transient failures do not qualify for replacement.
`locutus@3.0.36` requires case-sensitive extraction because its archive contains names that differ only by case.

## Operational cost

Measurements used an Apple M5 Pro with 48 GiB RAM and macOS 26.6.2.
Both scanner binaries used Rust 1.94.0. The installation binaries used the same shipping release profile and pinned toolchain.

The scan benchmark used all 7,000 tuning packages, four Rayon threads, two warmups, and seven measured pairs.
Each pair alternated binary order. The inputs and limits stayed identical.
The harness excluded pairs that overlapped detected Cargo activity and retained their records.

| Scan measurement | Baseline median | Candidate median | Change |
| --- | ---: | ---: | ---: |
| Whole-process elapsed time | 46.10 s | 47.16 s | +2.3% |
| Time inside package analysis | 44.23 s | 45.20 s | +2.2% |
| Peak resident memory | 260.25 MiB | 332.56 MiB | +27.8% |

The memory increase is material: about 72 MiB at the median peak.
This change retains that cost for scope-aware evaluator evidence and broader alias and VM coverage.
The additional evaluator coverage makes this an explicit correctness trade-off.
These measurements describe one machine and a bounded corpus workload.

The install benchmark used five verified local archives: Prettier, core-js, commander, json5, and diff.
Dependency lifecycle scripts stayed disabled. Separate homes and stores isolated each baseline/candidate pair.
Cold installs started with empty package stores. Warm installs reused the store after removal of project dependency state.
Up-to-date installs retained both. The operating-system file cache remained warm in all modes.
An unmeasured probe found five source-analysis caches with analysis enabled and none with it disabled, for both binaries.

After two warmups, seven measured pairs left source-disabled cold timing inconclusive.
A fixed extension added 20 pairs for every mode and setting, with no detector changes.
All original measurements remain in the published data. The table includes both runs and pooled descriptive medians.

| Cold install setting | First 7 pairs, baseline → candidate | Next 20 pairs, baseline → candidate | All 27 pairs, baseline → candidate |
| --- | ---: | ---: | ---: |
| Source analysis enabled | 649 → 665 ms | 596.5 → 642.5 ms | 599 → 652 ms (+8.8%) |
| Source analysis disabled | 502 → 555 ms | 494.5 → 492.5 ms | 498 → 530 ms (+6.4%) |

The extension exceeded the timing threshold for source-enabled cold installs: +46 ms (+7.7%).
This benchmark regression remains visible and accompanies the correctness improvements.
The source-disabled extension passed, but its differing results show the noise in short filesystem measurements.
The pooled values do not isolate the detector's causal cost.

Across all 27 pairs, warm-install medians were 55 ms for both binaries and both settings.
Up-to-date medians were 28 ms for both binaries and both settings.
Every installation completed successfully, and all install peak-memory comparisons passed their thresholds.
The performance gate itself did not pass because of the source-enabled cold-install regression.
These five-package results do not estimate network-heavy project installations.

[Performance data](performance.json) includes every scan attempt, paired measurements, binary hashes, fixture versions, and install comparison thresholds.

## Verification

The pinned Rust 1.94.0 workspace build, all-target Clippy, formatting, and dependency policy checks passed.
Build and Clippy produced no warnings. Dependency policy checks retain existing duplicate-version warnings.

The fast PR gates passed 6,335 non-CLI tests, 5,132 CLI unit tests, 99 binary tests, and seven source-analysis workflows.
Their configured skips and process-leak notices are recorded in [check results](checks.json).
The final security suite and all 18 corpus helper tests also passed.
Shell, Node, npm wrapper, and release helper checks passed.

The matching docs passed lint, type checking, and a production build with 402 generated pages.
See [docs PR 229](https://github.com/lpm-dev/rust-client-docs/pull/229).

## Recommendation

Keep the frozen corpora as regression sets and retain the separation between capabilities and security findings.
Prioritize threat-specific controls for the historical compromises that received no critical warning before another popularity expansion.
Add evidence for linked behaviors, such as sensitive-data collection followed by external transmission, with comparable benign controls.
Continue reporting parser gaps and sampling limits alongside every result.
