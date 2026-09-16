# Credential-exfiltration source detection

## Result

The detector now flags all five historical compromised controls, compared with two in the merged baseline.
The three new Critical findings identify supported secret flows into upload calls.
This deliberately selected set is not a malware recall estimate.

The same scanner produces zero credential-exfiltration findings and zero Critical source warnings across 12,000 popular package versions.
These packages are regression and tuning evidence. This study does not claim independent validation or a population false-positive rate.
No package code runs during source scans.

| Dataset | Packages | Critical before | Critical after | Complete package coverage before → after |
| --- | ---: | ---: | ---: | ---: |
| Original corpus | 1,000 | 0 | 0 | 997 → 998 |
| Expanded corpus | 9,000 | 0 | 0 | 8,812 → 8,860 |
| Former independent validation | 2,000 | 0 | 0 | 1,937 → 1,953 |
| Historical compromises | 5 | 2 | 5 | 4 → 5 |

Ten findings were verified and fixed. None remain rejected, externally blocked, or pending.
The [finding ledger](findings.md) records the evidence and regression coverage.

## Behavior

The new tag is `supplyChain.credentialExfiltration`. Its query selector is `:credential-exfiltration`, and its severity is Critical.
Installation reports the finding when source analysis is enabled. Default audit policy fails on it.
Audit JSON includes evidence at the upload call. The `:critical` query also selects it.
Schema version 9 refreshes cached local analyses. Registry metadata schema is unchanged.

The detector follows selected private-key names, wallet generator APIs, and the complete `process.env` object into supported uploads.
These uploads include fixed-URL `fetch` headers or bodies and repository-content upload calls.
Supported flow steps include assignments, selected encodings, local helpers, class methods, and numeric bundled-module relationships.
Normal token authentication, signatures, public addresses, quoted examples, and local security tools have benign controls.

The rule remains a heuristic. Names do not prove that a value contains a secret, and source flow does not prove execution or intent.
Unknown wrappers, dynamic URLs, destructuring, cross-file flows, and runtime mutation can prevent a finding.
Selected API shapes also remain heuristic when their external implementation is unknown.
These limits prevent this result from establishing package safety.

## Historical controls

| Version | Critical result | Evidence location |
| --- | --- | --- |
| `@solana/web3.js@1.95.7` | Credential exfiltration | `lib/index.cjs.js:3165`, plus browser builds |
| `xrpl@4.2.1` | Credential exfiltration | `build/xrpl-latest.js:17953`, plus the minified build |
| `@ctrl/tinycolor@4.1.1` | Credential exfiltration | `bundle.js:2` |
| `debug@4.4.2` | Existing obfuscation warning retained | `src/index.js` |
| `node-ipc@12.0.1` | Existing obfuscation warning retained | `node-ipc.cjs` |

The [historical manifest](../historical-controls.json) pins archive hashes and incident provenance.
Historical payloads remain outside public source control. [Evidence records](historical-evidence.json) contain locations and reasons, without payload excerpts.

Synthetic regressions cover overwritten values, duplicate properties, mutated aliases, local API names, static/instance methods, and computed properties that replace request fields.
A complete workflow covers installation output, the stored cache, default audit failure, JSON evidence, and query policies.

## Coverage and resource limits

Full-file analysis now accepts files through 4 MiB, compared with 2 MiB in the baseline.
This exposes the upload implementation in the 3.7 MB tinycolor bundle.
The package limits remain 50 MiB and 5,000 files.
Larger files receive bounded samples and retain incomplete-coverage reporting.

Disjoint head and tail samples cannot establish credential flow.
A regression demonstrates how joining those samples can otherwise connect unrelated function scopes and create a false warning.
The new detector runs only on complete, successfully parsed file inputs.
Other capability and artifact heuristics retain their existing sampled-input behavior.

[Coverage data](coverage.json) records scanned files, bytes, parser failures, input gaps, limits, and every partial package.
The previous [file inventory](../expanded/file-inventory.json) still describes selection exclusions because the manifests and selection rules are unchanged.
A file with no full scan never counts as fully inspected.

| Dataset | Fully scanned files | Scanned bytes | Unparsed files | Partial packages |
| --- | ---: | ---: | ---: | ---: |
| Original 1,000 | 25,731 | 139,449,687 | 8 | 2 |
| Expanded 9,000 | 290,836 | 2,847,173,244 | 1,502 | 140 |
| Former validation 2,000 | 96,184 | 859,860,945 | 340 | 47 |

No previously complete package becomes incomplete. The scanner reports no input/read gaps.
Complete coverage increases by 65 popular packages. This means the reported scan limits and parser checks pass, not that each package is safe.
The original, expanded, and former validation sets contain 55, 799, and 69 packages with no fully scanned source, respectively.
Two packages already at their resource limits receive fewer complete file scans because larger files consume more of the fixed package budget.
The count changes from 2,970 to 2,460 for `openclaw`, and from 1,956 to 1,955 for `ace-builds`.
Their package tags remain unchanged, but this is a coverage trade-off.

## Review of changed popular-package results

All 34 changed package rows received review: 28 from the expansion and six from the former validation set.
The original 1,000 packages have no tag changes.
The larger full-file limit changes capabilities and informational traits, with no new Critical findings.

Full-file context removes child-process matches on local callbacks in Sandpack and PDF.js, and on database methods in Expo SQLite.
It also removes dynamic-load matches on local throwing functions in AG Charts and AG Grid.
Cloudflare's removed WebSocket evidence was quoted source in the old sample.

Added capabilities include plugin loading, runtime compilation, shell helpers, network implementations, and crypto imports in newly covered bundles.
Some informational patterns still match quoted documentation or keyword lists.
For example, embedded DOM documentation supplies a telemetry pattern in `@ts-morph/common`.
These metadata patterns do not establish an upload and do not become security warnings.

Full-file string and layout statistics also change entropy, minification, and possible-obfuscation tags.
A removed informational tag does not prove the absence of encoded or generated code.
The [reviewed rows](reviewed-changes.json) record bounded evidence and a reason for each change.
This review does not provide ground-truth labels for every unchanged result or every file.

## Reproduction

The baseline is merged main `840d6ac5a397f9958e038d86493a94256678c262`.
Both binaries use Rust 1.94.0. The [freeze record](freeze.json) pins source and binary hashes.

The package manifests are unchanged:

- [Original 1,000](../top-1000.json).
- [Expanded 9,000](../expanded-9000.json).
- [Former validation 2,000](../fresh-validation-2000.json).
- [Historical controls](../historical-controls.json).

The ranking remains the June 8, 2026 npm-high-impact snapshot, with versions resolved on September 16, 2026.
It is not a current download ranking. Popularity does not label a package benign.
The former holdout was examined during this work and now belongs to the regression corpus.

[Aggregate results](summary.json) and the four comparison files preserve before/after tags and coverage:
[original](original-results.jsonl), [expanded](expanded-results.jsonl), [former validation](former-validation-results.jsonl), and [historical](historical-results.jsonl).

## Operational cost

Measurements used an Apple M5 Pro, 48 GiB RAM, macOS 26.6.2, and Rust 1.94.0.
The [protocol](performance-protocol.json) fixes sample counts before measurements.
Builds and tests finished before the timing runs. The harness detects Cargo activity and retains rejected attempts.

The source benchmark uses 7,000 tuning packages, four Rayon threads, two warmup pairs, and five measured pairs.
Binary order alternates. Both binaries scan the same pinned package trees.

| Scan measurement | Baseline median | Candidate median | Change |
| --- | ---: | ---: | ---: |
| Whole-process elapsed time | 46.52 s | 48.86 s | +5.0% |
| Time inside package analysis | 44.60 s | 46.20 s | +3.6% |
| Peak resident memory | 308.41 MiB | 401.23 MiB | +30.1% |

The memory increase is material: about 93 MiB at the median peak.
This cost accompanies broader full-file coverage and the new flow analysis. The measurement does not isolate their individual costs.
The change retains this trade-off for the three recovered historical controls and 65 additional packages with complete coverage.

The install benchmark uses five verified local archives: Prettier, core-js, commander, json5, and diff.
Both CLI binaries use the shipping release profile. Dependency scripts stay disabled, and each pair has isolated homes and stores.
Cold installs start with empty package stores. Warm installs reuse the store after removal of project dependency state.
Up-to-date installs retain both. The operating-system file cache remains warm.

Two warmup pairs precede twenty measured pairs per mode and source-analysis setting.
The source-enabled and source-disabled cells use the same configuration except for source analysis.
An untimed probe confirms five source-analysis caches with analysis enabled and none with it disabled, for both binaries.

| Install mode | Source analysis | Baseline median | Candidate median | Timing verdict |
| --- | --- | ---: | ---: | --- |
| Cold | Enabled | 696 ms | 683.5 ms | Regression at the 95th percentile |
| Cold | Disabled | 503 ms | 533 ms | Inconclusive |
| Warm | Enabled | 57 ms | 56.5 ms | Pass |
| Warm | Disabled | 57.5 ms | 56.5 ms | Pass |
| Up-to-date | Enabled | 28 ms | 29 ms | Pass |
| Up-to-date | Disabled | 28.5 ms | 29 ms | Pass |

The cold, source-enabled median decreases, but its 95th percentile rises from 960.1 to 1,072.05 ms (+11.7%).
That exceeds the fixed timing threshold, so the overall performance gate reports a regression.
The source-disabled cold comparison remains inconclusive. These noisy cold-install results do not isolate the detector's causal cost.
Every installation succeeds, and all install peak-memory comparisons pass their thresholds.
Warm and up-to-date timing comparisons also pass. No additional samples were selected to change these verdicts.

The change retains the measured scan cost and cold-install tail risk for the detection and coverage gains described above.
[Performance data](performance.json) preserves warmups, all measured pairs, binary hashes, paired deltas, and comparison thresholds.

These are single-machine measurements. The five-package fixture does not estimate network-heavy installations.

## Verification

The Rust 1.94.0 workspace build, all-target Clippy, formatting, and dependency policy checks pass.
Build and Clippy produce zero warnings. Dependency checks retain existing duplicate-version warnings.

The fast gates pass 6,347 non-CLI tests, 5,132 CLI unit tests, and 99 binary tests.
All 11 source-analysis workflows and catalog checks pass. The dedicated security suite passes 567 unit tests and one corpus integration test.
Shell, Python, Node, npm wrapper, and release-helper checks also pass.
Configured skips and process-leak notices remain visible in the [check records](checks.json).

The matching [docs PR](https://github.com/lpm-dev/rust-client-docs/pull/231) passes its 402-page production build, lint, types, and content-date checks.
Its 80 unit tests and 15 component tests also pass. The docs repository has no configured CI workflow.

The prior approved merges are complete. Every applicable Rust main CI job and CodeQL passed for merged commit `840d6ac5`.

## Recommendation

Keep these 12,000 packages and historical controls as permanent regression inputs.
Evaluate the frozen detector on fresh, previously unseen package families before further tuning.
Add more historical attack families with comparable benign controls to measure detection beyond these five selected incidents.
Keep reporting incomplete coverage and measured costs with every result.
