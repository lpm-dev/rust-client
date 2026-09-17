# Reviewed archive labels and targeted detection

## Result

This study improves archive labels and adds detection for supported source flows.
It preserves the [frozen pilot](../archive-pilot/report.md) and its baseline artifacts.
All archives were read as static data. No archived code, lifecycle script, or embedded destination was executed or contacted.

The candidate adds four credential-exfiltration findings and one encrypted-execution finding in the original 400-case pilot.
It also flags two added filesystem-wiper versions from one code family.
The original pilot has 399 successful scans. Its one ambiguous ZIP-root failure, `n8n-nodes-zalo-fevox`, remains unchanged.
Critical warnings increase from 17 to 21 packages. The encrypted-execution finding has High severity.
All original pilot supply-chain findings remain present.
All supply-chain findings also remain present across the five earlier incidents and three prior attack-family fixtures.

The candidate produces zero targeted warnings across 28 legitimate controls and 12,000 previously scanned popular packages.
These are regression sets. Popularity does not establish that a package is benign.
These counts do not estimate malware recall or the population false-positive rate.

Source coverage is unchanged: 37 pilot packages have no selected source, six reach scan limits, and 27 files do not parse.
These coverage limits remain separate from detector misses.

The [summary](summary.json) and [paired results](results.jsonl) record counts, coverage, and changed tags.
The [candidate identity](candidate.json) pins the detector source and both release binaries.
Public artifacts contain package identities, hashes, and evidence locations. They omit payload excerpts and private archive locations.

## Labels and grouping

The inventory contains 33,252 distinct archive hashes.
Eighteen cases now have [source reviews](source-reviews.json), including hashes, activation conditions, intent evidence, and limits.
The other 33,234 records remain unreviewed. Labels do not propagate to related packages.

The reviewed labels comprise 12 attack chains, two destructive-operation versions, one remote loader, one conditional chain, and two ambiguous cases.
The environment uploads in `es6-codify` and `fin-logger` remain distinct from credential-file theft.
The earlier ambiguous destruction labels remain ambiguous. These reviews do not certify those packages as safe.

[Grouping artifacts](grouping/summary.json) retain metadata relationships and add matches against reviewed source files.
An arbitrary shared utility file no longer establishes a new source link.
Nine reviewed-source links leave 15,265 groups across the inventory.
These groups prevent known overlap across study sets. They are not attributed campaigns or independent attack families.
Metadata links can still combine unrelated cases, and unopened code can hide additional relationships.

All 6,906 reserved records remain unopened and unscanned. No new source link required a reserved-record quarantine in this pass.
The grouping tool quarantines reserved records when their group contains reviewed or inspected material.
The reserve remains provisional until broader source and campaign relationships are checked.

## Reviewed detection changes

| Package | Candidate finding | Source-supported interpretation |
| --- | --- | --- |
| `autbank-core@99.0.2` | Critical credential exfiltration | Preinstall sends a report that can contain a package-directory `.env` file |
| `coin-fees@20.1.1` | Critical credential exfiltration | Postinstall schedules a home `.npmrc` upload behind delay and environment checks |
| `es6-codify@2.2.0` | Critical credential exfiltration | The ESM entry sends the complete environment when imported |
| `fin-logger@33.12.13` | Critical credential exfiltration | Preinstall sends the complete environment in an HTTPS report |
| `core-js-buffer@1.0.0` | High encrypted execution | Decrypted bytes reach a written file and a Python launcher |
| `cache-cleanup-module@2.5.0` and `2.6.0` | Critical destructive filesystem | An exported operation can recursively remove current-directory contents |

The two wiper versions share one code family.
They advertise cache/build cleanup but contain no corresponding path restriction.
They exclude only their own entry file. The caller must invoke the operation, and a remote response must authorize deletion.
Neither version declares an installation hook. Source confirms the destructive operation; campaign attribution remains unknown.

The `core-js-buffer` warning identifies the launcher chain, not the effects of the decrypted stage.
Likewise, a downloaded-execution warning describes remote code execution without deciding whether the remote code is malicious.
The new downloader rule passes paired synthetic controls, but adds no behavior-specific warning to the reviewed obfuscated downloader cases.

## Remaining gaps

| Cases | Candidate result | Coverage limit |
| --- | --- | --- |
| `price-scripping-js`, `wallet-watcher`, `debugcli`, `test__123q1` | No credential-exfiltration warning | Cross-module helpers, concealed APIs, encrypted reports, or multipart/archive transformations |
| `mutex-core`, `matrixflow-js` | No encrypted-execution warning | Selective activation and concealed API names obscure the launcher chain |
| `helmet-pro` | Existing Critical obfuscation warning | No behavior-specific download-to-execution finding |
| `greensaver` | No targeted warning | Encoded `.map` stages are outside source selection; activation also depends on relative paths |
| `kelly-sizing` | No targeted warning | Tarball-to-module loading crosses unsupported stages; the external stage is absent |

These limitations remain explicit. Seven newly flagged package versions are not seven independent campaigns.
No payload fingerprint or package-name rule was added to detection.

## Detector and control boundaries

The implementation follows recognized imports and supported values within complete source files.
It requires a credential value to reach a supported network payload, or downloaded/decrypted bytes to reach an execution operation.
Broad deletion requires recursive removal of a supported broad directory or its enumerated contents.

Paired controls cover ordinary file uploads, credential sanitization, local API lookalikes, overwritten values, dead code, and scoped cleanup.
They also cover unrelated downloads, data decryption, unrelated process launches, and filenames passed as ordinary arguments.
Direct `eval` requires supported text values. Buffers require an explicit string conversion or text encoding.
Credential paths require exact components. Similar public filenames do not establish credential access.
Callback reads do not count as returned credential contents. Unknown transformations do not establish a value relationship.

Seventeen unit regressions cover these patterns and controls.
A workflow test checks install analysis, cached results, audit JSON evidence, query selectors, and severity selectors for all three new tags.
The cache schema increases from 9 to 10 so older analysis receives a new scan.
Capabilities remain separate from security findings.

## Operational evidence

The [performance artifact](performance.json) records alternating baseline/candidate measurements, warmups, source timing, and peak resident memory.
The source comparison uses the same 1,000 frozen packages and four scanner threads.
The install comparison uses five local archives with source analysis enabled and disabled, across cold, warm, and up-to-date states.
It uses two warmup pairs and two batches of 20 measured pairs per state and configuration.
The first batch flagged disabled cold-install p95 and left enabled cold installs inconclusive.
One additional fixed batch retained all earlier samples. The pooled 40-pair comparison passes the original wall-time and memory thresholds.
Both batch results remain in the artifact, including the initial regression verdict.

| Measurement | Baseline median | Candidate median |
| --- | ---: | ---: |
| Source scan, 1,000 packages | 2.330 s | 2.320 s |
| Scanner peak memory | 96.16 MiB | 95.97 MiB |
| Cold install, analysis enabled | 659.5 ms | 681 ms |
| Warm install, analysis enabled | 63 ms | 61 ms |
| Up-to-date install, analysis enabled | 32 ms | 32 ms |
| Cold install, analysis disabled | 500.5 ms | 485 ms |
| Warm install, analysis disabled | 62.5 ms | 62 ms |
| Up-to-date install, analysis disabled | 32 ms | 33 ms |

Enabled cold installs add 21.5 ms at the median, or 3.3%, within the existing threshold.
Their median peak memory increases from 84.89 MiB to 86.83 MiB.
Source timing and scanner memory are essentially unchanged. These small differences do not establish a speed improvement.
The activation probe confirms five analysis-cache files in enabled runs and none in disabled runs.

These measurements concern one machine and a small local install fixture.
They do not estimate network-heavy installation cost. Cold installs start with an empty package store while operating-system caches remain warm.

The exploratory debug scanner also exposed an existing OXC assertion on `investing@0.1.57`.
The parser and dependency version predate this change, and the release scanner parses that archive successfully.
This development-build limitation is separate from the pilot extraction failure.

## Reproduction

The original inventory, selection, and baseline remain in `archive-pilot/`.
The grouping tool accepts a private inventory, inspection directories, reviewed source roots, and the public review file.
It checks evidence hashes and refuses to replace an existing output directory.

```sh
python3 bench/source-analysis/test_corpus.py
python3 bench/source-analysis/archive_labels.py --help
python3 bench/source-analysis/archive_pilot.py scan --help
```

Candidate scans require an explicit `--expected-binary-sha256` value.
Without that option, the scanner guard still requires the original frozen binary.
Use separate result directories for every baseline and candidate run.

The [finding ledger](findings.md) records implementation findings, evidence, coverage, and final dispositions.
The [validation record](validation.json) lists the local gates and their results.
