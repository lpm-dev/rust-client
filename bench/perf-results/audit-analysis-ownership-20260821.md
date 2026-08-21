# Audit analysis ownership

Date: 2026-08-21

## Result

The final candidate removes duplicate retained `PackageAnalysis` values.
It keeps exact package-instance attribution and reduces memory for cached analysis data.

The 12,000-instance final cache has 12,000 entries and one stored analysis.
The base cache has 12,000 entries and 12,000 stored analyses.
The final cache is 74.8% smaller for this fixture.

The final candidate decreases median warm-query peak RSS by 45.6%.
It decreases median warm-query time by 74.0%.

The same-content, distinct-inode control gives a similar result.
The final candidate decreases median warm-query peak RSS by 35.9% for this control.

The diverse-content control stores one analysis for each different input fingerprint.
Its final cache is 20.8% smaller, without incorrect value sharing.

The byte-heavy cold-query RSS ranges overlap.
Therefore, this measurement does not show a cold-query RSS change for that fixture.

## Binaries and source

The base is commit `15341efa3fb36abb317ece4a9a50f6cd3576cdc5`.
The final candidate contains the Area 9 source changes.

The release profile uses optimization level 3, LTO, and one codegen unit.
Rust `1.94.0` built the final candidate.

The binaries have these SHA-256 values:

- Base: `285a8ee5a9de6557764ec524ed6b183babbd356c49cb899996d76c845a5cee0e`
- Pre-final candidate: `fa545b454463879a666828846a3d2760d897ed54f24d0d3ec62a3488c56bbe83`
- Final candidate: `920540049be6cb2fb9788f5e6b896cd5d0441acf4496b18ef2452dc0c520a167`

The measured source diff has SHA-256 `66565b05dbb1194763e92c9cbb01c37091f76f749f6c95dab2e4dd1e0e13657b`.
The final pull-request source diff has SHA-256 `c9a0ec08bd640f5eda77a3be0cfd815e763682ff1e725778d840f097f2239bd5`.
These hashes exclude this report and cover the tracked Area 9 implementation and test diff at each point.

The final pull-request diff adds lint corrections and a standalone-lockfile projection fix after the measurements.
The benchmark fixtures do not use the corrected standalone-lockfile shape.

The raw result file has SHA-256 `d7c552e31f7508a4a580e081d936bc3cb91792095d4fd9add0e54231c71a44b9`.
The preserved raw file is `/tmp/lpm-area9-bench/area9-final-benchmark-raw.json`.

## Method

Each scenario has seven paired samples.
The order alternates between the two measured binaries.
`RAYON_NUM_THREADS` is 8 for all samples.
`/usr/bin/time -lp` measures wall time and peak RSS.

The machine is an Apple M5 Pro with 48 GiB of memory.
It runs macOS 26.5.2, build 25F84.

The cold runs use a new project path and a new `LPM_HOME`.
Fixture cloning occurs outside the timed region.
The warm runs use a primed analysis cache.

The local OSV server returns deterministic empty results.
Audit deduplicates the 12,000 installed copies into one OSV coordinate.

## Fixtures

The tiny fixture contains 12,000 identical package instances.
Its source files use hard links to model maximal duplicate content.

The byte-heavy fixture contains 2,000 identical package instances.
Each instance has a 128 KiB source file.

The distinct-inode fixture contains 4,000 equal package trees.
Each source file and manifest has a different inode.

The diverse fixture contains 4,000 package trees with different source bytes.
This fixture prevents content-fingerprint sharing.

The exact LPM fixture contains 1,000 exact instance IDs and V2 link entries.
It includes project links, link metadata, locked integrity, and exact root resolutions.

The large-manifest fixture contains eight 15 MiB manifests.
The pre-final and final candidates use separate primed caches for this control.

## Base and final medians

| Scenario | Base time | Final time | Time change | Base peak RSS | Final peak RSS | RSS change |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Tiny, cold query | 9.05 s | 2.31 s | -74.5% | 75.4 MiB | 61.3 MiB | -18.7% |
| Tiny, warm query | 7.43 s | 1.93 s | -74.0% | 89.8 MiB | 48.9 MiB | -45.6% |
| Byte-heavy, cold query | 2.35 s | 0.90 s | -61.7% | 43.1 MiB | 43.1 MiB | 0.0% |
| Byte-heavy, warm query | 1.49 s | 0.50 s | -66.4% | 36.0 MiB | 27.8 MiB | -22.7% |
| Distinct inode, cold query | 2.99 s | 0.84 s | -71.9% | 48.7 MiB | 42.3 MiB | -13.1% |
| Distinct inode, warm query | 2.84 s | 0.74 s | -73.9% | 53.3 MiB | 34.2 MiB | -35.9% |
| Diverse bytes, cold query | 2.92 s | 0.80 s | -72.6% | 49.2 MiB | 43.7 MiB | -11.2% |
| Diverse bytes, warm query | 2.64 s | 0.74 s | -72.0% | 52.7 MiB | 33.8 MiB | -35.9% |
| Tiny, cold audit | 31.07 s | 1.26 s | -95.9% | 70.5 MiB | 123.1 MiB | +74.6% |
| Tiny, warm audit | 26.33 s | 1.19 s | -95.5% | 86.9 MiB | 107.3 MiB | +23.5% |
| Exact LPM, cold simple query | 4.03 s | 1.98 s | -50.9% | 49.5 MiB | 42.5 MiB | -14.2% |
| Exact LPM, warm graph query | 4.06 s | 1.98 s | -51.2% | 42.7 MiB | 34.4 MiB | -19.5% |

The byte-heavy cold RSS ranges are 42.4–43.4 MiB and 42.1–45.2 MiB.
These ranges overlap.

The final audit retains one path-qualified result for each installed instance.
The base incorrectly merges these 12,000 instances into one coordinate-only result.
This correctness change explains the final audit RSS increase.

The final audit still sends one deduplicated OSV coordinate.
Therefore, the RSS increase does not come from duplicate OSV requests or responses.

## Final optimization controls

These controls compare the preserved pre-final candidate with the final candidate.
They isolate the final review changes more closely than the base comparison.

| Scenario | Pre-final time | Final time | Time change | Pre-final peak RSS | Final peak RSS | RSS change |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Buffered 3.64 MiB cache, warm query | 3.34 s | 2.26 s | -32.3% | 50.3 MiB | 49.3 MiB | -1.9% |
| Eight 15 MiB manifests, warm query | 0.28 s | 0.26 s | -7.1% | 237.8 MiB | 84.3 MiB | -64.5% |

The buffered-cache result includes changes after the pre-final binary.
It is supporting evidence, not an isolated syscall benchmark.

The large-manifest change directly replaces whole-manifest buffering with a streaming digest.
The median peak RSS decreases by 153.4 MiB.

## Cache size

| Fixture | Base | Final | Change |
| --- | ---: | ---: | ---: |
| 12,000 tiny instances | 14.465 MiB | 3.640 MiB | -74.8% |
| 2,000 byte-heavy instances | 2.415 MiB | 0.607 MiB | -74.9% |
| 4,000 equal, distinct-inode instances | 4.818 MiB | 1.214 MiB | -74.8% |
| 4,000 diverse instances | 4.818 MiB | 3.815 MiB | -20.8% |
| 1,000 exact LPM instances | 1.180 MiB | 1.030 MiB | -12.7% |

## Disposition

The duplicate retained analysis values are verified and removed.
The final candidate shares one `Arc<PackageAnalysis>` for each input fingerprint.
The signed cache stores one analysis for each input fingerprint.

Fresh equal inputs still require content reads before they can share an analysis.
The content fingerprint is the trusted equality proof.
A path, inode, size, timestamp, or integrity value is not equivalent proof.

No pre-read deduplication is accepted.
It can reuse stale or different source bytes.
The fused analysis pass removes the former extra source walks.
