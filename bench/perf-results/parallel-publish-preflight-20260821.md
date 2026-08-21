# Parallel publish preflight benchmark

- Date: 2026-08-21
- Host: Apple M5 Pro, macOS 26.5.2, arm64, 48 GiB RAM
- Toolchain: Rust 1.94.0
- Build profile: release with LTO
- Samples: seven alternating AB/BA pairs after one warm gate per binary, except the single-binary scaling run
- Peak RSS source: `/usr/bin/time -lp`

## Scope

The measurements cover six release-publish concerns:

1. bounded concurrent remote preflight under network delay;
2. fail-fast cancellation after an ordered preflight error;
3. npm packument retention and upload connection reuse;
4. LPM full-metadata fallback peak memory;
5. GitHub runtime provider-JWT reuse;
6. complete workspace-generation validation before every upload.

Every fixture used an isolated temporary project and home. No compiler process
ran during a measured sample. All network traffic used a loopback HTTP server.
Every comparison used the same fixture, environment, sample count, and
alternating execution order.

## Preserved binaries

| Role | Source state | SHA-256 |
| --- | --- | --- |
| Serial preflight baseline | `468876ac` | `613e74992caf57fef716d0ed6147d1028ce58425c73c9846ce2c2526d0837a75` |
| Targeted-projection candidate | Uncommitted pre-closeout candidate | `f695d93023fbbe66796c1bb5d133091045071af136a058df8a2821b6d8621fea` |
| Pre-residual-fix candidate | Uncommitted closeout candidate | `6219a0ae386c40e876114afbefd2563b0c1ec26bdaedbfee9b590542d4950478` |
| Final candidate | Uncommitted acceptance-enabled candidate | `e46a74061f583f2b8f4e0a88072ad3d5bf77339f810615fbca4b28e2e1a50a38` |
| Acceptance-storage baseline | `468876ac`, acceptance hooks | `f13d73a1f3da52a1cc96d22de4a27cde05596889ee7b3bf8d866cd3bfd683cf1` |

The acceptance hook only seeds registry-scoped credentials in disposable
homes. Credential setup completed before each timed command. The measured
publish path remained an optimized release build.

## Delayed remote preflight

The fixture contains 48 independent LPM packages. Every availability request
waits 100 ms before returning. Both binaries make exactly 48 requests.

| Metric | Serial median | Concurrent median | Change |
| --- | ---: | ---: | ---: |
| Wall time | 5,069.76 ms | 1,273.90 ms | -74.87% |
| Remote preflight | 4,930.57 ms | 1,231.92 ms | -75.02% |
| Peak RSS | 21.20 MiB | 21.00 MiB | -0.96% |
| Maximum request concurrency | 1 | 4 | bounded at 4 |

The scheduler fills four permits and refills a slot as soon as one request
finishes. Indexed completion state preserves workspace-order error selection.

## Fail-fast cancellation

Package zero returns a non-retriable HTTP 400 immediately. The other 47
preflights wait 100 ms. The baseline collected every bounded task before
reporting the first error. The candidate stops scheduling once the earliest
ordered error is known and drops the remaining in-flight futures.

| Metric | Pre-fix median | Final median | Change |
| --- | ---: | ---: | ---: |
| Wall time | 1,252.61 ms | 16.12 ms | -98.71% |
| Requests started | 48 | 4 | -91.67% |

The four candidate requests are the initial bounded window. No delayed tail
request is started.

## Large npm packuments and upload reuse

The fixture publishes eight packages to one npm-compatible registry. Each
packument contains a 24 MiB JSON string. The server drains and acknowledges the
real local upload after preflight.

| Metric | Baseline median | Final median | Change |
| --- | ---: | ---: | ---: |
| Peak RSS | 150.28 MiB | 134.02 MiB | -10.82% |
| Wall time | 1,039.99 ms | 892.30 ms | -14.20% |
| Accepted TCP connections | 17 | 2 | -88.24% |
| Packument requests | 8 | 8 | unchanged |
| Maximum large-response concurrency | 1 | 1 | unchanged |

Weighted permits serialize implicit packuments. The streaming visitor retains
only the requested version and the highest stable nondeprecated version. One
command-scoped upload client reuses the registry connection across all eight
uploads.

## LPM full-metadata fallback

The LPM exact-version endpoint reports that each package exists, forcing the
compatibility fallback to full metadata. Each of the eight metadata responses
contains a 24 MiB JSON string. The baseline treated these as four light jobs;
the candidate releases its light permit and then acquires the full four-permit
budget before fetching metadata.

| Metric | Baseline median | Final median | Change |
| --- | ---: | ---: | ---: |
| Peak RSS | 276.75 MiB | 139.64 MiB | -49.54% |
| Wall time | 557.64 ms | 886.18 ms | +58.92% |
| Maximum metadata concurrency | 4 | 1 | bounded at 1 |
| Metadata requests | 8 | 8 | unchanged |

The latency increase is intentional. It prevents four responses on a path
whose configured body cap is 100 MiB from being resident at the same time.

## GitHub runtime provider-JWT reuse

Eight LPM packages use GitHub Actions runtime OIDC. Each package still receives
its own scoped exchange token. Only the audience-wide provider JWT is cached.

| Metric | Pre-fix median | Final median | Change |
| --- | ---: | ---: | ---: |
| Provider-JWT requests | 8 | 1 | -87.50% |
| Package-scoped exchanges | 8 | 8 | unchanged |
| Availability requests | 8 | 8 | unchanged |
| Accepted TCP connections | 16 | 9 | -43.75% |
| Wall time | 14.59 ms | 14.40 ms | -1.31% |

The loopback wall-time difference is noise. Request and connection counts are
the relevant result; package authorization scopes remain distinct.

## Workspace-generation scaling and rejected linearization

This is a real, non-dry-run release with immediate loopback preflight and upload
responses. It measures the final candidate at 50, 100, and 200 members. Before
each irreversible upload, the client checks the complete captured generation.

| Members | Wall median | Post-preflight median | Upload span median |
| ---: | ---: | ---: | ---: |
| 50 | 104.94 ms | 88.46 ms | 79.90 ms |
| 100 | 309.10 ms | 283.77 ms | 269.05 ms |
| 200 | 1,033.38 ms | 990.62 ms | 963.41 ms |

The upload span grows by 12.06 times from 50 to 200 members while member count
grows by four. This confirms material quadratic filesystem-generation work.

The proposed linearization is rejected because it would weaken verified drift
behavior. Before every upload, the current contract detects:

- new, removed, and renamed workspace members;
- duplicate package names introduced by an unrelated member;
- root workspace and catalog changes;
- selected-member and internal-dependency manifest changes.

Directory metadata cannot detect in-place edits to an unrelated
`package.json`. Checking only the selected package and its known dependency
paths misses a renamed member that becomes a duplicate. A portable filesystem
watcher is not a proof of freshness because events can be delayed, coalesced,
or dropped. Without a reliable cross-platform filesystem change journal, the
absence of relevant drift requires checking the complete captured generation.
The measured cost is retained to preserve the pre-upload safety invariant.

## Conclusion

Four-way scheduling cuts delayed preflight wall time by about 75%. Ordered
fail-fast cancellation prevents an immediate error from running the delayed
tail. Streaming npm parsing, weighted heavy-path permits, provider-JWT caching,
and shared clients materially reduce retained memory, redundant requests, and
connections. The remaining quadratic workspace-generation cost is measured
and intentionally retained because the proposed optimization cannot preserve
the current drift-detection contract.

Raw artifacts:

- `/tmp/lpm-area5-final-preflight-results.json`
- `/tmp/lpm-area5-fail-fast-results.json`
- `/tmp/lpm-area5-current-packument-memory-results.json`
- `/tmp/lpm-area5-lpm-heavy-memory-results.json`
- `/tmp/lpm-area5-provider-jwt-results.json`
- `/tmp/lpm-area5-real-workspace-scaling-results.json`
