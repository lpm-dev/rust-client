# Bounded parallel tarball writing

The candidate reduces T3 first-install median by 113 ms and CI-cold median by 111 ms in this frozen local replay. It retains each output file handle through ordered acceptance. The tradeoff is higher T3 peak RSS: median +27.85 MiB on first install and +14.97 MiB on CI-cold.

## Method

- macOS arm64, Rust 1.94.0 release builds, Bun 1.4.2, Node 26.5.0.
- Four variants: published parent, candidate with writers disabled, candidate with its writer setting unset (default 2), and Bun.
- 24 balanced rounds per state and fixture: 768 scored installs. Forward/reverse rotations balance position and pair direction. Two untimed warm gates precede scoring.
- Dependency caches are cold; OS caches are warmed. Responses come from an immutable HTTPS loopback replay. There were zero upstream requests, misses or rejected routes. This does not measure live-registry tail latency.
- Scored installs have no tracing and no competing builds, tests, profiles or installs. Separate diagnostic runs follow scoring.
- Controls: 4 extraction permits, 24 downloads, 16 link tasks, default stream weighting, concurrent linking.
- Independent preflight checks compare selected packages, lock bytes, package-file bytes and executable bits across the three LPM variants. Bun package/version sets also match. Five CLI targets have identical bytes but different executable bits: Bun adds `0111`, while LPM retains zero. The LPM byte/mode comparison remains exact. Every scored inventory and LPM lock matches its preflight result. Empty directories, nested node_modules and other permission bits are outside the file fingerprint.

## Wall time

Values are median / observed interpolated p95, in milliseconds. Twenty-four samples do not support p99 conclusions.

| Fixture | State | Parent | Writers disabled | Default writers | Bun |
|---|---|---:|---:|---:|---:|
| t3 | first-install | 1689.41 / 1930.58 | 1618.17 / 1783.32 | 1576.06 / 1736.85 | 1649.55 / 1855.76 |
| t3 | ci-cold-cache | 1552.48 / 1751.39 | 1575.23 / 1739.22 | 1441.03 / 1582.38 | 1536.67 / 1787.60 |
| vite-react | first-install | 294.84 / 320.01 | 288.97 / 322.83 | 289.16 / 308.63 | 200.58 / 256.42 |
| vite-react | ci-cold-cache | 249.09 / 274.73 | 247.89 / 267.68 | 246.02 / 266.07 | 165.91 / 193.76 |
| native-sharp | first-install | 125.60 / 137.45 | 114.81 / 128.60 | 114.69 / 130.98 | 67.14 / 82.13 |
| native-sharp | ci-cold-cache | 85.00 / 88.85 | 84.15 / 91.67 | 84.49 / 91.28 | 55.20 / 60.96 |
| nest | first-install | 328.43 / 351.41 | 327.84 / 345.53 | 316.16 / 329.97 | 265.09 / 299.50 |
| nest | ci-cold-cache | 324.09 / 433.76 | 321.34 / 371.64 | 315.06 / 340.97 | 260.78 / 282.18 |

Paired median changes compare runs from the same round. They can differ from the difference between aggregate medians.

| Fixture | State | Parent to default | Faster pairs | Writers disabled to default | Faster pairs |
|---|---|---:|---:|---:|---:|
| t3 | first-install | -107.68 ms | 20/24 | -34.93 ms | 15/24 |
| t3 | ci-cold-cache | -98.82 ms | 21/24 | -150.45 ms | 20/24 |
| vite-react | first-install | -7.72 ms | 15/24 | -0.37 ms | 12/24 |
| vite-react | ci-cold-cache | -4.97 ms | 15/24 | -5.61 ms | 17/24 |
| native-sharp | first-install | -12.91 ms | 22/24 | -1.23 ms | 15/24 |
| native-sharp | ci-cold-cache | +0.49 ms | 11/24 | +0.09 ms | 12/24 |
| nest | first-install | -12.18 ms | 20/24 | -14.82 ms | 20/24 |
| nest | ci-cold-cache | +4.44 ms | 9/24 | -1.15 ms | 14/24 |

T3 gains remain present in both run-order directions and each eight-round block. Vite changes are small and order-sensitive; its writer-only first-install paired median is -0.37 ms with 12/24 wins. Sharp first-install improves through the file decoder route, with no writer pools. Sharp CI-cold is effectively flat; its observed p95 rises 2.43 ms. Nest first-install improves, but its CI-cold paired median is +4.44 ms despite a lower aggregate median and p95. Nest CI-cold is order-sensitive: paired median -19.79 ms when the candidate runs first versus +11.41 ms when it runs later. This does not identify the cause. Do not report a typical Nest CI-cold win.

## Peak RSS

Maximum resident size comes from `/usr/bin/time -l`. Values are median / observed interpolated p95 in MiB.

| Fixture | State | Parent | Writers disabled | Default writers | Bun |
|---|---|---:|---:|---:|---:|
| t3 | first-install | 345.02 / 368.49 | 343.98 / 376.08 | 372.88 / 405.88 | 475.38 / 509.13 |
| t3 | ci-cold-cache | 207.80 / 233.74 | 211.66 / 234.91 | 222.77 / 243.99 | 241.86 / 265.21 |
| vite-react | first-install | 187.90 / 197.36 | 185.84 / 192.06 | 183.67 / 194.10 | 144.91 / 151.47 |
| vite-react | ci-cold-cache | 92.42 / 97.17 | 86.16 / 98.64 | 87.84 / 95.27 | 58.15 / 60.46 |
| native-sharp | first-install | 57.16 / 61.79 | 57.64 / 59.91 | 57.89 / 60.09 | 39.37 / 40.48 |
| native-sharp | ci-cold-cache | 46.30 / 47.30 | 45.92 / 47.08 | 45.98 / 47.28 | 30.86 / 33.45 |
| nest | first-install | 78.62 / 84.49 | 76.77 / 83.03 | 76.80 / 83.21 | 43.62 / 44.63 |
| nest | ci-cold-cache | 52.62 / 56.99 | 52.17 / 58.41 | 52.45 / 56.29 | 28.88 / 29.48 |

## Attribution and bounds

The candidate also routes eligible regular downloaded files through the existing pipelined decoder. The disabled-writer variant measures that routing and shared writer scaffolding separately from enabling workers. It adds one decoder thread and 768 KiB of buffers per pipelined archive. The total parent-to-candidate gain must not be attributed only to parallel writing.

After 256 accepted files, eligible entries up to 256 KiB can use two writers. Each archive admits at most 64 entries and 4 MiB of queued payload. At most four pools run per process; Unix descriptor limits can reduce this further. Unavailable capacity or optional thread-start failure falls back to serial extraction. Directory preparation and file creation remain serial. Duplicate and large-entry barriers preserve archive order. Inspection/callback paths and uninterruptible generic streams remain serial.

Post-score traces show writer pool starts for T3, Vite and Nest. Sharp starts none. Sharp first-install changes from zero to one decoder under speculative file extraction; CI-cold already has one decoder under authoritative streaming extraction in all variants. This makes Sharp first-install a decoder-only control and CI-cold an unchanged-decoder control.

Pool spans establish startup attempts, not completed job or exact thread counts. The exported timeline omits the `writer_count` field. The preserved source and sanitized environment establish the configured default of two workers. All diagnostic traces retained their records and correlations.

The earlier closed-handle prototype and its measurements are excluded. This report uses only the final retained-handle source, descriptor-aware admission, cancellation wakeup, optional thread-start fallback and regular-file routing.

## Provenance

- Parent: `c4dde56e12ea0d02dbf69221ad652dd82204c638`.
- Parent binary SHA-256: `735f626a02f84890b23ecdbad736c9543665b36bc0e8e4513477647005870575`.
- Candidate binary SHA-256: `1e3fea7e71235c40fbc0f8067cab1b68c0b9090ed1d6f9d55d2c2cd27119f342`.
- Source patch SHA-256: `a28320cba681dbf63dedb3437701211a71a8fe350f6a22aa37a74c4907f120ab`.
- [Raw measurements and source hashes](parallel-entry-writes-20260924.json).

## Readiness check

The repository readiness harness also passed 216 scored installs: six balanced rounds across four fixtures, with cold, warm and up-to-date states. It used the same preserved binaries and frozen replay, with two untimed warmup rounds and no concurrent builds or tests. Every fixture comparison returned pass. This smaller follow-up checks default install behavior and warm-state regressions; it does not replace the 24-round results above.
