# Declared-output cache restore validation

Release binaries built with Rust 1.94.0 on macOS arm64. Baseline is the secrets parent; candidate adds declared-output validation and typed loopback URL handling. Binary hashes and measurements are in the companion JSON.

## Restore API

Six alternating AB/BA process pairs for each fixture, 20 measured restores after one warmup per process. Each process uses a fresh isolated cache. Each file contains 128 bytes. Measurements include durable filesystem publication.

| Files | Baseline median (ms) | Candidate median (ms) | Change |
| --- | ---: | ---: | ---: |
| 1 | 51.55 | 48.73 | -5.47% |
| 64 | 51.54 | 50.39 | -2.23% |
| 500 | 84.30 | 86.68 | +2.83% |

## End-to-end task cache hits

The runtime-readiness harness ran 10 alternating pairs per scenario after one warmup. Every baseline and candidate restored the expected output.

| Scenario | Baseline median/p95 (ms) | Candidate median/p95 (ms) | Result |
| --- | ---: | ---: | --- |
| 1 MiB | 84.79 / 117.06 | 80.92 / 117.73 | Pass |
| 500 files | 112.06 / 133.18 | 114.49 / 210.15 | Initial p95 gate failed |
| Deep path | 77.47 / 92.65 | 75.78 / 90.67 | Pass |
| Remove stale output | 81.90 / 93.63 | 79.94 / 129.91 | Pass |

The initial 500-file tail result warranted a 30-pair confirmation with the same binaries, fixture, and thresholds. Median was 113.46 → 113.19 ms; p95 was 130.67 → 141.77 ms. The confirmation passed. The initial failure is retained in the JSON.

The additional filesystem scan costs about 2.4 ms in the 500-file API microbenchmark. No material end-to-end regression reproduced in the larger confirmation. This scan verifies that an artifact cannot write undeclared project files before any project mutation.

Resource sampling was insufficient for these short cache-hit processes. RSS, descriptor, and thread readings are advisory; this run does not establish a memory improvement. No installation paths changed, so install-readiness was not run for this concept.
