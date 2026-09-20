# Service port and restart recovery measurements

Rust 1.94.0 release binaries on macOS arm64. The baseline is the remote-cache parent. The candidate adds explicit port intent, peer environments for portless services, and independent restart recovery. Binary hashes and raw samples are in the companion JSON.

## Peer environment helper

Twenty adjacent AB/BA pairs per fixture, with 100 warmup calls in each process. Both versions use the same assigned-port services. The harness compiles the exact helper body with `rustc -O`.

| Services | Baseline median (µs) | Candidate median (µs) |
| --- | ---: | ---: |
| 1 | 0.30 | 0.31 |
| 10 | 14.38 | 10.29 |
| 50 | 326.74 | 241.52 |

## Development runtime

Ten equal alternating pairs after one warmup per scenario. Each run verifies service readiness, final output, shutdown, and descendant cleanup. No build or test ran during the measurements.

| Scenario | Baseline startup median/p95 (ms) | Candidate startup median/p95 (ms) | Baseline/candidate peak tree RSS median (MiB) |
| --- | ---: | ---: | ---: |
| cleanup/multiservice-descendant-sigterm | 169.44 / 190.49 | 165.69 / 191.08 | 124.55 / 124.64 |
| dev/deep-10-services | 1781.72 / 2279.18 | 2049.96 / 2301.23 | 587.60 / 587.62 |
| dev/multi-service-dependency-readiness | 297.90 / 335.82 | 289.61 / 314.26 | 136.30 / 136.16 |
| dev/single-service-no-lpm-json | 86.40 / 106.37 | 90.87 / 117.87 | 76.45 / 76.59 |
| dev/wide-10-services | 128.39 / 220.51 | 126.09 / 201.19 | 592.31 / 592.96 |
| recovery/crash-cycles-resistant-descendants | 5486.36 / 5503.03 | 3520.95 / 3590.16 | 130.09 / 129.73 |

Runtime comparison verdict: `inconclusive`. See the JSON for wall time, shutdown, memory, process, descriptor, and thread gates.

## Installation confidence

The install-readiness harness compares the same binaries on the Vite/React fixture, with ten samples each for warm and up-to-date installs. It uses isolated project and cache state, paired execution order, and peak RSS measurements. Results are in the JSON.

The initial deep-graph startup result was inconclusive. A fixed 30-pair confirmation with the same binaries and thresholds did not reproduce the startup increase: median/p95 changed from 1840.06/2293.32 ms to 1801.75/2243.75 ms. Wall time and RSS gates also passed.

Deep-graph shutdown remains inconclusive. Its unpaired median changed from 632.56 to 710.23 ms; the paired median difference was 33.30 ms (4.94%). Both distributions have substantial variance. The normal no-restart path retains the same 500 ms supervisor polling interval, and no pending readiness jobs exist in this fixture. All 60 confirmation runs passed shutdown and descendant-cleanup checks. These measurements do not establish a shutdown regression or an overall performance pass. Both runs are retained in the JSON.

The crash-recovery fixture improved from 5486.36 to 3520.95 ms median startup. This result applies to that fixture; it is not a claim about all development runs.

Installation wall-time and peak-RSS gates passed. Warm installs remained at 67 ms median. Up-to-date installs changed from 36 to 35.5 ms median. There were no install failures.
