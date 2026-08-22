# Archive entry and depth limits — install readiness

## Result

The paired production-readiness comparison passed. All 90 installs completed, no run produced an unexpected warning, and no wall-time or peak-RSS landing threshold regressed.

## Method

- Baseline source: `origin/main` at `61dacfa886c451aef49a49ea7849b3235e59623e`
- Baseline binary SHA-256: `78c919f2951b3f57bd246cff05b95904d5a38aafdb049dac0c7c5b5dd1689772`
- Candidate binary SHA-256: `3db75bc5554f0598ea85681104362b9bb1701a3fe76e42e1a8d8d9ae3e03fb3d`
- Toolchain: Rust 1.94.0, optimized release profile with LTO
- Harness: `bench/scripts/run-install-readiness.mjs`
- Fixtures: dogfood, Nest, and VitePress
- Modes: cold, lockfile-and-cache warm, and up to date
- Samples: five adjacent baseline/candidate pairs per fixture and mode, alternating AB/BA order
- Wall thresholds: 5% and 20 ms at the median; 10% and 50 ms at p95
- Peak-RSS thresholds: 5% and 16 MiB at the median; 10% and 32 MiB at p95

Command:

```bash
node bench/scripts/run-install-readiness.mjs \
  --samples 5 \
  --fixtures dogfood,nest,vitepress \
  --managers lpm \
  --modes cold,warm,up-to-date \
  --lpm-binary main=/tmp/lpm-area1-bench-binaries/main-lpm-rs \
  --lpm-binary candidate=/tmp/lpm-area1-bench-binaries/candidate-lpm-rs \
  --lpm-compare main:candidate \
  --rss-median-regression-pct 5 \
  --rss-median-regression-mb 16
```

## Median results

| Fixture | Mode | Baseline wall | Candidate wall | Baseline peak RSS | Candidate peak RSS |
| --- | --- | ---: | ---: | ---: | ---: |
| dogfood | cold | 1,134 ms | 1,018 ms | 448.91 MiB | 451.11 MiB |
| dogfood | warm | 100 ms | 101 ms | 49.48 MiB | 48.95 MiB |
| dogfood | up to date | 30 ms | 30 ms | 24.11 MiB | 23.66 MiB |
| Nest | cold | 492 ms | 485 ms | 126.23 MiB | 127.80 MiB |
| Nest | warm | 46 ms | 45 ms | 38.08 MiB | 37.88 MiB |
| Nest | up to date | 22 ms | 22 ms | 21.30 MiB | 21.39 MiB |
| VitePress | cold | 954 ms | 893 ms | 485.31 MiB | 479.81 MiB |
| VitePress | warm | 74 ms | 75 ms | 49.22 MiB | 49.25 MiB |
| VitePress | up to date | 28 ms | 28 ms | 23.50 MiB | 23.97 MiB |

The Nest cold fetch substage was slower in the candidate samples, while its resolve stage and total wall time were faster. Archive-limit changes do not alter metadata routing or resolution, and the paired landing verdict remained a pass. The cold runs used the live registry, so the report treats the opposing substage movement as network variance rather than an extraction regression.
