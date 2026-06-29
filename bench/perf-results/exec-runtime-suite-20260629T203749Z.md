# lpm exec runtime benchmark suite

- Date: `2026-06-29T20:37:49.895Z`
- Source Git SHA: `2117b73f`
- Iterations: `30`
- Warmup iterations: `1`
- Module counts: `1, 10, 100`
- Binary: `/Users/tolga/Documents/Projects/lpm-dev/rust-client/target/release/lpm-rs`
- Binary source: `rebuilt release binary`
- LPM: `lpm 0.64.0`
- Node: `v22.22.1`
- Local tsx baseline: `skipped`

Cold clears the LPM TS runtime transform cache before every measured run. Warm runs one unmeasured warmup and then reuses that transform cache.

| Runner | Scenario | Cache | Modules | Format | Project mode | Status | Iterations | Avg ms | Min ms | P50 ms | P95 ms | Max ms |
| --- | --- | --- | ---: | --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| lpm | lpm-js-cjs-modules-1 | none | 1 | commonjs | commonjs-omitted | pass | 30 | 33.23 | 31.85 | 32.75 | 36.14 | 43.49 |
| lpm | lpm-ts-cjs-modules-1 | cold | 1 | commonjs | commonjs-omitted | pass | 30 | 46.83 | 45.65 | 46.55 | 48.69 | 50.00 |
| lpm | lpm-ts-cjs-modules-1 | warm | 1 | commonjs | commonjs-omitted | pass | 30 | 35.92 | 35.08 | 35.82 | 37.19 | 37.33 |
| lpm | lpm-ts-esm-modules-1 | cold | 1 | module | module | pass | 30 | 47.20 | 46.13 | 47.03 | 49.04 | 49.19 |
| lpm | lpm-ts-esm-modules-1 | warm | 1 | module | module | pass | 30 | 36.03 | 35.27 | 35.90 | 37.27 | 37.47 |
| lpm | lpm-tsx-esm-modules-1 | cold | 1 | module | module | pass | 30 | 48.10 | 47.28 | 47.89 | 49.30 | 51.33 |
| lpm | lpm-tsx-esm-modules-1 | warm | 1 | module | module | pass | 30 | 37.76 | 36.58 | 37.41 | 38.38 | 48.72 |
| local-tsx | local-tsx-tsx-esm-modules-1 | cold | 1 | module | module | skipped: LOCAL_TSX_BIN is unset or not executable | 0 | - | - | - | - | - |
| local-tsx | local-tsx-tsx-esm-modules-1 | warm | 1 | module | module | skipped: LOCAL_TSX_BIN is unset or not executable | 0 | - | - | - | - | - |
| lpm | lpm-ts-cjs-modules-10 | cold | 10 | commonjs | commonjs-omitted | pass | 30 | 93.49 | 90.73 | 93.66 | 95.72 | 97.23 |
| lpm | lpm-ts-cjs-modules-10 | warm | 10 | commonjs | commonjs-omitted | pass | 30 | 37.92 | 36.88 | 37.81 | 39.32 | 39.34 |
| lpm | lpm-ts-esm-modules-10 | cold | 10 | module | module | pass | 30 | 92.20 | 90.46 | 91.43 | 94.26 | 103.21 |
| lpm | lpm-ts-esm-modules-10 | warm | 10 | module | module | pass | 30 | 37.68 | 36.76 | 37.58 | 38.64 | 39.29 |
| lpm | lpm-tsx-esm-modules-10 | cold | 10 | module | module | pass | 30 | 95.29 | 93.16 | 94.46 | 97.75 | 100.09 |
| lpm | lpm-tsx-esm-modules-10 | warm | 10 | module | module | pass | 30 | 40.41 | 39.56 | 40.37 | 41.31 | 41.32 |
| local-tsx | local-tsx-tsx-esm-modules-10 | cold | 10 | module | module | skipped: LOCAL_TSX_BIN is unset or not executable | 0 | - | - | - | - | - |
| local-tsx | local-tsx-tsx-esm-modules-10 | warm | 10 | module | module | skipped: LOCAL_TSX_BIN is unset or not executable | 0 | - | - | - | - | - |
| lpm | lpm-ts-cjs-modules-100 | cold | 100 | commonjs | commonjs-omitted | pass | 30 | 557.41 | 514.30 | 546.45 | 675.23 | 686.14 |
| lpm | lpm-ts-cjs-modules-100 | warm | 100 | commonjs | commonjs-omitted | pass | 30 | 48.70 | 45.88 | 47.38 | 54.88 | 58.29 |
| lpm | lpm-ts-esm-modules-100 | cold | 100 | module | module | pass | 30 | 571.43 | 515.70 | 570.26 | 615.40 | 707.42 |
| lpm | lpm-ts-esm-modules-100 | warm | 100 | module | module | pass | 30 | 47.46 | 45.65 | 47.14 | 50.92 | 53.41 |
| lpm | lpm-tsx-esm-modules-100 | cold | 100 | module | module | pass | 30 | 556.35 | 528.10 | 542.57 | 603.95 | 679.69 |
| lpm | lpm-tsx-esm-modules-100 | warm | 100 | module | module | pass | 30 | 55.36 | 53.53 | 54.86 | 57.47 | 62.81 |
| local-tsx | local-tsx-tsx-esm-modules-100 | cold | 100 | module | module | skipped: LOCAL_TSX_BIN is unset or not executable | 0 | - | - | - | - | - |
| local-tsx | local-tsx-tsx-esm-modules-100 | warm | 100 | module | module | skipped: LOCAL_TSX_BIN is unset or not executable | 0 | - | - | - | - | - |
| lpm | lpm-mts-esm-modules-10 | cold | 10 | module | commonjs-omitted | pass | 30 | 100.26 | 92.54 | 95.54 | 136.80 | 141.74 |
| lpm | lpm-mts-esm-modules-10 | warm | 10 | module | commonjs-omitted | pass | 30 | 38.64 | 37.38 | 38.46 | 40.34 | 40.99 |
| lpm | lpm-cts-cjs-modules-10 | cold | 10 | commonjs | module | pass | 30 | 98.17 | 91.86 | 94.68 | 108.88 | 118.57 |
| lpm | lpm-cts-cjs-modules-10 | warm | 10 | commonjs | module | pass | 30 | 40.47 | 37.62 | 39.08 | 48.51 | 50.19 |

Skipped local tsx rows are benchmark-only comparisons; the harness never installs or fetches tsx.
