# lpm exec runtime benchmark suite

- Date: `2026-06-29T20:18:35.003Z`
- Git SHA: `13940ef9`
- Iterations: `10`
- Warmup iterations: `1`
- Module counts: `1, 10, 100`
- Binary: `/Users/tolga/Documents/Projects/lpm-dev/rust-client/target/release/lpm-rs`
- LPM: `lpm 0.64.0`
- Node: `v22.22.1`
- Local tsx baseline: `skipped`

Cold clears the LPM TS runtime transform cache before every measured run. Warm runs one unmeasured warmup and then reuses that transform cache.

| Runner | Scenario | Cache | Modules | Format | Project mode | Status | Iterations | Avg ms | Min ms | P50 ms | P95 ms | Max ms |
| --- | --- | --- | ---: | --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| lpm | lpm-js-cjs-modules-1 | none | 1 | commonjs | commonjs-omitted | pass | 10 | 35.40 | 32.53 | 34.16 | 39.11 | 39.11 |
| lpm | lpm-ts-cjs-modules-1 | cold | 1 | commonjs | commonjs-omitted | pass | 10 | 49.01 | 47.22 | 47.93 | 55.43 | 55.43 |
| lpm | lpm-ts-cjs-modules-1 | warm | 1 | commonjs | commonjs-omitted | pass | 10 | 37.46 | 35.83 | 37.09 | 42.24 | 42.24 |
| lpm | lpm-ts-esm-modules-1 | cold | 1 | module | module | pass | 10 | 47.38 | 46.09 | 47.50 | 48.32 | 48.32 |
| lpm | lpm-ts-esm-modules-1 | warm | 1 | module | module | pass | 10 | 36.99 | 36.47 | 36.86 | 38.31 | 38.31 |
| lpm | lpm-tsx-esm-modules-1 | cold | 1 | module | module | pass | 10 | 54.87 | 52.72 | 54.22 | 59.42 | 59.42 |
| lpm | lpm-tsx-esm-modules-1 | warm | 1 | module | module | pass | 10 | 37.75 | 36.43 | 37.40 | 39.87 | 39.87 |
| local-tsx | local-tsx-tsx-esm-modules-1 | cold | 1 | module | module | skipped: LOCAL_TSX_BIN is unset or not executable | 0 | - | - | - | - | - |
| local-tsx | local-tsx-tsx-esm-modules-1 | warm | 1 | module | module | skipped: LOCAL_TSX_BIN is unset or not executable | 0 | - | - | - | - | - |
| lpm | lpm-ts-cjs-modules-10 | cold | 10 | commonjs | commonjs-omitted | pass | 10 | 92.92 | 91.58 | 92.97 | 95.00 | 95.00 |
| lpm | lpm-ts-cjs-modules-10 | warm | 10 | commonjs | commonjs-omitted | pass | 10 | 39.06 | 37.22 | 37.93 | 46.03 | 46.03 |
| lpm | lpm-ts-esm-modules-10 | cold | 10 | module | module | pass | 10 | 92.49 | 90.31 | 91.35 | 99.70 | 99.70 |
| lpm | lpm-ts-esm-modules-10 | warm | 10 | module | module | pass | 10 | 37.77 | 36.46 | 37.73 | 38.62 | 38.62 |
| lpm | lpm-tsx-esm-modules-10 | cold | 10 | module | module | pass | 10 | 96.15 | 94.81 | 95.62 | 98.98 | 98.98 |
| lpm | lpm-tsx-esm-modules-10 | warm | 10 | module | module | pass | 10 | 40.54 | 40.21 | 40.53 | 41.00 | 41.00 |
| local-tsx | local-tsx-tsx-esm-modules-10 | cold | 10 | module | module | skipped: LOCAL_TSX_BIN is unset or not executable | 0 | - | - | - | - | - |
| local-tsx | local-tsx-tsx-esm-modules-10 | warm | 10 | module | module | skipped: LOCAL_TSX_BIN is unset or not executable | 0 | - | - | - | - | - |
| lpm | lpm-ts-cjs-modules-100 | cold | 100 | commonjs | commonjs-omitted | pass | 10 | 528.00 | 515.95 | 523.41 | 568.58 | 568.58 |
| lpm | lpm-ts-cjs-modules-100 | warm | 100 | commonjs | commonjs-omitted | pass | 10 | 46.40 | 46.02 | 46.21 | 46.98 | 46.98 |
| lpm | lpm-ts-esm-modules-100 | cold | 100 | module | module | pass | 10 | 516.51 | 510.57 | 513.98 | 524.01 | 524.01 |
| lpm | lpm-ts-esm-modules-100 | warm | 100 | module | module | pass | 10 | 44.51 | 43.81 | 44.47 | 45.36 | 45.36 |
| lpm | lpm-tsx-esm-modules-100 | cold | 100 | module | module | pass | 10 | 542.29 | 526.54 | 534.99 | 605.92 | 605.92 |
| lpm | lpm-tsx-esm-modules-100 | warm | 100 | module | module | pass | 10 | 56.88 | 53.19 | 57.37 | 59.52 | 59.52 |
| local-tsx | local-tsx-tsx-esm-modules-100 | cold | 100 | module | module | skipped: LOCAL_TSX_BIN is unset or not executable | 0 | - | - | - | - | - |
| local-tsx | local-tsx-tsx-esm-modules-100 | warm | 100 | module | module | skipped: LOCAL_TSX_BIN is unset or not executable | 0 | - | - | - | - | - |
| lpm | lpm-mts-esm-modules-10 | cold | 10 | module | commonjs-omitted | pass | 10 | 97.12 | 90.89 | 93.26 | 108.95 | 108.95 |
| lpm | lpm-mts-esm-modules-10 | warm | 10 | module | commonjs-omitted | pass | 10 | 39.00 | 37.48 | 38.03 | 44.54 | 44.54 |
| lpm | lpm-cts-cjs-modules-10 | cold | 10 | commonjs | module | pass | 10 | 91.96 | 90.74 | 91.64 | 93.74 | 93.74 |
| lpm | lpm-cts-cjs-modules-10 | warm | 10 | commonjs | module | pass | 10 | 37.42 | 36.45 | 37.27 | 38.65 | 38.65 |

Skipped local tsx rows are benchmark-only comparisons; the harness never installs or fetches tsx.

