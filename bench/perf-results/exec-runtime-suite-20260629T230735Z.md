# lpm exec runtime benchmark suite

- Date: `2026-06-29T23:07:36.183Z`
- Source Git SHA: `a57a14db`
- Iterations: `30`
- Warmup iterations: `1`
- Module counts: `1, 10, 100`
- Binary: `/Users/tolga/Documents/Projects/lpm-dev/rust-client/target/release/lpm-rs`
- Binary source: `rebuilt release binary`
- LPM: `lpm 0.64.0`
- Node: `v22.22.1` via `/Users/tolga/.n/bin/node`
- Node source: `current Node process`
- Bun: `1.3.14`
- Bun binary: `/Users/tolga/.bun/bin/bun`
- Nub: `v0.2.9`
- Nub binary: `/tmp/lpm-bench-tools/node_modules/.bin/nub`
- tsx: `tsx v4.19.4 node v22.22.1`
- tsx binary: `/tmp/lpm-bench-tools/node_modules/.bin/tsx`

Each comparison fixture uses the same generated module graph: `node` runs the JS baseline, while `bun`, `lpm`, `nub`, and `tsx` run the matching TS/TSX source.
Cold clears the runner's transform cache before every measured run. Warm runs 1 unmeasured warmup iteration(s) and then reuses that cache.
`lpm-oxc-helper` rows run `lpm-rs internal-ts-transform` directly through the same stdin/stdout JSON protocol the LPM TS loader uses on cache misses.

| Runner | Fixture | Entry | Cache | Modules | Helper calls | Format | Project mode | Status | Iterations | Avg ms | Min ms | P50 ms | P50/call ms | P95 ms | Max ms |
| --- | --- | --- | --- | ---: | ---: | --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| node | ts-cjs-modules-1 | scripts/entry.js | cold | 1 | - | commonjs | commonjs-omitted | pass | 30 | 18.24 | 17.25 | 17.84 | - | 19.27 | 24.97 |
| node | ts-cjs-modules-1 | scripts/entry.js | warm | 1 | - | commonjs | commonjs-omitted | pass | 30 | 18.26 | 16.86 | 17.86 | - | 20.10 | 23.36 |
| bun | ts-cjs-modules-1 | scripts/entry.ts | cold | 1 | - | commonjs | commonjs-omitted | pass | 30 | 16.04 | 14.66 | 15.83 | - | 17.56 | 20.14 |
| bun | ts-cjs-modules-1 | scripts/entry.ts | warm | 1 | - | commonjs | commonjs-omitted | pass | 30 | 14.71 | 13.80 | 14.24 | - | 16.31 | 16.39 |
| lpm | ts-cjs-modules-1 | scripts/entry.ts | cold | 1 | - | commonjs | commonjs-omitted | pass | 30 | 47.46 | 43.97 | 45.87 | - | 60.31 | 63.35 |
| lpm | ts-cjs-modules-1 | scripts/entry.ts | warm | 1 | - | commonjs | commonjs-omitted | pass | 30 | 37.24 | 33.54 | 36.37 | - | 43.06 | 47.78 |
| nub | ts-cjs-modules-1 | scripts/entry.ts | cold | 1 | - | commonjs | commonjs-omitted | pass | 30 | 78.00 | 75.06 | 76.63 | - | 83.49 | 84.24 |
| nub | ts-cjs-modules-1 | scripts/entry.ts | warm | 1 | - | commonjs | commonjs-omitted | pass | 30 | 76.35 | 74.27 | 75.79 | - | 79.40 | 80.26 |
| tsx | ts-cjs-modules-1 | scripts/entry.ts | cold | 1 | - | commonjs | commonjs-omitted | pass | 30 | 138.89 | 136.84 | 138.92 | - | 140.78 | 143.06 |
| tsx | ts-cjs-modules-1 | scripts/entry.ts | warm | 1 | - | commonjs | commonjs-omitted | pass | 30 | 102.86 | 97.56 | 98.45 | - | 132.05 | 134.14 |
| node | ts-esm-modules-1 | scripts/entry.js | cold | 1 | - | module | module | pass | 30 | 17.77 | 17.35 | 17.70 | - | 18.55 | 18.68 |
| node | ts-esm-modules-1 | scripts/entry.js | warm | 1 | - | module | module | pass | 30 | 17.66 | 17.16 | 17.58 | - | 18.49 | 18.54 |
| bun | ts-esm-modules-1 | scripts/entry.ts | cold | 1 | - | module | module | pass | 30 | 14.47 | 14.04 | 14.29 | - | 15.56 | 15.80 |
| bun | ts-esm-modules-1 | scripts/entry.ts | warm | 1 | - | module | module | pass | 30 | 14.37 | 13.89 | 14.39 | - | 14.85 | 15.03 |
| lpm | ts-esm-modules-1 | scripts/entry.ts | cold | 1 | - | module | module | pass | 30 | 46.24 | 44.19 | 46.10 | - | 48.90 | 55.07 |
| lpm | ts-esm-modules-1 | scripts/entry.ts | warm | 1 | - | module | module | pass | 30 | 35.88 | 34.41 | 35.07 | - | 38.69 | 51.24 |
| nub | ts-esm-modules-1 | scripts/entry.ts | cold | 1 | - | module | module | pass | 30 | 81.38 | 78.47 | 80.91 | - | 84.21 | 85.24 |
| nub | ts-esm-modules-1 | scripts/entry.ts | warm | 1 | - | module | module | pass | 30 | 79.04 | 77.79 | 78.81 | - | 80.19 | 80.60 |
| tsx | ts-esm-modules-1 | scripts/entry.ts | cold | 1 | - | module | module | pass | 30 | 110.20 | 107.88 | 109.27 | - | 117.30 | 117.91 |
| tsx | ts-esm-modules-1 | scripts/entry.ts | warm | 1 | - | module | module | pass | 30 | 102.76 | 100.65 | 102.07 | - | 108.51 | 108.78 |
| node | tsx-esm-modules-1 | scripts/entry.js | cold | 1 | - | module | module | pass | 30 | 19.75 | 19.10 | 19.65 | - | 20.62 | 20.78 |
| node | tsx-esm-modules-1 | scripts/entry.js | warm | 1 | - | module | module | pass | 30 | 19.64 | 19.13 | 19.63 | - | 20.00 | 20.03 |
| bun | tsx-esm-modules-1 | scripts/entry.tsx | cold | 1 | - | module | module | pass | 30 | 15.63 | 15.05 | 15.56 | - | 16.17 | 16.62 |
| bun | tsx-esm-modules-1 | scripts/entry.tsx | warm | 1 | - | module | module | pass | 30 | 15.34 | 14.78 | 15.30 | - | 15.90 | 16.18 |
| lpm | tsx-esm-modules-1 | scripts/entry.tsx | cold | 1 | - | module | module | pass | 30 | 49.74 | 48.17 | 49.02 | - | 53.45 | 63.85 |
| lpm | tsx-esm-modules-1 | scripts/entry.tsx | warm | 1 | - | module | module | pass | 30 | 37.95 | 36.51 | 37.89 | - | 39.09 | 39.34 |
| nub | tsx-esm-modules-1 | scripts/entry.tsx | cold | 1 | - | module | module | pass | 30 | 80.08 | 79.03 | 79.83 | - | 82.05 | 82.13 |
| nub | tsx-esm-modules-1 | scripts/entry.tsx | warm | 1 | - | module | module | pass | 30 | 79.44 | 78.71 | 79.34 | - | 80.12 | 80.61 |
| tsx | tsx-esm-modules-1 | scripts/entry.tsx | cold | 1 | - | module | module | pass | 30 | 111.26 | 109.55 | 110.71 | - | 114.50 | 117.17 |
| tsx | tsx-esm-modules-1 | scripts/entry.tsx | warm | 1 | - | module | module | pass | 30 | 103.14 | 102.16 | 103.00 | - | 103.94 | 106.95 |
| lpm-oxc-helper | oxc-helper-ts-cjs-files-1 | internal-ts-transform | none | 1 | 1 | commonjs | commonjs-omitted | pass | 30 | 4.67 | 4.04 | 4.68 | 4.68 | 5.09 | 5.25 |
| lpm-oxc-helper | oxc-helper-ts-esm-files-1 | internal-ts-transform | none | 1 | 1 | module | module | pass | 30 | 4.59 | 3.96 | 4.55 | 4.55 | 5.40 | 5.90 |
| lpm-oxc-helper | oxc-helper-tsx-esm-files-1 | internal-ts-transform | none | 1 | 1 | module | module | pass | 30 | 4.64 | 4.16 | 4.60 | 4.60 | 5.14 | 5.30 |
| node | ts-cjs-modules-10 | scripts/entry.js | cold | 10 | - | commonjs | commonjs-omitted | pass | 30 | 19.27 | 18.89 | 19.22 | - | 19.60 | 19.76 |
| node | ts-cjs-modules-10 | scripts/entry.js | warm | 10 | - | commonjs | commonjs-omitted | pass | 30 | 19.09 | 18.69 | 19.09 | - | 19.53 | 19.94 |
| bun | ts-cjs-modules-10 | scripts/entry.ts | cold | 10 | - | commonjs | commonjs-omitted | pass | 30 | 15.80 | 15.17 | 15.58 | - | 16.82 | 20.54 |
| bun | ts-cjs-modules-10 | scripts/entry.ts | warm | 10 | - | commonjs | commonjs-omitted | pass | 30 | 15.55 | 15.09 | 15.40 | - | 17.20 | 17.67 |
| lpm | ts-cjs-modules-10 | scripts/entry.ts | cold | 10 | - | commonjs | commonjs-omitted | pass | 30 | 94.14 | 92.26 | 93.89 | - | 96.01 | 101.57 |
| lpm | ts-cjs-modules-10 | scripts/entry.ts | warm | 10 | - | commonjs | commonjs-omitted | pass | 30 | 38.39 | 37.35 | 38.39 | - | 39.03 | 39.08 |
| nub | ts-cjs-modules-10 | scripts/entry.ts | cold | 10 | - | commonjs | commonjs-omitted | pass | 30 | 81.76 | 80.85 | 81.57 | - | 82.74 | 83.61 |
| nub | ts-cjs-modules-10 | scripts/entry.ts | warm | 10 | - | commonjs | commonjs-omitted | pass | 30 | 80.86 | 78.65 | 80.44 | - | 85.31 | 89.97 |
| tsx | ts-cjs-modules-10 | scripts/entry.ts | cold | 10 | - | commonjs | commonjs-omitted | pass | 30 | 155.85 | 152.01 | 153.27 | - | 179.57 | 181.94 |
| tsx | ts-cjs-modules-10 | scripts/entry.ts | warm | 10 | - | commonjs | commonjs-omitted | pass | 30 | 105.09 | 103.81 | 105.16 | - | 105.70 | 105.76 |
| node | ts-esm-modules-10 | scripts/entry.js | cold | 10 | - | module | module | pass | 30 | 20.70 | 20.19 | 20.64 | - | 21.33 | 21.40 |
| node | ts-esm-modules-10 | scripts/entry.js | warm | 10 | - | module | module | pass | 30 | 20.56 | 19.86 | 20.32 | - | 22.12 | 24.68 |
| bun | ts-esm-modules-10 | scripts/entry.ts | cold | 10 | - | module | module | pass | 30 | 15.53 | 15.18 | 15.51 | - | 15.81 | 16.63 |
| bun | ts-esm-modules-10 | scripts/entry.ts | warm | 10 | - | module | module | pass | 30 | 15.31 | 14.99 | 15.25 | - | 15.85 | 15.87 |
| lpm | ts-esm-modules-10 | scripts/entry.ts | cold | 10 | - | module | module | pass | 30 | 93.26 | 91.32 | 92.88 | - | 95.08 | 98.12 |
| lpm | ts-esm-modules-10 | scripts/entry.ts | warm | 10 | - | module | module | pass | 30 | 38.34 | 37.48 | 38.14 | - | 39.86 | 39.96 |
| nub | ts-esm-modules-10 | scripts/entry.ts | cold | 10 | - | module | module | pass | 30 | 82.08 | 80.39 | 82.17 | - | 82.87 | 83.05 |
| nub | ts-esm-modules-10 | scripts/entry.ts | warm | 10 | - | module | module | pass | 30 | 80.91 | 79.97 | 80.77 | - | 82.14 | 82.95 |
| tsx | ts-esm-modules-10 | scripts/entry.ts | cold | 10 | - | module | module | pass | 30 | 115.24 | 113.37 | 115.33 | - | 116.36 | 116.56 |
| tsx | ts-esm-modules-10 | scripts/entry.ts | warm | 10 | - | module | module | pass | 30 | 106.19 | 104.74 | 105.73 | - | 109.36 | 114.41 |
| node | tsx-esm-modules-10 | scripts/entry.js | cold | 10 | - | module | module | pass | 30 | 22.17 | 21.78 | 22.14 | - | 22.62 | 23.09 |
| node | tsx-esm-modules-10 | scripts/entry.js | warm | 10 | - | module | module | pass | 30 | 22.07 | 21.45 | 22.03 | - | 22.38 | 23.66 |
| bun | tsx-esm-modules-10 | scripts/entry.tsx | cold | 10 | - | module | module | pass | 30 | 15.98 | 15.59 | 15.96 | - | 16.57 | 16.72 |
| bun | tsx-esm-modules-10 | scripts/entry.tsx | warm | 10 | - | module | module | pass | 30 | 15.52 | 15.05 | 15.55 | - | 15.84 | 16.19 |
| lpm | tsx-esm-modules-10 | scripts/entry.tsx | cold | 10 | - | module | module | pass | 30 | 96.69 | 94.65 | 96.48 | - | 100.17 | 101.04 |
| lpm | tsx-esm-modules-10 | scripts/entry.tsx | warm | 10 | - | module | module | pass | 30 | 41.40 | 40.52 | 41.34 | - | 42.40 | 42.80 |
| nub | tsx-esm-modules-10 | scripts/entry.tsx | cold | 10 | - | module | module | pass | 30 | 84.44 | 82.74 | 83.67 | - | 87.03 | 97.95 |
| nub | tsx-esm-modules-10 | scripts/entry.tsx | warm | 10 | - | module | module | pass | 30 | 84.41 | 81.35 | 82.45 | - | 94.34 | 102.44 |
| tsx | tsx-esm-modules-10 | scripts/entry.tsx | cold | 10 | - | module | module | pass | 30 | 119.72 | 118.36 | 119.67 | - | 122.24 | 122.95 |
| tsx | tsx-esm-modules-10 | scripts/entry.tsx | warm | 10 | - | module | module | pass | 30 | 110.26 | 108.95 | 110.06 | - | 112.96 | 113.08 |
| lpm-oxc-helper | oxc-helper-ts-cjs-files-10 | internal-ts-transform | none | 10 | 10 | commonjs | commonjs-omitted | pass | 30 | 43.78 | 42.45 | 43.41 | 4.34 | 46.05 | 51.71 |
| lpm-oxc-helper | oxc-helper-ts-esm-files-10 | internal-ts-transform | none | 10 | 10 | module | module | pass | 30 | 43.69 | 41.92 | 43.62 | 4.36 | 45.66 | 46.36 |
| lpm-oxc-helper | oxc-helper-tsx-esm-files-10 | internal-ts-transform | none | 10 | 10 | module | module | pass | 30 | 43.25 | 42.11 | 43.29 | 4.33 | 44.44 | 45.03 |
| node | ts-cjs-modules-100 | scripts/entry.js | cold | 100 | - | commonjs | commonjs-omitted | pass | 30 | 24.32 | 23.59 | 24.24 | - | 25.11 | 25.73 |
| node | ts-cjs-modules-100 | scripts/entry.js | warm | 100 | - | commonjs | commonjs-omitted | pass | 30 | 23.52 | 23.12 | 23.55 | - | 23.87 | 23.95 |
| bun | ts-cjs-modules-100 | scripts/entry.ts | cold | 100 | - | commonjs | commonjs-omitted | pass | 30 | 18.87 | 18.47 | 18.69 | - | 20.49 | 21.48 |
| bun | ts-cjs-modules-100 | scripts/entry.ts | warm | 100 | - | commonjs | commonjs-omitted | pass | 30 | 17.76 | 17.33 | 17.68 | - | 18.10 | 18.92 |
| lpm | ts-cjs-modules-100 | scripts/entry.ts | cold | 100 | - | commonjs | commonjs-omitted | pass | 30 | 530.65 | 522.39 | 530.08 | - | 541.75 | 549.82 |
| lpm | ts-cjs-modules-100 | scripts/entry.ts | warm | 100 | - | commonjs | commonjs-omitted | pass | 30 | 46.95 | 46.19 | 47.03 | - | 47.65 | 47.68 |
| nub | ts-cjs-modules-100 | scripts/entry.ts | cold | 100 | - | commonjs | commonjs-omitted | pass | 30 | 103.87 | 101.27 | 102.26 | - | 107.64 | 124.68 |
| nub | ts-cjs-modules-100 | scripts/entry.ts | warm | 100 | - | commonjs | commonjs-omitted | pass | 30 | 90.80 | 89.99 | 90.70 | - | 92.26 | 92.90 |
| tsx | ts-cjs-modules-100 | scripts/entry.ts | cold | 100 | - | commonjs | commonjs-omitted | pass | 30 | 212.57 | 209.82 | 212.21 | - | 217.41 | 220.42 |
| tsx | ts-cjs-modules-100 | scripts/entry.ts | warm | 100 | - | commonjs | commonjs-omitted | pass | 30 | 125.75 | 121.79 | 124.12 | - | 135.83 | 137.28 |
| node | ts-esm-modules-100 | scripts/entry.js | cold | 100 | - | module | module | pass | 30 | 25.93 | 25.43 | 25.90 | - | 26.43 | 26.74 |
| node | ts-esm-modules-100 | scripts/entry.js | warm | 100 | - | module | module | pass | 30 | 25.13 | 24.30 | 25.05 | - | 25.65 | 27.58 |
| bun | ts-esm-modules-100 | scripts/entry.ts | cold | 100 | - | module | module | pass | 30 | 17.90 | 17.40 | 17.71 | - | 19.38 | 19.94 |
| bun | ts-esm-modules-100 | scripts/entry.ts | warm | 100 | - | module | module | pass | 30 | 17.23 | 16.39 | 16.76 | - | 20.94 | 23.76 |
| lpm | ts-esm-modules-100 | scripts/entry.ts | cold | 100 | - | module | module | pass | 30 | 527.93 | 512.63 | 522.24 | - | 577.50 | 598.96 |
| lpm | ts-esm-modules-100 | scripts/entry.ts | warm | 100 | - | module | module | pass | 30 | 45.66 | 44.91 | 45.50 | - | 47.33 | 47.53 |
| nub | ts-esm-modules-100 | scripts/entry.ts | cold | 100 | - | module | module | pass | 30 | 101.92 | 100.93 | 101.82 | - | 102.83 | 103.12 |
| nub | ts-esm-modules-100 | scripts/entry.ts | warm | 100 | - | module | module | pass | 30 | 90.85 | 89.75 | 90.27 | - | 94.39 | 97.37 |
| tsx | ts-esm-modules-100 | scripts/entry.ts | cold | 100 | - | module | module | pass | 30 | 146.96 | 144.74 | 146.17 | - | 151.05 | 153.57 |
| tsx | ts-esm-modules-100 | scripts/entry.ts | warm | 100 | - | module | module | pass | 30 | 128.59 | 126.92 | 128.39 | - | 131.16 | 131.48 |
| node | tsx-esm-modules-100 | scripts/entry.js | cold | 100 | - | module | module | pass | 30 | 30.24 | 29.56 | 30.16 | - | 31.06 | 31.41 |
| node | tsx-esm-modules-100 | scripts/entry.js | warm | 100 | - | module | module | pass | 30 | 29.17 | 28.75 | 29.17 | - | 29.53 | 30.11 |
| bun | tsx-esm-modules-100 | scripts/entry.tsx | cold | 100 | - | module | module | pass | 30 | 18.69 | 17.98 | 18.65 | - | 20.18 | 20.32 |
| bun | tsx-esm-modules-100 | scripts/entry.tsx | warm | 100 | - | module | module | pass | 30 | 17.63 | 17.31 | 17.57 | - | 18.13 | 18.17 |
| lpm | tsx-esm-modules-100 | scripts/entry.tsx | cold | 100 | - | module | module | pass | 30 | 540.81 | 526.92 | 535.11 | - | 558.18 | 637.79 |
| lpm | tsx-esm-modules-100 | scripts/entry.tsx | warm | 100 | - | module | module | pass | 30 | 54.25 | 53.18 | 54.17 | - | 55.36 | 56.30 |
| nub | tsx-esm-modules-100 | scripts/entry.tsx | cold | 100 | - | module | module | pass | 30 | 106.93 | 105.41 | 106.72 | - | 108.72 | 108.83 |
| nub | tsx-esm-modules-100 | scripts/entry.tsx | warm | 100 | - | module | module | pass | 30 | 94.92 | 94.05 | 94.77 | - | 96.16 | 97.62 |
| tsx | tsx-esm-modules-100 | scripts/entry.tsx | cold | 100 | - | module | module | pass | 30 | 176.06 | 173.60 | 176.04 | - | 177.40 | 179.55 |
| tsx | tsx-esm-modules-100 | scripts/entry.tsx | warm | 100 | - | module | module | pass | 30 | 158.53 | 156.54 | 158.26 | - | 160.78 | 161.61 |
| lpm-oxc-helper | oxc-helper-ts-cjs-files-100 | internal-ts-transform | none | 100 | 100 | commonjs | commonjs-omitted | pass | 30 | 437.51 | 424.52 | 432.45 | 4.32 | 466.45 | 486.61 |
| lpm-oxc-helper | oxc-helper-ts-esm-files-100 | internal-ts-transform | none | 100 | 100 | module | module | pass | 30 | 431.62 | 424.59 | 429.07 | 4.29 | 450.25 | 453.22 |
| lpm-oxc-helper | oxc-helper-tsx-esm-files-100 | internal-ts-transform | none | 100 | 100 | module | module | pass | 30 | 434.87 | 427.88 | 432.33 | 4.32 | 453.92 | 454.23 |
| lpm | mts-esm-modules-10 | scripts/entry.mts | cold | 10 | - | module | commonjs-omitted | pass | 30 | 93.15 | 90.66 | 92.36 | - | 98.26 | 98.48 |
| lpm | mts-esm-modules-10 | scripts/entry.mts | warm | 10 | - | module | commonjs-omitted | pass | 30 | 37.98 | 37.16 | 37.90 | - | 38.62 | 38.94 |
| lpm | cts-cjs-modules-10 | scripts/entry.cts | cold | 10 | - | commonjs | module | pass | 30 | 96.63 | 90.87 | 93.96 | - | 111.54 | 115.53 |
| lpm | cts-cjs-modules-10 | scripts/entry.cts | warm | 10 | - | commonjs | module | pass | 30 | 37.79 | 36.70 | 37.81 | - | 38.42 | 38.76 |

Skipped Bun/Nub/tsx rows are benchmark-only comparisons; the harness never installs or fetches comparison tools.
