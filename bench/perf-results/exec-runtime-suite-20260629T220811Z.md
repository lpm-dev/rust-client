# lpm exec runtime benchmark suite

- Date: `2026-06-29T22:08:11.822Z`
- Source Git SHA: `025de0e9`
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

| Runner | Fixture | Entry | Cache | Modules | Format | Project mode | Status | Iterations | Avg ms | Min ms | P50 ms | P95 ms | Max ms |
| --- | --- | --- | --- | ---: | --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| node | ts-cjs-modules-1 | scripts/entry.js | cold | 1 | commonjs | commonjs-omitted | pass | 30 | 18.07 | 16.98 | 17.55 | 21.04 | 23.08 |
| node | ts-cjs-modules-1 | scripts/entry.js | warm | 1 | commonjs | commonjs-omitted | pass | 30 | 17.25 | 16.87 | 17.15 | 17.59 | 19.03 |
| bun | ts-cjs-modules-1 | scripts/entry.ts | cold | 1 | commonjs | commonjs-omitted | pass | 30 | 15.32 | 14.62 | 14.94 | 18.78 | 19.48 |
| bun | ts-cjs-modules-1 | scripts/entry.ts | warm | 1 | commonjs | commonjs-omitted | pass | 30 | 14.76 | 14.30 | 14.67 | 15.80 | 15.88 |
| lpm | ts-cjs-modules-1 | scripts/entry.ts | cold | 1 | commonjs | commonjs-omitted | pass | 30 | 46.63 | 45.41 | 46.45 | 48.09 | 48.12 |
| lpm | ts-cjs-modules-1 | scripts/entry.ts | warm | 1 | commonjs | commonjs-omitted | pass | 30 | 36.96 | 35.40 | 36.92 | 37.94 | 39.17 |
| nub | ts-cjs-modules-1 | scripts/entry.ts | cold | 1 | commonjs | commonjs-omitted | pass | 30 | 78.23 | 76.00 | 76.74 | 82.93 | 91.78 |
| nub | ts-cjs-modules-1 | scripts/entry.ts | warm | 1 | commonjs | commonjs-omitted | pass | 30 | 76.46 | 75.80 | 76.31 | 77.09 | 78.48 |
| tsx | ts-cjs-modules-1 | scripts/entry.ts | cold | 1 | commonjs | commonjs-omitted | pass | 30 | 141.25 | 139.85 | 141.13 | 142.28 | 146.48 |
| tsx | ts-cjs-modules-1 | scripts/entry.ts | warm | 1 | commonjs | commonjs-omitted | pass | 30 | 100.59 | 98.65 | 100.04 | 102.74 | 106.09 |
| node | ts-esm-modules-1 | scripts/entry.js | cold | 1 | module | module | pass | 30 | 19.16 | 18.41 | 18.87 | 21.30 | 23.41 |
| node | ts-esm-modules-1 | scripts/entry.js | warm | 1 | module | module | pass | 30 | 18.43 | 17.88 | 18.36 | 19.04 | 19.66 |
| bun | ts-esm-modules-1 | scripts/entry.ts | cold | 1 | module | module | pass | 30 | 15.07 | 14.67 | 15.00 | 15.45 | 15.72 |
| bun | ts-esm-modules-1 | scripts/entry.ts | warm | 1 | module | module | pass | 30 | 15.15 | 14.54 | 14.92 | 17.03 | 18.47 |
| lpm | ts-esm-modules-1 | scripts/entry.ts | cold | 1 | module | module | pass | 30 | 47.61 | 46.39 | 47.26 | 49.75 | 49.98 |
| lpm | ts-esm-modules-1 | scripts/entry.ts | warm | 1 | module | module | pass | 30 | 36.31 | 35.26 | 36.21 | 37.33 | 38.00 |
| nub | ts-esm-modules-1 | scripts/entry.ts | cold | 1 | module | module | pass | 30 | 79.00 | 77.29 | 78.51 | 84.37 | 84.45 |
| nub | ts-esm-modules-1 | scripts/entry.ts | warm | 1 | module | module | pass | 30 | 78.22 | 77.03 | 77.93 | 79.76 | 82.92 |
| tsx | ts-esm-modules-1 | scripts/entry.ts | cold | 1 | module | module | pass | 30 | 108.39 | 105.54 | 108.09 | 111.08 | 111.88 |
| tsx | ts-esm-modules-1 | scripts/entry.ts | warm | 1 | module | module | pass | 30 | 102.93 | 98.14 | 101.62 | 110.38 | 115.78 |
| node | tsx-esm-modules-1 | scripts/entry.js | cold | 1 | module | module | pass | 30 | 19.35 | 18.81 | 19.32 | 19.82 | 20.41 |
| node | tsx-esm-modules-1 | scripts/entry.js | warm | 1 | module | module | pass | 30 | 19.25 | 18.51 | 19.20 | 19.77 | 20.34 |
| bun | tsx-esm-modules-1 | scripts/entry.tsx | cold | 1 | module | module | pass | 30 | 15.69 | 15.30 | 15.68 | 16.04 | 16.42 |
| bun | tsx-esm-modules-1 | scripts/entry.tsx | warm | 1 | module | module | pass | 30 | 15.46 | 15.11 | 15.33 | 16.25 | 16.26 |
| lpm | tsx-esm-modules-1 | scripts/entry.tsx | cold | 1 | module | module | pass | 30 | 48.96 | 47.79 | 48.55 | 51.32 | 52.48 |
| lpm | tsx-esm-modules-1 | scripts/entry.tsx | warm | 1 | module | module | pass | 30 | 37.23 | 36.13 | 37.10 | 38.07 | 39.08 |
| nub | tsx-esm-modules-1 | scripts/entry.tsx | cold | 1 | module | module | pass | 30 | 78.68 | 77.65 | 78.59 | 80.08 | 80.65 |
| nub | tsx-esm-modules-1 | scripts/entry.tsx | warm | 1 | module | module | pass | 30 | 78.67 | 77.12 | 78.55 | 80.98 | 82.90 |
| tsx | tsx-esm-modules-1 | scripts/entry.tsx | cold | 1 | module | module | pass | 30 | 109.38 | 108.41 | 109.24 | 111.55 | 112.48 |
| tsx | tsx-esm-modules-1 | scripts/entry.tsx | warm | 1 | module | module | pass | 30 | 101.41 | 99.96 | 101.39 | 102.27 | 103.23 |
| node | ts-cjs-modules-10 | scripts/entry.js | cold | 10 | commonjs | commonjs-omitted | pass | 30 | 18.80 | 18.23 | 18.74 | 19.43 | 19.75 |
| node | ts-cjs-modules-10 | scripts/entry.js | warm | 10 | commonjs | commonjs-omitted | pass | 30 | 18.80 | 18.39 | 18.73 | 19.99 | 20.35 |
| bun | ts-cjs-modules-10 | scripts/entry.ts | cold | 10 | commonjs | commonjs-omitted | pass | 30 | 15.60 | 15.20 | 15.57 | 15.95 | 16.92 |
| bun | ts-cjs-modules-10 | scripts/entry.ts | warm | 10 | commonjs | commonjs-omitted | pass | 30 | 16.12 | 15.09 | 15.61 | 18.71 | 19.13 |
| lpm | ts-cjs-modules-10 | scripts/entry.ts | cold | 10 | commonjs | commonjs-omitted | pass | 30 | 92.68 | 90.97 | 92.43 | 94.73 | 98.34 |
| lpm | ts-cjs-modules-10 | scripts/entry.ts | warm | 10 | commonjs | commonjs-omitted | pass | 30 | 37.79 | 37.12 | 37.61 | 38.50 | 38.60 |
| nub | ts-cjs-modules-10 | scripts/entry.ts | cold | 10 | commonjs | commonjs-omitted | pass | 30 | 80.75 | 79.81 | 80.51 | 82.63 | 83.80 |
| nub | ts-cjs-modules-10 | scripts/entry.ts | warm | 10 | commonjs | commonjs-omitted | pass | 30 | 79.25 | 78.51 | 79.18 | 80.96 | 81.16 |
| tsx | ts-cjs-modules-10 | scripts/entry.ts | cold | 10 | commonjs | commonjs-omitted | pass | 30 | 151.48 | 149.59 | 151.09 | 154.49 | 155.24 |
| tsx | ts-cjs-modules-10 | scripts/entry.ts | warm | 10 | commonjs | commonjs-omitted | pass | 30 | 106.32 | 102.42 | 104.39 | 115.50 | 117.34 |
| node | ts-esm-modules-10 | scripts/entry.js | cold | 10 | module | module | pass | 30 | 20.03 | 19.63 | 19.92 | 20.72 | 20.72 |
| node | ts-esm-modules-10 | scripts/entry.js | warm | 10 | module | module | pass | 30 | 19.87 | 19.41 | 19.82 | 20.60 | 21.15 |
| bun | ts-esm-modules-10 | scripts/entry.ts | cold | 10 | module | module | pass | 30 | 15.71 | 15.20 | 15.48 | 17.35 | 19.02 |
| bun | ts-esm-modules-10 | scripts/entry.ts | warm | 10 | module | module | pass | 30 | 15.57 | 15.01 | 15.30 | 17.33 | 18.25 |
| lpm | ts-esm-modules-10 | scripts/entry.ts | cold | 10 | module | module | pass | 30 | 92.28 | 90.68 | 92.05 | 93.99 | 100.33 |
| lpm | ts-esm-modules-10 | scripts/entry.ts | warm | 10 | module | module | pass | 30 | 37.55 | 36.86 | 37.47 | 38.38 | 38.93 |
| nub | ts-esm-modules-10 | scripts/entry.ts | cold | 10 | module | module | pass | 30 | 81.45 | 80.04 | 81.04 | 84.61 | 86.70 |
| nub | ts-esm-modules-10 | scripts/entry.ts | warm | 10 | module | module | pass | 30 | 79.86 | 78.68 | 79.84 | 81.12 | 81.29 |
| tsx | ts-esm-modules-10 | scripts/entry.ts | cold | 10 | module | module | pass | 30 | 114.73 | 113.41 | 114.16 | 119.57 | 126.57 |
| tsx | ts-esm-modules-10 | scripts/entry.ts | warm | 10 | module | module | pass | 30 | 104.69 | 103.55 | 104.58 | 105.78 | 106.97 |
| node | tsx-esm-modules-10 | scripts/entry.js | cold | 10 | module | module | pass | 30 | 21.84 | 21.48 | 21.82 | 22.21 | 22.49 |
| node | tsx-esm-modules-10 | scripts/entry.js | warm | 10 | module | module | pass | 30 | 21.84 | 20.79 | 21.81 | 22.82 | 22.91 |
| bun | tsx-esm-modules-10 | scripts/entry.tsx | cold | 10 | module | module | pass | 30 | 15.42 | 15.13 | 15.39 | 15.88 | 16.03 |
| bun | tsx-esm-modules-10 | scripts/entry.tsx | warm | 10 | module | module | pass | 30 | 15.82 | 14.94 | 15.52 | 18.14 | 19.38 |
| lpm | tsx-esm-modules-10 | scripts/entry.tsx | cold | 10 | module | module | pass | 30 | 95.38 | 93.81 | 95.32 | 96.55 | 96.72 |
| lpm | tsx-esm-modules-10 | scripts/entry.tsx | warm | 10 | module | module | pass | 30 | 41.12 | 40.29 | 40.94 | 43.05 | 43.17 |
| nub | tsx-esm-modules-10 | scripts/entry.tsx | cold | 10 | module | module | pass | 30 | 82.93 | 81.90 | 82.90 | 84.02 | 84.10 |
| nub | tsx-esm-modules-10 | scripts/entry.tsx | warm | 10 | module | module | pass | 30 | 81.67 | 80.02 | 81.41 | 83.82 | 84.03 |
| tsx | tsx-esm-modules-10 | scripts/entry.tsx | cold | 10 | module | module | pass | 30 | 120.26 | 117.56 | 118.79 | 126.14 | 136.13 |
| tsx | tsx-esm-modules-10 | scripts/entry.tsx | warm | 10 | module | module | pass | 30 | 109.29 | 108.06 | 109.12 | 111.52 | 112.86 |
| node | ts-cjs-modules-100 | scripts/entry.js | cold | 100 | commonjs | commonjs-omitted | pass | 30 | 24.02 | 23.47 | 23.99 | 24.75 | 25.15 |
| node | ts-cjs-modules-100 | scripts/entry.js | warm | 100 | commonjs | commonjs-omitted | pass | 30 | 23.30 | 22.70 | 23.30 | 23.62 | 23.92 |
| bun | ts-cjs-modules-100 | scripts/entry.ts | cold | 100 | commonjs | commonjs-omitted | pass | 30 | 18.66 | 17.97 | 18.48 | 19.84 | 21.66 |
| bun | ts-cjs-modules-100 | scripts/entry.ts | warm | 100 | commonjs | commonjs-omitted | pass | 30 | 17.84 | 17.37 | 17.62 | 19.14 | 20.70 |
| lpm | ts-cjs-modules-100 | scripts/entry.ts | cold | 100 | commonjs | commonjs-omitted | pass | 30 | 526.66 | 516.60 | 524.46 | 542.86 | 544.69 |
| lpm | ts-cjs-modules-100 | scripts/entry.ts | warm | 100 | commonjs | commonjs-omitted | pass | 30 | 46.79 | 46.10 | 46.68 | 47.50 | 47.58 |
| nub | ts-cjs-modules-100 | scripts/entry.ts | cold | 100 | commonjs | commonjs-omitted | pass | 30 | 102.97 | 100.53 | 102.59 | 105.84 | 106.24 |
| nub | ts-cjs-modules-100 | scripts/entry.ts | warm | 100 | commonjs | commonjs-omitted | pass | 30 | 90.08 | 88.95 | 89.94 | 91.84 | 92.03 |
| tsx | ts-cjs-modules-100 | scripts/entry.ts | cold | 100 | commonjs | commonjs-omitted | pass | 30 | 213.87 | 209.83 | 211.70 | 228.44 | 233.90 |
| tsx | ts-cjs-modules-100 | scripts/entry.ts | warm | 100 | commonjs | commonjs-omitted | pass | 30 | 123.90 | 121.74 | 123.41 | 128.27 | 130.58 |
| node | ts-esm-modules-100 | scripts/entry.js | cold | 100 | module | module | pass | 30 | 25.80 | 25.20 | 25.72 | 26.19 | 27.93 |
| node | ts-esm-modules-100 | scripts/entry.js | warm | 100 | module | module | pass | 30 | 25.02 | 24.30 | 24.97 | 25.70 | 25.77 |
| bun | ts-esm-modules-100 | scripts/entry.ts | cold | 100 | module | module | pass | 30 | 18.19 | 17.59 | 17.95 | 19.23 | 19.82 |
| bun | ts-esm-modules-100 | scripts/entry.ts | warm | 100 | module | module | pass | 30 | 16.73 | 16.44 | 16.69 | 17.35 | 17.49 |
| lpm | ts-esm-modules-100 | scripts/entry.ts | cold | 100 | module | module | pass | 30 | 518.53 | 493.56 | 518.83 | 531.45 | 531.53 |
| lpm | ts-esm-modules-100 | scripts/entry.ts | warm | 100 | module | module | pass | 30 | 45.25 | 44.45 | 45.16 | 46.24 | 46.45 |
| nub | ts-esm-modules-100 | scripts/entry.ts | cold | 100 | module | module | pass | 30 | 101.97 | 100.47 | 101.59 | 103.95 | 109.78 |
| nub | ts-esm-modules-100 | scripts/entry.ts | warm | 100 | module | module | pass | 30 | 91.71 | 89.34 | 90.59 | 96.67 | 105.85 |
| tsx | ts-esm-modules-100 | scripts/entry.ts | cold | 100 | module | module | pass | 30 | 147.26 | 145.05 | 146.80 | 151.05 | 156.53 |
| tsx | ts-esm-modules-100 | scripts/entry.ts | warm | 100 | module | module | pass | 30 | 128.12 | 126.49 | 128.02 | 130.06 | 130.90 |
| node | tsx-esm-modules-100 | scripts/entry.js | cold | 100 | module | module | pass | 30 | 29.81 | 29.23 | 29.83 | 30.35 | 30.65 |
| node | tsx-esm-modules-100 | scripts/entry.js | warm | 100 | module | module | pass | 30 | 29.06 | 28.60 | 28.97 | 29.83 | 30.93 |
| bun | tsx-esm-modules-100 | scripts/entry.tsx | cold | 100 | module | module | pass | 30 | 18.69 | 18.15 | 18.54 | 19.90 | 21.92 |
| bun | tsx-esm-modules-100 | scripts/entry.tsx | warm | 100 | module | module | pass | 30 | 17.44 | 16.89 | 17.42 | 18.04 | 18.49 |
| lpm | tsx-esm-modules-100 | scripts/entry.tsx | cold | 100 | module | module | pass | 30 | 529.72 | 522.18 | 528.58 | 540.52 | 551.12 |
| lpm | tsx-esm-modules-100 | scripts/entry.tsx | warm | 100 | module | module | pass | 30 | 54.06 | 53.07 | 53.78 | 55.58 | 56.73 |
| nub | tsx-esm-modules-100 | scripts/entry.tsx | cold | 100 | module | module | pass | 30 | 106.67 | 104.65 | 106.48 | 108.78 | 111.02 |
| nub | tsx-esm-modules-100 | scripts/entry.tsx | warm | 100 | module | module | pass | 30 | 94.34 | 91.50 | 94.36 | 96.15 | 96.51 |
| tsx | tsx-esm-modules-100 | scripts/entry.tsx | cold | 100 | module | module | pass | 30 | 176.45 | 173.23 | 175.39 | 187.70 | 189.82 |
| tsx | tsx-esm-modules-100 | scripts/entry.tsx | warm | 100 | module | module | pass | 30 | 157.67 | 156.13 | 157.54 | 158.71 | 159.54 |
| lpm | mts-esm-modules-10 | scripts/entry.mts | cold | 10 | module | commonjs-omitted | pass | 30 | 93.89 | 92.13 | 93.62 | 95.85 | 100.84 |
| lpm | mts-esm-modules-10 | scripts/entry.mts | warm | 10 | module | commonjs-omitted | pass | 30 | 38.03 | 37.03 | 38.06 | 38.64 | 39.26 |
| lpm | cts-cjs-modules-10 | scripts/entry.cts | cold | 10 | commonjs | module | pass | 30 | 93.59 | 91.66 | 93.39 | 95.55 | 99.69 |
| lpm | cts-cjs-modules-10 | scripts/entry.cts | warm | 10 | commonjs | module | pass | 30 | 37.72 | 37.07 | 37.60 | 38.73 | 38.81 |

Skipped Bun/Nub/tsx rows are benchmark-only comparisons; the harness never installs or fetches comparison tools.
