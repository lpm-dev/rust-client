# lpm exec runtime benchmark suite

- Date: `2026-06-29T23:30:39.420Z`
- Source Git SHA: `03726d5a`
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
`lpm-oxc-helper` rows run one transform helper process per file. `lpm-oxc-helper-persistent` rows run one `internal-ts-transform --persistent` process for the whole module set.

| Runner | Fixture | Entry | Cache | Modules | Helper calls | Format | Project mode | Status | Iterations | Avg ms | Min ms | P50 ms | P50/call ms | P95 ms | Max ms |
| --- | --- | --- | --- | ---: | ---: | --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| node | ts-cjs-modules-1 | scripts/entry.js | cold | 1 | - | commonjs | commonjs-omitted | pass | 30 | 17.32 | 16.99 | 17.26 | - | 17.86 | 17.88 |
| node | ts-cjs-modules-1 | scripts/entry.js | warm | 1 | - | commonjs | commonjs-omitted | pass | 30 | 17.23 | 16.83 | 17.17 | - | 17.90 | 18.65 |
| bun | ts-cjs-modules-1 | scripts/entry.ts | cold | 1 | - | commonjs | commonjs-omitted | pass | 30 | 14.73 | 14.43 | 14.70 | - | 15.04 | 15.05 |
| bun | ts-cjs-modules-1 | scripts/entry.ts | warm | 1 | - | commonjs | commonjs-omitted | pass | 30 | 14.44 | 14.18 | 14.40 | - | 14.86 | 15.15 |
| lpm | ts-cjs-modules-1 | scripts/entry.ts | cold | 1 | - | commonjs | commonjs-omitted | pass | 30 | 57.66 | 56.34 | 57.57 | - | 58.76 | 58.78 |
| lpm | ts-cjs-modules-1 | scripts/entry.ts | warm | 1 | - | commonjs | commonjs-omitted | pass | 30 | 35.92 | 34.93 | 35.75 | - | 37.31 | 38.40 |
| nub | ts-cjs-modules-1 | scripts/entry.ts | cold | 1 | - | commonjs | commonjs-omitted | pass | 30 | 77.63 | 76.18 | 77.33 | - | 80.80 | 81.54 |
| nub | ts-cjs-modules-1 | scripts/entry.ts | warm | 1 | - | commonjs | commonjs-omitted | pass | 30 | 77.03 | 75.91 | 76.91 | - | 77.98 | 79.41 |
| tsx | ts-cjs-modules-1 | scripts/entry.ts | cold | 1 | - | commonjs | commonjs-omitted | pass | 30 | 142.03 | 140.54 | 141.88 | - | 143.51 | 146.38 |
| tsx | ts-cjs-modules-1 | scripts/entry.ts | warm | 1 | - | commonjs | commonjs-omitted | pass | 30 | 100.61 | 99.29 | 100.40 | - | 101.39 | 104.09 |
| node | ts-esm-modules-1 | scripts/entry.js | cold | 1 | - | module | module | pass | 30 | 18.72 | 18.07 | 18.53 | - | 21.07 | 21.23 |
| node | ts-esm-modules-1 | scripts/entry.js | warm | 1 | - | module | module | pass | 30 | 18.26 | 17.97 | 18.26 | - | 18.58 | 18.81 |
| bun | ts-esm-modules-1 | scripts/entry.ts | cold | 1 | - | module | module | pass | 30 | 14.76 | 14.41 | 14.62 | - | 15.60 | 16.04 |
| bun | ts-esm-modules-1 | scripts/entry.ts | warm | 1 | - | module | module | pass | 30 | 14.57 | 14.17 | 14.53 | - | 15.10 | 15.15 |
| lpm | ts-esm-modules-1 | scripts/entry.ts | cold | 1 | - | module | module | pass | 30 | 58.01 | 57.06 | 57.96 | - | 58.74 | 58.75 |
| lpm | ts-esm-modules-1 | scripts/entry.ts | warm | 1 | - | module | module | pass | 30 | 36.51 | 35.67 | 36.38 | - | 37.17 | 39.89 |
| nub | ts-esm-modules-1 | scripts/entry.ts | cold | 1 | - | module | module | pass | 30 | 79.07 | 77.34 | 78.38 | - | 84.04 | 84.86 |
| nub | ts-esm-modules-1 | scripts/entry.ts | warm | 1 | - | module | module | pass | 30 | 80.50 | 76.81 | 78.71 | - | 86.26 | 94.12 |
| tsx | ts-esm-modules-1 | scripts/entry.ts | cold | 1 | - | module | module | pass | 30 | 107.71 | 106.39 | 107.51 | - | 109.18 | 109.28 |
| tsx | ts-esm-modules-1 | scripts/entry.ts | warm | 1 | - | module | module | pass | 30 | 100.21 | 99.22 | 100.09 | - | 101.10 | 101.49 |
| node | tsx-esm-modules-1 | scripts/entry.js | cold | 1 | - | module | module | pass | 30 | 19.46 | 18.72 | 19.17 | - | 22.20 | 22.77 |
| node | tsx-esm-modules-1 | scripts/entry.js | warm | 1 | - | module | module | pass | 30 | 19.11 | 18.75 | 19.04 | - | 19.59 | 19.61 |
| bun | tsx-esm-modules-1 | scripts/entry.tsx | cold | 1 | - | module | module | pass | 30 | 15.15 | 14.75 | 15.07 | - | 15.74 | 15.79 |
| bun | tsx-esm-modules-1 | scripts/entry.tsx | warm | 1 | - | module | module | pass | 30 | 14.97 | 14.62 | 14.88 | - | 15.44 | 16.51 |
| lpm | tsx-esm-modules-1 | scripts/entry.tsx | cold | 1 | - | module | module | pass | 30 | 60.68 | 58.57 | 60.55 | - | 62.55 | 62.56 |
| lpm | tsx-esm-modules-1 | scripts/entry.tsx | warm | 1 | - | module | module | pass | 30 | 38.81 | 36.94 | 38.55 | - | 40.22 | 40.98 |
| nub | tsx-esm-modules-1 | scripts/entry.tsx | cold | 1 | - | module | module | pass | 30 | 78.53 | 77.29 | 78.39 | - | 80.22 | 80.83 |
| nub | tsx-esm-modules-1 | scripts/entry.tsx | warm | 1 | - | module | module | pass | 30 | 77.77 | 77.25 | 77.68 | - | 78.88 | 79.75 |
| tsx | tsx-esm-modules-1 | scripts/entry.tsx | cold | 1 | - | module | module | pass | 30 | 109.38 | 107.29 | 108.38 | - | 112.58 | 113.92 |
| tsx | tsx-esm-modules-1 | scripts/entry.tsx | warm | 1 | - | module | module | pass | 30 | 102.05 | 99.67 | 100.60 | - | 106.52 | 107.74 |
| lpm-oxc-helper | oxc-helper-ts-cjs-files-1 | internal-ts-transform | none | 1 | 1 | commonjs | commonjs-omitted | pass | 30 | 4.78 | 4.04 | 4.71 | 4.71 | 5.65 | 5.78 |
| lpm-oxc-helper-persistent | oxc-helper-ts-cjs-files-1 | internal-ts-transform --persistent | none | 1 | 1 | commonjs | commonjs-omitted | pass | 30 | 4.27 | 3.89 | 4.14 | 4.14 | 4.96 | 4.98 |
| lpm-oxc-helper | oxc-helper-ts-esm-files-1 | internal-ts-transform | none | 1 | 1 | module | module | pass | 30 | 4.31 | 3.81 | 4.13 | 4.13 | 4.96 | 6.31 |
| lpm-oxc-helper-persistent | oxc-helper-ts-esm-files-1 | internal-ts-transform --persistent | none | 1 | 1 | module | module | pass | 30 | 4.24 | 3.84 | 4.14 | 4.14 | 4.78 | 5.07 |
| lpm-oxc-helper | oxc-helper-tsx-esm-files-1 | internal-ts-transform | none | 1 | 1 | module | module | pass | 30 | 4.31 | 3.84 | 4.26 | 4.26 | 5.21 | 5.21 |
| lpm-oxc-helper-persistent | oxc-helper-tsx-esm-files-1 | internal-ts-transform --persistent | none | 1 | 1 | module | module | pass | 30 | 5.04 | 3.90 | 4.45 | 4.45 | 7.27 | 7.61 |
| node | ts-cjs-modules-10 | scripts/entry.js | cold | 10 | - | commonjs | commonjs-omitted | pass | 30 | 18.63 | 18.32 | 18.53 | - | 19.60 | 19.80 |
| node | ts-cjs-modules-10 | scripts/entry.js | warm | 10 | - | commonjs | commonjs-omitted | pass | 30 | 18.60 | 18.22 | 18.57 | - | 19.10 | 19.18 |
| bun | ts-cjs-modules-10 | scripts/entry.ts | cold | 10 | - | commonjs | commonjs-omitted | pass | 30 | 15.14 | 14.77 | 15.08 | - | 15.86 | 15.91 |
| bun | ts-cjs-modules-10 | scripts/entry.ts | warm | 10 | - | commonjs | commonjs-omitted | pass | 30 | 15.22 | 14.53 | 14.89 | - | 16.69 | 17.41 |
| lpm | ts-cjs-modules-10 | scripts/entry.ts | cold | 10 | - | commonjs | commonjs-omitted | pass | 30 | 65.67 | 64.36 | 65.49 | - | 68.02 | 70.71 |
| lpm | ts-cjs-modules-10 | scripts/entry.ts | warm | 10 | - | commonjs | commonjs-omitted | pass | 30 | 37.79 | 36.96 | 37.74 | - | 38.72 | 39.72 |
| nub | ts-cjs-modules-10 | scripts/entry.ts | cold | 10 | - | commonjs | commonjs-omitted | pass | 30 | 83.58 | 79.36 | 81.95 | - | 89.10 | 101.11 |
| nub | ts-cjs-modules-10 | scripts/entry.ts | warm | 10 | - | commonjs | commonjs-omitted | pass | 30 | 79.09 | 77.97 | 78.99 | - | 80.53 | 82.47 |
| tsx | ts-cjs-modules-10 | scripts/entry.ts | cold | 10 | - | commonjs | commonjs-omitted | pass | 30 | 151.23 | 149.47 | 150.94 | - | 153.33 | 155.92 |
| tsx | ts-cjs-modules-10 | scripts/entry.ts | warm | 10 | - | commonjs | commonjs-omitted | pass | 30 | 103.36 | 102.34 | 103.27 | - | 104.30 | 104.78 |
| node | ts-esm-modules-10 | scripts/entry.js | cold | 10 | - | module | module | pass | 30 | 20.21 | 19.59 | 19.96 | - | 22.42 | 22.76 |
| node | ts-esm-modules-10 | scripts/entry.js | warm | 10 | - | module | module | pass | 30 | 19.86 | 19.36 | 19.82 | - | 20.24 | 20.55 |
| bun | ts-esm-modules-10 | scripts/entry.ts | cold | 10 | - | module | module | pass | 30 | 15.13 | 14.78 | 15.10 | - | 15.55 | 15.67 |
| bun | ts-esm-modules-10 | scripts/entry.ts | warm | 10 | - | module | module | pass | 30 | 15.00 | 14.67 | 14.91 | - | 15.62 | 16.39 |
| lpm | ts-esm-modules-10 | scripts/entry.ts | cold | 10 | - | module | module | pass | 30 | 65.39 | 64.32 | 65.27 | - | 66.73 | 66.89 |
| lpm | ts-esm-modules-10 | scripts/entry.ts | warm | 10 | - | module | module | pass | 30 | 37.79 | 36.91 | 37.75 | - | 38.46 | 39.10 |
| nub | ts-esm-modules-10 | scripts/entry.ts | cold | 10 | - | module | module | pass | 30 | 81.07 | 79.71 | 81.06 | - | 82.21 | 82.33 |
| nub | ts-esm-modules-10 | scripts/entry.ts | warm | 10 | - | module | module | pass | 30 | 79.58 | 79.08 | 79.50 | - | 80.05 | 80.46 |
| tsx | ts-esm-modules-10 | scripts/entry.ts | cold | 10 | - | module | module | pass | 30 | 113.77 | 112.09 | 113.17 | - | 119.64 | 119.87 |
| tsx | ts-esm-modules-10 | scripts/entry.ts | warm | 10 | - | module | module | pass | 30 | 103.61 | 102.83 | 103.59 | - | 104.37 | 104.83 |
| node | tsx-esm-modules-10 | scripts/entry.js | cold | 10 | - | module | module | pass | 30 | 21.74 | 21.26 | 21.68 | - | 22.45 | 22.65 |
| node | tsx-esm-modules-10 | scripts/entry.js | warm | 10 | - | module | module | pass | 30 | 21.50 | 21.04 | 21.44 | - | 21.94 | 22.47 |
| bun | tsx-esm-modules-10 | scripts/entry.tsx | cold | 10 | - | module | module | pass | 30 | 15.47 | 15.16 | 15.44 | - | 15.82 | 16.88 |
| bun | tsx-esm-modules-10 | scripts/entry.tsx | warm | 10 | - | module | module | pass | 30 | 15.48 | 14.78 | 15.32 | - | 16.54 | 16.98 |
| lpm | tsx-esm-modules-10 | scripts/entry.tsx | cold | 10 | - | module | module | pass | 30 | 68.43 | 66.80 | 68.24 | - | 69.73 | 71.79 |
| lpm | tsx-esm-modules-10 | scripts/entry.tsx | warm | 10 | - | module | module | pass | 30 | 43.23 | 40.22 | 42.54 | - | 49.83 | 54.05 |
| nub | tsx-esm-modules-10 | scripts/entry.tsx | cold | 10 | - | module | module | pass | 30 | 82.39 | 81.45 | 82.34 | - | 83.38 | 83.56 |
| nub | tsx-esm-modules-10 | scripts/entry.tsx | warm | 10 | - | module | module | pass | 30 | 80.91 | 80.08 | 80.80 | - | 81.69 | 82.00 |
| tsx | tsx-esm-modules-10 | scripts/entry.tsx | cold | 10 | - | module | module | pass | 30 | 117.55 | 116.23 | 117.39 | - | 118.44 | 121.39 |
| tsx | tsx-esm-modules-10 | scripts/entry.tsx | warm | 10 | - | module | module | pass | 30 | 107.72 | 107.01 | 107.57 | - | 108.97 | 108.98 |
| lpm-oxc-helper | oxc-helper-ts-cjs-files-10 | internal-ts-transform | none | 10 | 10 | commonjs | commonjs-omitted | pass | 30 | 41.80 | 40.12 | 41.24 | 4.12 | 44.71 | 50.22 |
| lpm-oxc-helper-persistent | oxc-helper-ts-cjs-files-10 | internal-ts-transform --persistent | none | 10 | 10 | commonjs | commonjs-omitted | pass | 30 | 4.46 | 3.87 | 4.32 | 0.43 | 5.32 | 5.66 |
| lpm-oxc-helper | oxc-helper-ts-esm-files-10 | internal-ts-transform | none | 10 | 10 | module | module | pass | 30 | 41.37 | 39.58 | 41.12 | 4.11 | 43.86 | 45.60 |
| lpm-oxc-helper-persistent | oxc-helper-ts-esm-files-10 | internal-ts-transform --persistent | none | 10 | 10 | module | module | pass | 30 | 4.37 | 3.92 | 4.24 | 0.42 | 5.12 | 5.26 |
| lpm-oxc-helper | oxc-helper-tsx-esm-files-10 | internal-ts-transform | none | 10 | 10 | module | module | pass | 30 | 41.80 | 40.33 | 41.25 | 4.13 | 44.07 | 46.87 |
| lpm-oxc-helper-persistent | oxc-helper-tsx-esm-files-10 | internal-ts-transform --persistent | none | 10 | 10 | module | module | pass | 30 | 4.42 | 3.99 | 4.34 | 0.43 | 5.15 | 5.21 |
| node | ts-cjs-modules-100 | scripts/entry.js | cold | 100 | - | commonjs | commonjs-omitted | pass | 30 | 23.58 | 23.15 | 23.51 | - | 24.03 | 24.39 |
| node | ts-cjs-modules-100 | scripts/entry.js | warm | 100 | - | commonjs | commonjs-omitted | pass | 30 | 23.30 | 22.59 | 23.05 | - | 26.48 | 26.92 |
| bun | ts-cjs-modules-100 | scripts/entry.ts | cold | 100 | - | commonjs | commonjs-omitted | pass | 30 | 18.32 | 17.89 | 18.17 | - | 19.47 | 19.65 |
| bun | ts-cjs-modules-100 | scripts/entry.ts | warm | 100 | - | commonjs | commonjs-omitted | pass | 30 | 17.30 | 16.92 | 17.20 | - | 17.80 | 18.11 |
| lpm | ts-cjs-modules-100 | scripts/entry.ts | cold | 100 | - | commonjs | commonjs-omitted | pass | 30 | 120.80 | 119.26 | 120.60 | - | 123.37 | 125.44 |
| lpm | ts-cjs-modules-100 | scripts/entry.ts | warm | 100 | - | commonjs | commonjs-omitted | pass | 30 | 46.95 | 45.16 | 46.19 | - | 52.26 | 53.16 |
| nub | ts-cjs-modules-100 | scripts/entry.ts | cold | 100 | - | commonjs | commonjs-omitted | pass | 30 | 100.17 | 99.12 | 100.27 | - | 100.80 | 101.47 |
| nub | ts-cjs-modules-100 | scripts/entry.ts | warm | 100 | - | commonjs | commonjs-omitted | pass | 30 | 89.06 | 88.06 | 88.97 | - | 90.84 | 90.89 |
| tsx | ts-cjs-modules-100 | scripts/entry.ts | cold | 100 | - | commonjs | commonjs-omitted | pass | 30 | 212.44 | 206.57 | 209.07 | - | 233.55 | 245.08 |
| tsx | ts-cjs-modules-100 | scripts/entry.ts | warm | 100 | - | commonjs | commonjs-omitted | pass | 30 | 121.92 | 120.81 | 121.69 | - | 123.51 | 124.40 |
| node | ts-esm-modules-100 | scripts/entry.js | cold | 100 | - | module | module | pass | 30 | 25.52 | 24.92 | 25.39 | - | 26.74 | 28.19 |
| node | ts-esm-modules-100 | scripts/entry.js | warm | 100 | - | module | module | pass | 30 | 25.19 | 24.18 | 24.68 | - | 28.11 | 33.72 |
| bun | ts-esm-modules-100 | scripts/entry.ts | cold | 100 | - | module | module | pass | 30 | 17.57 | 17.09 | 17.36 | - | 18.56 | 19.82 |
| bun | ts-esm-modules-100 | scripts/entry.ts | warm | 100 | - | module | module | pass | 30 | 16.27 | 15.96 | 16.23 | - | 16.61 | 17.00 |
| lpm | ts-esm-modules-100 | scripts/entry.ts | cold | 100 | - | module | module | pass | 30 | 118.49 | 116.77 | 117.88 | - | 119.27 | 132.35 |
| lpm | ts-esm-modules-100 | scripts/entry.ts | warm | 100 | - | module | module | pass | 30 | 45.91 | 44.57 | 45.32 | - | 49.06 | 52.53 |
| nub | ts-esm-modules-100 | scripts/entry.ts | cold | 100 | - | module | module | pass | 30 | 99.82 | 98.71 | 99.74 | - | 101.15 | 101.69 |
| nub | ts-esm-modules-100 | scripts/entry.ts | warm | 100 | - | module | module | pass | 30 | 88.59 | 87.78 | 88.50 | - | 89.37 | 89.59 |
| tsx | ts-esm-modules-100 | scripts/entry.ts | cold | 100 | - | module | module | pass | 30 | 144.48 | 142.14 | 144.58 | - | 146.07 | 146.34 |
| tsx | ts-esm-modules-100 | scripts/entry.ts | warm | 100 | - | module | module | pass | 30 | 126.37 | 125.58 | 126.24 | - | 127.11 | 128.88 |
| node | tsx-esm-modules-100 | scripts/entry.js | cold | 100 | - | module | module | pass | 30 | 29.57 | 28.90 | 29.40 | - | 30.42 | 32.35 |
| node | tsx-esm-modules-100 | scripts/entry.js | warm | 100 | - | module | module | pass | 30 | 28.67 | 27.81 | 28.63 | - | 29.89 | 30.82 |
| bun | tsx-esm-modules-100 | scripts/entry.tsx | cold | 100 | - | module | module | pass | 30 | 18.02 | 17.62 | 17.90 | - | 18.46 | 19.50 |
| bun | tsx-esm-modules-100 | scripts/entry.tsx | warm | 100 | - | module | module | pass | 30 | 18.42 | 16.73 | 18.12 | - | 20.62 | 24.37 |
| lpm | tsx-esm-modules-100 | scripts/entry.tsx | cold | 100 | - | module | module | pass | 30 | 127.51 | 125.41 | 126.65 | - | 133.50 | 136.28 |
| lpm | tsx-esm-modules-100 | scripts/entry.tsx | warm | 100 | - | module | module | pass | 30 | 53.43 | 52.71 | 53.28 | - | 55.10 | 55.64 |
| nub | tsx-esm-modules-100 | scripts/entry.tsx | cold | 100 | - | module | module | pass | 30 | 105.13 | 104.03 | 104.85 | - | 106.03 | 113.22 |
| nub | tsx-esm-modules-100 | scripts/entry.tsx | warm | 100 | - | module | module | pass | 30 | 93.83 | 92.61 | 93.41 | - | 96.97 | 99.59 |
| tsx | tsx-esm-modules-100 | scripts/entry.tsx | cold | 100 | - | module | module | pass | 30 | 174.51 | 170.95 | 173.51 | - | 182.16 | 193.24 |
| tsx | tsx-esm-modules-100 | scripts/entry.tsx | warm | 100 | - | module | module | pass | 30 | 155.44 | 154.37 | 155.34 | - | 156.27 | 156.42 |
| lpm-oxc-helper | oxc-helper-ts-cjs-files-100 | internal-ts-transform | none | 100 | 100 | commonjs | commonjs-omitted | pass | 30 | 420.31 | 402.90 | 414.07 | 4.14 | 476.59 | 554.00 |
| lpm-oxc-helper-persistent | oxc-helper-ts-cjs-files-100 | internal-ts-transform --persistent | none | 100 | 100 | commonjs | commonjs-omitted | pass | 30 | 4.80 | 4.39 | 4.74 | 0.05 | 5.48 | 5.76 |
| lpm-oxc-helper | oxc-helper-ts-esm-files-100 | internal-ts-transform | none | 100 | 100 | module | module | pass | 30 | 410.57 | 403.06 | 409.88 | 4.10 | 427.11 | 431.99 |
| lpm-oxc-helper-persistent | oxc-helper-ts-esm-files-100 | internal-ts-transform --persistent | none | 100 | 100 | module | module | pass | 30 | 5.86 | 4.31 | 5.60 | 0.06 | 7.67 | 7.69 |
| lpm-oxc-helper | oxc-helper-tsx-esm-files-100 | internal-ts-transform | none | 100 | 100 | module | module | pass | 30 | 413.74 | 403.53 | 411.12 | 4.11 | 421.04 | 478.78 |
| lpm-oxc-helper-persistent | oxc-helper-tsx-esm-files-100 | internal-ts-transform --persistent | none | 100 | 100 | module | module | pass | 30 | 6.26 | 5.21 | 5.91 | 0.06 | 7.98 | 8.95 |
| lpm | mts-esm-modules-10 | scripts/entry.mts | cold | 10 | - | module | commonjs-omitted | pass | 30 | 64.74 | 63.50 | 64.56 | - | 65.62 | 68.82 |
| lpm | mts-esm-modules-10 | scripts/entry.mts | warm | 10 | - | module | commonjs-omitted | pass | 30 | 37.50 | 36.85 | 37.42 | - | 38.65 | 38.96 |
| lpm | cts-cjs-modules-10 | scripts/entry.cts | cold | 10 | - | commonjs | module | pass | 30 | 64.88 | 63.34 | 64.70 | - | 66.36 | 67.25 |
| lpm | cts-cjs-modules-10 | scripts/entry.cts | warm | 10 | - | commonjs | module | pass | 30 | 39.85 | 37.02 | 39.60 | - | 43.39 | 47.76 |

Skipped Bun/Nub/tsx rows are benchmark-only comparisons; the harness never installs or fetches comparison tools.
