# lpm source runtime benchmark suite

- Date: `2026-06-30T12:02:28.371Z`
- Source Git SHA: `86777a20`
- Iterations: `30`
- Warmup iterations: `1`
- Module counts: `1, 10, 100`
- Binary: `/tmp/lpm-rs-main-target/release/lpm-rs`
- Binary source: `explicit LPM_BIN`
- LPM: `lpm 0.64.0`
- Node: `v22.22.1` via `/Users/tolga/.n/bin/node`
- Node source: `current Node process`
- Bun: `1.3.14`
- Bun binary: `/Users/tolga/.bun/bin/bun`
- Nub: `v0.2.10`
- Nub binary: `/tmp/lpm-bench-tools/node_modules/.bin/nub`
- tsx: `tsx v4.19.4 node v22.22.1`
- tsx binary: `/tmp/lpm-bench-tools/node_modules/.bin/tsx`

Each comparison fixture uses the same generated module graph: `node` runs the JS baseline, while `bun`, `lpm`, `nub`, and `tsx` run the matching TS/TSX source.
Cold clears the runner's transform cache before every measured run. Warm runs 1 unmeasured warmup iteration(s) and then reuses that cache.
`lpm-oxc-helper` rows run one transform helper process per file. `lpm-oxc-helper-persistent` rows run one `internal-ts-transform --persistent` process for the whole module set.

| Runner | Fixture | Entry | Cache | Modules | Helper calls | Format | Project mode | Status | Iterations | Avg ms | Min ms | P50 ms | P50/call ms | P95 ms | Max ms |
| --- | --- | --- | --- | ---: | ---: | --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| node | ts-cjs-modules-1 | scripts/entry.js | cold | 1 | - | commonjs | commonjs-omitted | pass | 30 | 17.13 | 16.72 | 17.09 | - | 17.78 | 17.81 |
| node | ts-cjs-modules-1 | scripts/entry.js | warm | 1 | - | commonjs | commonjs-omitted | pass | 30 | 17.27 | 16.77 | 17.05 | - | 18.57 | 18.59 |
| bun | ts-cjs-modules-1 | scripts/entry.ts | cold | 1 | - | commonjs | commonjs-omitted | pass | 30 | 14.81 | 14.50 | 14.80 | - | 15.15 | 15.24 |
| bun | ts-cjs-modules-1 | scripts/entry.ts | warm | 1 | - | commonjs | commonjs-omitted | pass | 30 | 15.03 | 14.27 | 14.65 | - | 18.44 | 19.26 |
| lpm | ts-cjs-modules-1 | scripts/entry.ts | cold | 1 | - | commonjs | commonjs-omitted | pass | 30 | 57.06 | 55.98 | 57.09 | - | 57.85 | 58.35 |
| lpm | ts-cjs-modules-1 | scripts/entry.ts | warm | 1 | - | commonjs | commonjs-omitted | pass | 30 | 35.46 | 34.72 | 35.29 | - | 36.39 | 37.44 |
| nub | ts-cjs-modules-1 | scripts/entry.ts | cold | 1 | - | commonjs | commonjs-omitted | pass | 30 | 75.30 | 73.85 | 75.00 | - | 78.54 | 79.95 |
| nub | ts-cjs-modules-1 | scripts/entry.ts | warm | 1 | - | commonjs | commonjs-omitted | pass | 30 | 76.02 | 74.19 | 75.83 | - | 77.87 | 83.25 |
| tsx | ts-cjs-modules-1 | scripts/entry.ts | cold | 1 | - | commonjs | commonjs-omitted | pass | 30 | 141.40 | 139.55 | 140.99 | - | 146.69 | 149.45 |
| tsx | ts-cjs-modules-1 | scripts/entry.ts | warm | 1 | - | commonjs | commonjs-omitted | pass | 30 | 100.25 | 98.27 | 99.84 | - | 104.15 | 105.04 |
| node | ts-esm-modules-1 | scripts/entry.js | cold | 1 | - | module | module | pass | 30 | 18.49 | 17.87 | 18.14 | - | 21.99 | 23.62 |
| node | ts-esm-modules-1 | scripts/entry.js | warm | 1 | - | module | module | pass | 30 | 18.19 | 17.88 | 18.14 | - | 18.76 | 18.93 |
| bun | ts-esm-modules-1 | scripts/entry.ts | cold | 1 | - | module | module | pass | 30 | 15.01 | 14.63 | 14.87 | - | 15.88 | 16.09 |
| bun | ts-esm-modules-1 | scripts/entry.ts | warm | 1 | - | module | module | pass | 30 | 14.90 | 14.62 | 14.88 | - | 15.19 | 15.20 |
| lpm | ts-esm-modules-1 | scripts/entry.ts | cold | 1 | - | module | module | pass | 30 | 57.18 | 56.43 | 57.03 | - | 58.30 | 58.44 |
| lpm | ts-esm-modules-1 | scripts/entry.ts | warm | 1 | - | module | module | pass | 30 | 36.32 | 35.22 | 36.14 | - | 37.95 | 37.96 |
| nub | ts-esm-modules-1 | scripts/entry.ts | cold | 1 | - | module | module | pass | 30 | 77.68 | 76.26 | 77.41 | - | 79.86 | 84.98 |
| nub | ts-esm-modules-1 | scripts/entry.ts | warm | 1 | - | module | module | pass | 30 | 77.40 | 75.87 | 76.98 | - | 81.30 | 81.79 |
| tsx | ts-esm-modules-1 | scripts/entry.ts | cold | 1 | - | module | module | pass | 30 | 107.51 | 105.72 | 107.26 | - | 110.10 | 111.40 |
| tsx | ts-esm-modules-1 | scripts/entry.ts | warm | 1 | - | module | module | pass | 30 | 103.35 | 99.31 | 100.50 | - | 115.74 | 118.76 |
| node | tsx-esm-modules-1 | scripts/entry.js | cold | 1 | - | module | module | pass | 30 | 19.19 | 18.55 | 19.14 | - | 19.88 | 19.99 |
| node | tsx-esm-modules-1 | scripts/entry.js | warm | 1 | - | module | module | pass | 30 | 18.88 | 18.46 | 18.86 | - | 19.46 | 19.52 |
| bun | tsx-esm-modules-1 | scripts/entry.tsx | cold | 1 | - | module | module | pass | 30 | 15.52 | 15.12 | 15.47 | - | 16.16 | 16.77 |
| bun | tsx-esm-modules-1 | scripts/entry.tsx | warm | 1 | - | module | module | pass | 30 | 15.26 | 14.80 | 15.21 | - | 15.67 | 15.84 |
| lpm | tsx-esm-modules-1 | scripts/entry.tsx | cold | 1 | - | module | module | pass | 30 | 59.28 | 58.53 | 59.03 | - | 60.70 | 63.13 |
| lpm | tsx-esm-modules-1 | scripts/entry.tsx | warm | 1 | - | module | module | pass | 30 | 37.51 | 36.56 | 37.30 | - | 38.50 | 39.24 |
| nub | tsx-esm-modules-1 | scripts/entry.tsx | cold | 1 | - | module | module | pass | 30 | 78.13 | 77.37 | 78.08 | - | 78.92 | 80.88 |
| nub | tsx-esm-modules-1 | scripts/entry.tsx | warm | 1 | - | module | module | pass | 30 | 78.29 | 76.81 | 77.99 | - | 80.94 | 81.24 |
| tsx | tsx-esm-modules-1 | scripts/entry.tsx | cold | 1 | - | module | module | pass | 30 | 109.79 | 108.21 | 109.15 | - | 113.38 | 115.65 |
| tsx | tsx-esm-modules-1 | scripts/entry.tsx | warm | 1 | - | module | module | pass | 30 | 101.71 | 100.40 | 101.56 | - | 102.80 | 105.67 |
| lpm-oxc-helper | oxc-helper-ts-cjs-files-1 | internal-ts-transform | none | 1 | 1 | commonjs | commonjs-omitted | pass | 30 | 4.46 | 3.89 | 4.40 | 4.40 | 5.12 | 5.21 |
| lpm-oxc-helper-persistent | oxc-helper-ts-cjs-files-1 | internal-ts-transform --persistent | none | 1 | 1 | commonjs | commonjs-omitted | pass | 30 | 4.37 | 4.01 | 4.31 | 4.31 | 4.84 | 5.22 |
| lpm-oxc-helper | oxc-helper-ts-esm-files-1 | internal-ts-transform | none | 1 | 1 | module | module | pass | 30 | 4.42 | 4.03 | 4.32 | 4.32 | 4.98 | 5.63 |
| lpm-oxc-helper-persistent | oxc-helper-ts-esm-files-1 | internal-ts-transform --persistent | none | 1 | 1 | module | module | pass | 30 | 4.45 | 4.04 | 4.38 | 4.38 | 5.25 | 5.29 |
| lpm-oxc-helper | oxc-helper-tsx-esm-files-1 | internal-ts-transform | none | 1 | 1 | module | module | pass | 30 | 4.33 | 3.87 | 4.26 | 4.26 | 5.06 | 5.14 |
| lpm-oxc-helper-persistent | oxc-helper-tsx-esm-files-1 | internal-ts-transform --persistent | none | 1 | 1 | module | module | pass | 30 | 4.78 | 4.02 | 4.34 | 4.34 | 6.86 | 7.73 |
| node | ts-cjs-modules-10 | scripts/entry.js | cold | 10 | - | commonjs | commonjs-omitted | pass | 30 | 18.69 | 18.29 | 18.60 | - | 19.24 | 19.30 |
| node | ts-cjs-modules-10 | scripts/entry.js | warm | 10 | - | commonjs | commonjs-omitted | pass | 30 | 18.53 | 17.98 | 18.47 | - | 19.43 | 19.52 |
| bun | ts-cjs-modules-10 | scripts/entry.ts | cold | 10 | - | commonjs | commonjs-omitted | pass | 30 | 16.18 | 15.60 | 15.94 | - | 16.94 | 21.16 |
| bun | ts-cjs-modules-10 | scripts/entry.ts | warm | 10 | - | commonjs | commonjs-omitted | pass | 30 | 15.38 | 15.05 | 15.31 | - | 15.83 | 16.77 |
| lpm | ts-cjs-modules-10 | scripts/entry.ts | cold | 10 | - | commonjs | commonjs-omitted | pass | 30 | 66.03 | 64.37 | 65.42 | - | 69.47 | 76.63 |
| lpm | ts-cjs-modules-10 | scripts/entry.ts | warm | 10 | - | commonjs | commonjs-omitted | pass | 30 | 37.81 | 36.75 | 37.79 | - | 38.61 | 39.18 |
| nub | ts-cjs-modules-10 | scripts/entry.ts | cold | 10 | - | commonjs | commonjs-omitted | pass | 30 | 80.85 | 79.40 | 80.45 | - | 85.11 | 85.55 |
| nub | ts-cjs-modules-10 | scripts/entry.ts | warm | 10 | - | commonjs | commonjs-omitted | pass | 30 | 79.49 | 78.09 | 79.49 | - | 80.71 | 80.82 |
| tsx | ts-cjs-modules-10 | scripts/entry.ts | cold | 10 | - | commonjs | commonjs-omitted | pass | 30 | 151.96 | 149.94 | 151.73 | - | 154.18 | 158.84 |
| tsx | ts-cjs-modules-10 | scripts/entry.ts | warm | 10 | - | commonjs | commonjs-omitted | pass | 30 | 107.24 | 103.04 | 104.51 | - | 120.66 | 130.53 |
| node | ts-esm-modules-10 | scripts/entry.js | cold | 10 | - | module | module | pass | 30 | 20.04 | 19.43 | 20.03 | - | 21.19 | 21.54 |
| node | ts-esm-modules-10 | scripts/entry.js | warm | 10 | - | module | module | pass | 30 | 19.74 | 19.34 | 19.67 | - | 20.26 | 20.40 |
| bun | ts-esm-modules-10 | scripts/entry.ts | cold | 10 | - | module | module | pass | 30 | 15.49 | 14.99 | 15.45 | - | 16.14 | 16.26 |
| bun | ts-esm-modules-10 | scripts/entry.ts | warm | 10 | - | module | module | pass | 30 | 15.61 | 14.97 | 15.32 | - | 18.53 | 20.13 |
| lpm | ts-esm-modules-10 | scripts/entry.ts | cold | 10 | - | module | module | pass | 30 | 65.65 | 64.28 | 65.41 | - | 68.64 | 69.73 |
| lpm | ts-esm-modules-10 | scripts/entry.ts | warm | 10 | - | module | module | pass | 30 | 37.56 | 36.53 | 37.34 | - | 38.86 | 39.46 |
| nub | ts-esm-modules-10 | scripts/entry.ts | cold | 10 | - | module | module | pass | 30 | 80.95 | 79.49 | 80.82 | - | 82.11 | 83.98 |
| nub | ts-esm-modules-10 | scripts/entry.ts | warm | 10 | - | module | module | pass | 30 | 79.87 | 78.11 | 79.74 | - | 82.32 | 82.65 |
| tsx | ts-esm-modules-10 | scripts/entry.ts | cold | 10 | - | module | module | pass | 30 | 113.83 | 111.63 | 114.05 | - | 114.75 | 115.10 |
| tsx | ts-esm-modules-10 | scripts/entry.ts | warm | 10 | - | module | module | pass | 30 | 104.96 | 103.46 | 104.56 | - | 108.27 | 112.17 |
| node | tsx-esm-modules-10 | scripts/entry.js | cold | 10 | - | module | module | pass | 30 | 22.06 | 21.26 | 21.80 | - | 23.76 | 28.26 |
| node | tsx-esm-modules-10 | scripts/entry.js | warm | 10 | - | module | module | pass | 30 | 21.49 | 20.60 | 21.45 | - | 22.05 | 22.19 |
| bun | tsx-esm-modules-10 | scripts/entry.tsx | cold | 10 | - | module | module | pass | 30 | 15.90 | 15.55 | 15.86 | - | 16.43 | 16.60 |
| bun | tsx-esm-modules-10 | scripts/entry.tsx | warm | 10 | - | module | module | pass | 30 | 15.89 | 15.39 | 15.75 | - | 16.51 | 16.57 |
| lpm | tsx-esm-modules-10 | scripts/entry.tsx | cold | 10 | - | module | module | pass | 30 | 69.00 | 67.75 | 68.73 | - | 70.86 | 73.43 |
| lpm | tsx-esm-modules-10 | scripts/entry.tsx | warm | 10 | - | module | module | pass | 30 | 41.31 | 39.87 | 41.32 | - | 42.15 | 42.65 |
| nub | tsx-esm-modules-10 | scripts/entry.tsx | cold | 10 | - | module | module | pass | 30 | 83.36 | 81.33 | 83.33 | - | 85.58 | 86.11 |
| nub | tsx-esm-modules-10 | scripts/entry.tsx | warm | 10 | - | module | module | pass | 30 | 81.16 | 80.34 | 81.03 | - | 82.10 | 83.09 |
| tsx | tsx-esm-modules-10 | scripts/entry.tsx | cold | 10 | - | module | module | pass | 30 | 119.30 | 117.35 | 118.93 | - | 123.24 | 125.46 |
| tsx | tsx-esm-modules-10 | scripts/entry.tsx | warm | 10 | - | module | module | pass | 30 | 109.22 | 107.09 | 108.79 | - | 112.94 | 115.74 |
| lpm-oxc-helper | oxc-helper-ts-cjs-files-10 | internal-ts-transform | none | 10 | 10 | commonjs | commonjs-omitted | pass | 30 | 41.65 | 40.33 | 41.49 | 4.15 | 43.89 | 44.66 |
| lpm-oxc-helper-persistent | oxc-helper-ts-cjs-files-10 | internal-ts-transform --persistent | none | 10 | 10 | commonjs | commonjs-omitted | pass | 30 | 4.37 | 3.94 | 4.28 | 0.43 | 5.03 | 5.68 |
| lpm-oxc-helper | oxc-helper-ts-esm-files-10 | internal-ts-transform | none | 10 | 10 | module | module | pass | 30 | 41.77 | 40.48 | 41.32 | 4.13 | 44.74 | 46.32 |
| lpm-oxc-helper-persistent | oxc-helper-ts-esm-files-10 | internal-ts-transform --persistent | none | 10 | 10 | module | module | pass | 30 | 4.40 | 3.89 | 4.36 | 0.44 | 4.81 | 4.86 |
| lpm-oxc-helper | oxc-helper-tsx-esm-files-10 | internal-ts-transform | none | 10 | 10 | module | module | pass | 30 | 42.54 | 40.77 | 41.78 | 4.18 | 44.06 | 57.51 |
| lpm-oxc-helper-persistent | oxc-helper-tsx-esm-files-10 | internal-ts-transform --persistent | none | 10 | 10 | module | module | pass | 30 | 4.45 | 4.03 | 4.41 | 0.44 | 5.01 | 5.12 |
| node | ts-cjs-modules-100 | scripts/entry.js | cold | 100 | - | commonjs | commonjs-omitted | pass | 30 | 23.95 | 23.37 | 23.89 | - | 24.53 | 25.06 |
| node | ts-cjs-modules-100 | scripts/entry.js | warm | 100 | - | commonjs | commonjs-omitted | pass | 30 | 23.11 | 22.54 | 23.14 | - | 23.51 | 23.83 |
| bun | ts-cjs-modules-100 | scripts/entry.ts | cold | 100 | - | commonjs | commonjs-omitted | pass | 30 | 18.61 | 18.21 | 18.54 | - | 19.15 | 19.18 |
| bun | ts-cjs-modules-100 | scripts/entry.ts | warm | 100 | - | commonjs | commonjs-omitted | pass | 30 | 17.76 | 17.45 | 17.70 | - | 18.61 | 18.86 |
| lpm | ts-cjs-modules-100 | scripts/entry.ts | cold | 100 | - | commonjs | commonjs-omitted | pass | 30 | 122.59 | 120.75 | 121.76 | - | 128.33 | 137.56 |
| lpm | ts-cjs-modules-100 | scripts/entry.ts | warm | 100 | - | commonjs | commonjs-omitted | pass | 30 | 46.92 | 46.00 | 46.90 | - | 47.99 | 48.85 |
| nub | ts-cjs-modules-100 | scripts/entry.ts | cold | 100 | - | commonjs | commonjs-omitted | pass | 30 | 101.76 | 100.32 | 101.42 | - | 104.76 | 107.65 |
| nub | ts-cjs-modules-100 | scripts/entry.ts | warm | 100 | - | commonjs | commonjs-omitted | pass | 30 | 89.60 | 88.78 | 89.55 | - | 90.27 | 90.65 |
| tsx | ts-cjs-modules-100 | scripts/entry.ts | cold | 100 | - | commonjs | commonjs-omitted | pass | 30 | 212.20 | 208.13 | 211.42 | - | 222.34 | 227.66 |
| tsx | ts-cjs-modules-100 | scripts/entry.ts | warm | 100 | - | commonjs | commonjs-omitted | pass | 30 | 123.67 | 122.06 | 123.19 | - | 127.44 | 129.07 |
| node | ts-esm-modules-100 | scripts/entry.js | cold | 100 | - | module | module | pass | 30 | 25.91 | 24.91 | 25.54 | - | 27.53 | 32.65 |
| node | ts-esm-modules-100 | scripts/entry.js | warm | 100 | - | module | module | pass | 30 | 25.01 | 24.31 | 24.81 | - | 26.26 | 26.33 |
| bun | ts-esm-modules-100 | scripts/entry.ts | cold | 100 | - | module | module | pass | 30 | 18.04 | 17.50 | 17.93 | - | 18.76 | 18.89 |
| bun | ts-esm-modules-100 | scripts/entry.ts | warm | 100 | - | module | module | pass | 30 | 17.23 | 16.39 | 16.85 | - | 18.11 | 23.19 |
| lpm | ts-esm-modules-100 | scripts/entry.ts | cold | 100 | - | module | module | pass | 30 | 120.19 | 118.79 | 119.58 | - | 124.72 | 125.05 |
| lpm | ts-esm-modules-100 | scripts/entry.ts | warm | 100 | - | module | module | pass | 30 | 45.59 | 44.49 | 45.37 | - | 47.42 | 47.99 |
| nub | ts-esm-modules-100 | scripts/entry.ts | cold | 100 | - | module | module | pass | 30 | 100.85 | 99.79 | 100.71 | - | 101.82 | 102.18 |
| nub | ts-esm-modules-100 | scripts/entry.ts | warm | 100 | - | module | module | pass | 30 | 89.41 | 88.43 | 89.05 | - | 91.47 | 93.82 |
| tsx | ts-esm-modules-100 | scripts/entry.ts | cold | 100 | - | module | module | pass | 30 | 145.85 | 144.36 | 145.72 | - | 147.26 | 148.45 |
| tsx | ts-esm-modules-100 | scripts/entry.ts | warm | 100 | - | module | module | pass | 30 | 127.89 | 126.53 | 127.34 | - | 131.06 | 136.17 |
| node | tsx-esm-modules-100 | scripts/entry.js | cold | 100 | - | module | module | pass | 30 | 29.70 | 29.15 | 29.57 | - | 30.45 | 31.37 |
| node | tsx-esm-modules-100 | scripts/entry.js | warm | 100 | - | module | module | pass | 30 | 28.93 | 28.34 | 28.93 | - | 29.56 | 29.60 |
| bun | tsx-esm-modules-100 | scripts/entry.tsx | cold | 100 | - | module | module | pass | 30 | 18.78 | 18.06 | 18.54 | - | 20.46 | 23.09 |
| bun | tsx-esm-modules-100 | scripts/entry.tsx | warm | 100 | - | module | module | pass | 30 | 17.45 | 17.01 | 17.42 | - | 17.98 | 18.21 |
| lpm | tsx-esm-modules-100 | scripts/entry.tsx | cold | 100 | - | module | module | pass | 30 | 129.30 | 127.19 | 128.86 | - | 138.22 | 138.96 |
| lpm | tsx-esm-modules-100 | scripts/entry.tsx | warm | 100 | - | module | module | pass | 30 | 53.86 | 52.99 | 53.75 | - | 54.90 | 56.19 |
| nub | tsx-esm-modules-100 | scripts/entry.tsx | cold | 100 | - | module | module | pass | 30 | 105.97 | 104.46 | 105.89 | - | 107.76 | 107.96 |
| nub | tsx-esm-modules-100 | scripts/entry.tsx | warm | 100 | - | module | module | pass | 30 | 94.39 | 92.60 | 94.15 | - | 98.28 | 99.05 |
| tsx | tsx-esm-modules-100 | scripts/entry.tsx | cold | 100 | - | module | module | pass | 30 | 175.41 | 172.92 | 174.56 | - | 183.78 | 184.89 |
| tsx | tsx-esm-modules-100 | scripts/entry.tsx | warm | 100 | - | module | module | pass | 30 | 158.83 | 156.17 | 158.09 | - | 166.09 | 174.53 |
| lpm-oxc-helper | oxc-helper-ts-cjs-files-100 | internal-ts-transform | none | 100 | 100 | commonjs | commonjs-omitted | pass | 30 | 422.71 | 413.64 | 420.29 | 4.20 | 436.57 | 444.48 |
| lpm-oxc-helper-persistent | oxc-helper-ts-cjs-files-100 | internal-ts-transform --persistent | none | 100 | 100 | commonjs | commonjs-omitted | pass | 30 | 4.84 | 4.42 | 4.79 | 0.05 | 5.32 | 5.32 |
| lpm-oxc-helper | oxc-helper-ts-esm-files-100 | internal-ts-transform | none | 100 | 100 | module | module | pass | 30 | 420.57 | 411.78 | 418.87 | 4.19 | 437.57 | 442.98 |
| lpm-oxc-helper-persistent | oxc-helper-ts-esm-files-100 | internal-ts-transform --persistent | none | 100 | 100 | module | module | pass | 30 | 4.78 | 4.34 | 4.74 | 0.05 | 5.23 | 5.57 |
| lpm-oxc-helper | oxc-helper-tsx-esm-files-100 | internal-ts-transform | none | 100 | 100 | module | module | pass | 30 | 425.50 | 416.30 | 421.38 | 4.21 | 456.10 | 459.31 |
| lpm-oxc-helper-persistent | oxc-helper-tsx-esm-files-100 | internal-ts-transform --persistent | none | 100 | 100 | module | module | pass | 30 | 4.97 | 4.52 | 4.91 | 0.05 | 5.80 | 5.96 |
| lpm | mts-esm-modules-10 | scripts/entry.mts | cold | 10 | - | module | commonjs-omitted | pass | 30 | 65.82 | 64.34 | 65.55 | - | 67.46 | 69.99 |
| lpm | mts-esm-modules-10 | scripts/entry.mts | warm | 10 | - | module | commonjs-omitted | pass | 30 | 38.20 | 37.34 | 37.93 | - | 39.57 | 39.89 |
| lpm | cts-cjs-modules-10 | scripts/entry.cts | cold | 10 | - | commonjs | module | pass | 30 | 65.40 | 64.40 | 65.37 | - | 66.55 | 66.91 |
| lpm | cts-cjs-modules-10 | scripts/entry.cts | warm | 10 | - | commonjs | module | pass | 30 | 37.45 | 36.63 | 37.42 | - | 38.16 | 38.57 |

Skipped Bun/Nub/tsx rows are benchmark-only comparisons; the harness never installs or fetches comparison tools.
