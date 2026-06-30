# lpm source runtime benchmark suite

- Date: `2026-06-30T12:06:32.014Z`
- Source Git SHA: `86777a20`
- Iterations: `30`
- Warmup iterations: `1`
- Module counts: `1, 10, 100`
- Binary: `/Users/tolga/Documents/Projects/lpm-dev/rust-client/target/release/lpm-rs`
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
| node | ts-cjs-modules-1 | scripts/entry.js | cold | 1 | - | commonjs | commonjs-omitted | pass | 30 | 16.48 | 15.78 | 16.48 | - | 17.18 | 17.38 |
| node | ts-cjs-modules-1 | scripts/entry.js | warm | 1 | - | commonjs | commonjs-omitted | pass | 30 | 17.82 | 15.73 | 16.29 | - | 31.18 | 41.97 |
| bun | ts-cjs-modules-1 | scripts/entry.ts | cold | 1 | - | commonjs | commonjs-omitted | pass | 30 | 16.96 | 15.43 | 16.88 | - | 19.01 | 19.70 |
| bun | ts-cjs-modules-1 | scripts/entry.ts | warm | 1 | - | commonjs | commonjs-omitted | pass | 30 | 14.94 | 14.13 | 14.59 | - | 17.98 | 18.02 |
| lpm | ts-cjs-modules-1 | scripts/entry.ts | cold | 1 | - | commonjs | commonjs-omitted | pass | 30 | 54.98 | 52.56 | 54.67 | - | 57.89 | 58.91 |
| lpm | ts-cjs-modules-1 | scripts/entry.ts | warm | 1 | - | commonjs | commonjs-omitted | pass | 30 | 35.44 | 34.27 | 35.33 | - | 36.63 | 36.80 |
| nub | ts-cjs-modules-1 | scripts/entry.ts | cold | 1 | - | commonjs | commonjs-omitted | pass | 30 | 77.87 | 75.27 | 77.10 | - | 81.36 | 87.74 |
| nub | ts-cjs-modules-1 | scripts/entry.ts | warm | 1 | - | commonjs | commonjs-omitted | pass | 30 | 77.84 | 76.76 | 77.69 | - | 79.57 | 80.15 |
| tsx | ts-cjs-modules-1 | scripts/entry.ts | cold | 1 | - | commonjs | commonjs-omitted | pass | 30 | 143.22 | 141.18 | 142.71 | - | 146.45 | 146.69 |
| tsx | ts-cjs-modules-1 | scripts/entry.ts | warm | 1 | - | commonjs | commonjs-omitted | pass | 30 | 101.37 | 100.13 | 101.08 | - | 103.70 | 104.31 |
| node | ts-esm-modules-1 | scripts/entry.js | cold | 1 | - | module | module | pass | 30 | 18.48 | 18.08 | 18.39 | - | 19.28 | 19.29 |
| node | ts-esm-modules-1 | scripts/entry.js | warm | 1 | - | module | module | pass | 30 | 18.70 | 18.15 | 18.52 | - | 19.62 | 20.23 |
| bun | ts-esm-modules-1 | scripts/entry.ts | cold | 1 | - | module | module | pass | 30 | 15.03 | 14.67 | 14.97 | - | 15.36 | 15.68 |
| bun | ts-esm-modules-1 | scripts/entry.ts | warm | 1 | - | module | module | pass | 30 | 14.92 | 14.39 | 14.84 | - | 15.29 | 15.46 |
| lpm | ts-esm-modules-1 | scripts/entry.ts | cold | 1 | - | module | module | pass | 30 | 56.45 | 54.74 | 56.09 | - | 57.56 | 65.63 |
| lpm | ts-esm-modules-1 | scripts/entry.ts | warm | 1 | - | module | module | pass | 30 | 36.90 | 36.29 | 36.68 | - | 37.97 | 38.20 |
| nub | ts-esm-modules-1 | scripts/entry.ts | cold | 1 | - | module | module | pass | 30 | 78.76 | 77.42 | 78.50 | - | 80.86 | 81.16 |
| nub | ts-esm-modules-1 | scripts/entry.ts | warm | 1 | - | module | module | pass | 30 | 78.10 | 77.52 | 78.00 | - | 78.94 | 80.32 |
| tsx | ts-esm-modules-1 | scripts/entry.ts | cold | 1 | - | module | module | pass | 30 | 109.33 | 107.51 | 108.53 | - | 114.23 | 119.43 |
| tsx | ts-esm-modules-1 | scripts/entry.ts | warm | 1 | - | module | module | pass | 30 | 100.99 | 100.00 | 100.58 | - | 103.54 | 105.68 |
| node | tsx-esm-modules-1 | scripts/entry.js | cold | 1 | - | module | module | pass | 30 | 19.28 | 18.88 | 19.22 | - | 20.16 | 20.63 |
| node | tsx-esm-modules-1 | scripts/entry.js | warm | 1 | - | module | module | pass | 30 | 19.15 | 18.78 | 19.11 | - | 19.56 | 19.74 |
| bun | tsx-esm-modules-1 | scripts/entry.tsx | cold | 1 | - | module | module | pass | 30 | 15.48 | 15.09 | 15.37 | - | 16.19 | 16.44 |
| bun | tsx-esm-modules-1 | scripts/entry.tsx | warm | 1 | - | module | module | pass | 30 | 15.27 | 14.81 | 15.21 | - | 15.67 | 16.71 |
| lpm | tsx-esm-modules-1 | scripts/entry.tsx | cold | 1 | - | module | module | pass | 30 | 57.62 | 56.08 | 57.68 | - | 58.80 | 58.96 |
| lpm | tsx-esm-modules-1 | scripts/entry.tsx | warm | 1 | - | module | module | pass | 30 | 38.41 | 37.43 | 38.18 | - | 40.47 | 43.29 |
| nub | tsx-esm-modules-1 | scripts/entry.tsx | cold | 1 | - | module | module | pass | 30 | 79.52 | 78.71 | 79.30 | - | 80.60 | 81.64 |
| nub | tsx-esm-modules-1 | scripts/entry.tsx | warm | 1 | - | module | module | pass | 30 | 78.88 | 77.27 | 78.54 | - | 81.36 | 83.56 |
| tsx | tsx-esm-modules-1 | scripts/entry.tsx | cold | 1 | - | module | module | pass | 30 | 110.15 | 108.77 | 110.12 | - | 110.99 | 111.09 |
| tsx | tsx-esm-modules-1 | scripts/entry.tsx | warm | 1 | - | module | module | pass | 30 | 102.63 | 100.63 | 102.38 | - | 106.18 | 107.01 |
| lpm-oxc-helper | oxc-helper-ts-cjs-files-1 | internal-ts-transform | none | 1 | 1 | commonjs | commonjs-omitted | pass | 30 | 4.50 | 4.00 | 4.46 | 4.46 | 5.14 | 5.80 |
| lpm-oxc-helper-persistent | oxc-helper-ts-cjs-files-1 | internal-ts-transform --persistent | none | 1 | 1 | commonjs | commonjs-omitted | pass | 30 | 4.38 | 3.97 | 4.31 | 4.31 | 5.05 | 5.20 |
| lpm-oxc-helper | oxc-helper-ts-esm-files-1 | internal-ts-transform | none | 1 | 1 | module | module | pass | 30 | 4.38 | 4.02 | 4.35 | 4.35 | 4.91 | 4.92 |
| lpm-oxc-helper-persistent | oxc-helper-ts-esm-files-1 | internal-ts-transform --persistent | none | 1 | 1 | module | module | pass | 30 | 4.84 | 3.97 | 4.45 | 4.45 | 7.09 | 7.45 |
| lpm-oxc-helper | oxc-helper-tsx-esm-files-1 | internal-ts-transform | none | 1 | 1 | module | module | pass | 30 | 4.52 | 3.90 | 4.47 | 4.47 | 5.18 | 5.35 |
| lpm-oxc-helper-persistent | oxc-helper-tsx-esm-files-1 | internal-ts-transform --persistent | none | 1 | 1 | module | module | pass | 30 | 4.50 | 3.98 | 4.44 | 4.44 | 5.16 | 5.18 |
| node | ts-cjs-modules-10 | scripts/entry.js | cold | 10 | - | commonjs | commonjs-omitted | pass | 30 | 18.89 | 18.49 | 18.90 | - | 19.12 | 19.30 |
| node | ts-cjs-modules-10 | scripts/entry.js | warm | 10 | - | commonjs | commonjs-omitted | pass | 30 | 18.93 | 18.50 | 18.87 | - | 19.43 | 20.34 |
| bun | ts-cjs-modules-10 | scripts/entry.ts | cold | 10 | - | commonjs | commonjs-omitted | pass | 30 | 15.80 | 15.34 | 15.71 | - | 16.47 | 16.57 |
| bun | ts-cjs-modules-10 | scripts/entry.ts | warm | 10 | - | commonjs | commonjs-omitted | pass | 30 | 15.48 | 15.07 | 15.33 | - | 16.31 | 16.52 |
| lpm | ts-cjs-modules-10 | scripts/entry.ts | cold | 10 | - | commonjs | commonjs-omitted | pass | 30 | 61.29 | 60.43 | 61.05 | - | 63.35 | 63.52 |
| lpm | ts-cjs-modules-10 | scripts/entry.ts | warm | 10 | - | commonjs | commonjs-omitted | pass | 30 | 38.92 | 37.79 | 38.76 | - | 39.79 | 39.91 |
| nub | ts-cjs-modules-10 | scripts/entry.ts | cold | 10 | - | commonjs | commonjs-omitted | pass | 30 | 80.70 | 79.74 | 80.58 | - | 81.50 | 81.73 |
| nub | ts-cjs-modules-10 | scripts/entry.ts | warm | 10 | - | commonjs | commonjs-omitted | pass | 30 | 80.09 | 78.53 | 80.08 | - | 81.25 | 82.22 |
| tsx | ts-cjs-modules-10 | scripts/entry.ts | cold | 10 | - | commonjs | commonjs-omitted | pass | 30 | 153.43 | 150.98 | 152.49 | - | 159.75 | 168.55 |
| tsx | ts-cjs-modules-10 | scripts/entry.ts | warm | 10 | - | commonjs | commonjs-omitted | pass | 30 | 105.11 | 103.43 | 104.69 | - | 107.24 | 114.27 |
| node | ts-esm-modules-10 | scripts/entry.js | cold | 10 | - | module | module | pass | 30 | 20.33 | 19.69 | 20.21 | - | 21.22 | 21.38 |
| node | ts-esm-modules-10 | scripts/entry.js | warm | 10 | - | module | module | pass | 30 | 20.20 | 19.70 | 20.02 | - | 21.35 | 23.55 |
| bun | ts-esm-modules-10 | scripts/entry.ts | cold | 10 | - | module | module | pass | 30 | 15.46 | 15.11 | 15.40 | - | 16.02 | 16.44 |
| bun | ts-esm-modules-10 | scripts/entry.ts | warm | 10 | - | module | module | pass | 30 | 15.17 | 14.73 | 15.17 | - | 15.45 | 15.81 |
| lpm | ts-esm-modules-10 | scripts/entry.ts | cold | 10 | - | module | module | pass | 30 | 62.06 | 60.16 | 61.37 | - | 66.99 | 69.30 |
| lpm | ts-esm-modules-10 | scripts/entry.ts | warm | 10 | - | module | module | pass | 30 | 38.59 | 37.79 | 38.51 | - | 39.53 | 39.55 |
| nub | ts-esm-modules-10 | scripts/entry.ts | cold | 10 | - | module | module | pass | 30 | 82.32 | 80.77 | 82.23 | - | 83.05 | 90.51 |
| nub | ts-esm-modules-10 | scripts/entry.ts | warm | 10 | - | module | module | pass | 30 | 80.33 | 79.20 | 80.21 | - | 82.17 | 83.12 |
| tsx | ts-esm-modules-10 | scripts/entry.ts | cold | 10 | - | module | module | pass | 30 | 116.77 | 113.51 | 114.87 | - | 123.90 | 130.75 |
| tsx | ts-esm-modules-10 | scripts/entry.ts | warm | 10 | - | module | module | pass | 30 | 105.70 | 103.96 | 105.43 | - | 107.90 | 109.24 |
| node | tsx-esm-modules-10 | scripts/entry.js | cold | 10 | - | module | module | pass | 30 | 22.24 | 21.40 | 22.14 | - | 23.89 | 24.01 |
| node | tsx-esm-modules-10 | scripts/entry.js | warm | 10 | - | module | module | pass | 30 | 22.93 | 21.31 | 22.65 | - | 24.36 | 29.05 |
| bun | tsx-esm-modules-10 | scripts/entry.tsx | cold | 10 | - | module | module | pass | 30 | 15.87 | 15.43 | 15.78 | - | 16.30 | 17.02 |
| bun | tsx-esm-modules-10 | scripts/entry.tsx | warm | 10 | - | module | module | pass | 30 | 15.87 | 15.19 | 15.62 | - | 17.04 | 17.21 |
| lpm | tsx-esm-modules-10 | scripts/entry.tsx | cold | 10 | - | module | module | pass | 30 | 64.57 | 63.44 | 64.56 | - | 66.32 | 66.37 |
| lpm | tsx-esm-modules-10 | scripts/entry.tsx | warm | 10 | - | module | module | pass | 30 | 43.89 | 41.00 | 43.81 | - | 46.70 | 51.29 |
| nub | tsx-esm-modules-10 | scripts/entry.tsx | cold | 10 | - | module | module | pass | 30 | 83.24 | 82.71 | 83.13 | - | 84.06 | 84.24 |
| nub | tsx-esm-modules-10 | scripts/entry.tsx | warm | 10 | - | module | module | pass | 30 | 81.38 | 79.74 | 81.15 | - | 83.92 | 86.18 |
| tsx | tsx-esm-modules-10 | scripts/entry.tsx | cold | 10 | - | module | module | pass | 30 | 118.84 | 116.66 | 118.54 | - | 122.80 | 123.95 |
| tsx | tsx-esm-modules-10 | scripts/entry.tsx | warm | 10 | - | module | module | pass | 30 | 109.82 | 107.31 | 108.96 | - | 118.75 | 124.53 |
| lpm-oxc-helper | oxc-helper-ts-cjs-files-10 | internal-ts-transform | none | 10 | 10 | commonjs | commonjs-omitted | pass | 30 | 45.23 | 42.13 | 44.17 | 4.42 | 54.28 | 56.78 |
| lpm-oxc-helper-persistent | oxc-helper-ts-cjs-files-10 | internal-ts-transform --persistent | none | 10 | 10 | commonjs | commonjs-omitted | pass | 30 | 4.51 | 4.07 | 4.51 | 0.45 | 4.97 | 4.97 |
| lpm-oxc-helper | oxc-helper-ts-esm-files-10 | internal-ts-transform | none | 10 | 10 | module | module | pass | 30 | 50.21 | 42.14 | 52.54 | 5.25 | 59.17 | 61.34 |
| lpm-oxc-helper-persistent | oxc-helper-ts-esm-files-10 | internal-ts-transform --persistent | none | 10 | 10 | module | module | pass | 30 | 4.70 | 4.03 | 4.64 | 0.46 | 5.30 | 5.56 |
| lpm-oxc-helper | oxc-helper-tsx-esm-files-10 | internal-ts-transform | none | 10 | 10 | module | module | pass | 30 | 42.56 | 39.56 | 41.38 | 4.14 | 50.51 | 55.74 |
| lpm-oxc-helper-persistent | oxc-helper-tsx-esm-files-10 | internal-ts-transform --persistent | none | 10 | 10 | module | module | pass | 30 | 4.53 | 4.03 | 4.53 | 0.45 | 4.92 | 5.14 |
| node | ts-cjs-modules-100 | scripts/entry.js | cold | 100 | - | commonjs | commonjs-omitted | pass | 30 | 24.10 | 23.58 | 24.10 | - | 24.96 | 25.28 |
| node | ts-cjs-modules-100 | scripts/entry.js | warm | 100 | - | commonjs | commonjs-omitted | pass | 30 | 23.36 | 22.66 | 23.30 | - | 23.79 | 24.74 |
| bun | ts-cjs-modules-100 | scripts/entry.ts | cold | 100 | - | commonjs | commonjs-omitted | pass | 30 | 18.82 | 18.21 | 18.73 | - | 19.53 | 19.62 |
| bun | ts-cjs-modules-100 | scripts/entry.ts | warm | 100 | - | commonjs | commonjs-omitted | pass | 30 | 17.89 | 17.53 | 17.85 | - | 18.53 | 19.06 |
| lpm | ts-cjs-modules-100 | scripts/entry.ts | cold | 100 | - | commonjs | commonjs-omitted | pass | 30 | 88.96 | 86.93 | 89.03 | - | 90.48 | 90.90 |
| lpm | ts-cjs-modules-100 | scripts/entry.ts | warm | 100 | - | commonjs | commonjs-omitted | pass | 30 | 47.48 | 46.46 | 47.30 | - | 49.25 | 49.27 |
| nub | ts-cjs-modules-100 | scripts/entry.ts | cold | 100 | - | commonjs | commonjs-omitted | pass | 30 | 102.06 | 100.18 | 101.91 | - | 103.09 | 103.56 |
| nub | ts-cjs-modules-100 | scripts/entry.ts | warm | 100 | - | commonjs | commonjs-omitted | pass | 30 | 90.37 | 88.86 | 90.24 | - | 91.86 | 92.42 |
| tsx | ts-cjs-modules-100 | scripts/entry.ts | cold | 100 | - | commonjs | commonjs-omitted | pass | 30 | 210.93 | 206.19 | 210.96 | - | 218.76 | 220.72 |
| tsx | ts-cjs-modules-100 | scripts/entry.ts | warm | 100 | - | commonjs | commonjs-omitted | pass | 30 | 124.23 | 122.81 | 123.87 | - | 128.23 | 130.21 |
| node | ts-esm-modules-100 | scripts/entry.js | cold | 100 | - | module | module | pass | 30 | 25.70 | 25.28 | 25.71 | - | 26.11 | 26.76 |
| node | ts-esm-modules-100 | scripts/entry.js | warm | 100 | - | module | module | pass | 30 | 25.09 | 24.51 | 25.02 | - | 26.07 | 26.13 |
| bun | ts-esm-modules-100 | scripts/entry.ts | cold | 100 | - | module | module | pass | 30 | 17.78 | 17.41 | 17.78 | - | 18.27 | 18.40 |
| bun | ts-esm-modules-100 | scripts/entry.ts | warm | 100 | - | module | module | pass | 30 | 17.03 | 16.40 | 16.74 | - | 19.13 | 22.33 |
| lpm | ts-esm-modules-100 | scripts/entry.ts | cold | 100 | - | module | module | pass | 30 | 85.91 | 84.54 | 85.54 | - | 87.80 | 87.82 |
| lpm | ts-esm-modules-100 | scripts/entry.ts | warm | 100 | - | module | module | pass | 30 | 45.84 | 44.73 | 45.63 | - | 46.92 | 48.19 |
| nub | ts-esm-modules-100 | scripts/entry.ts | cold | 100 | - | module | module | pass | 30 | 103.01 | 99.84 | 101.38 | - | 110.04 | 113.68 |
| nub | ts-esm-modules-100 | scripts/entry.ts | warm | 100 | - | module | module | pass | 30 | 89.51 | 88.43 | 89.53 | - | 90.34 | 91.12 |
| tsx | ts-esm-modules-100 | scripts/entry.ts | cold | 100 | - | module | module | pass | 30 | 146.55 | 144.38 | 146.35 | - | 148.44 | 150.70 |
| tsx | ts-esm-modules-100 | scripts/entry.ts | warm | 100 | - | module | module | pass | 30 | 127.96 | 126.02 | 127.89 | - | 129.34 | 130.27 |
| node | tsx-esm-modules-100 | scripts/entry.js | cold | 100 | - | module | module | pass | 30 | 29.76 | 29.24 | 29.70 | - | 30.54 | 30.93 |
| node | tsx-esm-modules-100 | scripts/entry.js | warm | 100 | - | module | module | pass | 30 | 29.00 | 28.47 | 28.93 | - | 29.61 | 30.90 |
| bun | tsx-esm-modules-100 | scripts/entry.tsx | cold | 100 | - | module | module | pass | 30 | 18.42 | 18.01 | 18.40 | - | 18.95 | 18.96 |
| bun | tsx-esm-modules-100 | scripts/entry.tsx | warm | 100 | - | module | module | pass | 30 | 17.61 | 17.24 | 17.54 | - | 17.92 | 19.12 |
| lpm | tsx-esm-modules-100 | scripts/entry.tsx | cold | 100 | - | module | module | pass | 30 | 97.49 | 94.98 | 96.26 | - | 106.40 | 111.95 |
| lpm | tsx-esm-modules-100 | scripts/entry.tsx | warm | 100 | - | module | module | pass | 30 | 54.74 | 53.67 | 54.54 | - | 56.41 | 57.40 |
| nub | tsx-esm-modules-100 | scripts/entry.tsx | cold | 100 | - | module | module | pass | 30 | 106.30 | 105.16 | 106.26 | - | 107.56 | 108.09 |
| nub | tsx-esm-modules-100 | scripts/entry.tsx | warm | 100 | - | module | module | pass | 30 | 94.20 | 93.09 | 94.09 | - | 95.16 | 97.64 |
| tsx | tsx-esm-modules-100 | scripts/entry.tsx | cold | 100 | - | module | module | pass | 30 | 177.24 | 173.82 | 176.25 | - | 189.03 | 190.14 |
| tsx | tsx-esm-modules-100 | scripts/entry.tsx | warm | 100 | - | module | module | pass | 30 | 159.90 | 156.96 | 158.27 | - | 172.19 | 174.82 |
| lpm-oxc-helper | oxc-helper-ts-cjs-files-100 | internal-ts-transform | none | 100 | 100 | commonjs | commonjs-omitted | pass | 30 | 433.56 | 423.52 | 429.67 | 4.30 | 464.02 | 475.73 |
| lpm-oxc-helper-persistent | oxc-helper-ts-cjs-files-100 | internal-ts-transform --persistent | none | 100 | 100 | commonjs | commonjs-omitted | pass | 30 | 5.02 | 4.63 | 4.98 | 0.05 | 5.48 | 5.50 |
| lpm-oxc-helper | oxc-helper-ts-esm-files-100 | internal-ts-transform | none | 100 | 100 | module | module | pass | 30 | 431.32 | 422.04 | 431.12 | 4.31 | 443.71 | 451.53 |
| lpm-oxc-helper-persistent | oxc-helper-ts-esm-files-100 | internal-ts-transform --persistent | none | 100 | 100 | module | module | pass | 30 | 5.21 | 4.43 | 4.97 | 0.05 | 7.30 | 7.41 |
| lpm-oxc-helper | oxc-helper-tsx-esm-files-100 | internal-ts-transform | none | 100 | 100 | module | module | pass | 30 | 446.40 | 429.48 | 437.78 | 4.38 | 493.61 | 498.51 |
| lpm-oxc-helper-persistent | oxc-helper-tsx-esm-files-100 | internal-ts-transform --persistent | none | 100 | 100 | module | module | pass | 30 | 5.26 | 4.64 | 5.14 | 0.05 | 5.80 | 6.84 |
| lpm | mts-esm-modules-10 | scripts/entry.mts | cold | 10 | - | module | commonjs-omitted | pass | 30 | 61.17 | 59.79 | 60.96 | - | 63.69 | 63.95 |
| lpm | mts-esm-modules-10 | scripts/entry.mts | warm | 10 | - | module | commonjs-omitted | pass | 30 | 38.22 | 37.34 | 38.14 | - | 38.96 | 39.45 |
| lpm | cts-cjs-modules-10 | scripts/entry.cts | cold | 10 | - | commonjs | module | pass | 30 | 60.93 | 59.95 | 60.55 | - | 62.05 | 70.69 |
| lpm | cts-cjs-modules-10 | scripts/entry.cts | warm | 10 | - | commonjs | module | pass | 30 | 38.32 | 37.31 | 38.11 | - | 39.61 | 40.21 |

Skipped Bun/Nub/tsx rows are benchmark-only comparisons; the harness never installs or fetches comparison tools.
