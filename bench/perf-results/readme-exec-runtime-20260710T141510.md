# lpm source runtime benchmark suite

- Date: `2026-07-10T13:15:10.741Z`
- Source Git SHA: `22d20109`
- Iterations: `10`
- Warmup iterations: `2`
- Module counts: `10`
- Binary: `/Users/tolga/Documents/Projects/lpm-dev/rust-client/target/release/lpm-rs`
- Binary source: `explicit LPM_BIN`
- LPM: `lpm 0.67.0`
- Node: `v22.22.1` via `/Users/tolga/.n/bin/node`
- Node source: `current Node process`
- Bun: `1.3.14`
- Bun binary: `/Users/tolga/.bun/bin/bun`
- Nub: `skipped`
- Nub binary: `set NUB_BIN to enable`
- tsx: `tsx v4.19.4 node v22.22.1`
- tsx binary: `/tmp/lpm-bench-tools/node_modules/.bin/tsx`

Each comparison fixture uses the same generated module graph: `node` runs the JS baseline, while `bun`, `lpm`, `nub`, and `tsx` run the matching TS/TSX source.
Cold clears the runner's transform cache before every measured run. Warm runs 2 unmeasured warmup iteration(s) and then reuses that cache.
`lpm-oxc-helper` rows run one transform helper process per file. `lpm-oxc-helper-persistent` rows run one `internal-ts-transform --persistent` process for the whole module set.

| Runner | Fixture | Entry | Cache | Modules | Helper calls | Format | Project mode | Status | Iterations | Avg ms | Min ms | P50 ms | P50/call ms | P95 ms | Max ms |
| --- | --- | --- | --- | ---: | ---: | --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| node | tsx-esm-modules-10 | scripts/entry.js | cold | 10 | - | module | module | pass | 10 | 20.84 | 20.62 | 20.79 | - | 21.11 | 21.11 |
| node | tsx-esm-modules-10 | scripts/entry.js | warm | 10 | - | module | module | pass | 10 | 20.91 | 20.38 | 20.69 | - | 22.24 | 22.24 |
| bun | tsx-esm-modules-10 | scripts/entry.tsx | cold | 10 | - | module | module | pass | 10 | 21.98 | 20.69 | 21.38 | - | 26.37 | 26.37 |
| bun | tsx-esm-modules-10 | scripts/entry.tsx | warm | 10 | - | module | module | pass | 10 | 18.94 | 18.16 | 18.58 | - | 21.22 | 21.22 |
| lpm | tsx-esm-modules-10 | scripts/entry.tsx | cold | 10 | - | module | module | pass | 10 | 66.63 | 62.88 | 65.55 | - | 71.88 | 71.88 |
| lpm | tsx-esm-modules-10 | scripts/entry.tsx | warm | 10 | - | module | module | pass | 10 | 41.09 | 40.03 | 40.82 | - | 42.50 | 42.50 |
| nub | tsx-esm-modules-10 | scripts/entry.tsx | cold | 10 | - | module | module | skipped: NUB_BIN is unset or not executable | 0 | - | - | - | - | - | - |
| nub | tsx-esm-modules-10 | scripts/entry.tsx | warm | 10 | - | module | module | skipped: NUB_BIN is unset or not executable | 0 | - | - | - | - | - | - |
| tsx | tsx-esm-modules-10 | scripts/entry.tsx | cold | 10 | - | module | module | pass | 10 | 121.94 | 117.82 | 120.63 | - | 129.91 | 129.91 |
| tsx | tsx-esm-modules-10 | scripts/entry.tsx | warm | 10 | - | module | module | pass | 10 | 112.70 | 108.87 | 112.14 | - | 116.62 | 116.62 |

Skipped Bun/Nub/tsx rows are benchmark-only comparisons; the harness never installs or fetches comparison tools.
