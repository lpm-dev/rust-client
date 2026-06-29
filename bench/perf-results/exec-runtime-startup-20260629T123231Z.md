# lpm exec runtime startup

- Date: `2026-06-29T18:03:07Z`
- Iterations: `20`
- Binary: `/Users/tolga/Documents/Projects/lpm-dev/rust-client/target/release/lpm-rs`
- Node: `v22.22.1`

| Case | Status | Avg ms | Min ms | Max ms |
| --- | --- | ---: | ---: | ---: |
| js exec startup | pass | 35.47 | 33.66 | 40.90 |
| ts lpm runtime startup | pass | 42.69 | 36.06 | 57.48 |
| tsx lpm runtime startup | pass | 41.65 | 37.98 | 55.42 |
| local tsx fallback startup | skipped: no local tsx binary available | - | - | - |
