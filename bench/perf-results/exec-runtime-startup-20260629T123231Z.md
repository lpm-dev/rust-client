# lpm exec runtime startup

- Date: `2026-06-29T12:32:31Z`
- Iterations: `20`
- Binary: `/Users/tolga/Documents/Projects/lpm-dev/rust-client/target/release/lpm-rs`
- Node: `v22.22.1`

| Case | Status | Avg ms | Min ms | Max ms |
| --- | --- | ---: | ---: | ---: |
| js exec startup | pass | 36.02 | 33.51 | 42.63 |
| ts lpm runtime startup | pass | 39.11 | 35.24 | 54.40 |
| tsx lpm runtime startup | pass | 39.81 | 35.71 | 57.92 |
| local tsx fallback startup | skipped: no local tsx binary available | - | - | - |
