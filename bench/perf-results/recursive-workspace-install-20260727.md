# Recursive workspace install — 2026-07-27

The baseline is `main` at `8555ddbe50747b481ac2956f205f998e67aa7a9e`.
Both binaries used the release profile with the default mimalloc allocator.
Fixtures contain an empty workspace root and 15–240 independent, empty members.
Every fixture was warm before timed rounds.

Environment:

- macOS 26.5.2 (25F84)
- Apple M5 Pro, 48 GB RAM
- rustc 1.94.1
- hyperfine 1.20.0
- 3 warmups and 20 measured runs for recursive installs
- 3 warmups and 5 measured runs for legacy full passes

## Results

The legacy arm launches one root-only `lpm install` process for every member,
then one for the workspace root. The final arm is a single no-flag
`lpm install` from the workspace root.

| Members | Legacy full pass | Final default | Improvement |
| ---: | ---: | ---: | ---: |
| 15 | 101.7 ms | 10.7 ms | 9.5× |
| 30 | 221.2 ms | 14.7 ms | 15.1× |
| 60 | 513.7 ms | 22.6 ms | 22.8× |
| 120 | 1,339.6 ms | 39.2 ms | 34.2× |
| 240 | 4,049.2 ms | 73.8 ms | 54.9× |

With 16× as many members, the legacy pass takes 39.8× as long. The final
default path takes 6.88× as long. A single process discovers the workspace
once, shares the immutable discovery metadata across target installs, refreshes
only the active manifest, and reuses one workspace lock.

The explicit `--recursive` checkpoint before default dispatch was enabled
measured 12.0, 15.1, 24.6, 45.9, and 100.7 ms for the same fixture sizes.
Replacing per-target workspace clones with shared metadata reduced the final
240-member result by a further 26.7%. The final measurement also includes a
post-`pnpm:devPreinstall` manifest reload for every target, matching the
single-project lifecycle contract when that script edits `package.json`.

## Peak RSS

At 240 members:

| Path | Maximum RSS |
| --- | ---: |
| Legacy full pass | 18,956,288 bytes (18.08 MiB) |
| Explicit checkpoint | 20,627,456 bytes (19.67 MiB) |
| Final default | 19,464,192 bytes (18.56 MiB) |

The final path adds 507,904 bytes (2.7%) over the legacy per-process peak. It
uses 1,163,264 fewer bytes than the first explicit checkpoint. The final value
is the highest of five measured runs.

## Reproduction

Build the release binary, then run the committed harness:

```bash
cargo build --release --locked -p lpm-cli
bench/bench-recursive-workspace-install.sh \
  target/release/lpm-rs \
  bench/perf-results/recursive-workspace-install-latest.json
```

The harness accepts `LPM_RECURSIVE_BENCH_MODE=default|explicit|legacy`.
`LPM_BENCH_RUNS` and `LPM_BENCH_WARMUP` override the measured and warmup
counts.

The recorded commands used these optional-work suppressions so the measurement
isolates workspace orchestration:

```bash
lpm install \
  --no-security-summary \
  --no-skills \
  --no-editor-setup \
  --no-audit-after-install
```
