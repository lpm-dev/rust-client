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
| 15 | 101.7 ms | 11.2 ms | 9.1× |
| 30 | 221.2 ms | 15.9 ms | 13.9× |
| 60 | 513.7 ms | 25.0 ms | 20.5× |
| 120 | 1,339.6 ms | 44.2 ms | 30.3× |
| 240 | 4,049.2 ms | 83.8 ms | 48.3× |

With 16× as many members, the legacy pass takes 39.8× as long. The final
default path takes 7.46× as long. A single process shares immutable discovery
metadata across member installs, refreshes only each active member manifest,
performs one fresh root discovery before the root install so merged
`pnpm-workspace.yaml` configuration stays current, and reuses one workspace
lock.

The explicit `--recursive` checkpoint before default dispatch was enabled
measured 12.0, 15.1, 24.6, 45.9, and 100.7 ms for the same fixture sizes.
Replacing per-target workspace clones with shared metadata reduced the final
240-member result by a further 16.8%. The final measurement also includes a
post-`pnpm:devPreinstall` manifest reload for every target, matching the
single-project lifecycle contract when that script edits `package.json`.

## Package-manager reference

A separate 240-member run compares one up-to-date root install per package
manager. Each manager has an isolated fixture, HOME, cache, and store. Samples
are round-robin with a rotating first manager. LPM, Bun, and npm use the
package.json workspace declaration; pnpm additionally receives its required
`pnpm-workspace.yaml`.

| Manager | Version | Median | p95 | Relative to fastest |
| --- | --- | ---: | ---: | ---: |
| LPM | 0.69.0 | 86.49 ms | 97.72 ms | 6.03× |
| Bun | 1.3.14 | 14.34 ms | 17.29 ms | 1.00× |
| pnpm | 11.3.0 | 174.31 ms | 192.51 ms | 12.16× |
| npm | 10.9.4 | 242.43 ms | 248.83 ms | 16.91× |

LPM is 2.02× faster than pnpm and 2.80× faster than npm in this
orchestration-only workload. Bun remains 6.03× faster than LPM. LPM writes one
`lpm.lock` and one binary sidecar per project (241 of each); the other managers
write one root lockfile.

## Peak RSS

At 240 members:

| Path | Maximum RSS |
| --- | ---: |
| Legacy full pass | 18,956,288 bytes (18.08 MiB) |
| Explicit checkpoint | 20,627,456 bytes (19.67 MiB) |
| Final default | 19,791,872 bytes (18.88 MiB) |

The final path adds 835,584 bytes (4.4%) over the legacy per-process peak. It
uses 835,584 fewer bytes than the first explicit checkpoint. The final value is
the highest of five measured runs.

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

Run the four-manager 240-member reference with:

```bash
node bench/scripts/recursive-workspace-install-benchmark.mjs \
  --members 240 \
  --samples 20 \
  --warmups 3 \
  --managers lpm,bun,pnpm,npm
```
