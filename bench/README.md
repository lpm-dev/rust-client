# LPM Benchmarks

Reproducible benchmarks comparing LPM against npm, pnpm, and bun.

## Quick Run

```bash
# Run all benchmarks (skips the destructive cold per-stage run by default)
./bench/run.sh

# Run a specific benchmark
./bench/run.sh cold-install
./bench/run.sh warm-install
./bench/run.sh up-to-date
./bench/run.sh script-overhead
./bench/run.sh builtin-tools
./bench/run.sh lpm-stages       # NEW: LPM per-stage breakdown via --json

# Enable the destructive cold per-stage run (wipes ~/.lpm/cache and ~/.lpm/store)
LPM_BENCH_ALLOW_WIPE=1 ./bench/run.sh lpm-stages
```

## Benchmarks

| Benchmark | What it measures |
|-----------|-----------------|
| `cold-install` | Install with no cache, no lockfile (cross-tool wall-clock) |
| `warm-install` | Install with lockfile + cached packages (real-world daily workflow) |
| `up-to-date` | Install with everything already in place (the no-op fast path agents care about) |
| `script-overhead` | Time to execute a no-op script via each package manager |
| `builtin-tools` | `lpm lint`/`lpm fmt` vs `npx oxlint`/`npx biome` |
| `lpm-stages` | **LPM-only.** Per-stage breakdown (resolve / fetch / link / total) parsed from `lpm install --json` |

## Methodology

### Cross-tool wall-clock benchmarks
- Each benchmark runs 3 times and reports the median.
- Caches are cleared between cold runs, preserved for warm runs.
- All tools use `--ignore-scripts` (or equivalent) to measure pure install speed.
- Benchmarked on the same machine, same network, same project.
- Results are wall-clock time (`date +%s%N`).

### LPM per-stage benchmark (`lpm-stages`)
- Drives `lpm install --allow-new --json` and parses the `timing` object: `{resolve_ms, fetch_ms, link_ms, total_ms}`.
- Runs warm and up-to-date variants by default — both are non-destructive.
- The cold variant wipes `~/.lpm/cache` and `~/.lpm/store` — only runs when `LPM_BENCH_ALLOW_WIPE=1` is set.
- Per-stage timings are LPM-only because no other package manager exposes a stable structured shape for stage breakdowns.
- Used by Phase 32 guardrail #3: install-path features must not regress these numbers.
- Requires `python3` for portable JSON parsing.

## Latest Results

Run `./bench/run.sh` to generate results for your machine. Recorded baselines live in [`baselines/`](./baselines/) once captured.
