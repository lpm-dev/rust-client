# LPM Benchmarks

Reproducible benchmarks comparing LPM against npm, pnpm, and bun.

## Quick Run

```bash
# Run all benchmarks (skips the destructive cold per-stage run by default)
./bench/run.sh

# Run a specific benchmark
./bench/run.sh cold-install          # Full-round (rm INSIDE timer)
./bench/run.sh cold-install-clean    # Equal-footing (rm OUTSIDE timer)
./bench/run.sh warm-install
./bench/run.sh up-to-date
./bench/run.sh script-overhead
./bench/run.sh builtin-tools
./bench/run.sh lpm-stages            # LPM per-stage breakdown via --json

# Enable the destructive cold per-stage run (wipes ~/.lpm/cache and ~/.lpm/store)
LPM_BENCH_ALLOW_WIPE=1 ./bench/run.sh lpm-stages
```

## Benchmarks

| Benchmark | What it measures |
|-----------|-----------------|
| `cold-install` | Full-round cold install — `rm -rf` INSIDE the timer. Measures the full "wipe + install" loop as a CI fresh-clone or bench iteration would see it. Pins Phase 32 guardrails. |
| `cold-install-clean` | Equal-footing cold install — `rm -rf` OUTSIDE the timer. Measures the install command ALONE, so per-tool global-cache wipe asymmetry doesn't skew the cross-tool comparison. |
| `warm-install` | Install with lockfile + cached packages (real-world daily workflow) |
| `up-to-date` | Install with everything already in place (the no-op fast path agents care about) |
| `script-overhead` | Time to execute a no-op script via each package manager |
| `builtin-tools` | `lpm lint`/`lpm fmt` vs `npx oxlint`/`npx biome` |
| `lpm-stages` | **LPM-only.** Per-stage breakdown (resolve / fetch / link / total) parsed from `lpm install --json` |

### Why two cold-install benchmarks?

Empirical measurement (2026-04-14) confirmed that per-iteration `rm -rf` of each tool's global cache charges ~700 ms of syscall time to that tool's cold-install number. LPM wipes `~/.lpm/cache` + `~/.lpm/store` (two paths); bun wipes `~/.bun/install/cache` (one). The asymmetric wipe cost was the dominant term in the lpm-vs-bun wall-clock gap, not engine speed.

- Use **`cold-install`** when you care about the full round-trip (CI cold-clone experience, guardrail regression checks).
- Use **`cold-install-clean`** when you care about the install command's actual performance independent of setup cost.

## Methodology

### Cross-tool wall-clock benchmarks
- Each benchmark runs 3 times and reports the median (configurable via `RUNS=N`).
- All tools use `--ignore-scripts` (or equivalent) to measure pure install speed.
- Benchmarked on the same machine, same network, same project.
- Results are wall-clock time (`date +%s%N`).
- `cold-install` wipes caches INSIDE the timed region. `cold-install-clean` wipes OUTSIDE.
- `warm-install` preserves lockfile + cache, wipes only `node_modules`.

### LPM per-stage benchmark (`lpm-stages`)
- Drives `lpm install --allow-new --json` and parses the `timing` object: `{resolve_ms, fetch_ms, link_ms, total_ms}`.
- Runs warm and up-to-date variants by default — both are non-destructive.
- The cold variant wipes `~/.lpm/cache` and `~/.lpm/store` — only runs when `LPM_BENCH_ALLOW_WIPE=1` is set.
- Per-stage timings are LPM-only because no other package manager exposes a stable structured shape for stage breakdowns.
- Used by Phase 32 guardrail #3: install-path features must not regress these numbers.
- Requires `python3` for portable JSON parsing.

## Latest Results

Run `./bench/run.sh` to generate results for your machine. Recorded baselines live in [`baselines/`](./baselines/) once captured.
