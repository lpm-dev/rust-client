# LPM Benchmarks

Reproducible benchmarks comparing LPM against npm, pnpm, and bun.

## Quick Run

```bash
# Run all benchmarks
./bench/run.sh

# Run a specific benchmark
./bench/run.sh warm-install
./bench/run.sh script-overhead
./bench/run.sh builtin-tools
```

## Benchmarks

| Benchmark | What it measures |
|-----------|-----------------|
| `warm-install` | Install with lockfile + cached packages (real-world daily workflow) |
| `script-overhead` | Time to execute a no-op script via each package manager |
| `builtin-tools` | `lpm lint`/`lpm fmt` vs `npx oxlint`/`npx biome` |

## Methodology

- Each benchmark runs 3 times and reports the median
- Caches are cleared between cold runs, preserved for warm runs
- All tools use `--ignore-scripts` where applicable to measure pure install speed
- Benchmarked on the same machine, same network, same project
- Results are wall-clock time (`time` command)

## Latest Results

Run `./bench/run.sh` to generate results for your machine.
