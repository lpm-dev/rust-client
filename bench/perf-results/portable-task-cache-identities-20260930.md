# Portable task-cache identities

The opt-in `cachePortable: true` shares relocatable task outputs across checkout roots and identical native Node/Bun installations. The default remains location-sensitive.

## Environment and method

- Apple M5 Pro, Mac17,9, 48 GiB RAM, macOS 27.0, arm64, APFS.
- Rust 1.94.0, shipped release profile (`opt-level=3`, LTO, one codegen unit).
- Node v24.19.0, Bun executable also present on PATH, esbuild 0.25.12, Python 3.14.6.
- Baseline source: `9ea1a79a980e01d7867c7abab571b3836a6a70b1` (0.79.0).
- Implementation source: `d6360673e01d645dd12164cbd68e5e80bebed6f0`.
- Before binary SHA-256: `7059355a5eb5a7ae7871676a40c6d3ee362319dbf5b5110485f71db8d346efe1`.
- After binary SHA-256: `22e2b78b2456f6af3c47dbb56b160d47d5fdf9a5dac00d806c99c6cb39b1d4e4`.
- Both binaries are preserved under `/tmp/lpm-portable-cache-bench/` on the measurement host.

The fixture bundles 400 TypeScript modules with 32,000 exported strings: 3,180,084 source bytes. It runs esbuild synchronously with bundling and minification. Producer and consumer have separate checkout roots and isolated homes. Both use the same fixed esbuild installation through a node_modules link. No dependency installation is timed.

The HTTP fixture stores signed artifacts by the exact requested key. Each remote sample clears the consumer's local task cache and seeds only the producer's artifact. A marker proves whether the consumer executes the task. All measured outputs have the same SHA-256. The fixture runs on loopback; these numbers do not measure hosted cache latency or a web/mobile frontend.

There are 20 samples per binary per state. Binary order alternates each round. State order rotates each round. Initial unmeasured runs seed artifacts and runtime digest records. Cold-digest states delete only runtime digest records before the measured invocation; executable bytes remain warm in the OS cache. An earlier sequential-state run showed drift and was replaced by this interleaved run.

Times include process startup, cache lookup, validation, task execution when needed, output restoration, and cache publication. `/usr/bin/time -l` supplies maximum resident set size. This metric is not the simultaneous sum of all process-tree memory.

## End-to-end results

| State | Before median (ms) | After median (ms) | Before / after executions |
| --- | ---: | ---: | ---: |
| Default identity, local hit | 117.3 | 116.0 | 0 / 0 |
| Portable opt-in, local hit | 116.9 | 116.5 | 0 / 0 |
| Cross-checkout remote lookup, warm digest | 291.0 | 164.3 | 20 / 0 |
| Cross-checkout remote lookup, cold digest | 282.9 | 238.6 | 20 / 0 |
| Local hit, cold digest | 118.9 | 194.4 | 0 / 0 |
| Uncached esbuild task | 123.9 | 125.5 | 20 / 20 |

The warm cross-checkout median decreases by 126.7 ms (about 44%) for this fixture because the consumer restores the producer's artifact. The baseline executes and publishes a second artifact. The interquartile ranges are 274.0–295.9 ms before and 157.8–168.4 ms after.

The default local-hit difference lies within the timing spread: before IQR 112.0–123.6 ms, after IQR 110.0–121.4 ms. The portable warm-hit ranges also overlap: before IQR 112.1–120.9 ms, after IQR 110.5–123.2 ms. This run does not establish a meaningful warm local regression or speedup.

First-use content hashing has a real cost. Deleting digest records adds about 78 ms to the portable local-hit median in this environment. Records persist under the existing metadata-cache category, so normal later invocations avoid this work. Metadata changes invalidate records; Unix ctime also detects edits that restore the previous mtime.

The warm remote state reports median maximum RSS of 64.9 MiB before and 23.7 MiB after. The task no longer starts Node/esbuild on a hit. Local-hit RSS remains about 20 MiB. Raw per-sample values are in [the JSON report](portable-task-cache-identities-20260930.json).

This fixture also shows the limits of caching small builds: the uncached task takes about 126 ms, less than the 164 ms remote restore. The result supports faster reuse within the existing cache-enabled workflow; it does not establish that remote caching beats uncached execution for every task.

## Runtime identity microbenchmark and optimization review

`task_cache_identity_bench` measures runtime snapshot capture without source hashing, HTTP, artifact extraction, or task execution. Each invocation has 1,000 warm samples:

| Invocation | First capture | Warm median |
| --- | ---: | ---: |
| No persisted digest records | 70.980 ms | 0.061 ms |
| Persisted digest records available | 0.205 ms | 0.062 ms |

The selected Node and Bun files are 121,306,800 and 61,884,464 bytes. Content hashes use a reusable 128 KiB streaming buffer, not a whole-file allocation. Fingerprint-indexed records avoid hashing these bytes on every invocation. Per-executable `OnceLock` cells also share one computation among concurrent tasks in one process; this concurrency benefit is a complexity analysis, not a separately measured speedup.

The end-to-end cold/warm difference confirms that avoiding repeated executable hashing matters at task-pipeline scale. Warm identity capture is already much smaller than artifact restoration. More allocation tuning in that helper has no demonstrated end-to-end benefit.

A separate optimization lead is remote-to-local cache promotion. `run/cache.rs` calls `store_cache` after a remote restore, and `lpm-task/src/cache.rs::store_cache_locked` creates another output archive. Reusing an admitted remote archive can avoid this second compression pass. This report does not attribute the entire restore time to that step or claim a speedup. A follow-on change needs profiling plus coverage for output admission, signatures, race validation, and interruption recovery before replacing the current publication path.

## Correctness and recovery validation

Final local gates passed: workspace build with zero warnings, workspace/all-target clippy, formatting, 6,896 non-CLI tests, 5,338 serial CLI unit tests, 116 CLI binary-surface tests, and 134 task-runner workflow tests. Public schemas match the generated CLI schema. The documentation production build, lint, types, and content-date checks passed.

The workflow tests run the real CLI with isolated homes and projects, and a signed HTTP cache indexed by the requested artifact key. They cover cross-checkout restoration, independently copied native runtimes, source and declared environment invalidation, workspace prerequisites in normal/parallel/stream/JSON modes, default location sensitivity, runtime mutation during a download, and same-root reuse with opaque launchers. The optimized CLI also runs all seven scenarios.

The original cross-checkout and native-installation regressions failed before implementation. Review added two failing unit regressions before their fixes: distinct non-UTF-8 relative paths must not collapse during normalization, and working-directory/PATH field boundaries must not collapse in opaque launcher identities. The non-UTF-8 test uses raw paths as pure inputs; it does not claim that APFS accepts those filenames.

Runtime mutation during a remote download must cause task execution instead of restoration and must prevent publication under the stale identity. Existing signature, output admission, secret filtering, and source/dependency race checks remain in the execution path. Linux PR CI and the Windows filesystem gate explicitly run the new portable-cache workflows.

No hosted service, browser, desktop frontend, or mobile frontend was exercised. The remote protocol is unchanged; identity generation and validation run on the execution host, regardless of which client starts the task.

## Reproduction

```bash
# Build and preserve the baseline before changing production sources.
df -h /tmp
CARGO_TARGET_DIR=/tmp/lpm-portable-cache-target cargo build --release --locked -p lpm-cli --bin lpm-rs
cp /tmp/lpm-portable-cache-target/release/lpm-rs /tmp/lpm-portable-cache-bench/before

# Build and preserve the implementation with the same release profile.
df -h /tmp
CARGO_TARGET_DIR=/tmp/lpm-portable-cache-target cargo build --release --locked -p lpm-cli --bin lpm-rs
cp /tmp/lpm-portable-cache-target/release/lpm-rs /tmp/lpm-portable-cache-bench/after

npm install --prefix /tmp/lpm-portable-cache-bench/tools --ignore-scripts --no-audit --no-fund esbuild@0.25.12
python3 bench/scripts/portable-task-cache-benchmark.py \
  --before /tmp/lpm-portable-cache-bench/before \
  --after /tmp/lpm-portable-cache-bench/after \
  --tools /tmp/lpm-portable-cache-bench/tools \
  --work-dir /tmp/lpm-portable-cache-bench/final-interleaved-20 \
  --samples 20

# Use a new metadata-cache home for the first microbenchmark invocation.
df -h /tmp
CARGO_TARGET_DIR=/tmp/lpm-portable-cache-target cargo build --release --locked -p lpm-runtime --example task_cache_identity_bench
LPM_HOME=/tmp/lpm-portable-cache-bench/final-micro-home /tmp/lpm-portable-cache-target/release/examples/task_cache_identity_bench 1000
LPM_HOME=/tmp/lpm-portable-cache-bench/final-micro-home /tmp/lpm-portable-cache-target/release/examples/task_cache_identity_bench 1000
```

Run the commands from the rust-client root. The benchmark requires a new dedicated `--work-dir`; it refuses to overwrite one. The binaries must come from their respective source revisions. The first microbenchmark invocation needs a previously unused `LPM_HOME` to reproduce the cold-record measurement.
