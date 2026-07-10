# Install benchmark scripts

## Production-readiness harness

`run-install-readiness.mjs` is the current install-readiness harness. It is
meant for production-default decisions and cross-package-manager references,
not for one-off hand-timed installs.

It provides:

- isolated temp project, `HOME`, package-manager cache, and `LPM_HOME`
- cold, warm-cache, and up-to-date modes
- round-robin interleaving by sample to reduce live-network bias
- configurable sample count, fixtures, package managers, lpm routes, lpm firewall modes, and lpm env cells
- JSON, Markdown, stdout/stderr, resolved fixture source, and per-run metrics artifacts
- expected/unexpected warning classification for known noisy installs
- top-package sweeps from a package-name file with offset/limit chunking

Warm mode first seeds the package-manager cache/store, then removes generated
project install artifacts before the counted run. That means warm numbers are
cache/store-warm clean-project reinstalls, not repeat no-op installs over an
already materialized `node_modules`.

Up-to-date mode runs one more install over the project materialized by the
previous successful install, so it measures the no-op state check.

Build lpm first:

```bash
cargo build --release --locked -p lpm-cli --bin lpm-rs
```

Run the harness self-test after changing warning or summary logic:

```bash
node bench/scripts/run-install-readiness.mjs --self-test
```

Capture the current lpm cold/warm/up-to-date reference first:

```bash
node bench/scripts/run-install-readiness.mjs \
  --samples 10 \
  --fixtures dogfood,nest,vitepress \
  --managers lpm \
  --modes cold,warm,up-to-date
```

Capture a one-off firewall-enabled reference without paying that cost on every
knob run:

```bash
node bench/scripts/run-install-readiness.mjs \
  --samples 1 \
  --fixtures dogfood,nest,vitepress \
  --managers lpm \
  --modes cold,warm,up-to-date \
  --lpm-firewall-modes off,report
```

Use `--lpm-firewall-modes off,enforce` for the fail-closed gate when the
benchmark environment has LPM auth, for example through `LPM_TOKEN`.

Capture an apples-to-apples package-manager reference snapshot when needed:

```bash
node bench/scripts/run-install-readiness.mjs \
  --samples 5 \
  --fixtures dogfood,nest,vitepress \
  --managers lpm,bun,pnpm,npm \
  --modes cold,warm,up-to-date \
  --lpm-firewall-modes off,report
```

Compare one candidate lpm knob against current lpm:

```bash
node bench/scripts/run-install-readiness.mjs \
  --samples 10 \
  --fixtures dogfood,nest,vitepress \
  --managers lpm \
  --modes cold,warm,up-to-date \
  --lpm-cell current \
  --lpm-cell cap:LPM_V2_FINALIZE_PERMITS=2
```

Compare the exact-version-doc experimental path explicitly:

```bash
node bench/scripts/run-install-readiness.mjs \
  --samples 5 \
  --fixtures dogfood,nest,vitepress \
  --managers lpm \
  --modes cold \
  --lpm-cell current \
  --lpm-cell exact-doc:LPM_EXPERIMENTAL_INSTALLER_SPIKE=1,LPM_INSTALLER_SPIKE_BENCHMARK_ONLY=1,LPM_INSTALLER_SPIKE_GRAPH=resolve-worklist,LPM_INSTALLER_SPIKE_PARITY=deny,LPM_INSTALLER_SPIKE_EXACT_DOC=1
```

Run a top-package correctness sweep in chunks:

```bash
node bench/scripts/run-install-readiness.mjs \
  --samples 1 \
  --top-npm-file bench/top-npm-audit/top-100.txt \
  --top-npm-offset 0 \
  --top-npm-limit 25 \
  --managers lpm \
  --modes cold \
  --lpm-cell current \
  --lpm-cell exact-doc:LPM_EXPERIMENTAL_INSTALLER_SPIKE=1,LPM_INSTALLER_SPIKE_BENCHMARK_ONLY=1,LPM_INSTALLER_SPIKE_GRAPH=resolve-worklist,LPM_INSTALLER_SPIKE_PARITY=deny,LPM_INSTALLER_SPIKE_EXACT_DOC=1 \
  --allow-failures
```

When `--top-npm-file` is used, lpm runs default to
`LPM_TYPOSQUAT_GUARD=0`. This sweep is meant to sample broad install
correctness, package identity, parity mismatches, and warnings; typosquat
policy can be audited separately without blocking the long-tail install
surface. Pass `--lpm-typosquat-guard default` to keep the production guard on.

Fixture names built in today:

- `dogfood`
- `nest`
- `vite-react`
- `vitepress`
- `native-sharp`

The harness also accepts `name=/path/to/project` and `pkg:<name>@<version>`
fixtures for focused checks and top-package sweeps.

`vitepress` prefers `bench/fixtures/vitepress-docs`, a tracked manifest-only
fixture derived from the VitePress 1.5.0 repository. If that fixture is absent,
the harness checks the local real-world audit cache and then falls back to a
generated VitePress install fixture.

For production-default decisions, keep competitor and firewall-enabled runs as
reference snapshots. Legacy proxy routes remain available for focused routing
checks, but normal knob work should usually compare current lpm against one
candidate lpm cell, with 5+ samples and round-robin ordering.

Every install subprocess has a timeout, defaulting to 10 minutes. Override it
with `--timeout-ms` for top-package sweeps that need a different failure bound.

Rows include `expected_warnings` and `unexpected_warnings`. Expected warning
families currently cover npm/npx bin-shadow notices from bundled npm fixtures,
Husky's missing `.git` message in copied fixtures, and Vite's CJS API
deprecation note. Unknown warning lines remain visible in `rows.json`,
`metrics.json`, per-run `warnings.json`, `warning-summary.json`,
`warning-summary.md`, and the summary's `Warnings exp/unknown` column.

## Run/bin wrapper benchmark

`run-bin-benchmark.mjs` measures local script-runner and local-bin runner
overhead against the same generated fixture. Setup installs exact local
dependencies before timing; measured rows only execute `package.json` scripts
or local `node_modules/.bin` entries.

The suite reports p50 and p95 as primary metrics, with avg/min/max and raw
samples in the JSON artifact. Markdown and JSON are written to
`bench/perf-results/`.

```bash
node bench/scripts/run-bin-benchmark.mjs --self-test
node bench/scripts/run-bin-benchmark.mjs --list

ITERATIONS=3 WARMUP_ITERATIONS=1 \
  node bench/scripts/run-bin-benchmark.mjs
```

Useful knobs:

```bash
LPM_BIN=/path/to/lpm-rs NUB_BIN=/path/to/nub NUBX_BIN=/path/to/nubx \
  ITERATIONS=30 WARMUP_ITERATIONS=2 \
  node bench/scripts/run-bin-benchmark.mjs

GROUPS=script-runner SCENARIOS='noop|node-noop' \
  node bench/scripts/run-bin-benchmark.mjs

GROUPS=local-bin-runner RUNNERS='lpm-exec,lpm-shorthand,pnpm-exec,npx-no-install' \
  node bench/scripts/run-bin-benchmark.mjs
```

Script-runner rows cover `noop`, `node-noop`, and a script that invokes the
local native `esbuild` bin. Local-bin rows report native `esbuild --version`
and Node CLI `tsc --version` separately; do not collapse those into one
"faster than npx" claim, because target startup cost changes the wrapper
overhead ratio.

## Install pipeline benchmark scripts

The older scripts in this directory captured the walker/resolver fusion and
lifecycle-script benchmark methodology. They are kept so the same
measurements can be re-run after future install-pipeline changes.

## Scripts

| Script | What it measures |
|---|---|
| `run-5cell.sh` | Main 3-arm + bun benchmark on `bench/fixture-large` (266 packages). 3 lpm cells (`pubgrub-stream`, `greedy-stream`, `greedy-fusion`) × n iterations + n_bun bun control. Round-robin per outer iter so adjacent samples see similar network state. |
| `run-script-policy.sh` | Four cells: `lpm-default` / `lpm-yolo-autobuild` / `bun-default` / `bun-ignore-scripts`. Quantifies the `--ignore-scripts` ↔ `--policy=allow` like-for-like delta vs the apples-to-oranges default comparison. |
| `capture-samply-fusion.sh` | Single cold install with `samply record`, debug symbols enabled. Outputs flame-graph-loadable JSON + side `.syms.json` for offline symbolication. |
| `summarize.py` | Common summarizer for any of the result directories above. Prints per-arm medians, paired t-stats, and the fusion gates (hard ≤1500 ms, stretch ≤1000 ms, stdev ≤500 ms). |

## Usage

Build a release binary first (separate target dir avoids polluting the
dev incremental cache):

```bash
CARGO_TARGET_DIR=/tmp/lpm-rs-bench-target cargo build --release -p lpm-cli
```

The scripts hardcode `BIN=/tmp/lpm-rs-bench-target/release/lpm-rs` and
`FIXTURE=/Users/tolga/.../bench/fixture-large`. Update those two lines at
the top of each script if your paths differ. (Kept as hardcoded paths
rather than env vars to favor exact reproducibility over portability.)

Then run any of:

```bash
bench/scripts/run-5cell.sh        20  my-tag    # n=20 main bench, ~5 min wall
bench/scripts/run-script-policy.sh 10  pol-tag  # n=10 4-cell policy, ~3 min
bench/scripts/capture-samply-fusion.sh         # single sample + flamegraph
```

Re-summarize an existing result set without re-running:

```bash
python3 bench/scripts/summarize.py /tmp/lpm-fusion-bench/<tag>-results
```

The scripts wipe `~/.lpm/{cache,store}` and the fixture's `node_modules`
between iterations for cold-equal-footing measurement. Don't run them
while you have a real lpm install you care about cached.

## Canonical baseline (default fusion, n=20)

Use these as the reference any future bench should approximately reproduce.
Captured 2026-04-27 on Apple M-series, macOS 15.4.

| Arm | n=20 median | mean | trim-mean (10%) | stdev |
|---|---:|---:|---:|---:|
| pubgrub-stream | 4,338 ms | 4,744 ms | 4,542 ms | 996 ms |
| greedy-stream (`LPM_GREEDY_FUSION=0`) | 4,487 ms | 4,795 ms | 4,673 ms | 894 ms |
| **greedy-fusion (default)** | **938 ms** | **990 ms** | **945 ms** | **164 ms** |
| bun (n=10) | 804 ms | 842 ms | 829 ms | 112 ms |

**Key paired comparisons (n=20):**
- greedy-stream → greedy-fusion: Δ −3,804 ms, t = −18.81 (massively significant)
- pubgrub-stream → greedy-fusion: Δ −3,754 ms, t = −16.46
- greedy-fusion vs bun: 1.17× bun median

**Fusion gates (applied to fusion arm):**
- Hard ≤ 1,500 ms ✓ (562 ms margin)
- Stretch ≤ 1,000 ms ✓ (62 ms margin)
- Stdev ≤ 500 ms ✓ (3× below limit)

## "Is something off?" thresholds

When re-running after future changes, consider:

- **greedy-fusion median in 850-1,050 ms range:** all good, network/CDN
  variance dominates within this band.
- **greedy-fusion median in 1,050-1,200 ms range:** mild regression worth
  flagging but probably not blocking — re-run to rule out network noise
  (the W3-vs-W4 cross-run drift was ±20 ms, but bun's stdev hit 500+ ms
  on one of those days, so single-run noise can mask the real signal).
- **greedy-fusion median ≥ 1,200 ms:** real regression, investigate.
  Check `dispatcher.inflight_high_water` and `parked_max_depth` in any
  iter's JSON to confirm the dispatcher is healthy; spot-check `fetch_ms`
  vs the baseline 298 ms to localize where the regression lives.
- **stdev ≥ 500 ms:** tail-stability regression. Could be a deadlock / sync
  primitive contention issue in the dispatcher; probably wants a samply
  flamegraph capture before guessing.

## Raw bench data location

The original n=20/n=10 result directories lived at
`/tmp/lpm-fusion-bench/{w1-validation,w3-fusion,w4-default-flip,script-policy}-results/`
on the original measurement machine. They are not version-controlled here
(~11 MB, stale by definition). The medians and stdevs in the table above are
the authoritative summary; raw per-iter JSONs can be re-generated by
re-running the harness against any specific commit.
