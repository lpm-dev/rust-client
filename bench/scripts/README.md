# Install benchmark scripts

## Production-readiness harness

`run-install-readiness.mjs` is the current install-readiness harness. It is
meant for production-default decisions and cross-package-manager references,
not for one-off hand-timed installs.

It provides:

- isolated temp project, `HOME`, package-manager cache, and `LPM_HOME`
- cold mode and warm-cache mode
- round-robin interleaving by sample to reduce live-network bias
- configurable sample count, fixtures, package managers, lpm routes, lpm firewall modes, and lpm env cells
- JSON, Markdown, stdout/stderr, resolved fixture source, and per-run metrics artifacts
- expected/unexpected warning classification for known noisy installs
- top-package sweeps from a package-name file with offset/limit chunking

Warm mode first seeds the package-manager cache/store, then removes generated
project install artifacts before the counted run. That means warm numbers are
cache/store-warm clean-project reinstalls, not repeat no-op installs over an
already materialized `node_modules`.

Build lpm first:

```bash
cargo build --release --locked -p lpm-cli --bin lpm-rs
```

Run the harness self-test after changing warning or summary logic:

```bash
node bench/scripts/run-install-readiness.mjs --self-test
```

Capture the current lpm cold/warm reference first:

```bash
node bench/scripts/run-install-readiness.mjs \
  --samples 10 \
  --fixtures dogfood,nest,vitepress \
  --managers lpm \
  --modes cold,warm
```

Capture a one-off firewall-enabled reference without paying that cost on every
knob run:

```bash
node bench/scripts/run-install-readiness.mjs \
  --samples 1 \
  --fixtures dogfood,nest,vitepress \
  --managers lpm \
  --modes cold,warm \
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
  --modes cold
```

Compare one candidate lpm knob against current lpm:

```bash
node bench/scripts/run-install-readiness.mjs \
  --samples 10 \
  --fixtures dogfood,nest,vitepress \
  --managers lpm \
  --modes cold,warm \
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

`vitepress` prefers the local real-world audit cache at
`bench/realworld-audit/.cache/vitepress-docs` when present, because that is
the full heavy graph used by the recent installer measurements. If the cache
is absent, the harness falls back to a generated VitePress install fixture.

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

## Historical fusion scripts

The older scripts in this directory drove every measurement in Phase 56
(walker/resolver fusion) and Phase 57 (measurement sprint + lifecycle-script
work). Captured here so the same methodology can be re-run after future
changes to the install pipeline.

## Scripts

| Script | What it measures |
|---|---|
| `run-5cell.sh` | Main 3-arm + bun benchmark on `bench/fixture-large` (266 packages). 3 lpm cells (`pubgrub-stream`, `greedy-stream`, `greedy-fusion`) × n iterations + n_bun bun control. Round-robin per outer iter so adjacent samples see similar network state. |
| `run-security-cost.sh` | Phase 57 Bench A. Measures the wall-clock cost of the security analyzer by toggling `LPM_SKIP_SECURITY=1`. Empirical answer: ~0 ms (Phase 38 P2's fused scan amortizes the cost into extraction). |
| `run-script-policy.sh` | Phase 57 Bench B. Four cells: `lpm-default` / `lpm-yolo-autobuild` / `bun-default` / `bun-ignore-scripts`. Quantifies the `--ignore-scripts` ↔ `--policy=allow` like-for-like delta vs the apples-to-oranges default comparison. |
| `capture-samply-fusion.sh` | Single cold install with `samply record`, debug symbols enabled. Outputs flame-graph-loadable JSON + side `.syms.json` for offline symbolication. |
| `summarize.py` | Common summarizer for any of the result directories above. Prints per-arm medians + paired t-stats + the post-W4 fusion gates (hard ≤1500 ms, stretch ≤1000 ms, stdev ≤500 ms). |

## Usage

Build a release binary first (separate target dir avoids polluting the
dev incremental cache):

```bash
CARGO_TARGET_DIR=/tmp/lpm-rs-bench-target cargo build --release -p lpm-cli
```

The scripts hardcode `BIN=/tmp/lpm-rs-phase56-target/release/lpm-rs` and
`FIXTURE=/Users/tolga/.../bench/fixture-large`. Update those two lines at
the top of each script if your paths differ. (Kept as hardcoded paths
rather than env vars to match how the original Phase 56-57 measurements
were taken — exact reproducibility over portability.)

Then run any of:

```bash
bench/scripts/run-5cell.sh        20  my-tag    # n=20 main bench, ~5 min wall
bench/scripts/run-security-cost.sh 20  sec-tag  # n=20 security cost, ~3 min
bench/scripts/run-script-policy.sh 10  pol-tag  # n=10 4-cell policy, ~3 min
bench/scripts/capture-samply-fusion.sh         # single sample + flamegraph
```

Re-summarize an existing result set without re-running:

```bash
python3 bench/scripts/summarize.py /tmp/phase56-fusion-bench/<tag>-results
```

The scripts wipe `~/.lpm/{cache,store}` and the fixture's `node_modules`
between iterations for cold-equal-footing measurement. Don't run them
while you have a real lpm install you care about cached.

## Canonical baseline (Phase 56 W4 default-flip, n=20)

These are the numbers committed at `102353e` (Phase 56 W4 — fusion-as-default
ship gate). Use as the reference any future bench should approximately
reproduce. Captured 2026-04-27 on Apple M-series, macOS 15.4.

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

**Phase 56 W4+ gates (applied to fusion arm):**
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

## Methodology references

- [Phase 56 fusion pre-plan](../../DOCS/new-features/37-rust-client-RUNNER-VISION-phase56-walker-resolver-fusion-preplan.md) (in `a-package-manager` repo)
- [Phase 57 measurement-sprint close-out](../../DOCS/new-features/37-rust-client-RUNNER-VISION-phase57-measurement-sprint-closeout.md) (in `a-package-manager` repo)
- Phase 56 W3 commit: `caf40f7` (W2 implementation) + W4 default-flip commit `102353e`
- Phase 57 commits: `bce527f` (`--policy=allow` runs scripts) + `44d485d` (lifecycle scripts run from live dir)

## Raw bench data location

The original n=20/n=10 result directories from Phases 56-57 lived at
`/tmp/phase56-fusion-bench/{w1-validation,w3-fusion,w4-default-flip,security-cost,script-policy}-results/`
on the original measurement machine. Not version-controlled here (~11 MB,
stale by definition). The medians + stdevs in the table above are the
authoritative summary; raw per-iter JSONs would be re-generated by
re-running the harness against any specific commit.
