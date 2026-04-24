# Phase 49 Ship Gate — Pre-Merge Checklist

Per preplan §9, Phase 49 ships as **one PR → one release** with a
measurement-gated merge. This document is the procedure.

Reference: [preplan §9 + §10.2](../DOCS/new-features/37-rust-client-RUNNER-VISION-phase49-streaming-resolver-preplan.md)
(in the `a-package-manager` repo).

## 1. Full CI gate (local)

Run every step from `.github/workflows/ci.yml` as workspace-wide:

```bash
cd /path/to/lpm-dev/rust-client

# Use a separate target dir so the bench gate doesn't trash the
# dev incremental cache.
export CARGO_TARGET_DIR=/tmp/lpm-phase49-ship-gate-target

cargo clippy --workspace -- -D warnings     # lint
cargo fmt --check                           # format
grep -r 'fancy-regex' crates/*/Cargo.toml   # banned; should be empty

cargo build --workspace
cargo nextest run --workspace --exclude lpm-integration-tests --no-fail-fast

# lpm-auth deterministic check (keychain race per memory).
# Run 3× in parallel-default cargo test:
for i in 1 2 3; do cargo test -p lpm-auth; done
```

Expected: all green. Phase 49 baseline on merge-ready branch:
- clippy `--workspace -D warnings` clean
- fmt clean
- 4375+ workspace tests pass, 0 failures, 7 skipped (platform-gated)
- `cargo test -p lpm-auth` deterministic across 3 runs

## 2. F1 interleaved A/B (51-pkg canonical fixture)

**Must not regress.** This is the continuity anchor with prior phases'
published numbers.

```bash
cd bench
./run.sh cold-install-clean              # engine + wall-clock stages
./run.sh cold-install                    # full wipe loop
```

Gates:
- Engine cold resolve: **≤ 250 ms** (currently 225 ms on main post-Phase-A)
- Wall-clock `cold-install-clean`: **≤ 800 ms** (currently 754 ms)

The script's `lpm (direct)` vs `lpm (proxy)` A/B (new in §8) is the
within-session comparison; Direct is the shipped default.

## 3. F2 interleaved A/B (266-pkg large fixture)

**Primary Phase 49 target.** Use the newly-committed `bench/fixture-large/`
fixture. If the bench harness doesn't automatically pick it up,
symlink or copy into `bench/project/` for that run.

```bash
cd bench
./run.sh cold-install-clean  # with fixture-large/ as the project
```

Gates (per preplan §10.2, math-checked):
- **Proxy mode** (`LPM_NPM_ROUTE=proxy`): no regression vs a fresh
  interleaved A/B of `origin/main` head (re-baseline at merge time —
  do NOT use the stale 1886 ms / 2135 ms numbers from the preplan,
  those are from different measurement rounds).
- **Direct mode** (shipped default, the `lpm (direct)` line in the
  A/B output): **≤ 1.8 s** wall-clock. See preplan §10.2 math check.
- **Cold CF edge** (long-tail uncached): **≤ 2.0 s** target.

If direct-mode comes in > 1.8 s, DO NOT MERGE. Diagnose the gap
(fetch-bound, concurrency-bound, or tarball-bound) and name the
Phase 50 lever (streaming tarball work, concurrency > 50 with 429
backoff). "≤ 15% of bun" is a *stretch* goal contingent on Phase
50 follow-on work; the ≤ 1.8 s direct-mode target is the merge gate.

## 4. Streaming-BFS observability spot-check

Run a single `--json` install and verify the new sub-object:

```bash
lpm install --json 2>&1 | jq '.timing.resolve.streaming_bfs'
```

Healthy shape (per preplan §5.6):
```json
{
  "walk_ms": <walker's metadata-producer wall-clock>,
  "manifests_fetched": <walker's SharedCache inserts>,
  "cache_hits": <walker skipped because cache already held>,
  "cache_waits": <PubGrub callbacks that entered the wait-loop>,
  "cache_wait_timeouts": 0,
  "escape_hatch_fetches": 0,
  "spec_tx_send_wait_ms": 0,
  "max_depth": <deepest BFS level>
}
```

Red flags:
- `cache_wait_timeouts > 0` — walker left a gap; timeout fired.
- `escape_hatch_fetches > 0` (in Direct mode with walker attached) —
  same signal as above.
- `spec_tx_send_wait_ms > 0` — dispatcher backpressure; mpsc buffer
  (512) may need raising or dispatcher is CPU-bound.

## 5. Revert rehearsal

Before merging, confirm `LPM_NPM_ROUTE=proxy` restores pre-49 routing
behavior end-to-end without touching any code:

```bash
LPM_NPM_ROUTE=proxy lpm install --json 2>&1 | jq '.timing.resolve.streaming_bfs.escape_hatch_fetches'
```

In Proxy mode the walker batches through `/api/registry/batch-metadata`,
and the provider's escape-hatch picks up individual gaps. This is the
runtime escape hatch; post-release rollback is `git revert <PR>` + a
prior-version release.

## 6. Merge checklist

- [ ] Step 1 (CI gate) green
- [ ] Step 2 (F1) within gates
- [ ] Step 3 (F2) within gates, direct mode ≤ 1.8 s
- [ ] Step 4 (`streaming_bfs` JSON) red flags clear
- [ ] Step 5 (revert rehearsal) works
- [ ] Fresh `git log origin/main...HEAD` reads cleanly — 15 Phase 49 commits + this PR

If any gate misses: diagnose, iterate, re-measure. Do NOT merge on
partial gates or plan to fix post-merge — the phased rollout model
was explicitly rejected in the preplan's beta-reality reframe (§2.1).
