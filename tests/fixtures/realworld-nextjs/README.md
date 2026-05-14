# realworld-nextjs fixture

**Purpose:** real-world-shaped dependency tree for exercising the install pipeline at production scale — Item 5 of `private/test-coverage-followup-plan.md`.

## What this fixture represents

The `package.json` pins exact versions of a minimal-but-realistic Next.js + TypeScript app's direct deps:

- `next@14.2.13` — published 2024-09
- `react@18.3.1` — published 2024-04
- `react-dom@18.3.1` — paired peer
- `typescript@5.6.3` — published 2024-09
- `@types/node@22.10.1`, `@types/react@18.3.12`, `@types/react-dom@18.3.1` — typed-app shapes

The resolved transitive closure is **~28 packages** (empirically measured against npmjs on 2026-05-14). That count came as a surprise — modern Next.js + React + TS trees are much tighter than what was floated in the original plan annotation (which guessed ~80-120). The smaller-than-expected real-world scale is informative: most of the perceived bulk in a `node_modules` directory comes from `eslint` / `tailwindcss` / build-tool deps, not from the app framework itself.

The resolved tree exercises:

- **Platform-specific optional deps** — Next.js ships `@next/swc-*` binaries gated by `os`/`cpu` predicates. The resolver must pick the right one for the current platform and skip the others without failing.
- **Peer-dependency resolution** — Next.js declares `react` and `react-dom` as peer deps; the lockfile must record the satisfying versions, not duplicate them.
- **Leaf typed packages** — `@types/*` packages have zero transitive deps each; their inclusion tests the resolver's handling of leaf-only nodes without inflating tarball-download work.
- **Real npm tarball shapes** — every tarball comes through Verdaccio's proxy to `registry.npmjs.org`, exercising real-world `.tgz` payloads (not the mock-registry's hand-rolled `package/package.json`-only tarballs).

## Empirical install timings (M-series macOS, 2026-05-14 dev box)

- **Cold install** (Verdaccio storage empty, all tarballs proxied from npmjs upstream): **~14 s** end-to-end. Internal breakdown observed: resolve ~4.7 s, fetch ~7.9-8.2 s (parallel tarball downloads through the proxy), link ~0.1 s.
- **Warm install** (second `lpm install` on the same project, lockfile + store populated): **~8.5 ms** via the install-hash fast path — the resolved-tree fingerprint matches, so the entire resolve / fetch / link pipeline short-circuits.
- **Cold/warm ratio**: ~1650× (yes, three orders of magnitude — the install-hash fast path is effectively a no-op).

## Budget calibration {#calibration}

The wall-clock and memory budgets enforced by [`install_realworld.rs`](../../workflows/tests/install_realworld.rs) under `LPM_BUDGET_GATE=1` are derived from N≥5 measured runs on the calibrated reference machine. **Current calibration: M-series macOS dev box, 2026-05-14.**

### Methodology

1. Run the test 5+ times on the target reference machine. Record:
   - Cold install wall-clock (logged as `cold_install_elapsed=<duration>`).
   - Warm install wall-clock (logged as `warm_install_elapsed=<duration>`).
   - Cold install peak resident-set size (logged as `peak_rss=<mib> MiB`).
2. Compute mean and max over the N runs.
3. Set the budget to **max × headroom factor**, where the factor reflects the metric's volatility:
   - Cold wall-clock: 1.5× — moderate variance from network/Verdaccio jitter.
   - Warm wall-clock: ~3× — micro-timing dominated by process-startup overhead; tight absolute window but a 3× factor absorbs OS-scheduling spikes.
   - Peak RSS: ~1.7× — memory ceilings depend on allocator behavior under load (in-flight tarball buffering), needs more headroom than CPU-bound metrics.
4. Round the result up to a clean value so future re-calibrations don't need to be re-rounded.

### Current numbers (calibrated 2026-05-14, M-series macOS, N=6)

| Metric | Mean | Max | Budget | Multiplier |
|---|---|---|---|---|
| Cold install (wall-clock) | 15.03 s | 16.6 s | **25 s** | 1.51× |
| Warm install (wall-clock) | 8.6 ms | 8.8 ms | **25 ms** | 2.84× |
| Cold install (peak RSS) | 822 MiB | 884 MiB | **1500 MiB** | 1.70× |

Raw N=6 cold-install runs: 15.5 s, 15.5 s, 16.6 s, 14.7 s, 14.1 s, 13.8 s.
Raw N=3 warm-install runs: 8.5 ms, 8.5 ms, 8.8 ms.
Raw N=3 peak-RSS runs (measured separately via standalone `/usr/bin/time -l`): 884 MiB, 832 MiB, 749 MiB.

### When to re-derive

Re-calibrate the budgets in [`install_realworld.rs`](../../workflows/tests/install_realworld.rs) (`COLD_INSTALL_BUDGET`, `WARM_INSTALL_BUDGET`, `COLD_PEAK_RSS_BUDGET_BYTES`) when:

- **The fixture changes** — adding/removing direct deps shifts the resolved tree size and therefore install wall-clock + memory.
- **The reference machine changes** — different CPU profile, different network latency to npmjs, different OS (macOS BSD `time -l` vs Linux GNU `time -v` for memory).
- **A measured run trends past the budget** — either fix the regression OR (if the slowdown is justified, e.g. a security-scan addition) bump the budget with a one-line entry in the "Calibration history" section below.

### Calibration history

- **2026-05-14, M-series macOS dev box** — initial calibration. N=6 cold + N=3 warm + N=3 RSS. Budgets: cold 25 s, warm 25 ms, RSS 1500 MiB.

These numbers are recorded to stderr by the test for future budget-calibration work (Item 5 §2-§4). They are **not** asserted against fixed thresholds because real wall-clock budgets need a calibrated reference machine + 5+ measured runs + headroom per the plan's acceptance criteria.

## Why exact versions

The version pin is for **test determinism**: the fixture must resolve to the same tree across CI runs so the install-success assertion is reproducible. A semver range like `^14.0.0` would let the resolver pick whatever's latest, which would change over time and could break the test if a future Next.js patch ships a breaking transitive dep.

When this fixture's pins fall behind real-world current versions:

1. Update the three version literals in `package.json` to the current stable patch.
2. Re-run the install tests; if they pass, commit.
3. If they fail, the failure mode is the test's job (regression in the install pipeline against a newer real-world tree).

## What this fixture is NOT

- **Not a perf budget.** Wall-clock numbers are deliberately not asserted by the bundled tests — they're CI-flake-prone without a calibrated reference machine. Item 5 §1 (this fixture) and Item 5 §2-§4 (cold/warm/memory budgets) are deliberately split so the fixture can ship without waiting on a reference-machine setup.
- **Not a published-app shape.** No build scripts, no `eslint`, no `typescript`, no app code. The smallest manifest that produces a real-world-scale transitive tree is enough; adding more deps would just inflate test runtime without exercising new install-pipeline surface.
- **Not committed `node_modules/` or `lpm.lock`.** Tests resolve and install fresh against Verdaccio so the contract is "install succeeds AT REAL SCALE", not "the install matches a snapshot".

## How tests use this fixture

Tests in [`tests/workflows/tests/install_realworld.rs`](../../workflows/tests/install_realworld.rs) load this fixture via `TempProject::from_fixture("realworld-nextjs")`, configure Verdaccio as the registry, and run `lpm install`. The contract pinned is end-to-end success: the install completes, the lockfile generates, the expected direct-dep packages materialize in `node_modules/`, and the install-hash is written.
