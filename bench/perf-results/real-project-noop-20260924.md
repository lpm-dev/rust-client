# Real-project synchronous no-op admission

Plain `lpm --json install` can now use the synchronous no-op path when locked dependencies have Node engine constraints.
The stored engine key admits a candidate; a live Node probe must still confirm that key before success.
One authoritative lockfile snapshot serves both admission and freshness checks, including content-based fallback after harmless file touches.

The path validates current configuration, registry routing, project policy, layout, and release state.
Root scripts, workspaces, source scanning, strict peers, policy extensions, and unsupported sources use the normal install pipeline.
Strict peer replay now checks cached manifests and exact provider identities during unchanged, frozen, and offline installs.
It preserves supported local, workspace, catalog, alias, Git, and tagged peer semantics.

## No-op measurements

Each fixture has 100 samples per state and variant, with all six variant orders balanced.
Baseline and candidate share physical project/store paths; each manifest is created once.
Each variant has two unscored warm gates. Cache removal occurs outside timing.
All 800 candidate responses confirm synchronous admission: `up_to_date: true` without the asynchronous `counts` field.
All 2,400 installs pass the installed-package resolution check.

Times are median / nearest-rank p95 milliseconds. RSS is the median process peak in MiB.

| Fixture | State | Baseline ms | Candidate ms | Bun ms | LPM RSS before → after |
|---|---|---:|---:|---:|---:|
| T3 | Up to date | 29.96 / 30.92 | 22.91 / 23.36 | 11.72 / 13.16 | 28.81 → 20.31 |
| T3 | Cache removed | 30.06 / 30.79 | 22.91 / 23.60 | 12.12 / 13.73 | 28.72 → 20.31 |
| Vite React | Up to date | 26.11 / 27.21 | 21.78 / 22.35 | 9.59 / 11.00 | 25.72 → 20.31 |
| Vite React | Cache removed | 26.26 / 27.08 | 21.87 / 22.45 | 9.80 / 10.86 | 25.72 → 20.31 |
| Sharp | Up to date | 23.83 / 24.39 | 21.32 / 21.75 | 7.48 / 7.92 | 23.19 → 20.31 |
| Sharp | Cache removed | 23.92 / 24.70 | 21.34 / 21.91 | 7.54 / 7.97 | 23.23 → 20.31 |
| Nest | Up to date | 23.75 / 24.53 | 21.31 / 21.74 | 7.87 / 8.41 | 23.11 → 20.31 |
| Nest | Cache removed | 23.93 / 24.61 | 21.40 / 22.07 | 8.03 / 8.54 | 23.09 → 20.31 |

All LPM lockfiles match byte-for-byte between variants. Distinct package-name/version inventories match across both LPM binaries and Bun.
That inventory check does not establish identical filesystem layouts or complete installed-file byte parity with Bun.
The remaining Node process probe and startup costs remain measurable; this change does not reach Bun's no-op latency.

## Regression controls

The standard readiness matrix ran six samples for all four fixtures in cold, warm, and up-to-date modes.
Its flags use the normal asynchronous pipeline. All installs succeeded; warm and up-to-date wall/RSS comparisons passed.
The live comparison was inconclusive overall: Vite cold median increased from 498.5 to 602.5 ms, mainly during resolver waiting.
Some phase comparisons were also inconclusive. These observations do not identify their cause.

A separate 60-round Vite cold comparison used frozen metadata and original tarball bytes.
The capture contains 283 responses and 63 tarballs verified against registry integrity hashes.
Scoring had zero upstream requests, misses, or rejected requests. Both LPM lockfiles and all selected-package inventories matched.

| Variant | Median / p95 ms | Median peak RSS MiB |
|---|---:|---:|
| Baseline | 285.67 / 316.33 | 188.20 |
| Candidate | 288.01 / 313.58 | 187.61 |
| Bun | 184.42 / 218.31 | 143.79 |

The median paired candidate-minus-baseline difference was +0.40 ms.
The large live slowdown did not repeat with fixed inputs. This control does not prove a cold-install speedup or explain the live difference.
The six-sample live cohort is retained alongside the frozen comparison; it is not replaced by it.

## Validation and evidence

Rust 1.94.0 workspace build, Clippy with warnings denied, and formatting passed.
The final source passed 6,735 non-CLI tests, 5,292 serial CLI unit tests, 116 CLI surface tests, and 87 affected workflows.
Previously completed unchanged shell, Node, and npm helper gates also passed.
Regression coverage includes configuration/policy changes, live Node shims, strict peer replay, source substitution, recovery, sidecars, and normalized lockfile freshness.

The ledger has 30 reports: 26 addressed and four rejected with evidence; none are blocked or pending for this concept.
The addressed reports include two duplicates, two design constraints, five measurement safeguards, and 17 implementation findings.
Design constraints preserve parsed lockfile authority and live Node probing. They are not additional production bugs.
Other approved performance concepts remain separate investigations.

[Raw samples and provenance](real-project-noop-20260924.json) include binary hashes, source hashes, all no-op samples, live comparison results, and frozen Vite samples.
The baseline production source matches main `1e48536213ec39dbcebef075bf2a764710283fa1`; the candidate source is `11c64e2d4`.
The baseline build began before the final test-only merge; those intervening changes did not affect production source.
Scoring used Node 22.22.1, Bun 1.4.2, macOS arm64, and V2 stores. Builds, tests, and profilers did not run during scoring.

To repeat the no-op cohort, copy the [reproduction files](../scripts/install-noop-benchmark/) to an evidence directory.
Set absolute binary and fresh output paths in all four JSON configurations.
From the repository root, run `node <evidence>/paired-warm.mjs <evidence>/bare-<fixture>-100.json` for each fixture, then `python3 <evidence>/summarize.py`.
The reproduction script keeps the scored execution path; unused legacy reporting helpers were removed. Both script hashes are recorded.
