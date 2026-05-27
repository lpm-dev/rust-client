# top-npm-audit — long-tail npm package install audit

Closes Phase 66 confidence-followup §1b. Generates a fixture
per package in [`top-100.txt`](./top-100.txt), runs each
under both isolated and hoisted modes, and reports any
mode-asymmetric outcomes.

## Why this exists

The curated `bench/audit-fixtures` suite tests ~30 representative
dep-graph shapes. This suite tests **breadth at scale** — long-tail
breakage that only surfaces with real-world download volume. Together
they form the §1b coverage tier described in
[the confidence-followup doc](../../DOCS/new-features/37-rust-client-RUNNER-VISION-phase66-confidence-followup.md).

## Usage

```bash
# build lpm-rs once
cargo build --release -p lpm-cli

# regenerate fixtures from top-100.txt + run all
./bench/top-npm-audit/run-all.sh

# filter by substring (e.g., only run @babel/* fixtures)
./bench/top-npm-audit/run-all.sh babel

# tune parallelism (default 4)
LPM_TOP_NPM_PARALLEL=8 ./bench/top-npm-audit/run-all.sh
```

## How it works

1. **Generate** — `generate.sh` produces a `package.json` + `smoke.sh`
  per package under `bench/audit-fixtures/top-npm/<safe-name>/`.
  Most fixtures keep the default root-load smoke (`require` first,
  `import` fallback only for genuine ESM-only surfaces), but packages
  with a different consumer contract get a matching fixture class:
  CLI bin invocation, type-check smoke, runner smoke, or peer-aware
  companion deps.
2. **Run** — `run-all.sh` invokes the existing
   `bench/audit-fixtures/run-audit.sh` for each generated fixture in
   parallel, with per-slot `LPM_HOME` so concurrent installs don't
   stomp on each other's `~/.lpm/cache` / `~/.lpm/store`.
3. **Aggregate** — same asymmetric-outcome gate as the curated suite.

## Result interpretation

- **PASS/PASS** — done.
- **FAIL/FAIL** — symmetric. Not a hoisted regression. The category-aware
  summary now tells you whether the residual is a non-runtime package,
  entrypoint mismatch, fixture limitation, upstream interop failure, or
  another typed bucket.
- **PASS/FAIL or FAIL/PASS** — asymmetric. Real hoisted regression.
  Investigate immediately.

## Maintaining the list

`top-100.txt` is hand-curated. Refresh quarterly from npm download
stats (npms.io / npm-stat). Skip:

- Packages requiring native toolchain (better-sqlite3, sharp) — those
  belong in the curated audit-fixtures bucket with a `requirements.sh`.

ESM-only packages are first-class citizens in this audit tier, and the
generator now supports a small number of explicit fixture classes for
packages whose real consumer contract is not a blank-project root import.

## CI gating

Workflow-dispatch + weekly schedule only (see `.github/workflows/ci.yml`).
Each run takes ~5–15 minutes depending on parallelism + network.
