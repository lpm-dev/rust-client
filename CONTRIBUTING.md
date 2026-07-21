# Contributing to LPM

LPM is a security- and performance-sensitive package manager. Contributions should be narrowly scoped, tested at the correct layer, and explicit about compatibility and trust-boundary changes.

## Development setup

CI uses Rust 1.94.0. Install that toolchain with `rustfmt` and Clippy, plus `cargo-nextest`:

```bash
rustup toolchain install 1.94.0 --component rustfmt,clippy
cargo install cargo-nextest --locked
```

Node.js 22 is required for npm wrapper, release-artifact, and some workflow tests. On Debian or Ubuntu, install the native keyring build dependencies:

```bash
sudo apt-get update
sudo apt-get install -y pkg-config libdbus-1-dev
```

Run Cargo commands below with Rust 1.94.0, either through a directory override or the `cargo +1.94.0` form.

## Testing changes

Run targeted tests while iterating:

```bash
cargo test -p lpm-common --locked
cargo test -p lpm-cli -- self_update
cargo nextest run --locked -p lpm-workflows --test install -E 'test(install_updates_lockfile)'
```

For a bug, add a regression test that fails before the fix, then implement the fix. A feature or behavior change must include tests.

Use the correct test tier:

| Tier | Location | Purpose |
| --- | --- | --- |
| Workflow | `tests/workflows/tests/` | Default for multi-step CLI workflows; use `TempProject`, `lpm()`, and `MockRegistry`. |
| CLI binary | `crates/lpm-cli/tests/` | TTY/stdin, global state, parser/schema corpora, or minimal binary-only reproductions. |
| Integration | `tests/integration/tests/` | Cross-crate local pipelines that do not need the CLI binary. |
| Unit | Inline `#[cfg(test)]` modules | Pure helpers and internal invariants. |

Before opening a pull request, run the fast PR-equivalent build and test gate:

```bash
cargo build --workspace --locked
cargo nextest run --locked -p lpm-workflows --test native_build_cache --no-fail-fast --status-level slow --final-status-level fail
cargo nextest run --locked --workspace --exclude lpm-workflows --exclude lpm-cli --no-fail-fast --status-level slow --final-status-level fail
cargo test --locked -p lpm-cli --bin lpm-rs -- --test-threads=1
cargo nextest run --locked -p lpm-cli -E 'not binary_id(/bin\/lpm-rs/)' --no-fail-fast --status-level slow --final-status-level fail
```

Also run the formatting and lint checks:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets --locked -- -D warnings
```

List the exact commands and results in the pull request. The current [CI workflow](.github/workflows/ci.yml) is authoritative for additional platform, shell, npm, audit, and release checks.

## Contracts and documentation

- Public product language uses **env**. `vault` is reserved for internal crate and module names.
- New or changed `--json` output requires a JSON snapshot plus semantic assertions for stable fields such as error or doctor codes.
- User-facing behavior changes require corresponding documentation updates in [lpm-dev/rust-client-docs](https://github.com/lpm-dev/rust-client-docs).
- Performance-sensitive changes should include comparable before-and-after measurements at both microbenchmark and end-to-end levels where applicable.
- Never include credentials, tokens, private registry URLs, or private project data in tests, fixtures, issues, commits, or logs.

## Pull requests

Create a descriptive branch, keep unrelated changes out of the diff, and open a pull request against `main`. Do not push directly to `main`. CI must be green before merge, but green CI is not permission to merge without maintainer consent.

Keep commits and PR descriptions focused on the behavior being changed. Do not add deferred TODOs for work that can be completed in the same change. Source comments should explain only non-obvious invariants, interoperability contracts, security boundaries, or performance constraints.

Report suspected vulnerabilities privately according to [SECURITY.md](SECURITY.md).
