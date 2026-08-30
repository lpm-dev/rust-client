# Outdated release-time fixture ledger

Concept branch: `codex/outdated-release-time-fixture`

Implementation commit: `57c49ea1`

Concept pull request: [lpm-dev/rust-client#672](https://github.com/lpm-dev/rust-client/pull/672)

| ID | Source | Category | Location | Claim | Evidence | Disposition | Coverage | Commit | PR status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| COR-009 / TEST-OUTDATED-001 | primary post-fix CI review | Correctness | `tests/workflows/tests/outdated.rs::outdated_hydrates_release_times_in_bounded_parallel_waves` | The fixture used a fixed metadata timestamp and became older than the 24-hour hydration threshold after midnight UTC on 2026-08-30, so the test expected release-time requests that the production code correctly skipped. | The test failed unchanged on `origin/main` with zero requests instead of four. Replacing the fixed timestamp with the existing `iso8601_n_secs_ago(60)` helper keeps the package metadata inside the intended hydration window. | Verified | The formerly failing test passes, and the full `outdated` workflow target passes all 31 tests. | `57c49ea1` | Included in [#672](https://github.com/lpm-dev/rust-client/pull/672) |

## Verification

- `cargo test -p lpm-workflows --test outdated outdated_hydrates_release_times_in_bounded_parallel_waves --locked -- --exact`: passed.
- `cargo test -p lpm-workflows --test outdated --locked`: 31 passed.
- `cargo clippy -p lpm-workflows --test outdated --locked -- -D warnings`: passed.
- `cargo fmt --all -- --check`: passed.
- Install-readiness was not run because no shared install or runtime path changed.

## Final totals

- Findings received: 1.
- Findings verified and fixed: 1.
- Findings rejected with evidence: 0.
- Findings externally blocked: 0.
- Findings still pending: 0.
