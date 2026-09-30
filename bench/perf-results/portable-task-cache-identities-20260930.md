# Portable task-cache identities

The opt-in `cachePortable: true` shares relocatable task outputs across checkout roots and identical native Node/Bun installations. The default remains location-sensitive.

## Environment and method

- Apple M5 Pro, Mac17,9, 48 GiB RAM, macOS 27.0 build 26A428, arm64, APFS, 18 logical CPUs.
- Rust 1.94.0, shipped release profile (`opt-level=3`, LTO, one codegen unit).
- Node v24.19.0, Bun executable also present on PATH, esbuild 0.25.12, Python 3.14.6.
- Baseline source: `9ea1a79a980e01d7867c7abab571b3836a6a70b1` (0.79.0).
- Implementation source: `0417cbed66a4368a0bbe33ff00b98047d2a83cce`.
- Before binary SHA-256: `7059355a5eb5a7ae7871676a40c6d3ee362319dbf5b5110485f71db8d346efe1`.
- After binary SHA-256: `27e2060d969b6965438846e0ab9cc0224de5531bdc342b9c00b8188a12244dd1`.
- Both binaries are preserved under `/tmp/lpm-portable-cache-bench/` on the measurement host.

The fixture bundles 400 TypeScript modules with 32,000 exported strings: 3,180,084 source bytes. It runs esbuild synchronously with bundling and minification. Producer and consumer have separate checkout roots and isolated homes. Both use the same fixed esbuild installation through a node_modules link. No dependency installation is timed.

The HTTP fixture stores signed artifacts by the exact requested key. Each remote sample clears the consumer's local task cache and seeds only the producer's artifact. A marker proves whether the consumer runs the task. All measured outputs have the same SHA-256. The fixture runs on loopback. These numbers do not measure hosted cache latency or a web/mobile frontend.

There are 20 samples per binary per state. Binary order alternates each round. State order rotates each round. Initial unmeasured runs seed artifacts and runtime digest records. Cold-digest states delete only runtime digest records before the measured command. Executable bytes remain warm in the OS cache.

Times include process startup, cache lookup, validation, task execution when needed, output restoration, and cache publication. `/usr/bin/time -l` supplies maximum resident set size. This metric is not the simultaneous sum of all process-tree memory. Table ranges use the inclusive 25th and 75th percentiles.

The shared host had unrelated CPU-heavy activity. This task ran no builds or tests during timing. One-minute load averages ranged from 9.18 to 10.44, with a median of 10.32. The driver captures load before each timed interval. Alternating samples limits drift but cannot remove host interference. This report replaces earlier measurements against an intermediate implementation.

## End-to-end results

| State | Before median (IQR), ms | After median (IQR), ms | Before / after executions |
| --- | ---: | ---: | ---: |
| Default identity, local hit | 114.1 (109.3–128.1) | 113.2 (108.8–120.7) | 0 / 0 |
| Portable opt-in, local hit | 113.5 (107.9–121.6) | 115.3 (109.3–121.5) | 0 / 0 |
| Cross-checkout remote lookup, warm digest | 297.7 (281.9–318.4) | 169.7 (151.4–189.3) | 20 / 0 |
| Cross-checkout remote lookup, cold digest | 300.6 (281.2–322.6) | 247.0 (235.4–258.9) | 20 / 0 |
| Local hit, cold digest | 117.7 (110.0–127.0) | 198.0 (193.2–213.8) | 0 / 0 |
| Uncached esbuild task | 132.1 (130.3–141.8) | 135.7 (127.3–147.1) | 20 / 20 |

The warm cross-checkout median decreases by 128.0 ms (about 43%) for this fixture because the consumer restores the producer's artifact. The baseline runs the task and publishes a second artifact. Execution markers prove the reuse change independently of timing noise. The percentage describes this fixture under the recorded host load.

Default local-hit and portable warm-hit ranges overlap. This run does not establish a meaningful warm local regression or speedup. The uncached task ranges also overlap.

First-use content hashing has a real cost. Deleting digest records adds about 83 ms to the portable local-hit median in this environment. Records persist under the existing metadata-cache category, so normal later commands avoid this work. Metadata changes invalidate records. Unix ctime and the Windows change timestamp also detect edits that restore the previous mtime.

The warm remote state reports median maximum RSS of 64.8 MiB before and 23.9 MiB after. The task no longer starts Node/esbuild on a hit. Local-hit RSS remains about 20 MiB. Raw samples, timing spread, binary hashes, and host load are in [the JSON report](portable-task-cache-identities-20260930.json).

This fixture also shows the limits of caching small builds. The uncached task takes about 136 ms, less than the 170 ms remote restore. The result supports faster reuse within the existing cache-enabled workflow. It does not establish that remote caching beats uncached execution for every task.

## Runtime identity microbenchmark and optimization review

`task_cache_identity_bench` measures runtime snapshot capture without source hashing, HTTP, artifact extraction, or task execution. Each process runs 1,000 warm samples:

| Process | First capture | Warm median |
| --- | ---: | ---: |
| No persisted digest records | 94.940 ms | 0.066 ms |
| Persisted digest records available | 0.368 ms | 0.068 ms |

Each first-capture value is one observation, not a sample distribution. The first process uses a new metadata-cache home. The second process reuses its records. Host load also affects these measurements.

The selected Node and Bun files are 121,306,800 and 61,884,464 bytes. Content hashes use a reusable 128 KiB streaming buffer. Fingerprint-indexed records avoid hashing these bytes on every command. Per-executable `OnceLock` cells share one computation among concurrent tasks in one process. This concurrency benefit is a complexity analysis, not a separately measured speedup.

The end-to-end cold/warm difference shows that executable hashing matters at task-pipeline scale. Warm identity capture is much smaller than artifact restoration. More allocation tuning in that helper has no demonstrated end-to-end benefit.

A separate optimization lead is remote-to-local cache promotion. `crates/lpm-cli/src/commands/run/cache.rs:496` calls `store_cache` after a remote restore. `crates/lpm-task/src/cache.rs:614` creates another output archive, with gzip compression at line 1514. The remote archive contains `outputs/` and `.lpm-cache/` entries, while the local archive uses a different layout. Reuse needs a compatible representation or reader.

This analysis identifies a second compression pass but does not measure its contribution or predict a speedup. A future change needs profiling and coverage for signatures, output admission, race validation, and interruption recovery. The current implementation keeps the established publication path.

## Correctness and recovery validation

Local gates passed on the implementation source:

- Workspace build and final release build: zero warnings.
- Workspace/all-target clippy and formatting: clean.
- Non-CLI tests: 6,900 passed, 12 skipped (two marked leaky).
- Serial CLI unit tests: 5,338 passed, 10 ignored.
- CLI binary-surface tests: 116 passed with reduced concurrency.
- Task-runner and portability workflows: 135 passed.
- Portability workflows with a synthetic ambient `PGPASSWORD`: eight passed.
- Final optimized CLI: all eight portability workflows passed in 3.44 seconds.
- Public schema parity: nine tests passed against the linked schema and documentation copies.
- Documentation production build: 402 pages. Lint, types, and content-date checks passed.

GitHub CI passed for `7eac1d50a`, including Linux, macOS, and the complete Windows filesystem gate. A manual run at `8b98536e3` passed all jobs, including 16,135 full-workspace tests and the audit-scale workflow fixture. CI at the final implementation `0417cbed6` passed all required jobs, including the complete Windows filesystem gate. The Windows preserved-mtime regression and portability workflows passed. Complex-workspace acceptance jobs also passed on Linux and Windows.

Windows passed six project-glob cases, 13 publication/restore/recovery cases, and seven applicable portability workflows. The opaque-launcher workflow is Unix-only.

Three existing TTY benchmark cases intermittently timed out locally with empty output. Independent reproduction passed all 12 baseline and 12 implementation debug runs. The final 116-case gate passed with reduced concurrency. No root cause was established, and this concept contains no unrelated TTY changes.

The workflows run the real CLI with isolated homes and projects, and a signed HTTP cache indexed by the requested artifact key. They cover checkout relocation, native runtime relocation, source/environment invalidation, workspace prerequisites, default location sensitivity, runtime mutation, PATH selection changes, and opaque launchers. Workspace scenarios cover normal, parallel, stream, and JSON modes.

Runtime or effective PATH changes during a download cause task execution instead of restoration. They also prevent publication under the stale identity. Existing signatures, output admission, secret filtering, and source/dependency race checks remain in the execution path. New fixture isolation excludes ambient credentials while preserving the harness isolation and essential OS variables. The production secret-upload policy is unchanged.

Windows coverage exposed blocked directory renames and cleanup while capability handles remained open. Publication and restore paths now close those handles before rename or deletion. A separate glob fix preserves canonical Windows namespace prefixes while escaping directory names. The regression uses a canonical local-drive path with a `project[abc]` directory. It does not establish network-share behavior.

A Windows regression also reproduced identical fingerprints after an in-place runtime edit restored its original mtime. The persisted-record lookup uses that fingerprint, so the old record can survive the edit. The fix includes `FILE_BASIC_INFO.ChangeTime` through a metadata-only handle. Caching is bypassed if the query fails or supplies no usable timestamp. This adds a Windows metadata query whose performance cost is unmeasured.

No hosted service, browser, desktop frontend, or mobile frontend was exercised. The remote protocol is unchanged. Identity generation and validation run on the execution host, regardless of which client starts the task.

## Finding ledger

All findings came from primary investigation or review. No subagents were used. Each verified finding has a fix in client PR #910. Linked documentation PR #369 and public-schema PR #202 describe the same opt-in contract.

| ID | Category and location | Claim and evidence | Coverage | Fix commit | Disposition / PR status |
| --- | --- | --- | --- | --- | --- |
| PC-1 | Correctness: `crates/lpm-runtime/src/task_identity.rs`, `crates/lpm-runner/src/npm_context.rs` | Physical checkout/runtime paths prevented equivalent remote reuse. Original cross-root and copied-runtime workflows failed before the feature. | `portable_cache_restores_across_checkout_roots_and_isolated_homes`, `portable_cache_reuses_identical_native_runtime_installations` | `d6360673e` | Verified / open |
| PC-2 | Correctness: `crates/lpm-runner/src/npm_context.rs` | Lossy non-UTF-8 relative-path encoding collapsed distinct logical inputs. Pure-input regression failed before the fix. | `portable_context_keeps_distinct_non_utf8_member_paths_distinct` | `d6360673e` | Verified / open |
| PC-3 | Correctness: `crates/lpm-runtime/src/task_identity.rs` | Unframed cwd/PATH fields collapsed opaque-launcher identities. Unit regression failed before the fix. | `launcher_identity_keeps_working_directory_and_path_boundaries_distinct` | `d6360673e` | Verified / open |
| PC-4 | Correctness: `crates/lpm-cli/src/commands/run/cache.rs` | Original captured PATH missed new project-bin selection during a download. Workflow failed before fresh PATH validation. | `portable_cache_rejects_restore_when_a_new_project_bin_changes_runtime_selection` | `6b04d8fb7` | Verified / open |
| PC-5 | Correctness: `crates/lpm-task/src/cache.rs`, `crates/lpm-task/src/cache/restore.rs` | Open directory handles blocked Windows rename/cleanup with sharing error 32. Windows round trips failed before handle closure. | Round trips, `staged_restore_drop_removes_its_directory_and_recovery_record`, `restore_context_rejection_rolls_back_and_removes_recovery_data` | `288ef1cd1`, `336dac242` | Verified / open |
| PC-6 | Correctness: `crates/lpm-common/src/project_glob.rs` | Escaped canonical Windows namespace prefixes produced missing outputs. Windows round trips exposed the failure. | `rooted_glob_finds_outputs_under_canonical_windows_project_paths` and remote round trips | `eb3f5ee90` | Verified / open |
| PC-7 | Test reliability: `tests/workflows/tests/portable_task_cache.rs` | Inherited `PGPASSWORD` correctly activated secret-upload protection and blocked fixture PUTs. A synthetic ambient value reproduced the failure. | All eight workflows with `PGPASSWORD=fixture-ambient-password` | `7eac1d50a` | Verified / open |
| PC-8 | Correctness: `crates/lpm-runtime/src/task_identity.rs` | Windows returned an unchanged fingerprint after an in-place edit restored mtime. Regression failed at `6caca2241` and passed with the change-timestamp fix. | `runtime_edit_invalidates_record_even_with_preserved_size_and_mtime` on Windows and Unix | `0417cbed6` | Verified / open |

Totals: eight findings received, eight verified and fixed, zero rejected, zero externally blocked, zero pending.

## Reproduction

```bash
# Build the baseline at its source revision, then preserve the binary.
df -h /tmp
CARGO_TARGET_DIR=/tmp/lpm-portable-cache-target cargo +1.94.0 build --release --locked -p lpm-cli --bin lpm-rs
cp /tmp/lpm-portable-cache-target/release/lpm-rs /tmp/lpm-portable-cache-bench/before

# Build the implementation at its source revision, then preserve the binary.
df -h /tmp
CARGO_TARGET_DIR=/tmp/lpm-portable-cache-target cargo +1.94.0 build --release --locked -p lpm-cli --bin lpm-rs
cp /tmp/lpm-portable-cache-target/release/lpm-rs /tmp/lpm-portable-cache-bench/after

npm install --prefix /tmp/lpm-portable-cache-bench/tools --ignore-scripts --no-audit --no-fund esbuild@0.25.12
python3 bench/scripts/portable-task-cache-benchmark.py \
  --before /tmp/lpm-portable-cache-bench/before \
  --after /tmp/lpm-portable-cache-bench/after \
  --tools /tmp/lpm-portable-cache-bench/tools \
  --work-dir /tmp/lpm-portable-cache-bench/change-time-final-interleaved-20 \
  --samples 20

# Use a new metadata-cache home for the first microbenchmark process.
df -h /tmp
CARGO_TARGET_DIR=/tmp/lpm-portable-cache-target cargo +1.94.0 build --release --locked -p lpm-runtime --example task_cache_identity_bench
LPM_HOME=/tmp/lpm-portable-cache-bench/change-time-final-micro-home /tmp/lpm-portable-cache-target/release/examples/task_cache_identity_bench 1000
LPM_HOME=/tmp/lpm-portable-cache-bench/change-time-final-micro-home /tmp/lpm-portable-cache-target/release/examples/task_cache_identity_bench 1000

# Run the workflow binary against the final optimized CLI.
env 'CARGO_BIN_EXE_lpm-rs=/tmp/lpm-portable-cache-bench/after' \
  /tmp/lpm-portable-cache-gate/debug/deps/portable_task_cache-17f0de3d35b14bb7
```

Run the commands from the rust-client root. The benchmark requires a new dedicated `--work-dir` and refuses to overwrite one. The binaries must come from their respective source revisions. The first microbenchmark process needs a previously unused `LPM_HOME` for the cold-record measurement. The compiled workflow binary suffix depends on the build environment.
