//! Per-spawn sandbox overhead micro-bench. Phase 46 P5 Chunk 5.
//!
//! Run: `cargo bench -p lpm-sandbox`
//!
//! What this measures:
//! - `factory_cold_enforce`: one call to [`new_for_platform`] with
//!   `SandboxMode::Enforce`. On macOS this is Seatbelt profile
//!   rendering (~50µs expected). On Linux it's a kernel probe via
//!   `landlock_create_ruleset` (~microseconds). The Enforce backend
//!   is the hot path every lifecycle script goes through.
//! - `factory_cold_noop`: the escape-hatch baseline. Validates
//!   [`SandboxMode::Disabled`] stays near-free so
//!   `--unsafe-full-env --no-sandbox` doesn't add meaningful overhead.
//! - `end_to_end_spawn_true`: full construct + `Sandbox::spawn` of
//!   `/usr/bin/true` + `wait`. Represents the actual per-script
//!   cost a lifecycle-script loop pays. Depends on host `fork` +
//!   `execve` timing; brittle under system load, so this bench
//!   exists to detect order-of-magnitude regressions, not
//!   micro-fluctuations.
//!
//! Performance budget (informal):
//! - `factory_cold_enforce`: < 200µs on a warm system.
//! - `factory_cold_noop`: < 50µs.
//! - `end_to_end_spawn_true`: < 10ms.
//!
//! If any of these blow their budget by >2x, investigate before
//! shipping. Chunk 6's auto-execution loop amplifies per-spawn
//! regressions — a 1ms-per-spawn regression across 100 packages
//! is a 100ms install slowdown.

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use lpm_sandbox::{SandboxMode, SandboxSpec, SandboxStdio, SandboxedCommand, new_for_platform};
use std::path::PathBuf;

fn realistic_spec() -> SandboxSpec {
    let home = dirs::home_dir().expect("home dir for bench");
    SandboxSpec {
        package_dir: home.join(".lpm/store/bench-pkg@0.1.0"),
        project_dir: home.join("lpm-sandbox-bench-project"),
        package_name: "bench-pkg".into(),
        package_version: "0.1.0".into(),
        store_root: home.join(".lpm/store"),
        home_dir: home,
        tmpdir: PathBuf::from("/tmp"),
        extra_write_dirs: Vec::new(),
    }
}

fn bench_factory_cold_enforce(c: &mut Criterion) {
    c.bench_function("factory_cold_enforce", |b| {
        b.iter(|| {
            let spec = realistic_spec();
            let sb = match new_for_platform(spec, SandboxMode::Enforce) {
                Ok(sb) => sb,
                // On kernels/platforms without sandbox support, the
                // bench still runs (measures the rejection path).
                // Don't panic — that'd kill `cargo bench` on CI
                // runners without landlock.
                Err(_) => return,
            };
            black_box(sb.backend_name());
        });
    });
}

fn bench_factory_cold_noop(c: &mut Criterion) {
    c.bench_function("factory_cold_noop", |b| {
        b.iter(|| {
            let spec = realistic_spec();
            let sb = new_for_platform(spec, SandboxMode::Disabled)
                .expect("NoopSandbox must always succeed");
            black_box(sb.backend_name());
        });
    });
}

fn bench_end_to_end_spawn_true(c: &mut Criterion) {
    c.bench_function("end_to_end_spawn_true", |b| {
        b.iter(|| {
            let spec = realistic_spec();
            let sb = match new_for_platform(spec, SandboxMode::Enforce) {
                Ok(sb) => sb,
                Err(_) => return,
            };
            let mut cmd =
                SandboxedCommand::new("/usr/bin/true").envs_cleared([("PATH", "/usr/bin:/bin")]);
            cmd.stdout = SandboxStdio::Null;
            cmd.stderr = SandboxStdio::Null;
            let mut child = sb.spawn(cmd).expect("spawn /usr/bin/true");
            let status = child.wait().expect("wait");
            black_box(status);
        });
    });
}

criterion_group!(
    benches,
    bench_factory_cold_enforce,
    bench_factory_cold_noop,
    bench_end_to_end_spawn_true,
);
criterion_main!(benches);
