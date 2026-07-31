//! Lightweight profiling accumulators for resolver internals.
//!
//! Uses `AtomicU64` for cross-thread accumulation — the resolver runs
//! inside `spawn_blocking` on a different thread than the caller, so
//! thread-local counters won't work. Atomics have negligible overhead
//! in the uncontended case (single writer thread during resolution).
//!
//! Call `reset_all()` before resolution, then `summary()` after.

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

/// Drop guard that accumulates elapsed time on drop.
/// Handles functions with multiple return paths automatically.
pub struct Guard {
    start: Instant,
    elapsed_ns: &'static AtomicU64,
    calls: &'static AtomicU32,
}

impl Drop for Guard {
    fn drop(&mut self) {
        let ns = self.start.elapsed().as_nanos() as u64;
        self.elapsed_ns.fetch_add(ns, Ordering::Relaxed);
        self.calls.fetch_add(1, Ordering::Relaxed);
    }
}

macro_rules! define_counter {
    ($name:ident) => {
        pub mod $name {
            use super::*;

            static ELAPSED_NS: AtomicU64 = AtomicU64::new(0);
            static CALLS: AtomicU32 = AtomicU32::new(0);

            /// Start timing. Returns a Guard that accumulates on drop.
            pub fn start() -> Guard {
                Guard {
                    start: Instant::now(),
                    elapsed_ns: &ELAPSED_NS,
                    calls: &CALLS,
                }
            }

            pub fn read() -> (Duration, u32) {
                let ns = ELAPSED_NS.load(Ordering::Relaxed);
                let c = CALLS.load(Ordering::Relaxed);
                (Duration::from_nanos(ns), c)
            }

            pub fn reset() {
                ELAPSED_NS.store(0, Ordering::Relaxed);
                CALLS.store(0, Ordering::Relaxed);
            }
        }
    };
}

define_counter!(to_pubgrub_ranges);
define_counter!(available_versions);
define_counter!(ensure_cached);
define_counter!(choose_version);
define_counter!(get_dependencies);

static RELEASE_AGE_NS: AtomicU64 = AtomicU64::new(0);
static RELEASE_AGE_CHECKS: AtomicU64 = AtomicU64::new(0);
static RELEASE_AGE_REJECTED: AtomicU64 = AtomicU64::new(0);
static RELEASE_AGE_MISSING: AtomicU64 = AtomicU64::new(0);
static TRUST_POLICY_NS: AtomicU64 = AtomicU64::new(0);
static TRUST_POLICY_CHECKS: AtomicU64 = AtomicU64::new(0);
static TRUST_POLICY_REJECTED: AtomicU64 = AtomicU64::new(0);
static COMMAND_SCOPE_ACTIVE: AtomicBool = AtomicBool::new(false);
static COMMAND_SCOPE_LOCK: OnceLock<Arc<tokio::sync::Mutex<()>>> = OnceLock::new();

#[derive(Debug, Clone, Copy, Default)]
pub struct PolicySummary {
    pub release_age: PolicyCheckSummary,
    pub trust_policy: PolicyCheckSummary,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct PolicyCheckSummary {
    pub elapsed: Duration,
    pub checked_count: u64,
    pub rejected_count: u64,
    pub missing_count: u64,
}

pub fn record_release_age_check(elapsed: Duration, rejected: bool, missing_release_time: bool) {
    RELEASE_AGE_NS.fetch_add(elapsed.as_nanos() as u64, Ordering::Relaxed);
    RELEASE_AGE_CHECKS.fetch_add(1, Ordering::Relaxed);
    if rejected {
        RELEASE_AGE_REJECTED.fetch_add(1, Ordering::Relaxed);
    }
    if missing_release_time {
        RELEASE_AGE_MISSING.fetch_add(1, Ordering::Relaxed);
    }
}

pub fn record_trust_policy_check(elapsed: Duration, rejected: bool) {
    TRUST_POLICY_NS.fetch_add(elapsed.as_nanos() as u64, Ordering::Relaxed);
    TRUST_POLICY_CHECKS.fetch_add(1, Ordering::Relaxed);
    if rejected {
        TRUST_POLICY_REJECTED.fetch_add(1, Ordering::Relaxed);
    }
}

fn reset_policy() {
    RELEASE_AGE_NS.store(0, Ordering::Relaxed);
    RELEASE_AGE_CHECKS.store(0, Ordering::Relaxed);
    RELEASE_AGE_REJECTED.store(0, Ordering::Relaxed);
    RELEASE_AGE_MISSING.store(0, Ordering::Relaxed);
    TRUST_POLICY_NS.store(0, Ordering::Relaxed);
    TRUST_POLICY_CHECKS.store(0, Ordering::Relaxed);
    TRUST_POLICY_REJECTED.store(0, Ordering::Relaxed);
}

pub fn policy_summary() -> PolicySummary {
    PolicySummary {
        release_age: PolicyCheckSummary {
            elapsed: Duration::from_nanos(RELEASE_AGE_NS.load(Ordering::Relaxed)),
            checked_count: RELEASE_AGE_CHECKS.load(Ordering::Relaxed),
            rejected_count: RELEASE_AGE_REJECTED.load(Ordering::Relaxed),
            missing_count: RELEASE_AGE_MISSING.load(Ordering::Relaxed),
        },
        trust_policy: PolicyCheckSummary {
            elapsed: Duration::from_nanos(TRUST_POLICY_NS.load(Ordering::Relaxed)),
            checked_count: TRUST_POLICY_CHECKS.load(Ordering::Relaxed),
            rejected_count: TRUST_POLICY_REJECTED.load(Ordering::Relaxed),
            missing_count: 0,
        },
    }
}

fn reset_all_unscoped() {
    to_pubgrub_ranges::reset();
    available_versions::reset();
    ensure_cached::reset();
    choose_version::reset();
    get_dependencies::reset();
    reset_policy();
}

/// Reset all counters unless a recursive command is collecting one
/// aggregate across concurrent resolver passes.
pub fn reset_all() {
    if !COMMAND_SCOPE_ACTIVE.load(Ordering::Acquire) {
        reset_all_unscoped();
    }
}

/// Guard that keeps resolver profiling cumulative across one command.
pub struct CommandProfileScope {
    _exclusive: tokio::sync::OwnedMutexGuard<()>,
}

/// Starts an exclusive command aggregate and suppresses resolver resets.
pub async fn command_scope() -> CommandProfileScope {
    let lock = Arc::clone(COMMAND_SCOPE_LOCK.get_or_init(|| Arc::new(tokio::sync::Mutex::new(()))));
    let exclusive = lock.lock_owned().await;
    reset_all_unscoped();
    COMMAND_SCOPE_ACTIVE.store(true, Ordering::Release);
    CommandProfileScope {
        _exclusive: exclusive,
    }
}

impl Drop for CommandProfileScope {
    fn drop(&mut self) {
        COMMAND_SCOPE_ACTIVE.store(false, Ordering::Release);
    }
}

/// Format a summary of all counters. Returns a multi-line string.
pub fn summary() -> String {
    let fmt = |name: &str, d: Duration, c: u32| -> String {
        format!(
            "  {name:<25} {calls:>5} calls  {ms:>8.2}ms",
            name = name,
            calls = c,
            ms = d.as_secs_f64() * 1000.0,
        )
    };

    let (d, c) = to_pubgrub_ranges::read();
    let mut lines = vec![fmt("to_pubgrub_ranges", d, c)];
    let (d, c) = available_versions::read();
    lines.push(fmt("available_versions", d, c));
    let (d, c) = ensure_cached::read();
    lines.push(fmt("ensure_cached", d, c));
    let (d, c) = choose_version::read();
    lines.push(fmt("choose_version", d, c));
    let (d, c) = get_dependencies::read();
    lines.push(fmt("get_dependencies", d, c));

    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn command_scopes_do_not_merge_overlapping_resolver_metrics() {
        let first_scope = command_scope().await;
        drop(to_pubgrub_ranges::start());
        reset_all();
        assert_eq!(to_pubgrub_ranges::read().1, 1);

        let second_acquired = Arc::new(AtomicBool::new(false));
        let second_acquired_in_task = Arc::clone(&second_acquired);
        let second = tokio::spawn(async move {
            let _scope = command_scope().await;
            second_acquired_in_task.store(true, Ordering::Release);
            to_pubgrub_ranges::read().1
        });

        tokio::task::yield_now().await;
        assert!(!second_acquired.load(Ordering::Acquire));

        drop(first_scope);
        let second_count = second.await.expect("second resolver command scope task");
        assert!(second_acquired.load(Ordering::Acquire));
        assert_eq!(second_count, 0);
    }
}
