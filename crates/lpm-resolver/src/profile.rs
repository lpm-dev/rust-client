//! Phase 34.4: lightweight profiling accumulators for resolver internals.
//!
//! Uses `AtomicU64` for cross-thread accumulation — the resolver runs
//! inside `spawn_blocking` on a different thread than the caller, so
//! thread-local counters won't work. Atomics have negligible overhead
//! in the uncontended case (single writer thread during resolution).
//!
//! Call `reset_all()` before resolution, then `summary()` after.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
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

/// Reset all counters. Call before resolution starts.
pub fn reset_all() {
    to_pubgrub_ranges::reset();
    available_versions::reset();
    ensure_cached::reset();
    choose_version::reset();
    get_dependencies::reset();
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
