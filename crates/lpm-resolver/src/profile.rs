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

macro_rules! define_total_counter {
    ($name:ident) => {
        pub mod $name {
            use super::*;

            static TOTAL: AtomicU64 = AtomicU64::new(0);

            pub fn add(value: u64) {
                TOTAL.fetch_add(value, Ordering::Relaxed);
            }

            pub fn increment() {
                add(1);
            }

            pub fn read() -> u64 {
                TOTAL.load(Ordering::Relaxed)
            }

            pub fn reset() {
                TOTAL.store(0, Ordering::Relaxed);
            }
        }
    };
}

define_counter!(to_pubgrub_ranges);
define_counter!(available_versions);
define_counter!(ensure_cached);
define_counter!(choose_version);
define_counter!(get_dependencies);
define_counter!(streaming_lookup);
define_total_counter!(streaming_lookup_hits);
define_total_counter!(streaming_lookup_misses);
define_total_counter!(streaming_promotions);
define_total_counter!(streaming_singleton_hits);
define_total_counter!(root_batch_calls);
define_total_counter!(root_batch_requested);
define_total_counter!(dep_batch_calls);
define_total_counter!(dep_batch_requested);

pub fn record_streaming_lookup(hit: bool) {
    if hit {
        streaming_lookup_hits::increment();
    } else {
        streaming_lookup_misses::increment();
    }
}

pub fn record_streaming_promotion() {
    streaming_promotions::increment();
}

pub fn record_streaming_singleton_hit() {
    streaming_singleton_hits::increment();
}

pub fn record_root_batch(package_count: usize) {
    root_batch_calls::increment();
    root_batch_requested::add(package_count as u64);
}

pub fn record_dep_batch(package_count: usize) {
    dep_batch_calls::increment();
    dep_batch_requested::add(package_count as u64);
}

/// Reset all counters. Call before resolution starts.
pub fn reset_all() {
    to_pubgrub_ranges::reset();
    available_versions::reset();
    ensure_cached::reset();
    choose_version::reset();
    get_dependencies::reset();
    streaming_lookup::reset();
    streaming_lookup_hits::reset();
    streaming_lookup_misses::reset();
    streaming_promotions::reset();
    streaming_singleton_hits::reset();
    root_batch_calls::reset();
    root_batch_requested::reset();
    dep_batch_calls::reset();
    dep_batch_requested::reset();
}

pub fn json_value() -> serde_json::Value {
    let duration_ms = |duration: Duration| duration.as_secs_f64() * 1000.0;

    let (to_pubgrub_ranges_d, to_pubgrub_ranges_c) = to_pubgrub_ranges::read();
    let (available_versions_d, available_versions_c) = available_versions::read();
    let (ensure_cached_d, ensure_cached_c) = ensure_cached::read();
    let (choose_version_d, choose_version_c) = choose_version::read();
    let (get_dependencies_d, get_dependencies_c) = get_dependencies::read();
    let (streaming_lookup_d, streaming_lookup_c) = streaming_lookup::read();

    serde_json::json!({
        "to_pubgrub_ranges": {
            "calls": to_pubgrub_ranges_c,
            "elapsed_ms": duration_ms(to_pubgrub_ranges_d),
        },
        "available_versions": {
            "calls": available_versions_c,
            "elapsed_ms": duration_ms(available_versions_d),
        },
        "ensure_cached": {
            "calls": ensure_cached_c,
            "elapsed_ms": duration_ms(ensure_cached_d),
        },
        "choose_version": {
            "calls": choose_version_c,
            "elapsed_ms": duration_ms(choose_version_d),
        },
        "get_dependencies": {
            "calls": get_dependencies_c,
            "elapsed_ms": duration_ms(get_dependencies_d),
        },
        "streaming_lookup": {
            "calls": streaming_lookup_c,
            "elapsed_ms": duration_ms(streaming_lookup_d),
            "hits": streaming_lookup_hits::read(),
            "misses": streaming_lookup_misses::read(),
        },
        "streaming_promotions": streaming_promotions::read(),
        "streaming_singleton_hits": streaming_singleton_hits::read(),
        "root_batch": {
            "calls": root_batch_calls::read(),
            "requested_packages": root_batch_requested::read(),
        },
        "dep_batch": {
            "calls": dep_batch_calls::read(),
            "requested_packages": dep_batch_requested::read(),
        },
    })
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
    let (d, c) = streaming_lookup::read();
    lines.push(fmt("streaming_lookup", d, c));
    lines.push(format!(
        "  streaming_lookup_hits      {:>5} total",
        streaming_lookup_hits::read()
    ));
    lines.push(format!(
        "  streaming_lookup_misses    {:>5} total",
        streaming_lookup_misses::read()
    ));
    lines.push(format!(
        "  streaming_promotions       {:>5} total",
        streaming_promotions::read()
    ));
    lines.push(format!(
        "  streaming_singleton_hits   {:>5} total",
        streaming_singleton_hits::read()
    ));
    lines.push(format!(
        "  root_batch                 {:>5} calls  {:>5} packages",
        root_batch_calls::read(),
        root_batch_requested::read()
    ));
    lines.push(format!(
        "  dep_batch                  {:>5} calls  {:>5} packages",
        dep_batch_calls::read(),
        dep_batch_requested::read()
    ));

    lines.join("\n")
}
