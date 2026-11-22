//! What tracking the personal overrides' origins allocates. Its own test
//! binary, since the probe replaces the global allocator.

use lpm_env::{PersonalOverrideLayer, PersonalOverrideOrigins, ValidationError};
use std::cell::Cell;
use std::collections::HashMap;

struct ProbeAllocator;

thread_local! {
    static PROBE_ENABLED: Cell<bool> = const { Cell::new(false) };
    static MAX_ALLOCATION: Cell<usize> = const { Cell::new(0) };
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}

fn record_allocation(size: usize) {
    if PROBE_ENABLED.try_with(Cell::get).unwrap_or(false) {
        MAX_ALLOCATION.with(|value| value.set(value.get().max(size)));
        ALLOCATIONS.with(|count| count.set(count.get() + 1));
    }
}

#[global_allocator]
static ALLOCATOR: ProbeAllocator = ProbeAllocator;

// SAFETY: every call forwards the caller's unchanged contract to `System`.
unsafe impl std::alloc::GlobalAlloc for ProbeAllocator {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        record_allocation(layout.size());
        // SAFETY: System receives the caller's unchanged allocation contract.
        unsafe { std::alloc::System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: std::alloc::Layout) {
        // SAFETY: System allocated the pointer with this layout.
        unsafe { std::alloc::System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: std::alloc::Layout, size: usize) -> *mut u8 {
        record_allocation(size);
        // SAFETY: System receives the original pointer, layout, and requested size.
        unsafe { std::alloc::System.realloc(ptr, layout, size) }
    }
}

/// What `work` allocates on this thread: its largest single allocation and
/// how many it makes.
fn allocations<T>(work: impl FnOnce() -> T) -> (T, usize, usize) {
    MAX_ALLOCATION.with(|value| value.set(0));
    ALLOCATIONS.with(|count| count.set(0));
    PROBE_ENABLED.with(|enabled| enabled.set(true));
    let result = work();
    PROBE_ENABLED.with(|enabled| enabled.set(false));
    (
        result,
        MAX_ALLOCATION.with(Cell::get),
        ALLOCATIONS.with(Cell::get),
    )
}

#[test]
fn the_origins_keep_no_copy_of_an_override_s_value() {
    const LARGE: usize = 64 * 1024;
    let set = HashMap::from([("TOKEN".to_owned(), "v".repeat(LARGE))]);
    let unset = Vec::new();
    let vars = HashMap::from([("TOKEN".to_owned(), "team".to_owned())]);
    let layer = PersonalOverrideLayer {
        set: &set,
        unset: &unset,
    };

    let (origins, largest, _) =
        allocations(|| PersonalOverrideOrigins::changing(&vars, layer, false));

    assert_eq!(origins.names(), ["TOKEN"]);
    assert!(
        largest < LARGE,
        "a {largest}-byte allocation copied the override's value"
    );
}

#[test]
fn attributing_no_errors_allocates_nothing() {
    let set = HashMap::from([("TOKEN".to_owned(), "mine".to_owned())]);
    let unset = vec!["GONE".to_owned()];
    let before = HashMap::from([
        ("TOKEN".to_owned(), "team".to_owned()),
        ("GONE".to_owned(), "team".to_owned()),
        ("OTHER".to_owned(), "team".to_owned()),
    ]);
    let after = HashMap::from([
        ("TOKEN".to_owned(), "mine".to_owned()),
        ("OTHER".to_owned(), "team".to_owned()),
    ]);
    let layer = PersonalOverrideLayer {
        set: &set,
        unset: &unset,
    };
    let no_errors: [ValidationError; 0] = [];
    for case_insensitive in [false, true] {
        let origins = PersonalOverrideOrigins::changing(&before, layer, case_insensitive);
        let (caused, _, count) =
            allocations(|| origins.attribute(&no_errors, &after, layer, |_, _| false));
        assert!(caused.is_empty());
        assert_eq!(
            count, 0,
            "with case_insensitive {case_insensitive}, attributing no errors allocated"
        );
    }
}
