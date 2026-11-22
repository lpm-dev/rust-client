//! What tracking the personal overrides' origins allocates. Its own test
//! binary, since the probe replaces the global allocator.

use lpm_env::{PersonalOverrideLayer, PersonalOverrideOrigins};
use std::cell::Cell;
use std::collections::HashMap;

struct ProbeAllocator;

thread_local! {
    static PROBE_ENABLED: Cell<bool> = const { Cell::new(false) };
    static MAX_ALLOCATION: Cell<usize> = const { Cell::new(0) };
}

fn record_allocation(size: usize) {
    if PROBE_ENABLED.try_with(Cell::get).unwrap_or(false) {
        MAX_ALLOCATION.with(|value| value.set(value.get().max(size)));
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

/// The largest single allocation `work` makes on this thread.
fn largest_allocation<T>(work: impl FnOnce() -> T) -> (T, usize) {
    MAX_ALLOCATION.with(|value| value.set(0));
    PROBE_ENABLED.with(|enabled| enabled.set(true));
    let result = work();
    PROBE_ENABLED.with(|enabled| enabled.set(false));
    (result, MAX_ALLOCATION.with(Cell::get))
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

    let (origins, largest) =
        largest_allocation(|| PersonalOverrideOrigins::changing(&vars, layer, false));

    assert_eq!(origins.names(), ["TOKEN"]);
    assert!(
        largest < LARGE,
        "a {largest}-byte allocation copied the override's value"
    );
}
