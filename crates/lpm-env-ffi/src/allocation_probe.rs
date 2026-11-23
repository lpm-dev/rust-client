//! The test build's allocator: the wiping one, counting the bytes a test's
//! thread holds while the test measures it.

use std::alloc::{GlobalAlloc, Layout};
use std::cell::Cell;

pub(crate) struct Tracking;

thread_local! {
    static MEASURING: Cell<bool> = const { Cell::new(false) };
    static HELD: Cell<isize> = const { Cell::new(0) };
    static PEAK: Cell<isize> = const { Cell::new(0) };
}

fn held(change: isize) {
    if MEASURING.try_with(Cell::get).unwrap_or(false) {
        let _ = HELD.try_with(|held| {
            let now = held.get().saturating_add(change);
            held.set(now);
            let _ = PEAK.try_with(|peak| peak.set(peak.get().max(now)));
        });
    }
}

fn signed(bytes: usize) -> isize {
    isize::try_from(bytes).unwrap_or(isize::MAX)
}

// SAFETY: every call forwards the caller's unchanged contract to the wiping
// allocator; the counting touches only this thread's cells.
unsafe impl GlobalAlloc for Tracking {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        held(signed(layout.size()));
        // SAFETY: forwarded unchanged.
        unsafe { lpm_env_backup::WipingAllocator.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        held(-signed(layout.size()));
        // SAFETY: forwarded unchanged.
        unsafe { lpm_env_backup::WipingAllocator.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        held(signed(size) - signed(layout.size()));
        // SAFETY: forwarded unchanged.
        unsafe { lpm_env_backup::WipingAllocator.realloc(ptr, layout, size) }
    }
}

/// The most `work` held on this thread at once, beyond what it held before.
pub(crate) fn peak_during<T>(work: impl FnOnce() -> T) -> (T, usize) {
    HELD.with(|held| held.set(0));
    PEAK.with(|peak| peak.set(0));
    MEASURING.with(|measuring| measuring.set(true));
    let result = work();
    MEASURING.with(|measuring| measuring.set(false));
    let peak = PEAK.with(Cell::get);
    (result, usize::try_from(peak).unwrap_or(0))
}
