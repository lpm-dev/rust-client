//! The unit tests' allocator, which can watch whether a heap block holding a
//! marker is ever freed or moved without being wiped first.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

pub(crate) const MARKER: &[u8] = b"probe-secret-5ac1d9e3";

struct Probe;

static ARMED: AtomicBool = AtomicBool::new(false);
static FOUND: AtomicBool = AtomicBool::new(false);
/// Only one test watches at a time.
static WATCH: Mutex<()> = Mutex::new(());

#[global_allocator]
static PROBE: Probe = Probe;

// SAFETY: Every method forwards to `System` with the caller's arguments; the
// scan only reads the `layout.size()` bytes the block still owns.
unsafe impl GlobalAlloc for Probe {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, block: *mut u8, layout: Layout) {
        unsafe {
            scan(block, layout.size());
            System.dealloc(block, layout);
        }
    }

    unsafe fn realloc(&self, block: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        unsafe {
            scan(block, layout.size());
            System.realloc(block, layout, new_size)
        }
    }
}

/// # Safety
/// `block` must reference `length` readable bytes.
unsafe fn scan(block: *const u8, length: usize) {
    if !ARMED.load(Ordering::Relaxed) || length < MARKER.len() {
        return;
    }
    // SAFETY: Guaranteed by the caller.
    let bytes = unsafe { std::slice::from_raw_parts(block, length) };
    if bytes.windows(MARKER.len()).any(|window| window == MARKER) {
        FOUND.store(true, Ordering::Relaxed);
    }
}

/// Runs `body` while watching freed and moved blocks, and says whether any
/// of them still held the marker. Inputs holding it must outlive the call.
pub(crate) fn watch(body: impl FnOnce()) -> bool {
    let _only = WATCH
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    FOUND.store(false, Ordering::Relaxed);
    ARMED.store(true, Ordering::Relaxed);
    body();
    ARMED.store(false, Ordering::Relaxed);
    FOUND.load(Ordering::Relaxed)
}
