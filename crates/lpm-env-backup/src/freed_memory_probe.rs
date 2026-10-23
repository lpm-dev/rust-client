//! The unit tests' allocator, which can watch whether a heap block holding a
//! marker is ever freed or moved without being wiped first, and can free
//! through [`WipingAllocator`](crate::WipingAllocator)'s wiping to watch it work.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

pub(crate) const MARKER: &[u8] = b"probe-secret-5ac1d9e3";

struct Probe;

static ARMED: AtomicBool = AtomicBool::new(false);
static FOUND: AtomicBool = AtomicBool::new(false);
/// Whether blocks are freed through the wiping allocator's wiping, and the
/// marker was in a block about to be wiped, and was left after it.
static WIPING: AtomicBool = AtomicBool::new(false);
static FOUND_AFTER_WIPING: AtomicBool = AtomicBool::new(false);
/// Only one test watches at a time.
static WATCH: Mutex<()> = Mutex::new(());

#[global_allocator]
static PROBE: Probe = Probe;

// SAFETY: Blocks come from `System` zero-filled and go back to it with their
// layouts. Every byte of a block is initialized from the start, and a resize
// moves into a new zero-filled block, so the scan only reads initialized
// bytes the block still owns.
unsafe impl GlobalAlloc for Probe {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, block: *mut u8, layout: Layout) {
        unsafe {
            scan(block, layout.size(), &FOUND);
            if WIPING.load(Ordering::Relaxed) {
                crate::wiping_allocator::release(block, layout, |block, layout| {
                    scan(block, layout.size(), &FOUND_AFTER_WIPING);
                    System.dealloc(block, layout);
                });
            } else {
                System.dealloc(block, layout);
            }
        }
    }

    unsafe fn realloc(&self, block: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        unsafe {
            scan(block, layout.size(), &FOUND);
            if WIPING.load(Ordering::Relaxed) {
                let resized = crate::wiping_allocator::reallocate(
                    block,
                    layout,
                    new_size,
                    |layout| System.alloc_zeroed(layout),
                    |block, layout| {
                        scan(block, layout.size(), &FOUND_AFTER_WIPING);
                        System.dealloc(block, layout);
                    },
                );
                if resized == block {
                    scan(block, layout.size(), &FOUND_AFTER_WIPING);
                }
                return resized;
            }
            let moved =
                System.alloc_zeroed(Layout::from_size_align_unchecked(new_size, layout.align()));
            if moved.is_null() {
                return moved;
            }
            std::ptr::copy_nonoverlapping(block, moved, layout.size().min(new_size));
            System.dealloc(block, layout);
            moved
        }
    }
}

/// Sets `found` when the `length` bytes at `block` hold the marker.
///
/// # Safety
/// `block` must reference `length` initialized bytes.
unsafe fn scan(block: *const u8, length: usize, found: &AtomicBool) {
    if !ARMED.load(Ordering::Relaxed) || length < MARKER.len() {
        return;
    }
    // SAFETY: Guaranteed by the caller.
    let bytes = unsafe { std::slice::from_raw_parts(block, length) };
    if bytes.windows(MARKER.len()).any(|window| window == MARKER) {
        found.store(true, Ordering::Relaxed);
    }
}

#[test]
fn the_probe_reads_only_bytes_that_were_written_or_zero_filled() {
    let found = watch(|| {
        drop(Vec::<u8>::with_capacity(64));
        let mut grown = Vec::with_capacity(8);
        grown.extend_from_slice(b"abc");
        grown.reserve(4096);
        grown.shrink_to_fit();
        drop(grown);
    });
    assert!(!found);
    let mut marked = Vec::with_capacity(MARKER.len() * 2);
    marked.extend_from_slice(MARKER);
    assert!(
        watch(move || drop(marked)),
        "a freed block holding the marker is found"
    );
}

/// Runs `body` while watching freed and moved blocks, and says whether any
/// of them still held the marker. Inputs holding it must outlive the call.
pub(crate) fn watch(body: impl FnOnce()) -> bool {
    watch_freeing(false, body).0
}

/// Runs `body` while freeing through the wiping allocator's wiping, and says
/// whether a block held the marker before it was wiped, and after.
pub(crate) fn watch_wiping(body: impl FnOnce()) -> (bool, bool) {
    watch_freeing(true, body)
}

fn watch_freeing(wiping: bool, body: impl FnOnce()) -> (bool, bool) {
    let _only = WATCH
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    FOUND.store(false, Ordering::Relaxed);
    FOUND_AFTER_WIPING.store(false, Ordering::Relaxed);
    WIPING.store(wiping, Ordering::Relaxed);
    ARMED.store(true, Ordering::Relaxed);
    body();
    ARMED.store(false, Ordering::Relaxed);
    WIPING.store(false, Ordering::Relaxed);
    (
        FOUND.load(Ordering::Relaxed),
        FOUND_AFTER_WIPING.load(Ordering::Relaxed),
    )
}
