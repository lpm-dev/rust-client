//! The unit tests' allocator, which can watch whether a heap block holding a
//! marker is ever freed or moved without being wiped first, and can free
//! through [`WipingAllocator`](crate::WipingAllocator)'s wiping to watch it work.
//! It watches only the thread that asks, so tests running alongside don't
//! count. It reads blocks with inline assembly, which Miri can't run, so Miri
//! builds leave it out.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("the freed-memory probe reads blocks with x86_64 or aarch64 assembly");

pub(crate) const MARKER: &[u8] = b"probe-secret-5ac1d9e3";

struct Probe;

thread_local! {
    static WATCHED: Cell<bool> = const { Cell::new(false) };
    /// Whether this thread frees through the wiping allocator's wiping.
    static WIPING: Cell<bool> = const { Cell::new(false) };
}
static FOUND: AtomicBool = AtomicBool::new(false);
/// Whether the marker was in a block the wiping allocator wiped, and was left after it.
static FOUND_AFTER_WIPING: AtomicBool = AtomicBool::new(false);
/// The most bytes one allocation asked for while watching.
static LARGEST: AtomicUsize = AtomicUsize::new(0);
/// Only one test watches at a time.
static WATCH: Mutex<()> = Mutex::new(());

#[global_allocator]
static PROBE: Probe = Probe;

fn watched() -> bool {
    WATCHED.try_with(Cell::get).unwrap_or(false)
}

fn wiping() -> bool {
    WIPING.try_with(Cell::get).unwrap_or(false)
}

// SAFETY: Blocks come from `System` and go back to it with their layouts, and
// scans read only bytes a block owns. Blocks start zero-filled, so a block
// never holds what an earlier one left.
unsafe impl GlobalAlloc for Probe {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        note_size(layout.size());
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        note_size(layout.size());
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, block: *mut u8, layout: Layout) {
        unsafe {
            scan(block, layout.size(), &FOUND);
            if wiping() {
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
        note_size(new_size);
        if new_size == layout.size() {
            return block;
        }
        unsafe {
            scan(block, layout.size(), &FOUND);
            if wiping() {
                return crate::wiping_allocator::reallocate(
                    block,
                    layout,
                    new_size,
                    |layout| System.alloc_zeroed(layout),
                    |block, layout| {
                        scan(block, layout.size(), &FOUND_AFTER_WIPING);
                        System.dealloc(block, layout);
                    },
                );
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

fn note_size(size: usize) {
    if watched() {
        LARGEST.fetch_max(size, Ordering::Relaxed);
    }
}

/// Sets `found` when the `length` bytes at `block` hold the marker, on a
/// watched thread.
///
/// # Safety
/// `block` must be valid for reading `length` bytes.
unsafe fn scan(block: *const u8, length: usize, found: &AtomicBool) {
    const CHUNK: usize = 4096;
    if length < MARKER.len() || !watched() {
        return;
    }
    // Each chunk follows the end of the one before, so a marker split
    // between them is still found.
    let mut window = [0u8; MARKER.len() - 1 + CHUNK];
    let mut carried = 0;
    let mut offset = 0;
    while offset < length {
        let taken = CHUNK.min(length - offset);
        // SAFETY: The bytes from `offset` lie inside the block.
        unsafe {
            copy_as_the_machine_holds(block.add(offset), &mut window[carried..carried + taken])
        };
        let filled = carried + taken;
        if window[..filled]
            .windows(MARKER.len())
            .any(|candidate| candidate == MARKER)
        {
            found.store(true, Ordering::Relaxed);
            return;
        }
        carried = filled.min(MARKER.len() - 1);
        window.copy_within(filled - carried..filled, 0);
        offset += taken;
    }
}

/// Copies the bytes at `source` into `into` as the machine holds them. Inline
/// assembly reads below Rust's model of memory, so a byte Rust considers
/// uninitialized, such as a struct's padding or a `None`'s payload, reads as
/// whatever it holds instead of being undefined behavior.
///
/// # Safety
/// `source` must be valid for reading `into.len()` bytes.
unsafe fn copy_as_the_machine_holds(source: *const u8, into: &mut [u8]) {
    let mut words = into.chunks_exact_mut(8);
    let mut at = source;
    for word in &mut words {
        // SAFETY: Eight of the bytes the caller guarantees.
        word.copy_from_slice(&unsafe { machine_word(at) }.to_ne_bytes());
        at = at.wrapping_add(8);
    }
    for byte in words.into_remainder() {
        // SAFETY: One of the bytes the caller guarantees.
        *byte = unsafe { machine_byte(at) };
        at = at.wrapping_add(1);
    }
}

/// # Safety
/// The eight bytes at `at` must be readable. They needn't be aligned: both
/// architectures load unaligned words from ordinary memory.
#[cfg(target_arch = "aarch64")]
unsafe fn machine_word(at: *const u8) -> u64 {
    let word: u64;
    // SAFETY: Guaranteed by the caller; the load writes only `word`.
    unsafe {
        std::arch::asm!(
            "ldr {word}, [{at}]",
            at = in(reg) at,
            word = out(reg) word,
            options(nostack, readonly, preserves_flags),
        );
    }
    word
}

/// # Safety
/// The byte at `at` must be readable.
#[cfg(target_arch = "aarch64")]
unsafe fn machine_byte(at: *const u8) -> u8 {
    let byte: u32;
    // SAFETY: Guaranteed by the caller; the load writes only `byte`.
    unsafe {
        std::arch::asm!(
            "ldrb {byte:w}, [{at}]",
            at = in(reg) at,
            byte = out(reg) byte,
            options(nostack, readonly, preserves_flags),
        );
    }
    byte.to_le_bytes()[0]
}

/// # Safety
/// The eight bytes at `at` must be readable. They needn't be aligned: both
/// architectures load unaligned words from ordinary memory.
#[cfg(target_arch = "x86_64")]
unsafe fn machine_word(at: *const u8) -> u64 {
    let word: u64;
    // SAFETY: Guaranteed by the caller; the load writes only `word`.
    unsafe {
        std::arch::asm!(
            "mov {word}, qword ptr [{at}]",
            at = in(reg) at,
            word = out(reg) word,
            options(nostack, readonly, preserves_flags),
        );
    }
    word
}

/// # Safety
/// The byte at `at` must be readable.
#[cfg(target_arch = "x86_64")]
unsafe fn machine_byte(at: *const u8) -> u8 {
    let byte: u8;
    // SAFETY: Guaranteed by the caller; the load writes only `byte`.
    unsafe {
        std::arch::asm!(
            "mov {byte}, byte ptr [{at}]",
            at = in(reg) at,
            byte = out(reg_byte) byte,
            options(nostack, readonly, preserves_flags),
        );
    }
    byte
}

#[test]
fn the_probe_finds_the_marker_only_in_a_block_freed_holding_it() {
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
    let mut split = vec![0u8; 4096 + MARKER.len()];
    split[4090..4090 + MARKER.len()].copy_from_slice(MARKER);
    assert!(
        watch(move || drop(split)),
        "a marker split between chunks is found"
    );
}

#[test]
fn only_the_watching_thread_is_watched() {
    let marked = MARKER.to_vec();
    let watched = watch_freeing(false, || {
        std::thread::scope(|scope| {
            scope.spawn(move || {
                drop(marked);
                drop(Vec::<u8>::with_capacity(1 << 20));
            });
        });
    });
    assert!(!watched.held, "a block another thread frees isn't watched");
    assert!(
        watched.largest < 1 << 20,
        "another thread's allocation isn't counted"
    );
}

#[test]
fn padding_and_unset_enum_payloads_are_read_as_the_machine_holds_them() {
    #[repr(C)]
    struct Padded {
        narrow: u8,
        wide: u64,
        short: u16,
    }
    let found = watch(|| {
        let padded = Box::new(Padded {
            narrow: 1,
            wide: 2,
            short: 3,
        });
        assert_eq!(
            u64::from(padded.narrow) + padded.wide + u64::from(padded.short),
            6
        );
        drop(padded);
        drop(vec![Some(1u8), None, Some(3)]);
    });
    assert!(!found);
}

#[test]
fn resizing_while_wiping_reports_only_blocks_freed_or_moved_with_the_marker() {
    let mut kept = Vec::with_capacity(MARKER.len() * 4);
    kept.extend_from_slice(MARKER);
    let (_, left) = watch_wiping(|| kept.shrink_to_fit());
    assert_eq!(kept, MARKER);
    assert!(
        !left,
        "a marker the shrunk vector still holds isn't left in freed memory"
    );

    let mut given_up = vec![0u8; MARKER.len() * 4];
    given_up[MARKER.len() * 2..MARKER.len() * 3].copy_from_slice(MARKER);
    let (held, left) = watch_wiping(|| {
        given_up.truncate(8);
        given_up.shrink_to_fit();
    });
    assert!(held && !left, "the marker in the end given up is wiped");

    let layout = Layout::from_size_align(MARKER.len() * 2, 1).expect("layout");
    // SAFETY: The layout is nonzero.
    let block = unsafe { std::alloc::alloc_zeroed(layout) };
    assert!(!block.is_null());
    // SAFETY: The block holds twice the marker's length.
    unsafe { block.copy_from_nonoverlapping(MARKER.as_ptr(), MARKER.len()) };
    let (held, left) = watch_wiping(|| {
        // SAFETY: The block is a live allocation of `layout`.
        let same = unsafe { std::alloc::realloc(block, layout, layout.size()) };
        assert_eq!(same, block);
    });
    assert!(
        !held && !left,
        "a block resized to its own size is neither moved nor freed"
    );
    // SAFETY: Freed once, with its layout.
    unsafe { std::alloc::dealloc(block, layout) };
}

/// Runs `body` while watching freed and moved blocks, and says whether any
/// of them still held the marker. Inputs holding it must outlive the call.
pub(crate) fn watch(body: impl FnOnce()) -> bool {
    watch_freeing(false, body).held
}

/// Runs `body` while freeing through the wiping allocator's wiping, and says
/// whether a block held the marker before it was wiped, and after.
pub(crate) fn watch_wiping(body: impl FnOnce()) -> (bool, bool) {
    let watched = watch_freeing(true, body);
    (watched.held, watched.left)
}

/// Runs `body` and returns the most bytes one allocation asked for meanwhile.
pub(crate) fn largest_allocation(body: impl FnOnce()) -> usize {
    watch_freeing(false, body).largest
}

struct Watched {
    held: bool,
    left: bool,
    largest: usize,
}

fn watch_freeing(wiping: bool, body: impl FnOnce()) -> Watched {
    let _only = WATCH
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    FOUND.store(false, Ordering::Relaxed);
    FOUND_AFTER_WIPING.store(false, Ordering::Relaxed);
    LARGEST.store(0, Ordering::Relaxed);
    WIPING.set(wiping);
    WATCHED.set(true);
    body();
    WATCHED.set(false);
    WIPING.set(false);
    Watched {
        held: FOUND.load(Ordering::Relaxed),
        left: FOUND_AFTER_WIPING.load(Ordering::Relaxed),
        largest: LARGEST.load(Ordering::Relaxed),
    }
}
