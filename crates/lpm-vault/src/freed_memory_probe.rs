//! The unit tests' allocator, which can watch whether a heap block holding a
//! marker is ever freed or moved without being wiped first. It watches only
//! the thread that asks, so tests running alongside don't count. It reads
//! blocks with inline assembly, which Miri can't run, so Miri builds leave it
//! out.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("the freed-memory probe reads blocks with x86_64 or aarch64 assembly");

pub(crate) const MARKER: &str = "probe-secret-7d40b2c9";

struct Probe;

thread_local! {
    static WATCHED: Cell<bool> = const { Cell::new(false) };
}
static FOUND: AtomicBool = AtomicBool::new(false);
/// Only one test watches at a time.
static WATCH: Mutex<()> = Mutex::new(());

#[global_allocator]
static PROBE: Probe = Probe;

fn watched() -> bool {
    WATCHED.try_with(Cell::get).unwrap_or(false)
}

// SAFETY: Blocks come from `System` and go back to it with their layouts, and
// scans read only bytes a block owns. Blocks start zero-filled, so a block
// never holds what an earlier one left.
unsafe impl GlobalAlloc for Probe {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc_zeroed(layout) }
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
        if new_size == layout.size() {
            return block;
        }
        // A resize that fails keeps the block, so it's scanned only once
        // the new one is given.
        unsafe {
            let moved =
                System.alloc_zeroed(Layout::from_size_align_unchecked(new_size, layout.align()));
            if moved.is_null() {
                return moved;
            }
            scan(block, layout.size());
            std::ptr::copy_nonoverlapping(block, moved, layout.size().min(new_size));
            System.dealloc(block, layout);
            moved
        }
    }
}

/// Notes whether the `length` bytes at `block` hold the marker, on a watched
/// thread.
///
/// # Safety
/// `block` must be valid for reading `length` bytes.
unsafe fn scan(block: *const u8, length: usize) {
    const CHUNK: usize = 4096;
    const MARKER_LEN: usize = MARKER.len();
    if length < MARKER_LEN || !watched() {
        return;
    }
    // Each chunk follows the end of the one before, so a marker split
    // between them is still found.
    let mut window = [0u8; MARKER_LEN - 1 + CHUNK];
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
            .windows(MARKER_LEN)
            .any(|candidate| candidate == MARKER.as_bytes())
        {
            FOUND.store(true, Ordering::Relaxed);
            return;
        }
        carried = filled.min(MARKER_LEN - 1);
        window.copy_within(filled - carried..filled, 0);
        offset += taken;
    }
}

/// Copies the bytes at `source` into `into` as the machine holds them. Inline
/// assembly reads below Rust's model of memory, so a byte Rust considers
/// uninitialized, such as a struct's padding or a vector's spare capacity,
/// reads as whatever it holds instead of being undefined behavior.
///
/// # Safety
/// `source` must be valid for reading `into.len()` bytes.
unsafe fn copy_as_the_machine_holds(source: *const u8, into: &mut [u8]) {
    let (words, rest) = into.as_chunks_mut::<8>();
    let mut at = source;
    for word in words {
        // SAFETY: Eight of the bytes the caller guarantees.
        *word = unsafe { machine_word(at) }.to_ne_bytes();
        at = at.wrapping_add(8);
    }
    for byte in rest {
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

/// Runs `body` while watching freed and moved blocks, and says whether any
/// of them still held the marker. Inputs holding it must outlive the call,
/// or be wiped before they're dropped.
pub(crate) fn watch<T>(body: impl FnOnce() -> T) -> (T, bool) {
    let _only = WATCH
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    FOUND.store(false, Ordering::Relaxed);
    let watching = Watching::start();
    let output = body();
    drop(watching);
    (output, FOUND.load(Ordering::Relaxed))
}

/// This thread's watch, which ends when it's dropped, even by a panic.
struct Watching;

impl Watching {
    fn start() -> Self {
        WATCHED.set(true);
        Self
    }
}

impl Drop for Watching {
    fn drop(&mut self) {
        WATCHED.set(false);
    }
}

#[test]
fn the_probe_finds_the_marker_only_in_a_block_freed_or_moved_holding_it() {
    let ((), found) = watch(|| {
        drop(Vec::<u8>::with_capacity(64));
        let mut grown = String::with_capacity(8);
        grown.push_str("abc");
        grown.reserve(4096);
        drop(grown);
    });
    assert!(!found);
    let marked = MARKER.to_owned();
    let ((), found) = watch(move || drop(marked));
    assert!(found, "a freed block holding the marker is found");
    let mut grown = String::with_capacity(MARKER.len());
    grown.push_str(MARKER);
    let ((), found) = watch(|| grown.reserve(4096));
    assert!(found, "a block moved by a resize is found");
    let mut split = vec![0u8; 4096 + MARKER.len()];
    split[4090..4090 + MARKER.len()].copy_from_slice(MARKER.as_bytes());
    let ((), found) = watch(move || drop(split));
    assert!(found, "a marker split between chunks is found");
    let mut wiped = MARKER.to_owned();
    let ((), found) = watch(move || {
        zeroize::Zeroize::zeroize(&mut wiped);
        drop(wiped);
    });
    assert!(!found, "a block wiped before it's freed isn't found");
}

#[test]
fn only_the_watching_thread_is_watched() {
    let marked = MARKER.to_owned();
    let ((), found) = watch(|| {
        std::thread::scope(|scope| {
            scope.spawn(move || drop(marked));
        });
    });
    assert!(!found, "a block another thread frees isn't watched");
}

#[test]
fn a_panic_while_watching_leaves_the_thread_unwatched() {
    let unwound = std::panic::catch_unwind(|| watch(|| panic!("watched")));
    assert!(unwound.is_err());
    assert!(!watched());
}
