//! An allocator for programs that hold backups and passphrases: the
//! system's, except that every block is zeroed before it's freed. This crate
//! wipes its own buffers, but dependencies don't: zxcvbn frees the copies it
//! makes of a passphrase it scores, and serde_json its scratch buffers,
//! without wiping them. A program only gets that guarantee by installing
//! this as its global allocator:
//!
//! ```ignore
//! #[global_allocator]
//! static ALLOCATOR: lpm_env_backup::WipingAllocator = lpm_env_backup::WipingAllocator;
//! ```
//!
//! Resizing a block always moves it: the system allocator could move it and
//! free the old copy unwiped, and a block it kept in place would later be
//! freed with a layout that isn't its own. So resizing a large buffer briefly
//! holds both copies.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{Ordering, compiler_fence};

/// The system allocator, zeroing every block before it's freed.
pub struct WipingAllocator;

// SAFETY: Blocks come from `System` and go back to it with the layouts they
// were allocated with; wiping writes only the bytes a block owns.
unsafe impl GlobalAlloc for WipingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, block: *mut u8, layout: Layout) {
        unsafe { release(block, layout, |block, layout| System.dealloc(block, layout)) }
    }

    unsafe fn realloc(&self, block: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        unsafe {
            reallocate(
                block,
                layout,
                new_size,
                |layout| System.alloc(layout),
                |block, layout| System.dealloc(block, layout),
            )
        }
    }
}

/// Zeroes `block`, then gives it to `free`.
///
/// # Safety
/// `block` must be a live allocation of `layout`.
pub(crate) unsafe fn release(block: *mut u8, layout: Layout, free: impl FnOnce(*mut u8, Layout)) {
    // SAFETY: Guaranteed by the caller.
    unsafe { wipe(block, layout.size()) };
    free(block, layout);
}

/// Zeroes the `length` bytes at `start`. Raw writes are defined for bytes
/// never written, and no reference to the block outlives them, so `start`
/// can still free it. Volatile writes aren't removed though the block is
/// freed straight after, and words wipe a large block, such as key
/// derivation's 256 MiB, about eight times faster than bytes.
///
/// # Safety
/// `start` must be valid for writing `length` bytes.
unsafe fn wipe(start: *mut u8, length: usize) {
    let word = size_of::<u64>();
    let head = start.align_offset(word).min(length);
    let words = (length - head) / word;
    // SAFETY: Every write lies inside the `length` bytes the caller
    // guarantees, and the words start where `start` is word-aligned.
    unsafe {
        for offset in 0..head {
            start.add(offset).write_volatile(0);
        }
        let aligned = start.add(head).cast::<u64>();
        for index in 0..words {
            aligned.add(index).write_volatile(0);
        }
        for offset in head + words * word..length {
            start.add(offset).write_volatile(0);
        }
    }
    compiler_fence(Ordering::SeqCst);
}

/// Resizes `block` to `new_size` bytes by moving it into a new allocation
/// and releasing the old one wiped, or leaves it as it is at its own size.
/// Resizing in place through the system allocator could move the block and
/// free the old copy unwiped, and keeping a shrunk block in place would
/// leave it to be freed with a smaller layout than it was allocated with.
///
/// # Safety
/// `block` must be a live allocation of `layout`, and `new_size` must be
/// nonzero and, rounded up to the alignment, at most `isize::MAX`.
pub(crate) unsafe fn reallocate(
    block: *mut u8,
    layout: Layout,
    new_size: usize,
    allocate: impl FnOnce(Layout) -> *mut u8,
    free: impl FnOnce(*mut u8, Layout),
) -> *mut u8 {
    if new_size == layout.size() {
        return block;
    }
    // SAFETY: The caller guarantees the size and alignment are valid.
    let new_layout = unsafe { Layout::from_size_align_unchecked(new_size, layout.align()) };
    let moved = allocate(new_layout);
    if moved.is_null() {
        return moved;
    }
    // SAFETY: Both blocks are live, distinct, and hold at least this many bytes.
    unsafe {
        std::ptr::copy_nonoverlapping(block, moved, layout.size().min(new_size));
        release(block, layout, free);
    }
    moved
}

#[cfg(test)]
mod tests {
    use super::*;

    fn filled(size: usize) -> (*mut u8, Layout) {
        let layout = Layout::from_size_align(size, 8).expect("layout");
        (filled_with(layout), layout)
    }

    fn filled_with(layout: Layout) -> *mut u8 {
        // SAFETY: The layout is nonzero; the block is filled before any read.
        let block = unsafe { System.alloc(layout) };
        assert!(!block.is_null());
        // SAFETY: The block holds `layout.size()` bytes.
        unsafe { block.write_bytes(0xA5, layout.size()) };
        block
    }

    fn assert_zeroed(block: *mut u8, layout: Layout) {
        // SAFETY: Called before the block is freed, while it's still live.
        let bytes = unsafe { std::slice::from_raw_parts(block, layout.size()) };
        assert!(
            bytes.iter().all(|byte| *byte == 0),
            "the block was freed holding data"
        );
    }

    #[test]
    fn a_freed_block_is_zeroed_first_whatever_its_size_and_alignment() {
        for size in [1, 7, 8, 9, 63, 4096, 4099] {
            let (block, layout) = filled(size);
            let mut freed = false;
            // SAFETY: The block is a live allocation of `layout`.
            unsafe {
                release(block, layout, |block, layout| {
                    assert_zeroed(block, layout);
                    freed = true;
                    System.dealloc(block, layout);
                });
            }
            assert!(freed);
        }
        // A block whose start isn't word-aligned has unaligned ends to wipe.
        let (block, layout) = filled(64);
        // SAFETY: Bytes 3..64 lie inside the block.
        let inner = unsafe { block.add(3) };
        let inner_layout = Layout::from_size_align(61, 1).expect("layout");
        // SAFETY: The inner range is live; it's freed through the outer block below.
        unsafe {
            release(inner, inner_layout, |block, layout| {
                assert_zeroed(block, layout)
            })
        };
        // SAFETY: The block is live; its first three bytes were left alone.
        assert_eq!(unsafe { std::slice::from_raw_parts(block, 3) }, [0xA5; 3]);
        // SAFETY: Freed once, with its layout.
        unsafe { System.dealloc(block, layout) };
    }

    #[test]
    fn resizing_moves_the_data_and_frees_the_old_block_wiped_with_its_own_layout() {
        for align in [1, 8, 64, 4096] {
            for (size, new_size) in [(4096, 100), (100, 4096), (64, 63), (1, 4099), (4099, 1)] {
                let layout = Layout::from_size_align(size, align).expect("layout");
                let new_layout = Layout::from_size_align(new_size, align).expect("layout");
                let block = filled_with(layout);
                let (mut allocated, mut freed) = (None, None);
                // SAFETY: The block is a live allocation of `layout`, and the new size is valid.
                let moved = unsafe {
                    reallocate(
                        block,
                        layout,
                        new_size,
                        |layout| {
                            allocated = Some(layout);
                            System.alloc(layout)
                        },
                        |old, layout| {
                            assert_zeroed(old, layout);
                            freed = Some((old, layout));
                            System.dealloc(old, layout);
                        },
                    )
                };
                let case = format!("{size} to {new_size} bytes, aligned to {align}");
                assert_eq!(allocated, Some(new_layout), "{case}");
                assert_eq!(freed, Some((block, layout)), "{case}");
                assert_eq!(moved.align_offset(align), 0, "{case}");
                // SAFETY: The moved block holds `new_size` bytes, the first ones copied.
                let copied = unsafe { std::slice::from_raw_parts(moved, size.min(new_size)) };
                assert!(copied.iter().all(|byte| *byte == 0xA5), "{case}");
                // SAFETY: Freed once, with the layout it was allocated with.
                unsafe { System.dealloc(moved, new_layout) };
            }
        }
    }

    #[test]
    fn resizing_to_the_same_size_keeps_the_block_as_it_is() {
        let (block, layout) = filled(64);
        // SAFETY: The block is a live allocation of `layout`.
        let kept = unsafe {
            reallocate(
                block,
                layout,
                64,
                |_| panic!("moved"),
                |_, _| panic!("freed"),
            )
        };
        assert_eq!(kept, block);
        // SAFETY: The block is still live and filled.
        let bytes = unsafe { std::slice::from_raw_parts(block, 64) };
        assert!(bytes.iter().all(|byte| *byte == 0xA5));
        // SAFETY: Freed once, with its layout.
        unsafe { System.dealloc(block, layout) };
    }

    #[test]
    fn a_failed_move_keeps_the_old_block() {
        for new_size in [128, 16] {
            let (block, layout) = filled(64);
            // SAFETY: The block is a live allocation of `layout`.
            let moved = unsafe {
                reallocate(
                    block,
                    layout,
                    new_size,
                    |_| std::ptr::null_mut(),
                    |_, _| panic!("freed"),
                )
            };
            assert!(moved.is_null());
            // SAFETY: The block is still live and filled.
            let bytes = unsafe { std::slice::from_raw_parts(block, 64) };
            assert!(bytes.iter().all(|byte| *byte == 0xA5));
            // SAFETY: Freed once, with its layout.
            unsafe { System.dealloc(block, layout) };
        }
    }
}
