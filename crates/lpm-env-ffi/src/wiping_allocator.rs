//! The engine's allocator: the system's, except that every block is zeroed
//! before it's freed. The engine holds env values, decrypted backups and
//! passphrases, and its dependencies (serde_json's scratch buffers, zxcvbn's
//! copies of what it scores) free memory holding them without wiping it.
//! Resizing always moves a block, so growing a large buffer step by step
//! briefly holds both copies; the engine sizes its large buffers exactly.

use std::alloc::{GlobalAlloc, Layout, System};

struct WipingAllocator;

#[global_allocator]
static ALLOCATOR: WipingAllocator = WipingAllocator;

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
unsafe fn release(block: *mut u8, layout: Layout, free: impl FnOnce(*mut u8, Layout)) {
    // SAFETY: Guaranteed by the caller.
    let bytes = unsafe { std::slice::from_raw_parts_mut(block, layout.size()) };
    // Words wipe a large block, such as key derivation's 256 MiB, about eight
    // times faster than bytes; the unaligned ends are wiped as bytes.
    // SAFETY: Every byte pattern is a valid u64.
    let (head, words, tail) = unsafe { bytes.align_to_mut::<u64>() };
    zeroize::Zeroize::zeroize(head);
    zeroize::Zeroize::zeroize(words);
    zeroize::Zeroize::zeroize(tail);
    free(block, layout);
}

/// Moves `block` into a new allocation of `new_size` bytes and releases the
/// old one wiped. Resizing in place through the system allocator could move
/// the block and free the old copy unwiped.
///
/// # Safety
/// `block` must be a live allocation of `layout`, and `new_size` must be
/// nonzero and, rounded up to the alignment, at most `isize::MAX`.
unsafe fn reallocate(
    block: *mut u8,
    layout: Layout,
    new_size: usize,
    allocate: impl FnOnce(Layout) -> *mut u8,
    free: impl FnOnce(*mut u8, Layout),
) -> *mut u8 {
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
        // SAFETY: The layout is nonzero; the block is filled before any read.
        let block = unsafe { System.alloc(layout) };
        assert!(!block.is_null());
        // SAFETY: The block holds `size` bytes.
        unsafe { block.write_bytes(0xA5, size) };
        (block, layout)
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
    fn growing_or_shrinking_moves_the_data_and_zeroes_the_old_block() {
        for (size, new_size) in [(64, 4096), (4096, 64)] {
            let (block, layout) = filled(size);
            // SAFETY: The block is a live allocation of `layout`, and the new size is valid.
            let moved = unsafe {
                reallocate(
                    block,
                    layout,
                    new_size,
                    |layout| System.alloc(layout),
                    |old, layout| {
                        assert_zeroed(old, layout);
                        System.dealloc(old, layout);
                    },
                )
            };
            assert_ne!(moved, block);
            let kept = size.min(new_size);
            // SAFETY: The moved block holds `new_size` bytes, `kept` of them copied.
            let copied = unsafe { std::slice::from_raw_parts(moved, kept) };
            assert!(copied.iter().all(|byte| *byte == 0xA5));
            // SAFETY: Freed once, with the layout it was allocated with.
            unsafe { System.dealloc(moved, Layout::from_size_align(new_size, 8).expect("layout")) };
        }
    }

    #[test]
    fn a_failed_move_keeps_the_old_block() {
        let (block, layout) = filled(64);
        // SAFETY: The block is a live allocation of `layout`.
        let moved = unsafe {
            reallocate(
                block,
                layout,
                128,
                |_| std::ptr::null_mut(),
                |_, _| panic!("freed"),
            )
        };
        assert!(moved.is_null());
        // SAFETY: The block is still live and filled.
        assert_eq!(unsafe { *block }, 0xA5);
        // SAFETY: Freed once, with its layout.
        unsafe { System.dealloc(block, layout) };
    }
}
