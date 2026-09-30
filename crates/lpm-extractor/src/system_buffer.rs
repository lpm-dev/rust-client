//! Byte buffers owned through the system allocator.

use std::alloc::{GlobalAlloc, Layout, System};
use std::ptr::NonNull;

/// Bytes allocated from the system allocator instead of the global one.
///
/// Extraction holds whole compressed and decompressed tarballs for a few
/// milliseconds at a time on many threads. In mimalloc's per-thread arenas
/// those multi-megabyte blocks keep hundreds of MiB committed after they are
/// freed during a cold install. The system allocator maps blocks this large
/// separately and returns them to the OS when they are freed.
pub(crate) struct SystemBuffer {
    ptr: NonNull<u8>,
    len: usize,
    capacity: usize,
}

// SAFETY: the buffer uniquely owns its allocation, like `Vec<u8>`.
unsafe impl Send for SystemBuffer {}
// SAFETY: shared access only reads the initialized bytes.
unsafe impl Sync for SystemBuffer {}

impl SystemBuffer {
    pub(crate) const fn new() -> Self {
        Self {
            ptr: NonNull::dangling(),
            len: 0,
            capacity: 0,
        }
    }

    /// A buffer of `len` zero bytes.
    pub(crate) fn zeroed(len: usize) -> Self {
        let mut buffer = Self::new();
        if len > 0 {
            let layout = layout(len);
            // SAFETY: `layout` has a non-zero size.
            buffer.ptr = allocated(unsafe { System.alloc_zeroed(layout) }, layout);
            buffer.capacity = len;
            buffer.len = len;
        }
        buffer
    }

    pub(crate) fn capacity(&self) -> usize {
        self.capacity
    }

    pub(crate) fn truncate(&mut self, len: usize) {
        self.len = self.len.min(len);
    }

    /// Grow the capacity to exactly `len + additional` when it is smaller.
    pub(crate) fn reserve_exact(&mut self, additional: usize) {
        let required = self
            .len
            .checked_add(additional)
            .expect("buffer size overflows usize");
        if required > self.capacity {
            self.grow_to(required);
        }
    }

    pub(crate) fn extend_from_slice(&mut self, bytes: &[u8]) {
        let required = self
            .len
            .checked_add(bytes.len())
            .expect("buffer size overflows usize");
        if required > self.capacity {
            self.grow_to(required.max(self.capacity.saturating_mul(2)));
        }
        // SAFETY: capacity covers `len + bytes.len()`, and `bytes` cannot
        // alias this uniquely owned allocation.
        unsafe {
            std::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                self.ptr.as_ptr().add(self.len),
                bytes.len(),
            );
        }
        self.len = required;
    }

    fn grow_to(&mut self, capacity: usize) {
        let new_layout = layout(capacity);
        let ptr = if self.capacity == 0 {
            // SAFETY: `new_layout` has a non-zero size.
            unsafe { System.alloc(new_layout) }
        } else {
            // SAFETY: `ptr` was allocated by `System` with `layout(self.capacity)`,
            // and the new size is non-zero.
            unsafe { System.realloc(self.ptr.as_ptr(), layout(self.capacity), capacity) }
        };
        self.ptr = allocated(ptr, new_layout);
        self.capacity = capacity;
    }
}

fn layout(size: usize) -> Layout {
    Layout::from_size_align(size, 1).expect("buffer size overflows isize")
}

fn allocated(ptr: *mut u8, layout: Layout) -> NonNull<u8> {
    NonNull::new(ptr).unwrap_or_else(|| std::alloc::handle_alloc_error(layout))
}

impl Default for SystemBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for SystemBuffer {
    fn drop(&mut self) {
        if self.capacity > 0 {
            // SAFETY: `ptr` was allocated by `System` with this layout.
            unsafe { System.dealloc(self.ptr.as_ptr(), layout(self.capacity)) }
        }
    }
}

impl std::ops::Deref for SystemBuffer {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        // SAFETY: the first `len` bytes are initialized, and a dangling
        // pointer is valid for an empty slice.
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }
}

impl std::ops::DerefMut for SystemBuffer {
    fn deref_mut(&mut self) -> &mut [u8] {
        // SAFETY: as for `deref`, with unique access through `&mut self`.
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }
}

impl AsRef<[u8]> for SystemBuffer {
    fn as_ref(&self) -> &[u8] {
        self
    }
}

impl std::fmt::Debug for SystemBuffer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SystemBuffer")
            .field("len", &self.len)
            .field("capacity", &self.capacity)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zeroed_buffers_are_zero_filled_and_writable() {
        let mut buffer = SystemBuffer::zeroed(3 * 1024 * 1024);
        assert!(buffer.iter().all(|&byte| byte == 0));
        buffer[7] = 9;
        buffer.truncate(8);
        assert_eq!(&buffer[..], &[0, 0, 0, 0, 0, 0, 0, 9]);
        assert_eq!(buffer.capacity(), 3 * 1024 * 1024);
    }

    #[test]
    fn extending_grows_and_keeps_earlier_bytes() {
        let mut buffer = SystemBuffer::new();
        for chunk in 0..200_u8 {
            buffer.extend_from_slice(&[chunk; 1024]);
        }
        assert_eq!(buffer.len(), 200 * 1024);
        assert!(
            buffer
                .chunks(1024)
                .enumerate()
                .all(|(index, chunk)| { chunk.iter().all(|&byte| usize::from(byte) == index) })
        );
    }

    #[test]
    fn reserve_exact_sets_the_capacity_without_changing_the_bytes() {
        let mut buffer = SystemBuffer::new();
        buffer.extend_from_slice(b"abc");
        buffer.reserve_exact(10);
        assert_eq!(buffer.capacity(), 13);
        assert_eq!(&buffer[..], b"abc");
    }

    #[test]
    fn empty_buffers_do_not_allocate() {
        let buffer = SystemBuffer::zeroed(0);
        assert!(buffer.is_empty());
        assert_eq!(buffer.capacity(), 0);
        assert!(SystemBuffer::default().is_empty());
    }
}
