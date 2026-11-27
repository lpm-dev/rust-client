//! Byte buffers that return their memory to the OS when freed.

use std::alloc::{GlobalAlloc, Layout, System};
use std::ptr::NonNull;

/// Bytes allocated outside the global allocator.
///
/// Extraction holds whole compressed and decompressed tarballs for a few
/// milliseconds at a time on many threads. In mimalloc's per-thread arenas
/// those multi-megabyte blocks keep hundreds of MiB committed after they are
/// freed during a cold install, and the system allocators keep freed large
/// blocks resident in caches of their own (macOS's large-block cache, glibc's
/// heap once its mmap threshold has risen). On Unix, blocks of 256 KiB and up
/// are therefore mapped straight from the OS and unmapped when freed; smaller
/// ones come from the system allocator.
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
            let (ptr, capacity) = allocate(len, true);
            buffer.ptr = ptr;
            buffer.capacity = capacity;
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
        if self.capacity == 0 {
            let (ptr, capacity) = allocate(capacity, false);
            self.ptr = ptr;
            self.capacity = capacity;
            return;
        }
        if !is_mapped(self.capacity) && !is_mapped(capacity) {
            // SAFETY: `ptr` was allocated by `System` with `layout(self.capacity)`,
            // and the new size is non-zero.
            let ptr = unsafe { System.realloc(self.ptr.as_ptr(), layout(self.capacity), capacity) };
            self.ptr = allocated(ptr, layout(capacity));
            self.capacity = capacity;
            return;
        }
        #[cfg(target_os = "linux")]
        if is_mapped(self.capacity) && is_mapped(capacity) {
            let new_capacity = mapped_capacity(capacity);
            // SAFETY: `ptr` maps exactly `self.capacity` bytes. The kernel
            // moves the pages instead of copying them, keeping their contents;
            // on failure the old mapping is untouched.
            let ptr = unsafe { remap(self.ptr.as_ptr().cast(), self.capacity, new_capacity) };
            // A seccomp profile can refuse mremap; copying into a new
            // mapping still works there.
            if ptr != libc::MAP_FAILED {
                self.ptr = allocated(ptr.cast(), layout(new_capacity));
                self.capacity = new_capacity;
                return;
            }
        }
        let (ptr, new_capacity) = allocate(capacity, false);
        // SAFETY: both allocations are live and distinct; `len <= capacity`.
        unsafe { std::ptr::copy_nonoverlapping(self.ptr.as_ptr(), ptr.as_ptr(), self.len) };
        // SAFETY: the old allocation came from `allocate` with `self.capacity`.
        unsafe { release(self.ptr, self.capacity) };
        self.ptr = ptr;
        self.capacity = new_capacity;
    }
}

/// `mremap(MREMAP_MAYMOVE)`, which tests can make fail.
///
/// # Safety
/// `old` must be a live mapping of exactly `old_len` bytes.
#[cfg(target_os = "linux")]
unsafe fn remap(old: *mut libc::c_void, old_len: usize, new_len: usize) -> *mut libc::c_void {
    #[cfg(test)]
    if FAIL_NEXT_REMAP.with(|fail| fail.replace(false)) {
        return libc::MAP_FAILED;
    }
    // SAFETY: the caller passes a live mapping of exactly `old_len` bytes.
    unsafe { libc::mremap(old, old_len, new_len, libc::MREMAP_MAYMOVE) }
}

#[cfg(all(test, target_os = "linux"))]
thread_local! {
    static FAIL_NEXT_REMAP: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(any(unix, windows))]
const MAP_THRESHOLD: usize = 256 * 1024;

#[cfg(unix)]
fn page_size() -> usize {
    static PAGE: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    // SAFETY: sysconf has no preconditions.
    *PAGE.get_or_init(|| {
        usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).unwrap_or(16384)
    })
}

#[cfg(windows)]
fn page_size() -> usize {
    4096
}

#[cfg(any(unix, windows))]
fn mapped_capacity(size: usize) -> usize {
    let page = page_size();
    size.div_ceil(page)
        .checked_mul(page)
        .expect("buffer size overflows usize")
}

#[cfg(any(unix, windows))]
fn is_mapped(capacity: usize) -> bool {
    capacity >= MAP_THRESHOLD
}

#[cfg(not(any(unix, windows)))]
fn is_mapped(_capacity: usize) -> bool {
    false
}

#[cfg(windows)]
mod win_mem {
    pub(super) const MEM_COMMIT: u32 = 0x0000_1000;
    pub(super) const MEM_RESERVE: u32 = 0x0000_2000;
    pub(super) const MEM_RELEASE: u32 = 0x0000_8000;
    pub(super) const PAGE_READWRITE: u32 = 0x04;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        pub(super) fn VirtualAlloc(
            lp_address: *const std::ffi::c_void,
            dw_size: usize,
            fl_allocation_type: u32,
            fl_protect: u32,
        ) -> *mut std::ffi::c_void;
        pub(super) fn VirtualFree(
            lp_address: *mut std::ffi::c_void,
            dw_size: usize,
            dw_free_type: u32,
        ) -> i32;
    }
}

/// Allocate at least `size` bytes; returns the pointer and the capacity owned.
fn allocate(size: usize, zeroed: bool) -> (NonNull<u8>, usize) {
    #[cfg(unix)]
    if is_mapped(size) {
        let capacity = mapped_capacity(size);
        // SAFETY: an anonymous private mapping with no address hint.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                capacity,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            std::alloc::handle_alloc_error(layout(capacity));
        }
        // Fresh anonymous pages are already zero.
        return (allocated(ptr.cast(), layout(capacity)), capacity);
    }
    #[cfg(windows)]
    if is_mapped(size) {
        let capacity = mapped_capacity(size);
        // SAFETY: `VirtualAlloc` with a null base address commits fresh zeroed
        // private pages owned exclusively by this buffer.
        let ptr = unsafe {
            win_mem::VirtualAlloc(
                std::ptr::null(),
                capacity,
                win_mem::MEM_COMMIT | win_mem::MEM_RESERVE,
                win_mem::PAGE_READWRITE,
            )
        };
        return (allocated(ptr.cast(), layout(capacity)), capacity);
    }
    let layout = layout(size);
    // SAFETY: `layout` has a non-zero size.
    let ptr = unsafe {
        if zeroed {
            System.alloc_zeroed(layout)
        } else {
            System.alloc(layout)
        }
    };
    (allocated(ptr, layout), size)
}

/// Free an allocation made by [`allocate`] with this `capacity`.
unsafe fn release(ptr: NonNull<u8>, capacity: usize) {
    #[cfg(unix)]
    if is_mapped(capacity) {
        // SAFETY: the caller passes a mapping of exactly `capacity` bytes.
        unsafe { libc::munmap(ptr.as_ptr().cast(), capacity) };
        return;
    }
    #[cfg(windows)]
    if is_mapped(capacity) {
        // SAFETY: `ptr` was returned by `VirtualAlloc` with `MEM_RESERVE` and is
        // released in full with `dwSize = 0` and `MEM_RELEASE`.
        unsafe {
            win_mem::VirtualFree(ptr.as_ptr().cast(), 0, win_mem::MEM_RELEASE);
        }
        return;
    }
    // SAFETY: the caller passes a `System` allocation with this layout.
    unsafe { System.dealloc(ptr.as_ptr(), layout(capacity)) }
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
            // SAFETY: `ptr` came from `allocate` with this capacity.
            unsafe { release(self.ptr, self.capacity) }
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
    fn growing_past_the_mapping_threshold_keeps_every_byte() {
        let mut buffer = SystemBuffer::new();
        let mut expected = Vec::new();
        for chunk in 0..1200_u32 {
            let bytes = [(chunk % 251) as u8; 1000];
            buffer.extend_from_slice(&bytes);
            expected.extend_from_slice(&bytes);
        }
        assert_eq!(&buffer[..], &expected[..]);
        assert!(buffer.capacity() >= expected.len());
        buffer.reserve_exact(5 * 1024 * 1024);
        assert_eq!(&buffer[..], &expected[..]);
        assert!(buffer.capacity() >= expected.len() + 5 * 1024 * 1024);
    }

    #[cfg(unix)]
    #[test]
    fn only_buffers_from_the_threshold_up_are_mapped_in_whole_pages() {
        let len = MAP_THRESHOLD + 3;
        let mut buffer = SystemBuffer::zeroed(len);
        assert_eq!(buffer.len(), len);
        assert!(buffer.iter().all(|&byte| byte == 0));
        assert_eq!(buffer.capacity(), len.div_ceil(page_size()) * page_size());
        buffer[len - 1] = 1;
        assert_eq!(buffer[len - 1], 1);

        let below = MAP_THRESHOLD - 3;
        assert_eq!(SystemBuffer::zeroed(below).capacity(), below);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_refused_remap_grows_by_copying_instead() {
        let mut buffer = SystemBuffer::new();
        let first: Vec<u8> = (0..MAP_THRESHOLD as u32 + 7)
            .map(|value| value as u8)
            .collect();
        buffer.extend_from_slice(&first);
        FAIL_NEXT_REMAP.with(|fail| fail.set(true));

        buffer.reserve_exact(3 * 1024 * 1024);

        assert!(
            !FAIL_NEXT_REMAP.with(std::cell::Cell::get),
            "the remap was attempted"
        );
        assert_eq!(&buffer[..], &first[..]);
        assert!(buffer.capacity() >= first.len() + 3 * 1024 * 1024);
    }

    #[test]
    fn empty_buffers_do_not_allocate() {
        let buffer = SystemBuffer::zeroed(0);
        assert!(buffer.is_empty());
        assert_eq!(buffer.capacity(), 0);
        assert!(SystemBuffer::default().is_empty());
    }
}
