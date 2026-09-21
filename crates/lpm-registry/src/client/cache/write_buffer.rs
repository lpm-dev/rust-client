use std::io::{self, Write};
use std::sync::Arc;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use super::{METADATA_CACHE_FILE_CAP, reserve_pending_metadata_cache_bytes};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum BufferLimit {
    Budget,
    FileSize,
}

pub(super) struct MetadataCacheBuffer {
    bytes: Vec<u8>,
    budget: Arc<Semaphore>,
    reservation: OwnedSemaphorePermit,
    file_limit: usize,
    exhausted: Option<BufferLimit>,
}

impl MetadataCacheBuffer {
    pub(super) fn new(budget: &Arc<Semaphore>, prefix: &[&[u8]]) -> Result<Self, BufferLimit> {
        Self::with_limit(budget, prefix, METADATA_CACHE_FILE_CAP as usize)
    }

    fn with_limit(
        budget: &Arc<Semaphore>,
        prefix: &[&[u8]],
        file_limit: usize,
    ) -> Result<Self, BufferLimit> {
        let len = prefix.iter().try_fold(0usize, |size, part| {
            size.checked_add(part.len()).ok_or(BufferLimit::FileSize)
        })?;
        if len > file_limit {
            return Err(BufferLimit::FileSize);
        }
        let capacity = len.saturating_add(4096).min(file_limit);
        let reservation =
            reserve_pending_metadata_cache_bytes(budget, capacity).ok_or(BufferLimit::Budget)?;
        let mut bytes = Vec::with_capacity(capacity);
        for part in prefix {
            bytes.extend_from_slice(part);
        }
        Ok(Self {
            bytes,
            budget: Arc::clone(budget),
            reservation,
            file_limit,
            exhausted: None,
        })
    }

    #[inline]
    pub(super) fn len(&self) -> usize {
        self.bytes.len()
    }

    pub(super) fn exhausted(&self) -> Option<BufferLimit> {
        self.exhausted
    }

    fn reject(&mut self, limit: BufferLimit) -> io::Error {
        self.exhausted = Some(limit);
        io::Error::other(match limit {
            BufferLimit::Budget => "metadata cache allocation budget exhausted",
            BufferLimit::FileSize => "metadata cache file size limit exceeded",
        })
    }

    fn reserve_for(&mut self, additional: usize) -> io::Result<()> {
        let Some(required) = self.bytes.len().checked_add(additional) else {
            return Err(self.reject(BufferLimit::FileSize));
        };
        if required > self.file_limit {
            return Err(self.reject(BufferLimit::FileSize));
        }
        let previous_capacity = self.bytes.capacity();
        let capacity = previous_capacity
            .saturating_mul(2)
            .max(required)
            .min(self.file_limit);
        // Reallocation can retain the old allocation until the copy finishes.
        let Some(reservation) = reserve_pending_metadata_cache_bytes(&self.budget, capacity) else {
            return Err(self.reject(BufferLimit::Budget));
        };
        self.reservation.merge(reservation);
        self.bytes.reserve_exact(capacity - self.bytes.len());
        drop(self.reservation.split(previous_capacity));
        Ok(())
    }

    #[inline]
    fn append(&mut self, bytes: &[u8]) -> io::Result<()> {
        if let Some(limit) = self.exhausted {
            return Err(self.reject(limit));
        }
        if bytes.len() > self.bytes.capacity() - self.bytes.len() {
            self.reserve_for(bytes.len())?;
        }
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    pub(super) fn write_to(&self, writer: &mut impl Write) -> io::Result<()> {
        writer.write_all(&self.bytes)
    }
}

impl Write for MetadataCacheBuffer {
    #[inline]
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.append(bytes)?;
        Ok(bytes.len())
    }

    #[inline]
    fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.append(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buffer_capacity_stays_reserved_until_the_buffer_is_dropped() {
        let budget = Arc::new(Semaphore::new(2 * 1024 * 1024));
        let mut buffer =
            MetadataCacheBuffer::with_limit(&budget, &[b"header"], 1024 * 1024).unwrap();
        let payload = vec![0x5a; 192 * 1024];
        buffer.write_all(&payload).unwrap();
        assert_eq!(
            budget.available_permits(),
            2 * 1024 * 1024 - buffer.bytes.capacity()
        );
        let mut actual = Vec::new();
        buffer.write_to(&mut actual).unwrap();
        assert_eq!(&actual[..6], b"header");
        assert_eq!(&actual[6..], payload);
        drop(buffer);
        assert_eq!(budget.available_permits(), 2 * 1024 * 1024);
    }

    #[test]
    fn growth_requires_budget_for_both_old_and_new_allocations() {
        let budget = Arc::new(Semaphore::new(8192));
        let mut buffer = MetadataCacheBuffer::with_limit(&budget, &[], 8192).unwrap();
        buffer.write_all(&[0x5a; 4096]).unwrap();
        assert_eq!(budget.available_permits(), 4096);
        assert!(buffer.write_all(&[0x5a]).is_err());
        assert_eq!(buffer.exhausted(), Some(BufferLimit::Budget));
        assert_eq!(buffer.len(), 4096);
        assert_eq!(buffer.bytes.capacity(), 4096);
        assert_eq!(budget.available_permits(), 4096);
        assert!(buffer.write_all(&[]).is_err());
        drop(buffer);
        assert_eq!(budget.available_permits(), 8192);
    }

    #[test]
    fn successful_growth_releases_the_old_allocation_reservation() {
        let budget = Arc::new(Semaphore::new(12288));
        let mut buffer = MetadataCacheBuffer::with_limit(&budget, &[], 8192).unwrap();
        buffer.write_all(&[0x5a; 4097]).unwrap();
        assert_eq!(buffer.bytes.capacity(), 8192);
        assert_eq!(budget.available_permits(), 4096);
        drop(buffer);
        assert_eq!(budget.available_permits(), 12288);
    }

    #[test]
    fn file_size_limit_rejects_the_overflow_before_allocating() {
        let budget = Arc::new(Semaphore::new(1024 * 1024));
        let mut buffer = MetadataCacheBuffer::with_limit(&budget, &[b"header"], 8192).unwrap();
        let charged = budget.available_permits();
        assert!(buffer.write_all(&[0x5a; 8192]).is_err());
        assert_eq!(buffer.exhausted(), Some(BufferLimit::FileSize));
        assert_eq!(buffer.len(), 6);
        assert_eq!(budget.available_permits(), charged);
    }

    #[test]
    fn growth_and_small_writes_stop_at_a_non_power_of_two_file_limit() {
        let budget = Arc::new(Semaphore::new(16384));
        let mut buffer = MetadataCacheBuffer::with_limit(&budget, &[], 5003).unwrap();
        for _ in 0..5003 {
            buffer.write_all(b"a").unwrap();
        }
        assert_eq!(buffer.len(), 5003);
        assert_eq!(buffer.bytes.capacity(), 5003);
        assert!(buffer.write_all(b"b").is_err());
        assert_eq!(buffer.exhausted(), Some(BufferLimit::FileSize));
        assert_eq!(buffer.len(), 5003);
    }

    #[test]
    fn output_handles_interruptions_and_short_writes() {
        struct ShortWriter {
            bytes: Vec<u8>,
            interrupted: bool,
            calls: usize,
        }
        impl Write for ShortWriter {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.calls += 1;
                if !self.interrupted {
                    self.interrupted = true;
                    return Err(io::ErrorKind::Interrupted.into());
                }
                let count = bytes.len().min(8191);
                self.bytes.extend_from_slice(&bytes[..count]);
                Ok(count)
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let budget = Arc::new(Semaphore::new(8 * 1024 * 1024));
        let mut buffer =
            MetadataCacheBuffer::with_limit(&budget, &[b"header"], 6 * 1024 * 1024).unwrap();
        let bytes = vec![0x5a; 65 * 64 * 1024];
        buffer.write_all(&bytes).unwrap();
        let mut writer = ShortWriter {
            bytes: Vec::new(),
            interrupted: false,
            calls: 0,
        };
        buffer.write_to(&mut writer).unwrap();
        assert!(writer.calls > 2);
        assert_eq!(&writer.bytes[..6], b"header");
        assert_eq!(&writer.bytes[6..], bytes);
    }
}
