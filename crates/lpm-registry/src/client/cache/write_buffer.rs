use std::io::{self, IoSlice, Write};
use std::sync::Arc;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use super::{METADATA_CACHE_FILE_CAP, reserve_pending_metadata_cache_bytes};

const CHUNK_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum BufferLimit {
    Budget,
    FileSize,
}

pub(super) struct MetadataCacheBuffer {
    first: Vec<u8>,
    chunks: Vec<Vec<u8>>,
    budget: Arc<Semaphore>,
    reservation: OwnedSemaphorePermit,
    file_limit: usize,
    payload_capacity: usize,
    len: usize,
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
        let mut first = Vec::with_capacity(capacity);
        for part in prefix {
            first.extend_from_slice(part);
        }
        Ok(Self {
            first,
            chunks: Vec::new(),
            budget: Arc::clone(budget),
            reservation,
            file_limit,
            payload_capacity: capacity,
            len,
            exhausted: None,
        })
    }

    #[inline]
    pub(super) fn len(&self) -> usize {
        self.len
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

    fn add_chunk(&mut self) -> io::Result<()> {
        let tail_capacity = self.chunks.last().unwrap_or(&self.first).capacity();
        let capacity = tail_capacity
            .saturating_mul(2)
            .min(CHUNK_BYTES)
            .min(self.file_limit - self.payload_capacity);
        if capacity == 0 {
            return Err(self.reject(BufferLimit::FileSize));
        }
        let directory_capacity = if self.chunks.len() == self.chunks.capacity() {
            self.chunks.capacity().saturating_mul(2).max(4)
        } else {
            0
        };
        let allocation = capacity + directory_capacity * std::mem::size_of::<Vec<u8>>();
        let Some(reservation) = reserve_pending_metadata_cache_bytes(&self.budget, allocation)
        else {
            return Err(self.reject(BufferLimit::Budget));
        };
        self.reservation.merge(reservation);
        if directory_capacity != 0 {
            let previous_bytes = self.chunks.capacity() * std::mem::size_of::<Vec<u8>>();
            self.chunks
                .reserve_exact(directory_capacity - self.chunks.len());
            drop(self.reservation.split(previous_bytes));
        }
        self.chunks.push(Vec::with_capacity(capacity));
        self.payload_capacity += capacity;
        Ok(())
    }

    fn write_across_chunks(&mut self, mut bytes: &[u8]) -> io::Result<usize> {
        let written = bytes.len();
        if self
            .len
            .checked_add(written)
            .is_none_or(|size| size > self.file_limit)
        {
            return Err(self.reject(BufferLimit::FileSize));
        }
        while !bytes.is_empty() {
            let tail = self.chunks.last().unwrap_or(&self.first);
            if tail.len() == tail.capacity() {
                self.add_chunk()?;
            }
            let tail = self.chunks.last_mut().unwrap_or(&mut self.first);
            let count = bytes.len().min(tail.capacity() - tail.len());
            tail.extend_from_slice(&bytes[..count]);
            self.len += count;
            bytes = &bytes[count..];
        }
        Ok(written)
    }

    pub(super) fn write_to(&self, writer: &mut impl Write) -> io::Result<()> {
        let mut chunks = std::iter::once(self.first.as_slice())
            .chain(self.chunks.iter().map(Vec::as_slice))
            .filter(|chunk| !chunk.is_empty());
        loop {
            let mut slices: [IoSlice<'_>; 64] = std::array::from_fn(|_| IoSlice::new(&[]));
            let mut count = 0;
            for (slot, chunk) in slices.iter_mut().zip(chunks.by_ref()) {
                *slot = IoSlice::new(chunk);
                count += 1;
            }
            if count == 0 {
                return Ok(());
            }
            let mut remaining = &mut slices[..count];
            while !remaining.is_empty() {
                match writer.write_vectored(remaining) {
                    Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                    Ok(written) => IoSlice::advance_slices(&mut remaining, written),
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) => return Err(error),
                }
            }
        }
    }
}

impl Write for MetadataCacheBuffer {
    #[inline]
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if let Some(limit) = self.exhausted {
            return Err(self.reject(limit));
        }
        let tail = self.chunks.last_mut().unwrap_or(&mut self.first);
        if bytes.len() <= tail.capacity() - tail.len() {
            tail.extend_from_slice(bytes);
            self.len += bytes.len();
            return Ok(bytes.len());
        }
        self.write_across_chunks(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_allocations_and_directory_stay_reserved_until_the_buffer_is_dropped() {
        let budget = Arc::new(Semaphore::new(2 * 1024 * 1024));
        let mut buffer =
            MetadataCacheBuffer::with_limit(&budget, &[b"header"], 1024 * 1024).unwrap();
        let payload = vec![0x5a; 3 * CHUNK_BYTES];
        buffer.write_all(&payload).unwrap();
        assert!(
            buffer
                .chunks
                .iter()
                .all(|chunk| chunk.capacity() <= CHUNK_BYTES)
        );
        let charged = buffer.first.capacity()
            + buffer.chunks.iter().map(Vec::capacity).sum::<usize>()
            + buffer.chunks.capacity() * std::mem::size_of::<Vec<u8>>();
        assert_eq!(budget.available_permits(), 2 * 1024 * 1024 - charged);
        assert!(buffer.payload_capacity - buffer.len() < CHUNK_BYTES);
        let mut actual = Vec::new();
        buffer.write_to(&mut actual).unwrap();
        assert_eq!(&actual[..6], b"header");
        assert_eq!(&actual[6..], payload);
        drop(buffer);
        assert_eq!(budget.available_permits(), 2 * 1024 * 1024);
    }

    #[test]
    fn growth_budget_exhaustion_allocates_no_extra_chunk_and_releases_all_permits() {
        let budget = Arc::new(Semaphore::new(8192));
        let mut buffer = MetadataCacheBuffer::new(&budget, &[b"header"]).unwrap();
        let charged = budget.available_permits();
        assert!(buffer.write_all(&[0x5a; 8192]).is_err());
        assert_eq!(buffer.exhausted(), Some(BufferLimit::Budget));
        assert!(buffer.chunks.is_empty());
        assert_eq!(budget.available_permits(), charged);
        drop(buffer);
        assert_eq!(budget.available_permits(), 8192);
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
    fn vectored_output_handles_interruptions_and_short_writes_across_batches() {
        struct ShortWriter {
            bytes: Vec<u8>,
            interrupted: bool,
            crossed_boundary: bool,
        }
        impl Write for ShortWriter {
            fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
                panic!("expected vectored output");
            }
            fn write_vectored(&mut self, slices: &[IoSlice<'_>]) -> io::Result<usize> {
                if !self.interrupted {
                    self.interrupted = true;
                    return Err(io::ErrorKind::Interrupted.into());
                }
                let mut written = 0;
                for (index, slice) in slices.iter().enumerate() {
                    let count = slice.len().min(8191 - written);
                    self.bytes.extend_from_slice(&slice[..count]);
                    self.crossed_boundary |= index > 0 && count > 0;
                    written += count;
                    if written == 8191 {
                        break;
                    }
                }
                Ok(written)
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let budget = Arc::new(Semaphore::new(8 * 1024 * 1024));
        let mut buffer =
            MetadataCacheBuffer::with_limit(&budget, &[b"header"], 6 * 1024 * 1024).unwrap();
        let bytes = vec![0x5a; 65 * CHUNK_BYTES];
        buffer.write_all(&bytes).unwrap();
        let mut writer = ShortWriter {
            bytes: Vec::new(),
            interrupted: false,
            crossed_boundary: false,
        };
        buffer.write_to(&mut writer).unwrap();
        assert!(writer.crossed_boundary);
        assert_eq!(&writer.bytes[..6], b"header");
        assert_eq!(&writer.bytes[6..], bytes);
    }
}
