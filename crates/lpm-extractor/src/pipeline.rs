use super::{
    DecompressedLimitReader, ExtractedFileDigest, ExtractionLimits, InspectionMode,
    extract_tar_archive_with_inspector,
};
use flate2::read::GzDecoder;
use lpm_common::LpmError;
use std::io::{self, Read};
use std::path::Path;
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};

const BUFFER_SIZE: usize = 256 * 1024;
const BUFFER_COUNT: usize = 3;

enum Message {
    Bytes(Vec<u8>, usize),
    Finished(io::Result<()>),
}

struct DecodedReader {
    ready: Receiver<Message>,
    recycle: SyncSender<Vec<u8>>,
    current: Option<Vec<u8>>,
    offset: usize,
    length: usize,
    finished: bool,
}

impl Read for DecodedReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() || self.finished {
            return Ok(0);
        }
        if self.offset == self.length {
            if let Some(bytes) = self.current.take() {
                let _ = self.recycle.send(bytes);
            }
            match {
                let _wait =
                    tracing::trace_span!(target: "lpm_install_timeline", "decoded_buffer_wait")
                        .entered();
                self.ready.recv()
            } {
                Ok(Message::Bytes(bytes, length)) => {
                    self.current = Some(bytes);
                    self.offset = 0;
                    self.length = length;
                }
                Ok(Message::Finished(result)) => {
                    self.finished = true;
                    return result.map(|()| 0);
                }
                Err(_) => {
                    self.finished = true;
                    return Err(io::Error::other("gzip decoder stopped before completion"));
                }
            }
        }
        let bytes = self
            .current
            .as_ref()
            .ok_or_else(|| io::Error::other("gzip decoder returned an empty buffer"))?;
        let count = output.len().min(self.length - self.offset);
        output[..count].copy_from_slice(&bytes[self.offset..self.offset + count]);
        self.offset += count;
        Ok(count)
    }
}

struct CancelOnDrop<F: FnOnce()>(Option<F>);

impl<F: FnOnce()> CancelOnDrop<F> {
    fn cancel(&mut self) {
        if let Some(cancel) = self.0.take() {
            cancel();
        }
    }
}

impl<F: FnOnce()> Drop for CancelOnDrop<F> {
    fn drop(&mut self) {
        self.cancel();
    }
}

pub(super) fn extract(
    reader: impl Read + Send,
    target_dir: &Path,
    limits: ExtractionLimits,
    cancel_input: impl FnOnce(),
) -> Result<Vec<ExtractedFileDigest>, LpmError> {
    with_decoder(reader, limits, cancel_input, |decoded| {
        extract_tar_archive_with_inspector(
            decoded,
            target_dir,
            limits,
            true,
            |_, _| false,
            |_| {},
            InspectionMode::WithoutCallback,
            |mut reader| {
                io::copy(&mut reader, &mut io::sink())
                    .map(|_| ())
                    .map_err(LpmError::Io)
            },
        )
    })
}

fn with_decoder<T>(
    reader: impl Read + Send,
    limits: ExtractionLimits,
    cancel_input: impl FnOnce(),
    consume: impl FnOnce(DecodedReader) -> Result<T, LpmError>,
) -> Result<T, LpmError> {
    std::thread::scope(|scope| {
        let mut cancellation = CancelOnDrop(Some(cancel_input));
        let (ready_tx, ready_rx) = sync_channel(BUFFER_COUNT - 1);
        let (recycle_tx, recycle_rx) = sync_channel(BUFFER_COUNT);
        for _ in 0..BUFFER_COUNT {
            recycle_tx
                .send(vec![0; BUFFER_SIZE])
                .map_err(|_| LpmError::Io(io::Error::other("gzip buffer pool disconnected")))?;
        }
        let decoder_span = tracing::trace_span!(target: "lpm_install_timeline", "pipeline_decoder");
        let worker = std::thread::Builder::new()
            .name("lpm-gzip".into())
            .spawn_scoped(scope, move || {
                let _entered = decoder_span.enter();
                decode(reader, limits, ready_tx, recycle_rx);
            })?;
        let decoded = DecodedReader {
            ready: ready_rx,
            recycle: recycle_tx,
            current: None,
            offset: 0,
            length: 0,
            finished: false,
        };
        let result = consume(decoded);
        // A failed consumer can leave the producer blocked inside its input reader.
        if result.is_err() {
            cancellation.cancel();
        }
        let joined = worker
            .join()
            .map_err(|_| LpmError::Io(io::Error::other("gzip decoder worker panicked")));
        cancellation.0 = None;
        result.and_then(|files| joined.map(|()| files))
    })
}

fn decode(
    reader: impl Read,
    limits: ExtractionLimits,
    ready: SyncSender<Message>,
    recycle: Receiver<Vec<u8>>,
) {
    let mut decoder = DecompressedLimitReader::new(
        super::timeline::TimelineReader::decoded(GzDecoder::new(
            super::timeline::TimelineReader::input(reader),
        )),
        limits.max_decompressed_stream_size(),
    );
    while let Ok(mut bytes) = recycle.recv() {
        let mut length = 0;
        while length < bytes.len() {
            match decoder.read(&mut bytes[length..]) {
                Ok(0) => {
                    if length != 0 && ready.send(Message::Bytes(bytes, length)).is_err() {
                        return;
                    }
                    let _ = ready.send(Message::Finished(Ok(())));
                    return;
                }
                Ok(count) => length += count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    let _ = ready.send(Message::Finished(Err(error)));
                    return;
                }
            }
        }
        if ready.send(Message::Bytes(bytes, length)).is_err() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DEFAULT_EXTRACTION_LIMITS, tests::create_test_tarball_with_entries};
    use std::cell::Cell;
    use std::time::Duration;

    struct ShortReads<R>(R);
    impl<R: Read> Read for ShortReads<R> {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            let count = output.len().min(7);
            self.0.read(&mut output[..count])
        }
    }

    #[test]
    fn short_reads_preserve_files_and_final_duplicate_digests() {
        let large = (0..BUFFER_SIZE * 4 + 19)
            .map(|i| (i % 251) as u8)
            .collect::<Vec<_>>();
        let archive = create_test_tarball_with_entries(&[
            ("large.bin", &large),
            ("empty", b""),
            ("small", b"abc"),
            ("small", b"final"),
        ]);
        let root = tempfile::tempdir().unwrap();
        let cancelled = Cell::new(false);
        let files = extract(
            ShortReads(archive.as_slice()),
            root.path(),
            DEFAULT_EXTRACTION_LIMITS,
            || cancelled.set(true),
        )
        .unwrap();
        for (file, (name, bytes)) in files.iter().zip([
            ("large.bin", large.as_slice()),
            ("empty", b"".as_slice()),
            ("small", b"final".as_slice()),
        ]) {
            assert_eq!(file.relative_path, Path::new(name));
            assert_eq!(file.blake3_digest, *blake3::hash(bytes).as_bytes());
            assert_eq!(std::fs::read(root.path().join(name)).unwrap(), bytes);
        }
        assert_eq!(files.len(), 3);
        assert!(!cancelled.get());
    }

    #[test]
    fn truncated_gzip_trailer_is_rejected_and_outputs_are_removed() {
        let mut archive = create_test_tarball_with_entries(&[("large", &vec![1; BUFFER_SIZE * 4])]);
        archive.truncate(archive.len() - 4);
        let root = tempfile::tempdir().unwrap();
        assert!(
            extract(
                archive.as_slice(),
                root.path(),
                DEFAULT_EXTRACTION_LIMITS,
                || {}
            )
            .is_err()
        );
        assert!(!root.path().join("large").exists());
    }

    #[test]
    fn invalid_gzip_crc_is_rejected_and_outputs_are_removed() {
        let mut archive = create_test_tarball_with_entries(&[("large", &vec![1; BUFFER_SIZE * 4])]);
        let crc = archive.len() - 8;
        archive[crc] ^= 1;
        let root = tempfile::tempdir().unwrap();
        assert!(
            extract(
                archive.as_slice(),
                root.path(),
                DEFAULT_EXTRACTION_LIMITS,
                || {}
            )
            .is_err()
        );
        assert!(!root.path().join("large").exists());
    }

    #[test]
    fn decompressed_limit_rejects_trailing_bytes_after_valid_tar_entries() {
        use std::io::Write;
        let archive = create_test_tarball_with_entries(&[("empty", b"")]);
        let mut tar = Vec::new();
        GzDecoder::new(archive.as_slice())
            .read_to_end(&mut tar)
            .unwrap();
        tar.resize(32 * 1024, 0);
        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gzip.write_all(&tar).unwrap();
        let archive = gzip.finish().unwrap();
        let root = tempfile::tempdir().unwrap();
        let limits = ExtractionLimits {
            max_extraction_size: 128,
            max_file_count: 1,
            ..DEFAULT_EXTRACTION_LIMITS
        };
        let error = extract(archive.as_slice(), root.path(), limits, || {}).unwrap_err();
        assert!(error.to_string().contains("gzip decompression exceeded"));
        assert!(!root.path().join("empty").exists());
    }

    #[test]
    fn decoder_panic_is_an_error_and_requests_input_cancellation() {
        struct Panics;
        impl Read for Panics {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                panic!("injected decoder input panic")
            }
        }
        let root = tempfile::tempdir().unwrap();
        let cancelled = Cell::new(false);
        let result = extract(Panics, root.path(), DEFAULT_EXTRACTION_LIMITS, || {
            cancelled.set(true)
        });
        assert!(result.is_err());
        assert!(cancelled.get());
    }

    #[test]
    fn consumer_failure_cancels_a_stalled_input_before_joining() {
        use std::io::Write;
        struct StalledReader {
            prefix: io::Cursor<Vec<u8>>,
            entered: std::sync::mpsc::Sender<()>,
            cancelled: Receiver<()>,
        }
        impl Read for StalledReader {
            fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
                let count = self.prefix.read(output)?;
                if count != 0 {
                    return Ok(count);
                }
                self.entered.send(()).unwrap();
                self.cancelled
                    .recv_timeout(Duration::from_secs(5))
                    .expect("consumer must cancel before worker join");
                Err(io::Error::other("cancelled input"))
            }
        }
        let mut tar = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size((BUFFER_SIZE * 8) as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(
            &mut header,
            "package/blocked",
            io::repeat(1).take((BUFFER_SIZE * 8) as u64),
        )
        .unwrap();
        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::none());
        gzip.write_all(&tar.into_inner().unwrap()).unwrap();
        let mut bytes = gzip.finish().unwrap();
        bytes.truncate(BUFFER_SIZE + BUFFER_SIZE / 2);
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (cancel_tx, cancel_rx) = std::sync::mpsc::channel();
        let reader = StalledReader {
            prefix: io::Cursor::new(bytes),
            entered: entered_tx,
            cancelled: cancel_rx,
        };
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("blocked")).unwrap();
        let result = extract(reader, root.path(), DEFAULT_EXTRACTION_LIMITS, || {
            entered_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("producer should be inside its pending read");
            cancel_tx.send(()).unwrap();
        });
        assert!(result.is_err());
        assert!(root.path().join("blocked").is_dir());
    }

    #[test]
    fn consumer_panic_cancels_input_before_the_scope_joins() {
        struct Stalled(Receiver<()>);
        impl Read for Stalled {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                self.0
                    .recv_timeout(Duration::from_secs(5))
                    .expect("scope must cancel before joining");
                Err(io::Error::other("cancelled input"))
            }
        }
        let (sender, receiver) = std::sync::mpsc::channel();
        let cancelled = Cell::new(false);
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _: Result<(), LpmError> = with_decoder(
                Stalled(receiver),
                DEFAULT_EXTRACTION_LIMITS,
                || {
                    cancelled.set(true);
                    let _ = sender.send(());
                },
                |_decoded| panic!("injected consumer panic"),
            );
        }))
        .unwrap_err();
        assert_eq!(
            panic.downcast_ref::<&str>(),
            Some(&"injected consumer panic")
        );
        assert!(cancelled.get());
    }

    #[test]
    fn consumer_failure_releases_a_producer_waiting_for_buffer_capacity() {
        let archive = create_test_tarball_with_entries(&[("large", &vec![1; BUFFER_SIZE * 12])]);
        let target = tempfile::NamedTempFile::new().unwrap();
        let cancelled = Cell::new(false);
        assert!(
            extract(
                archive.as_slice(),
                target.path(),
                DEFAULT_EXTRACTION_LIMITS,
                || cancelled.set(true)
            )
            .is_err()
        );
        assert!(cancelled.get());
    }
}
