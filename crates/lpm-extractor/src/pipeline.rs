#[cfg(test)]
use super::extract_tar_archive_with_writers;
use super::{
    ArchiveEnd, DecompressedLimitReader, ExtractedFileDigest, ExtractionLimits, ExtractionRecord,
    InspectionMode, extract_tar_archive_until,
};
use flate2::read::GzDecoder;
use lpm_common::LpmError;
use std::io::{self, Read};
use std::path::Path;
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, sync_channel};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const BUFFER_SIZE: usize = 256 * 1024;
const BUFFER_COUNT: usize = 4;

#[cfg(test)]
thread_local! {
    static FAIL_DECODER_SPAWN: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

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
    writer_failed: Arc<crate::writers::FailureSignal>,
    /// [`StreamFormat::reader`], for errors.
    reader: &'static str,
}

impl Read for DecodedReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() || self.finished {
            return Ok(0);
        }
        if self.writer_failed.has_failed() {
            return Err(io::Error::other("tarball file writer failed"));
        }
        if self.offset == self.length {
            if let Some(bytes) = self.current.take() {
                let _ = self.recycle.send(bytes);
            }
            let message = {
                let _wait =
                    tracing::trace_span!(target: "lpm_install_timeline", "decoded_buffer_wait")
                        .entered();
                if self.writer_failed.is_active() {
                    loop {
                        match self.ready.recv_timeout(Duration::from_millis(5)) {
                            Err(RecvTimeoutError::Timeout) if !self.writer_failed.has_failed() => {
                                continue;
                            }
                            result => break result,
                        }
                    }
                } else {
                    self.ready
                        .recv()
                        .map_err(|_| RecvTimeoutError::Disconnected)
                }
            };
            match message {
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
                    return Err(io::Error::other(format!(
                        "{} stopped before completion",
                        self.reader
                    )));
                }
            }
        }
        let bytes = self
            .current
            .as_ref()
            .ok_or_else(|| io::Error::other(format!("{} returned an empty buffer", self.reader)))?;
        let count = output.len().min(self.length - self.offset);
        output[..count].copy_from_slice(&bytes[self.offset..self.offset + count]);
        self.offset += count;
        Ok(count)
    }
}

/// What the pipeline's input reader yields.
#[derive(Clone, Copy)]
pub(super) enum StreamFormat {
    /// A gzip-compressed tar archive, decoded on the reading thread.
    Gzip,
    /// A tar archive the caller has already decompressed, read to its end.
    Tar,
}

impl StreamFormat {
    /// What the reading thread does, for its name and errors.
    fn reader(self) -> &'static str {
        match self {
            Self::Gzip => "gzip decoder",
            Self::Tar => "tar stream reader",
        }
    }
}

type GzipDecoder<R> = DecompressedLimitReader<
    super::timeline::TimelineReader<GzDecoder<super::timeline::TimelineReader<R>>>,
>;

enum SerialDecoder<R> {
    Gzip(Box<GzipDecoder<R>>),
    /// The caller's tar stream as npm's tar reads it, and whether it has
    /// ended: the walk reads to the end, and the drain after it must not read
    /// the caller's reader again. The limit counts what the stream reads,
    /// payloads it skips included.
    Tar(
        Box<
            super::npm_tar::NpmTarStream<
                DecompressedLimitReader<super::timeline::TimelineReader<R>>,
            >,
        >,
        bool,
    ),
}

impl<R: Read> Read for SerialDecoder<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Gzip(decoder) => decoder.read(output),
            Self::Tar(_, true) => Ok(0),
            Self::Tar(reader, ended) => {
                let read = reader.read(output)?;
                *ended = read == 0 && !output.is_empty();
                Ok(read)
            }
        }
    }
}

enum DecodedInput<R: Read> {
    Parallel(DecodedReader),
    Serial(Box<std::io::BufReader<SerialDecoder<R>>>),
}

impl<R: Read> DecodedInput<R> {
    fn writer_failure_signal(&self) -> Option<Arc<crate::writers::FailureSignal>> {
        match self {
            Self::Parallel(reader) => Some(Arc::clone(&reader.writer_failed)),
            Self::Serial(_) => None,
        }
    }
}

impl<R: Read> Read for DecodedInput<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Parallel(reader) => reader.read(output),
            Self::Serial(reader) => reader.read(output),
        }
    }
}

fn serial_decoder<R: Read>(
    reader: R,
    format: StreamFormat,
    limits: ExtractionLimits,
) -> SerialDecoder<R> {
    let limit = limits.max_decompressed_stream_size();
    match format {
        StreamFormat::Gzip => SerialDecoder::Gzip(Box::new(DecompressedLimitReader::new(
            super::timeline::TimelineReader::decoded(GzDecoder::new(
                super::timeline::TimelineReader::input(reader),
            )),
            limit,
        ))),
        StreamFormat::Tar => SerialDecoder::Tar(
            Box::new(super::npm_tar::NpmTarStream::new(
                DecompressedLimitReader::for_tar_stream(
                    super::timeline::TimelineReader::decoded(reader),
                    limit,
                ),
            )),
            false,
        ),
    }
}

fn take_reader<R>(input: &Mutex<Option<R>>) -> io::Result<R> {
    input
        .lock()
        .map_err(|_| io::Error::other("pipeline input lock poisoned"))?
        .take()
        .ok_or_else(|| io::Error::other("pipeline input already consumed"))
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
    extract_stream(
        reader,
        target_dir,
        limits,
        StreamFormat::Gzip,
        true,
        cancel_input,
    )
}

pub(super) fn extract_stream<E: ExtractionRecord>(
    reader: impl Read + Send,
    target_dir: &Path,
    limits: ExtractionLimits,
    format: StreamFormat,
    compute_blake3: bool,
    cancel_input: impl FnOnce(),
) -> Result<Vec<E>, LpmError> {
    with_decoder(reader, format, limits, cancel_input, |decoded| {
        let writer_setup = decoded.writer_failure_signal().map_or(
            crate::writers::WriterSetup::Disabled,
            |signal| {
                crate::writers::WriterSetup::configured()
                    .with_minimum_files(4)
                    .with_failure_signal(signal)
            },
        );
        extract_tar_archive_until(
            decoded,
            target_dir,
            limits,
            compute_blake3,
            |_, _| false,
            |_| {},
            InspectionMode::WithoutCallback,
            |mut reader| {
                io::copy(&mut reader, &mut io::sink())
                    .map(|_| ())
                    .map_err(LpmError::Io)
            },
            writer_setup,
            match format {
                StreamFormat::Gzip => ArchiveEnd::FirstZeroBlock,
                StreamFormat::Tar => ArchiveEnd::EndOfInput,
            },
        )
    })
}

fn with_decoder<T, R: Read + Send>(
    reader: R,
    format: StreamFormat,
    limits: ExtractionLimits,
    cancel_input: impl FnOnce(),
    consume: impl FnOnce(DecodedInput<R>) -> Result<T, LpmError>,
) -> Result<T, LpmError> {
    let input = Mutex::new(Some(reader));
    std::thread::scope(|scope| {
        let input = &input;
        let mut cancellation = CancelOnDrop(Some(cancel_input));
        let (ready_tx, ready_rx) = sync_channel(BUFFER_COUNT - 1);
        let (recycle_tx, recycle_rx) = sync_channel(BUFFER_COUNT);
        for _ in 0..BUFFER_COUNT {
            recycle_tx
                .send(vec![0; BUFFER_SIZE])
                .map_err(|_| LpmError::Io(io::Error::other("decode buffer pool disconnected")))?;
        }
        let decoder_span = tracing::trace_span!(target: "lpm_install_timeline", "pipeline_decoder");
        #[cfg(test)]
        let spawn_error = FAIL_DECODER_SPAWN
            .replace(false)
            .then(|| io::Error::other("injected decoder thread exhaustion"));
        #[cfg(not(test))]
        let spawn_error: Option<io::Error> = None;
        let worker = spawn_error.map_or_else(
            || {
                std::thread::Builder::new()
                    .name(
                        match format {
                            StreamFormat::Gzip => "lpm-gzip",
                            StreamFormat::Tar => "lpm-tar",
                        }
                        .into(),
                    )
                    .spawn_scoped(scope, move || {
                        let _entered = decoder_span.enter();
                        match take_reader(input) {
                            Ok(reader) => decode(reader, format, limits, ready_tx, recycle_rx),
                            Err(error) => {
                                let _ = ready_tx.send(Message::Finished(Err(error)));
                            }
                        }
                    })
            },
            Err,
        );
        let worker = match worker {
            Ok(worker) => worker,
            Err(_) => {
                let reader = take_reader(input)?;
                let decoded = std::io::BufReader::with_capacity(
                    64 * 1024,
                    serial_decoder(reader, format, limits),
                );
                let result = consume(DecodedInput::Serial(Box::new(decoded)));
                if result.is_err() {
                    cancellation.cancel();
                }
                cancellation.0 = None;
                return result;
            }
        };
        let decoded = DecodedReader {
            ready: ready_rx,
            recycle: recycle_tx,
            current: None,
            offset: 0,
            length: 0,
            finished: false,
            writer_failed: Arc::default(),
            reader: format.reader(),
        };
        let result = consume(DecodedInput::Parallel(decoded));
        // A failed consumer can leave the producer blocked inside its input reader.
        if result.is_err() {
            cancellation.cancel();
        }
        let joined = worker.join().map_err(|_| {
            LpmError::Io(io::Error::other(format!(
                "{} worker panicked",
                format.reader()
            )))
        });
        cancellation.0 = None;
        result.and_then(|files| joined.map(|()| files))
    })
}

fn decode(
    reader: impl Read,
    format: StreamFormat,
    limits: ExtractionLimits,
    ready: SyncSender<Message>,
    recycle: Receiver<Vec<u8>>,
) {
    let mut decoder = serial_decoder(reader, format, limits);
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
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tracing::{Event, Metadata, Subscriber, span};

    #[test]
    fn decoder_spawn_failure_preserves_serial_extraction_and_validation() {
        let valid = create_test_tarball_with_entries(&[("file", b"content")]);
        for truncated in [false, true] {
            let mut archive = valid.clone();
            if truncated {
                archive.truncate(archive.len() - 4);
            }
            let root = tempfile::tempdir().unwrap();
            FAIL_DECODER_SPAWN.set(true);
            let result = extract(
                archive.as_slice(),
                root.path(),
                DEFAULT_EXTRACTION_LIMITS,
                || {},
            );
            if truncated {
                assert!(result.is_err());
                assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
            } else {
                assert_eq!(result.unwrap().len(), 1);
                assert_eq!(std::fs::read(root.path().join("file")).unwrap(), b"content");
            }
        }
    }

    #[derive(Default)]
    struct MaterializationTrace {
        next: u64,
        materialization: HashMap<u64, bool>,
        created: usize,
        depth: usize,
        waits: usize,
        uncontained_waits: usize,
    }

    struct MaterializationProbe(Arc<Mutex<MaterializationTrace>>);

    impl Subscriber for MaterializationProbe {
        fn enabled(&self, metadata: &Metadata<'_>) -> bool {
            metadata.is_span()
                && metadata.target() == "lpm_install_timeline"
                && matches!(
                    metadata.name(),
                    "tar_materialization" | "decoded_buffer_wait"
                )
        }

        fn new_span(&self, attrs: &span::Attributes<'_>) -> span::Id {
            let mut state = self.0.lock().unwrap();
            state.next += 1;
            let id = state.next;
            let materialization = attrs.metadata().name() == "tar_materialization";
            state.created += usize::from(materialization);
            state.materialization.insert(id, materialization);
            span::Id::from_u64(id)
        }

        fn enter(&self, id: &span::Id) {
            let mut state = self.0.lock().unwrap();
            if state.materialization[&id.into_u64()] {
                state.depth += 1;
            } else {
                state.waits += 1;
                state.uncontained_waits += usize::from(state.depth != 1);
            }
        }

        fn exit(&self, id: &span::Id) {
            let mut state = self.0.lock().unwrap();
            if state.materialization[&id.into_u64()] {
                state.depth -= 1;
            }
        }

        fn record(&self, _: &span::Id, _: &span::Record<'_>) {}
        fn record_follows_from(&self, _: &span::Id, _: &span::Id) {}
        fn event(&self, _: &Event<'_>) {}
    }

    #[test]
    fn pipelined_and_buffered_extraction_emit_one_materialization_span() {
        let archive = create_test_tarball_with_entries(&[("file", b"content")]);
        // A second dispatcher prevents tracing's single-subscriber cache from
        // registering shared callsites through another test's empty dispatcher.
        let _other_dispatcher =
            tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default());
        for pipelined in [true, false] {
            let root = tempfile::tempdir().unwrap();
            let trace = Arc::new(Mutex::new(MaterializationTrace::default()));
            let files =
                tracing::subscriber::with_default(MaterializationProbe(Arc::clone(&trace)), || {
                    if pipelined {
                        extract(
                            archive.as_slice(),
                            root.path(),
                            DEFAULT_EXTRACTION_LIMITS,
                            || {},
                        )
                    } else {
                        crate::extract_tarball_digests(&archive, root.path())
                    }
                })
                .unwrap();
            assert_eq!(files.len(), 1);
            assert_eq!(std::fs::read(root.path().join("file")).unwrap(), b"content");
            let trace = trace.lock().unwrap();
            assert_eq!(trace.created, 1, "pipelined={pipelined}");
            assert_eq!(trace.depth, 0);
            if pipelined {
                assert!(trace.waits > 0);
                assert_eq!(trace.uncontained_waits, 0);
            }
        }
    }

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
    fn writer_failure_cancels_input_while_the_next_entry_is_stalled() {
        use std::io::Write;
        use std::sync::atomic::{AtomicBool, Ordering};
        struct StalledReader {
            prefix: io::Cursor<Vec<u8>>,
            entered: std::sync::mpsc::Sender<()>,
            cancelled: Receiver<()>,
            timed_out: Arc<AtomicBool>,
        }
        impl Read for StalledReader {
            fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
                let count = self.prefix.read(output)?;
                if count != 0 {
                    return Ok(count);
                }
                let _ = self.entered.send(());
                if self.cancelled.recv_timeout(Duration::from_secs(2)).is_err() {
                    self.timed_out.store(true, Ordering::Relaxed);
                }
                Err(io::Error::other("cancelled input"))
            }
        }
        let mut tar = tar::Builder::new(Vec::new());
        for (name, size) in [("first", 1024), ("next", BUFFER_SIZE)] {
            let mut header = tar::Header::new_gnu();
            header.set_size(size as u64);
            header.set_mode(0o644);
            header.set_cksum();
            tar.append_data(
                &mut header,
                format!("package/{name}"),
                io::repeat(1).take(size as u64),
            )
            .unwrap();
        }
        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::none());
        gzip.write_all(&tar.into_inner().unwrap()).unwrap();
        let mut bytes = gzip.finish().unwrap();
        bytes.truncate(BUFFER_SIZE + 1024);
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (cancel_tx, cancel_rx) = std::sync::mpsc::channel();
        let timed_out = Arc::new(AtomicBool::new(false));
        let reader = StalledReader {
            prefix: io::Cursor::new(bytes),
            entered: entered_tx,
            cancelled: cancel_rx,
            timed_out: Arc::clone(&timed_out),
        };
        let root = tempfile::tempdir().unwrap();
        let entered_rx = Mutex::new(entered_rx);
        let result = with_decoder(
            reader,
            StreamFormat::Gzip,
            DEFAULT_EXTRACTION_LIMITS,
            || {
                let _ = cancel_tx.send(());
            },
            |decoded| {
                let pool = crate::writers::WriterPool::new_with_hooks(
                    1,
                    crate::writers::TestHooks {
                        after_write: Some(Arc::new(move |_| {
                            entered_rx
                                .lock()
                                .unwrap()
                                .recv_timeout(Duration::from_secs(5))
                                .unwrap();
                            Err(io::Error::other("injected writer failure").into())
                        })),
                        ..crate::writers::TestHooks::default()
                    },
                    decoded.writer_failure_signal(),
                )
                .unwrap();
                extract_tar_archive_with_writers::<_, _, _, _, ExtractedFileDigest>(
                    decoded,
                    root.path(),
                    DEFAULT_EXTRACTION_LIMITS,
                    true,
                    |_, _| false,
                    |_| {},
                    InspectionMode::WithoutCallback,
                    |_| Ok(()),
                    crate::writers::WriterSetup::Ready(pool),
                )
            },
        );
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("injected writer failure")
        );
        assert!(
            !timed_out.load(Ordering::Relaxed),
            "input must be cancelled before its read deadline"
        );
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
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
                StreamFormat::Gzip,
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

    fn tar_stream(entries: &[(&[u8], &[u8])]) -> Vec<u8> {
        let mut tar = tar::Builder::new(Vec::new());
        for (name, bytes) in entries {
            let mut header = tar::Header::new_ustar();
            header.as_mut_bytes()[..name.len()].copy_from_slice(name);
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            tar.append(&header, *bytes).unwrap();
        }
        tar.into_inner().unwrap()
    }

    #[test]
    fn tar_stream_extracts_every_entry_and_lists_a_repeated_path_again() {
        let large = (0..BUFFER_SIZE * 3 + 5)
            .map(|i| (i % 241) as u8)
            .collect::<Vec<_>>();
        let tar = tar_stream(&[
            (b"package/a", b"first"),
            (b"package/dir/large.bin", &large),
            (b"package/a", b"final"),
        ]);
        let root = tempfile::tempdir().unwrap();
        let cancelled = Cell::new(false);
        let files = crate::extract_tar_from_reader_pipelined(
            ShortReads(tar.as_slice()),
            root.path(),
            || cancelled.set(true),
        )
        .unwrap();
        assert_eq!(
            files,
            [Path::new("a"), Path::new("dir/large.bin"), Path::new("a")]
        );
        assert_eq!(std::fs::read(root.path().join("a")).unwrap(), b"final");
        assert_eq!(
            std::fs::read(root.path().join("dir/large.bin")).unwrap(),
            large
        );
        assert!(!cancelled.get());
    }

    #[test]
    fn tar_stream_extracts_entries_after_a_lone_zero_block_as_npm_does() {
        let first = tar_stream(&[(b"package/a.js", b"first")]);
        let second = tar_stream(&[(b"package/hidden.js", b"second")]);
        // One zero block between the entries, as a crafted archive can carry; npm's tar reads on.
        let mut stream = first[..1024].to_vec();
        stream.extend_from_slice(&[0; 512]);
        stream.extend_from_slice(&second);
        let root = tempfile::tempdir().unwrap();
        let files = crate::extract_tar_from_reader_pipelined(stream.as_slice(), root.path(), || {})
            .unwrap();
        assert_eq!(files, [Path::new("a.js"), Path::new("hidden.js")]);
        assert_eq!(
            std::fs::read(root.path().join("hidden.js")).unwrap(),
            b"second"
        );
    }

    #[test]
    fn tar_stream_extracts_a_file_npm_reads_inside_a_directory_s_payload() {
        let hidden = tar_stream(&[(b"package/hidden.js", b"payload")]);
        let hidden = &hidden[..1024];
        // A directory header that claims a payload: npm's tar reads a directory's
        // payload as empty, so the entry inside it is one npm unpacks.
        let mut directory = tar::Header::new_ustar();
        directory.set_path("package/lib/").unwrap();
        directory.set_entry_type(tar::EntryType::Directory);
        directory.set_size(hidden.len() as u64);
        directory.set_mode(0o755);
        directory.set_cksum();
        let mut stream = directory.as_bytes().to_vec();
        stream.extend_from_slice(hidden);
        stream.extend_from_slice(&[0; 1024]);
        let root = tempfile::tempdir().unwrap();
        let files = crate::extract_tar_from_reader_pipelined(stream.as_slice(), root.path(), || {})
            .unwrap();
        assert_eq!(files, [Path::new("hidden.js")]);
        assert_eq!(
            std::fs::read(root.path().join("hidden.js")).unwrap(),
            b"payload"
        );
    }

    #[test]
    fn the_serial_tar_route_reads_the_caller_reader_once_past_its_end() {
        struct FailsAfterEnd(io::Cursor<Vec<u8>>, bool);
        impl Read for FailsAfterEnd {
            fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
                if self.1 {
                    return Err(io::Error::other("read again after the end"));
                }
                let read = self.0.read(output)?;
                self.1 = read == 0 && !output.is_empty();
                Ok(read)
            }
        }
        // Without its end blocks, the route reads the caller's reader to its end.
        let mut tar = tar_stream(&[(b"package/a.js", b"content")]);
        tar.truncate(tar.len() - 1024);
        let root = tempfile::tempdir().unwrap();
        FAIL_DECODER_SPAWN.set(true);
        let files = extract_stream::<std::path::PathBuf>(
            FailsAfterEnd(io::Cursor::new(tar), false),
            root.path(),
            DEFAULT_EXTRACTION_LIMITS,
            StreamFormat::Tar,
            false,
            || {},
        )
        .unwrap();
        assert_eq!(files, [Path::new("a.js")]);
    }

    #[test]
    fn tar_stream_ends_at_two_zero_blocks_and_leaves_what_follows_to_the_caller() {
        let mut tar = tar_stream(&[(b"package/a", b"content")]);
        let end = (512 + 512 + 1024) as u64;
        tar.truncate(end as usize);
        tar.extend_from_slice(&[0; 100]);
        tar.extend_from_slice(b"garbage npm ignores after the end of the archive");
        let mut input = io::Cursor::new(tar);
        let root = tempfile::tempdir().unwrap();
        let files =
            crate::extract_tar_from_reader_pipelined(&mut input, root.path(), || {}).unwrap();
        assert_eq!(files, [Path::new("a")]);
        assert_eq!(input.position(), end);
    }

    #[test]
    fn tar_stream_with_a_parent_entry_is_rejected_and_outputs_are_removed() {
        let tar = tar_stream(&[(b"package/a", b"kept?"), (b"package/../escape", b"x")]);
        let root = tempfile::tempdir().unwrap();
        let output = root.path().join("out");
        assert!(crate::extract_tar_from_reader_pipelined(tar.as_slice(), &output, || {}).is_err());
        assert!(!output.join("a").exists());
        assert!(!root.path().join("escape").exists());
    }

    #[test]
    fn tar_stream_past_the_extraction_limits_is_rejected_and_outputs_are_removed() {
        let tar = tar_stream(&[(b"package/large", &vec![1; 64 * 1024])]);
        let root = tempfile::tempdir().unwrap();
        let limits = ExtractionLimits {
            max_extraction_size: 128,
            max_file_count: 1,
            ..DEFAULT_EXTRACTION_LIMITS
        };
        assert!(
            extract_stream::<std::path::PathBuf>(
                tar.as_slice(),
                root.path(),
                limits,
                StreamFormat::Tar,
                false,
                || {},
            )
            .is_err()
        );
        assert!(!root.path().join("large").exists());

        let mut bounded = DecompressedLimitReader::for_tar_stream(&[0u8; 16][..], 4);
        let error = bounded.read_to_end(&mut Vec::new()).unwrap_err();
        assert!(error.to_string().contains("tar stream exceeded"), "{error}");
    }

    #[test]
    fn truncated_tar_stream_is_rejected_and_outputs_are_removed() {
        let mut tar = tar_stream(&[(b"package/large", &vec![1; BUFFER_SIZE * 2])]);
        tar.truncate(BUFFER_SIZE);
        let root = tempfile::tempdir().unwrap();
        assert!(
            crate::extract_tar_from_reader_pipelined(tar.as_slice(), root.path(), || {}).is_err()
        );
        assert!(!root.path().join("large").exists());
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
