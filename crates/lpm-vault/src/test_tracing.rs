//! Capturing what the crate logs, for tests that check a notice.

use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
struct Buffer(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Buffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'writer> tracing_subscriber::fmt::MakeWriter<'writer> for Buffer {
    type Writer = Self;

    fn make_writer(&'writer self) -> Self::Writer {
        self.clone()
    }
}

/// Every warning `action` logs on this thread, one per line.
pub(crate) fn warnings(action: impl FnOnce()) -> String {
    let buffer = Buffer::default();
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_target(false)
        .with_level(false)
        .with_ansi(false)
        .with_max_level(tracing::Level::WARN)
        .with_writer(buffer.clone())
        .finish();
    // A second live dispatcher makes callsites first reached by another
    // test's thread register with this subscriber too.
    let _registration = tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default());
    tracing::subscriber::with_default(subscriber, action);
    let bytes = buffer
        .0
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    String::from_utf8_lossy(&bytes).into_owned()
}
