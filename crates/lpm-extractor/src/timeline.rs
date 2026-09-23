use std::io::{self, Read};

pub(super) struct TimelineReader<R> {
    inner: R,
    compressed: bool,
}

impl<R> TimelineReader<R> {
    pub(super) fn input(inner: R) -> Self {
        Self {
            inner,
            compressed: true,
        }
    }

    pub(super) fn decoded(inner: R) -> Self {
        Self {
            inner,
            compressed: false,
        }
    }
}

impl<R: Read> Read for TimelineReader<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let span = if self.compressed {
            tracing::trace_span!(target: "lpm_install_timeline", "compressed_read")
        } else {
            tracing::trace_span!(target: "lpm_install_timeline", "decode_read")
        };
        let _entered = span.enter();
        let result = self.inner.read(output);
        // Per-chunk completion events exhaust the trace budget before finalization.
        if !matches!(&result, Ok(count) if *count != 0) {
            tracing::event!(name: "read_terminal", target: "lpm_install_timeline", tracing::Level::TRACE,
                success = result.is_ok());
        }
        result
    }
}
