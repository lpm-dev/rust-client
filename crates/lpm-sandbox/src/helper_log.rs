//! What `lpm-sandbox-helper` logs on stderr, and how the process that
//! started it reads that once the helper has ended.
//!
//! The helper's stderr is also its script's, so each of its lines starts
//! with [`PREFIX`]. What it logs and goes on after has a label. A helper
//! that cleans up runs no script and writes one more line at most, the
//! unlabelled one that says why it failed.

#![cfg(any(target_os = "windows", test))]

use std::fmt::Write as _;
use std::io::Write;
use std::sync::{Mutex, PoisonError};

use tracing::field::{Field, Visit};
use tracing::span;
use tracing::{Event, Level, Metadata, Subscriber};

/// How each of the helper's own lines starts.
pub const PREFIX: &str = "lpm-sandbox-helper: ";
const WARNING: &str = "warning: ";
const ERROR: &str = "error: ";

/// Writes every warning and error the helper logs to `W`, one line each.
/// The helper has no other log output, so without it these go nowhere.
pub struct Warnings<W>(Mutex<W>);

impl<W> Warnings<W> {
    /// A log that writes to `writer`.
    pub fn to(writer: W) -> Self {
        Self(Mutex::new(writer))
    }
}

impl<W: Write + Send + 'static> Subscriber for Warnings<W> {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.is_event() && *metadata.level() <= Level::WARN
    }

    fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
        Some(tracing::level_filters::LevelFilter::WARN)
    }

    fn new_span(&self, _: &span::Attributes<'_>) -> span::Id {
        span::Id::from_u64(1)
    }

    fn record(&self, _: &span::Id, _: &span::Record<'_>) {}

    fn record_follows_from(&self, _: &span::Id, _: &span::Id) {}

    fn event(&self, event: &Event<'_>) {
        let label = if *event.metadata().level() == Level::ERROR {
            ERROR
        } else {
            WARNING
        };
        let mut line = Line(format!("{PREFIX}{label}"));
        event.record(&mut line);
        line.0.push('\n');
        // A reader gone from the other end mustn't stop the helper.
        let _ = self
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .write_all(line.0.as_bytes());
    }

    fn enter(&self, _: &span::Id) {}

    fn exit(&self, _: &span::Id) {}
}

/// An event on one line: its message, then its other fields as
/// `name=value`. A line break in either would start a line without the
/// helper's prefix, so each becomes a space.
struct Line(String);

impl Visit for Line {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        let written = self.0.len();
        let _ = if field.name() == "message" {
            write!(self.0, "{value:?}")
        } else {
            write!(self.0, " {}={value:?}", field.name())
        };
        if self.0[written..].contains(['\n', '\r']) {
            let one_line = self.0[written..].replace(['\n', '\r'], " ");
            self.0.truncate(written);
            self.0.push_str(&one_line);
        }
    }
}

/// What a helper that has ended wrote to stderr.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Said {
    /// What it warned of, without the prefix and the label.
    pub warnings: Vec<String>,
    /// Everything else: why it failed, when it did.
    pub reason: String,
}

impl Said {
    /// Reads what the helper wrote to `stderr`.
    pub fn on(stderr: &[u8]) -> Self {
        let mut said = Self::default();
        for line in String::from_utf8_lossy(stderr).lines() {
            let warning = line.strip_prefix(PREFIX).and_then(|rest| {
                rest.strip_prefix(WARNING)
                    .or_else(|| rest.strip_prefix(ERROR))
            });
            match warning {
                Some(warning) => said.warnings.push(warning.to_owned()),
                None => {
                    said.reason.push_str(line);
                    said.reason.push('\n');
                }
            }
        }
        said.reason = said.reason.trim().to_owned();
        said
    }
}

/// Runs `log` and returns what [`Warnings`] wrote of it.
#[cfg(test)]
pub(crate) fn written_while<T>(log: impl FnOnce() -> T) -> (T, String) {
    use std::sync::Arc;

    #[derive(Clone, Default)]
    struct Written(Arc<Mutex<Vec<u8>>>);

    impl Write for Written {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let written = Written::default();
    // With one dispatcher alive, a callsite another test's thread reached
    // first, without a subscriber, stays disabled here. A second one makes
    // tracing ask every subscriber.
    let _second = tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default());
    let result = tracing::subscriber::with_default(Warnings::to(written.clone()), log);
    let bytes = written.0.lock().unwrap().clone();
    (result, String::from_utf8(bytes).unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct NoReader(Arc<AtomicUsize>);

    impl Write for NoReader {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Err(std::io::ErrorKind::BrokenPipe.into())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn logged(log: impl FnOnce()) -> String {
        written_while(log).1
    }

    #[test]
    fn a_warning_and_an_error_are_each_written_as_one_labelled_line() {
        let written = logged(|| {
            tracing::warn!(target: "lpm_sandbox::helper_appcontainer", "couldn't revoke {}: {}", r"C:\tree", "denied");
            tracing::error!("the profile stays");
        });

        assert_eq!(
            written,
            "lpm-sandbox-helper: warning: couldn't revoke C:\\tree: denied\n\
             lpm-sandbox-helper: error: the profile stays\n"
        );
    }

    #[test]
    fn what_is_below_a_warning_is_not_written() {
        let written = logged(|| {
            tracing::info!("granted");
            tracing::debug!("skip DACL grant");
            let _entered = tracing::warn_span!("a run").entered();
        });

        assert_eq!(written, "");
    }

    #[test]
    fn an_event_s_fields_follow_its_message_on_the_same_line() {
        let written = logged(|| {
            tracing::warn!(path = %r"C:\secret", tries = 2, "access stays:\r\nin use");
        });

        assert_eq!(
            written,
            "lpm-sandbox-helper: warning: access stays:  in use path=C:\\secret tries=2\n"
        );
    }

    #[test]
    fn a_warning_nobody_reads_stops_nothing() {
        let tried = Arc::new(AtomicUsize::new(0));

        tracing::subscriber::with_default(Warnings::to(NoReader(Arc::clone(&tried))), || {
            tracing::warn!("nobody reads this");
        });

        assert_eq!(tried.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn what_a_helper_said_is_read_as_its_warnings_and_why_it_failed() {
        let said = Said::on(
            b"lpm-sandbox-helper: warning: couldn't take back C:\\a: denied\r\n\
              lpm-sandbox-helper: error: the profile stays\n\
              lpm-sandbox-helper: another process holds this package's sandbox identity\n",
        );

        assert_eq!(
            said,
            Said {
                warnings: vec![
                    r"couldn't take back C:\a: denied".to_owned(),
                    "the profile stays".to_owned(),
                ],
                reason: "lpm-sandbox-helper: another process holds this package's sandbox identity"
                    .to_owned(),
            }
        );
        assert_eq!(Said::on(b""), Said::default());
    }
}
