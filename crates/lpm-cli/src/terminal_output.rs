use std::fmt;

use tracing_subscriber::field::RecordFields;
use tracing_subscriber::fmt::format::{DefaultFields, FormatFields, Writer};

#[derive(Default)]
pub(crate) struct SanitizedTracingFields {
    inner: DefaultFields,
}

impl<'writer> FormatFields<'writer> for SanitizedTracingFields {
    fn format_fields<R: RecordFields>(
        &self,
        mut writer: Writer<'writer>,
        fields: R,
    ) -> fmt::Result {
        let mut rendered = String::new();
        self.inner
            .format_fields(Writer::new(&mut rendered), fields)?;
        writer.write_str(&lpm_common::sanitize_terminal_inline(&rendered))
    }
}

#[cfg(test)]
mod tests {
    use std::io::{self, Write};
    use std::sync::{Arc, Mutex};

    use tracing_subscriber::fmt::MakeWriter;

    use super::SanitizedTracingFields;

    #[derive(Clone, Default)]
    struct SharedBuffer(Arc<Mutex<Vec<u8>>>);

    impl Write for SharedBuffer {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().expect("trace buffer poisoned").extend(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'writer> MakeWriter<'writer> for SharedBuffer {
        type Writer = SharedBuffer;

        fn make_writer(&'writer self) -> Self::Writer {
            self.clone()
        }
    }

    #[test]
    fn tracing_fields_cannot_inject_terminal_controls() {
        let output = SharedBuffer::default();
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_target(false)
            .with_level(false)
            .with_ansi(false)
            .fmt_fields(SanitizedTracingFields::default())
            .with_writer(output.clone())
            .finish();
        let malicious =
            "safe\nforged\rrewritten\u{8}\u{1b}[2J\u{1b}]52;c;AAAA\u{7}\u{0090}hidden\u{009c}end";

        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(registry_message = %malicious, "request failed");
        });

        let rendered = String::from_utf8(output.0.lock().expect("trace buffer poisoned").clone())
            .expect("trace output must be UTF-8");
        assert!(
            rendered.contains("safe?forged?rewritten?end"),
            "{rendered:?}"
        );
        for attacker_fragment in [
            "\u{1b}", "\u{7}", "\u{8}", "\r", "\u{0090}", "\u{009c}", "hidden",
        ] {
            assert!(
                !rendered.contains(attacker_fragment),
                "trace output retained {attacker_fragment:?}: {rendered:?}"
            );
        }
    }
}
