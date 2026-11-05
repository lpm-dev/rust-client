//! Buffers for bytes that may hold values: wiped when dropped, and moved
//! to a larger block, wiping the old, when they outgrow theirs, so no freed
//! block keeps a copy.

use zeroize::Zeroizing;

/// A growable buffer that wipes every block it leaves.
pub(crate) struct WipingBuffer(Zeroizing<Vec<u8>>);

impl WipingBuffer {
    pub(crate) fn with_capacity(capacity: usize) -> Self {
        Self(Zeroizing::new(Vec::with_capacity(capacity)))
    }

    /// The bytes, moved out without a copy.
    pub(crate) fn into_bytes(mut self) -> Vec<u8> {
        std::mem::take(&mut *self.0)
    }
}

impl std::io::Write for WipingBuffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let needed = self.0.len() + bytes.len();
        if needed > self.0.capacity() {
            let mut grown = Zeroizing::new(Vec::with_capacity(
                needed.max(self.0.capacity().saturating_mul(2)),
            ));
            grown.extend_from_slice(&self.0);
            self.0 = grown;
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// `value` as one line of JSON, in a buffer wiped when dropped, for output
/// that may hold values, such as local history's revealed values. Writing
/// it to stdout in one call passes the line straight through stdout's line
/// buffer, so no other copy is left.
pub fn json_line(value: &impl serde::Serialize) -> Result<Zeroizing<Vec<u8>>, serde_json::Error> {
    let mut line = WipingBuffer::with_capacity(4 * 1024);
    serde_json::to_writer(&mut line, value)?;
    std::io::Write::write_all(&mut line, b"\n").expect("a memory buffer takes every byte");
    Ok(Zeroizing::new(line.into_bytes()))
}

#[cfg(all(test, not(miri)))]
mod tests {
    use super::*;
    use crate::freed_memory_probe::{MARKER, watch};

    #[test]
    fn a_json_line_leaves_no_copy_of_what_it_holds() {
        // Larger than the first block, so the line outgrows it.
        let value = serde_json::json!({ "values": [MARKER.repeat(400)] });
        let (line, found) = watch(|| json_line(&value).expect("serializes"));
        assert!(!found, "no block the line outgrew keeps a copy");
        assert!(line.ends_with(b"\n"));
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&line).expect("JSON"),
            value
        );
        let ((), found) = watch(move || drop(line));
        assert!(!found, "the line is wiped when dropped");
    }
}
