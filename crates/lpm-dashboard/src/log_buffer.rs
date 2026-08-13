//! Bounded ring buffer for service log lines.

use std::collections::VecDeque;

/// A bounded buffer that drops oldest entries when full.
pub struct LogBuffer {
    lines: VecDeque<String>,
    capacity: usize,
    max_bytes: usize,
    retained_bytes: usize,
    dropped_lines: u64,
}

impl LogBuffer {
    pub fn new(capacity: usize) -> Self {
        Self::with_limits(capacity, usize::MAX)
    }

    pub fn with_limits(capacity: usize, max_bytes: usize) -> Self {
        assert!(capacity > 0, "LogBuffer capacity must be > 0");
        assert!(max_bytes > 0, "LogBuffer byte limit must be > 0");
        Self {
            lines: VecDeque::with_capacity(capacity.min(1024)),
            capacity,
            max_bytes,
            retained_bytes: 0,
            dropped_lines: 0,
        }
    }

    pub fn push(&mut self, line: String) {
        let clean = lpm_common::sanitize_terminal_inline(&line).into_owned();
        let line_bytes = clean.capacity();
        if line_bytes > self.max_bytes {
            self.dropped_lines = self.dropped_lines.saturating_add(1);
            return;
        }
        while self.lines.len() >= self.capacity
            || self.retained_bytes.saturating_add(line_bytes) > self.max_bytes
        {
            let Some(evicted) = self.lines.pop_front() else {
                break;
            };
            self.retained_bytes = self.retained_bytes.saturating_sub(evicted.capacity());
            self.dropped_lines = self.dropped_lines.saturating_add(1);
        }
        self.retained_bytes += line_bytes;
        self.lines.push_back(clean);
    }

    pub fn lines(&self) -> impl Iterator<Item = &str> {
        self.lines.iter().map(|s| s.as_str())
    }

    pub fn len(&self) -> usize {
        self.lines.len()
    }

    pub fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }

    pub fn retained_bytes(&self) -> usize {
        self.retained_bytes
    }

    pub fn dropped_lines(&self) -> u64 {
        self.dropped_lines
    }

    /// Get lines starting from `offset` (for scrolling).
    pub fn lines_from(&self, offset: usize) -> impl Iterator<Item = &str> {
        self.lines.iter().skip(offset).map(|s| s.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_and_iterate() {
        let mut buf = LogBuffer::new(5);
        buf.push("line 1".into());
        buf.push("line 2".into());
        buf.push("line 3".into());

        assert_eq!(buf.len(), 3);
        let lines: Vec<&str> = buf.lines().collect();
        assert_eq!(lines, vec!["line 1", "line 2", "line 3"]);
    }

    #[test]
    fn overflow_drops_oldest() {
        let mut buf = LogBuffer::new(3);
        buf.push("a".into());
        buf.push("b".into());
        buf.push("c".into());
        buf.push("d".into()); // should drop "a"

        assert_eq!(buf.len(), 3);
        let lines: Vec<&str> = buf.lines().collect();
        assert_eq!(lines, vec!["b", "c", "d"]);
    }

    #[test]
    fn scroll_with_offset() {
        let mut buf = LogBuffer::new(10);
        for i in 0..5 {
            buf.push(format!("line {i}"));
        }

        let from_2: Vec<&str> = buf.lines_from(2).collect();
        assert_eq!(from_2, vec!["line 2", "line 3", "line 4"]);
    }

    #[test]
    fn empty_buffer() {
        let buf = LogBuffer::new(10);
        assert!(buf.is_empty());
        assert_eq!(buf.len(), 0);
        assert_eq!(buf.lines().count(), 0);
    }

    #[test]
    #[should_panic(expected = "LogBuffer capacity must be > 0")]
    fn zero_capacity_is_rejected() {
        LogBuffer::with_limits(0, 1024);
    }

    #[test]
    #[should_panic(expected = "LogBuffer byte limit must be > 0")]
    fn zero_byte_limit_is_rejected() {
        LogBuffer::with_limits(10, 0);
    }

    #[test]
    fn shared_policy_removes_csi_sequences() {
        assert_eq!(
            lpm_common::sanitize_terminal_inline("\x1b[31mred\x1b[0m"),
            "red"
        );
    }

    #[test]
    fn shared_policy_preserves_normal_text() {
        assert_eq!(
            lpm_common::sanitize_terminal_inline("normal text"),
            "normal text"
        );
    }

    #[test]
    fn shared_policy_removes_osc_sequences() {
        assert_eq!(
            lpm_common::sanitize_terminal_inline("\x1b]0;evil title\x07visible"),
            "visible"
        );
    }

    #[test]
    fn shared_policy_removes_osc_with_st_terminator() {
        assert_eq!(
            lpm_common::sanitize_terminal_inline("\x1b]0;title\x1b\\visible"),
            "visible"
        );
    }

    #[test]
    fn shared_inline_policy_neutralizes_control_chars_and_tabs() {
        assert_eq!(
            lpm_common::sanitize_terminal_inline("hello\x01\tworld"),
            "hello??world"
        );
    }

    #[test]
    fn push_strips_ansi_from_stored_lines() {
        let mut buf = LogBuffer::new(10);
        buf.push("\x1b[31mred text\x1b[0m".into());
        let lines: Vec<&str> = buf.lines().collect();
        assert_eq!(lines, vec!["red text"]);
    }

    #[test]
    fn push_removes_terminal_string_controls_with_shared_policy() {
        let mut buf = LogBuffer::new(10);
        buf.push("safe\x1bP1;2|dcs payload\x1b\\ tail\u{009d}0;title\u{009c} end".into());

        let lines: Vec<&str> = buf.lines().collect();
        assert_eq!(lines, vec!["safe tail end"]);
    }

    #[test]
    fn byte_limit_evicts_oldest_lines() {
        let mut buf = LogBuffer::with_limits(10, 6);
        buf.push("abc".into());
        buf.push("def".into());
        buf.push("ghi".into());

        assert_eq!(buf.lines().collect::<Vec<_>>(), vec!["def", "ghi"]);
        assert!(buf.retained_bytes() <= 6);
        assert_eq!(buf.dropped_lines(), 1);
    }

    #[test]
    fn noisy_service_output_stays_within_the_byte_budget() {
        let line = "x".repeat(8 * 1024);
        let byte_limit = 64 * 1024;
        let mut buf = LogBuffer::with_limits(1_000, byte_limit);

        for _ in 0..1_000 {
            buf.push(line.clone());
        }

        assert!(buf.retained_bytes() <= byte_limit);
        assert_eq!(buf.len(), byte_limit / line.len());
        assert_eq!(buf.dropped_lines(), 1_000 - buf.len() as u64);
    }
}
