//! Bounded ring buffer for service log lines.

use std::collections::VecDeque;

/// Strip ANSI escape sequences and dangerous control characters from a string.
///
/// Removes CSI (`ESC[...letter`), OSC (`ESC]...BEL/ST`), and raw control characters
/// (except tab) to prevent terminal escape injection from malicious process output.
fn strip_ansi(s: &str) -> String {
	let mut result = String::with_capacity(s.len());
	let mut chars = s.chars().peekable();
	while let Some(c) = chars.next() {
		if c == '\x1b' {
			// ESC sequence
			match chars.peek() {
				Some('[') => {
					// CSI: skip until ASCII letter
					chars.next();
					while let Some(&ch) = chars.peek() {
						chars.next();
						if ch.is_ascii_alphabetic() {
							break;
						}
					}
				}
				Some(']') => {
					// OSC: skip until BEL (\x07) or ST (ESC \)
					chars.next();
					while let Some(&ch) = chars.peek() {
						chars.next();
						if ch == '\x07' {
							break;
						}
						if ch == '\x1b' {
							if chars.peek() == Some(&'\\') {
								chars.next();
								break;
							}
						}
					}
				}
				_ => {
					// Unknown ESC sequence, skip the next char too
					chars.next();
				}
			}
		} else if c.is_control() && c != '\t' {
			// Skip control chars except tab
			continue;
		} else {
			result.push(c);
		}
	}
	result
}

/// A bounded buffer that drops oldest entries when full.
pub struct LogBuffer {
	lines: VecDeque<String>,
	capacity: usize,
}

impl LogBuffer {
	pub fn new(capacity: usize) -> Self {
		Self {
			lines: VecDeque::with_capacity(capacity.min(1024)),
			capacity,
		}
	}

	pub fn push(&mut self, line: String) {
		let clean = strip_ansi(&line);
		if self.lines.len() >= self.capacity {
			self.lines.pop_front();
		}
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
	fn strip_ansi_removes_csi_sequences() {
		assert_eq!(strip_ansi("\x1b[31mred\x1b[0m"), "red");
	}

	#[test]
	fn strip_ansi_preserves_normal_text() {
		assert_eq!(strip_ansi("normal text"), "normal text");
	}

	#[test]
	fn strip_ansi_removes_osc_sequences() {
		assert_eq!(strip_ansi("\x1b]0;evil title\x07visible"), "visible");
	}

	#[test]
	fn strip_ansi_removes_osc_with_st_terminator() {
		assert_eq!(strip_ansi("\x1b]0;title\x1b\\visible"), "visible");
	}

	#[test]
	fn strip_ansi_removes_control_chars() {
		// \x01 (SOH) should be stripped, but \t should be kept
		assert_eq!(strip_ansi("hello\x01\tworld"), "hello\tworld");
	}

	#[test]
	fn push_strips_ansi_from_stored_lines() {
		let mut buf = LogBuffer::new(10);
		buf.push("\x1b[31mred text\x1b[0m".into());
		let lines: Vec<&str> = buf.lines().collect();
		assert_eq!(lines, vec!["red text"]);
	}
}
