//! Bounded ring buffer for service log lines.

use std::collections::VecDeque;

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
		if self.lines.len() >= self.capacity {
			self.lines.pop_front();
		}
		self.lines.push_back(line);
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
}
