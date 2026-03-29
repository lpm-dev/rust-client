//! In-memory ring buffer for recently captured webhooks.
//!
//! Provides O(1) push with automatic eviction of the oldest entry when
//! capacity is reached. Used by the inspector UI and dashboard to display
//! recent webhook traffic without hitting disk.

use crate::webhook::CapturedWebhook;
use std::collections::VecDeque;

/// Fixed-capacity ring buffer of captured webhooks.
///
/// When full, `push` drops the oldest entry before inserting the new one.
/// Iteration order is oldest-to-newest (front-to-back of the deque).
pub struct WebhookBuffer {
	webhooks: VecDeque<CapturedWebhook>,
	capacity: usize,
}

impl WebhookBuffer {
	/// Create a new buffer with the given maximum capacity.
	///
	/// # Panics
	/// Panics if `capacity` is 0.
	pub fn new(capacity: usize) -> Self {
		assert!(capacity > 0, "WebhookBuffer capacity must be > 0");
		Self {
			webhooks: VecDeque::with_capacity(capacity),
			capacity,
		}
	}

	/// Push a webhook into the buffer, evicting the oldest if at capacity.
	pub fn push(&mut self, webhook: CapturedWebhook) {
		if self.webhooks.len() == self.capacity {
			self.webhooks.pop_front();
		}
		self.webhooks.push_back(webhook);
	}

	/// Iterate over webhooks from oldest to newest.
	pub fn iter(&self) -> impl Iterator<Item = &CapturedWebhook> {
		self.webhooks.iter()
	}

	/// Get a webhook by index (0 = oldest).
	pub fn get(&self, index: usize) -> Option<&CapturedWebhook> {
		self.webhooks.get(index)
	}

	/// Get the most recently pushed webhook.
	pub fn last(&self) -> Option<&CapturedWebhook> {
		self.webhooks.back()
	}

	/// Find a webhook by its unique ID.
	///
	/// Searches from newest to oldest (most likely lookup pattern) for
	/// better average-case performance.
	pub fn find_by_id(&self, id: &str) -> Option<&CapturedWebhook> {
		self.webhooks.iter().rev().find(|w| w.id == id)
	}

	/// Number of webhooks currently in the buffer.
	pub fn len(&self) -> usize {
		self.webhooks.len()
	}

	/// Whether the buffer is empty.
	pub fn is_empty(&self) -> bool {
		self.webhooks.is_empty()
	}

	/// Remove all webhooks from the buffer.
	pub fn clear(&mut self) {
		self.webhooks.clear();
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::collections::HashMap;

	fn make_webhook(id: &str) -> CapturedWebhook {
		CapturedWebhook {
			id: id.to_string(),
			timestamp: "2026-01-01T00:00:00Z".to_string(),
			method: "POST".to_string(),
			path: "/webhook".to_string(),
			request_headers: HashMap::new(),
			request_body: Vec::new(),
			response_status: 200,
			response_headers: HashMap::new(),
			response_body: Vec::new(),
			duration_ms: 10,
			provider: None,
			summary: String::new(),
			signature_diagnostic: None,
		}
	}

	#[test]
	fn push_and_retrieve() {
		let mut buf = WebhookBuffer::new(10);
		buf.push(make_webhook("a"));
		buf.push(make_webhook("b"));

		assert_eq!(buf.len(), 2);
		assert_eq!(buf.get(0).unwrap().id, "a");
		assert_eq!(buf.get(1).unwrap().id, "b");
		assert_eq!(buf.last().unwrap().id, "b");
	}

	#[test]
	fn capacity_overflow_evicts_oldest() {
		let mut buf = WebhookBuffer::new(3);
		buf.push(make_webhook("a"));
		buf.push(make_webhook("b"));
		buf.push(make_webhook("c"));
		assert_eq!(buf.len(), 3);

		buf.push(make_webhook("d"));
		assert_eq!(buf.len(), 3);

		// "a" should have been evicted
		assert!(buf.find_by_id("a").is_none());
		assert_eq!(buf.get(0).unwrap().id, "b");
		assert_eq!(buf.get(1).unwrap().id, "c");
		assert_eq!(buf.get(2).unwrap().id, "d");
	}

	#[test]
	fn iteration_order_oldest_to_newest() {
		let mut buf = WebhookBuffer::new(5);
		buf.push(make_webhook("1"));
		buf.push(make_webhook("2"));
		buf.push(make_webhook("3"));

		let ids: Vec<&str> = buf.iter().map(|w| w.id.as_str()).collect();
		assert_eq!(ids, vec!["1", "2", "3"]);
	}

	#[test]
	fn find_by_id_returns_correct_webhook() {
		let mut buf = WebhookBuffer::new(10);
		buf.push(make_webhook("x"));
		buf.push(make_webhook("y"));
		buf.push(make_webhook("z"));

		assert_eq!(buf.find_by_id("y").unwrap().id, "y");
		assert!(buf.find_by_id("nonexistent").is_none());
	}

	#[test]
	fn clear_empties_buffer() {
		let mut buf = WebhookBuffer::new(10);
		buf.push(make_webhook("a"));
		buf.push(make_webhook("b"));
		assert_eq!(buf.len(), 2);

		buf.clear();
		assert!(buf.is_empty());
		assert_eq!(buf.len(), 0);
		assert!(buf.last().is_none());
	}

	#[test]
	fn empty_buffer() {
		let buf = WebhookBuffer::new(5);
		assert!(buf.is_empty());
		assert_eq!(buf.len(), 0);
		assert!(buf.last().is_none());
		assert!(buf.get(0).is_none());
		assert!(buf.find_by_id("any").is_none());
	}

	#[test]
	#[should_panic(expected = "capacity must be > 0")]
	fn zero_capacity_panics() {
		WebhookBuffer::new(0);
	}

	#[test]
	fn capacity_one_always_has_latest() {
		let mut buf = WebhookBuffer::new(1);
		buf.push(make_webhook("a"));
		buf.push(make_webhook("b"));
		buf.push(make_webhook("c"));

		assert_eq!(buf.len(), 1);
		assert_eq!(buf.last().unwrap().id, "c");
	}
}
