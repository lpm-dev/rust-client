//! In-memory ring buffer for recently captured webhooks.
//!
//! Provides O(1) push with automatic eviction of the oldest entry when
//! capacity is reached. Used by the inspector UI and dashboard to display
//! recent webhook traffic without hitting disk.

use crate::webhook::CapturedWebhook;
use std::collections::VecDeque;
use std::sync::Arc;

/// Fixed-capacity ring buffer of captured webhooks.
///
/// When full, `push` drops the oldest entry before inserting the new one.
/// Iteration order is oldest-to-newest (front-to-back of the deque).
pub struct WebhookBuffer {
    webhooks: VecDeque<Arc<CapturedWebhook>>,
    capacity: usize,
    max_bytes: usize,
    retained_bytes: usize,
    dropped_events: u64,
}

impl WebhookBuffer {
    /// Create a new buffer with the given maximum capacity.
    ///
    /// # Panics
    /// Panics if `capacity` is 0.
    pub fn new(capacity: usize) -> Self {
        Self::with_limits(capacity, usize::MAX)
    }

    /// Create a buffer bounded by both entry count and estimated retained bytes.
    pub fn with_limits(capacity: usize, max_bytes: usize) -> Self {
        assert!(capacity > 0, "WebhookBuffer capacity must be > 0");
        assert!(max_bytes > 0, "WebhookBuffer byte limit must be > 0");
        Self {
            webhooks: VecDeque::with_capacity(capacity),
            capacity,
            max_bytes,
            retained_bytes: 0,
            dropped_events: 0,
        }
    }

    /// Push a webhook into the buffer, evicting the oldest if at capacity.
    pub fn push(&mut self, webhook: CapturedWebhook) {
        self.push_shared(Arc::new(webhook));
    }

    /// Push a shared webhook without copying its headers and bodies.
    pub fn push_shared(&mut self, webhook: Arc<CapturedWebhook>) {
        let webhook_bytes = retained_size_bytes(&webhook);
        if webhook_bytes > self.max_bytes {
            self.dropped_events = self.dropped_events.saturating_add(1);
            return;
        }
        while self.webhooks.len() >= self.capacity
            || self.retained_bytes.saturating_add(webhook_bytes) > self.max_bytes
        {
            let Some(evicted) = self.webhooks.pop_front() else {
                break;
            };
            self.retained_bytes = self
                .retained_bytes
                .saturating_sub(retained_size_bytes(&evicted));
            self.dropped_events = self.dropped_events.saturating_add(1);
        }
        self.retained_bytes += webhook_bytes;
        self.webhooks.push_back(webhook);
    }

    /// Iterate over webhooks from oldest to newest.
    pub fn iter(&self) -> impl Iterator<Item = &CapturedWebhook> {
        self.webhooks.iter().map(AsRef::as_ref)
    }

    /// Get a webhook by index (0 = oldest).
    pub fn get(&self, index: usize) -> Option<&CapturedWebhook> {
        self.webhooks.get(index).map(AsRef::as_ref)
    }

    /// Get the most recently pushed webhook.
    pub fn last(&self) -> Option<&CapturedWebhook> {
        self.webhooks.back().map(AsRef::as_ref)
    }

    /// Find a webhook by its unique ID.
    ///
    /// Searches from newest to oldest (most likely lookup pattern) for
    /// better average-case performance.
    pub fn find_by_id(&self, id: &str) -> Option<&CapturedWebhook> {
        self.webhooks
            .iter()
            .rev()
            .map(AsRef::as_ref)
            .find(|webhook| webhook.id == id)
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
        self.retained_bytes = 0;
    }

    /// Estimated bytes retained by webhook-owned strings, headers, and bodies.
    pub fn retained_bytes(&self) -> usize {
        self.retained_bytes
    }

    /// Number of incoming or previously retained events dropped by the limits.
    pub fn dropped_events(&self) -> u64 {
        self.dropped_events
    }
}

fn retained_size_bytes(webhook: &CapturedWebhook) -> usize {
    webhook.retained_size_bytes()
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
            auto_acked: false,
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

    #[test]
    fn byte_limit_evicts_oldest_large_webhooks() {
        let mut first = make_webhook("a");
        first.request_body = vec![0; 5];
        let mut second = make_webhook("b");
        second.request_body = vec![0; 5];
        let byte_limit = retained_size_bytes(&first);
        let mut buf = WebhookBuffer::with_limits(10, byte_limit);

        buf.push(first);
        buf.push(second);

        assert_eq!(buf.len(), 1);
        assert_eq!(buf.last().map(|webhook| webhook.id.as_str()), Some("b"));
        assert!(buf.retained_bytes() <= byte_limit);
        assert_eq!(buf.dropped_events(), 1);
    }

    #[test]
    fn byte_limit_does_not_retain_an_oversized_webhook() {
        let mut webhook = make_webhook("too-large");
        webhook.request_body = vec![0; 32];
        let byte_limit = retained_size_bytes(&webhook) - 1;
        let mut buf = WebhookBuffer::with_limits(10, byte_limit);

        buf.push(webhook);

        assert!(buf.is_empty());
        assert_eq!(buf.retained_bytes(), 0);
        assert_eq!(buf.dropped_events(), 1);
    }

    #[test]
    fn repeated_large_webhooks_stay_within_the_byte_budget() {
        let mut webhook = make_webhook("large");
        webhook.request_body = vec![0; 1024 * 1024];
        let one_capture_bytes = retained_size_bytes(&webhook);
        let byte_limit = one_capture_bytes * 3;
        let mut buf = WebhookBuffer::with_limits(100, byte_limit);

        for index in 0..100 {
            let mut next = webhook.clone();
            next.id = index.to_string();
            buf.push(next);
        }

        assert!(buf.retained_bytes() <= byte_limit);
        assert!(buf.len() <= 3);
        assert_eq!(buf.dropped_events(), 100 - buf.len() as u64);
    }

    #[test]
    fn shared_webhook_push_does_not_copy_large_bodies() {
        let mut webhook = make_webhook("shared");
        webhook.request_body = vec![0; 1024 * 1024];
        let webhook = Arc::new(webhook);
        let mut buf = WebhookBuffer::with_limits(10, 2 * 1024 * 1024);

        buf.push_shared(Arc::clone(&webhook));

        assert_eq!(Arc::strong_count(&webhook), 2);
        assert_eq!(
            buf.last().unwrap().request_body.as_ptr(),
            webhook.request_body.as_ptr()
        );
    }
}
