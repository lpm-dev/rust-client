//! The entry and filter types `lpm tunnel log` prints and selects captured
//! requests with.

use serde::{Deserialize, Serialize};

/// One captured request, without its bodies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookLogEntry {
    pub id: String,
    pub ts: String,
    pub method: String,
    pub path: String,
    pub status: u16,
    pub ms: u64,
    pub provider: Option<String>,
    pub summary: String,
    pub req_size: usize,
    pub res_size: usize,
}

/// Which captured requests to list.
pub struct WebhookFilter {
    /// Filter by provider name (case-insensitive).
    pub provider: Option<String>,
    /// Filter by response status.
    pub status: Option<StatusFilter>,
}

/// Status code filter variants.
pub enum StatusFilter {
    /// Exact status code match (e.g., 200).
    Exact(u16),
    /// Inclusive range (e.g., 400..=499).
    Range(u16, u16),
    /// Status class: 2 = 2xx, 4 = 4xx, 5 = 5xx.
    Class(u16),
}
