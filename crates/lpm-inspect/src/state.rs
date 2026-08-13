//! Shared state for the inspector server.
//!
//! Wraps the tunnel's `WebhookBuffer` (in-memory ring buffer) and provides
//! a broadcast channel for SSE streaming. The state is shared between the
//! axum handlers via `Arc`.

use crate::db::InspectorDb;
use lpm_tunnel::webhook::CapturedWebhook;
use lpm_tunnel::webhook_buffer::WebhookBuffer;
use lpm_tunnel::ws_capture::WsEvent;
use std::collections::VecDeque;
use std::sync::{Arc, RwLock as SyncRwLock};
use tokio::sync::{RwLock, broadcast};

/// Maximum number of requests held in the in-memory ring buffer.
const DEFAULT_BUFFER_CAPACITY: usize = 1000;
const DEFAULT_BUFFER_BYTES: usize = 64 * 1024 * 1024;

/// Maximum number of WebSocket events held in memory.
const WS_EVENT_CAPACITY: usize = 5000;
const WS_EVENT_BYTE_BUDGET: usize = 32 * 1024 * 1024;

struct WsEventBuffer {
    events: VecDeque<Arc<WsEvent>>,
    retained_bytes: usize,
    dropped_events: u64,
}

impl WsEventBuffer {
    fn new() -> Self {
        Self {
            events: VecDeque::with_capacity(WS_EVENT_CAPACITY),
            retained_bytes: 0,
            dropped_events: 0,
        }
    }

    fn push(&mut self, event: Arc<WsEvent>) -> bool {
        let event_bytes = event.retained_size_bytes();
        if event_bytes > WS_EVENT_BYTE_BUDGET {
            self.dropped_events = self.dropped_events.saturating_add(1);
            return false;
        }
        while self.events.len() >= WS_EVENT_CAPACITY
            || self.retained_bytes.saturating_add(event_bytes) > WS_EVENT_BYTE_BUDGET
        {
            let Some(evicted) = self.events.pop_front() else {
                break;
            };
            self.retained_bytes = self
                .retained_bytes
                .saturating_sub(evicted.retained_size_bytes());
            self.dropped_events = self.dropped_events.saturating_add(1);
        }
        self.retained_bytes += event_bytes;
        self.events.push_back(event);
        true
    }
}

#[cfg(test)]
mod ws_event_buffer_tests {
    use super::*;
    use lpm_tunnel::ws_capture::FrameDirection;

    #[test]
    fn repeated_large_frames_stay_within_the_byte_budget() {
        let payload = vec![b'x'; 1024 * 1024];
        let event = WsEvent::captured_frame(
            "connection".to_string(),
            FrameDirection::Inbound,
            &payload,
            false,
            String::new(),
        );
        let event_bytes = event.retained_size_bytes();
        let mut buffer = WsEventBuffer::new();

        for _ in 0..WS_EVENT_CAPACITY * 2 {
            assert!(buffer.push(Arc::new(event.clone())));
        }

        assert!(buffer.retained_bytes <= WS_EVENT_BYTE_BUDGET);
        assert!(buffer.events.len() <= WS_EVENT_BYTE_BUDGET / event_bytes);
        assert!(buffer.dropped_events > 0);
    }
}

/// Capacity of the SSE broadcast channel.
/// Slow consumers that fall behind this many events will receive a lagged error
/// and must re-fetch via the REST API.
///
/// Set to 512 to handle burst scenarios (e.g., Stripe batch actions sending
/// 150+ webhooks/sec). Events contain compact request summaries instead of
/// request and response bodies.
const SSE_BROADCAST_CAPACITY: usize = 512;

/// Shared inspector state, cheaply cloneable via `Arc`.
#[derive(Clone)]
pub struct InspectorState {
    inner: Arc<Inner>,
}

struct Inner {
    /// In-memory ring buffer of recent requests. Bounded to prevent OOM.
    buffer: RwLock<WebhookBuffer>,
    /// Broadcast channel for real-time SSE streaming to browser clients.
    /// Uses `broadcast` so multiple browser tabs can subscribe independently.
    sse_tx: broadcast::Sender<Arc<crate::api::RequestSummary>>,
    /// SQLite database for persistent storage and full-text search.
    /// `None` only for explicitly in-memory state.
    db: Option<InspectorDb>,
    /// Whether SSE should watch SQLite for captures written by another process.
    observe_database: bool,
    /// WebSocket events ring buffer (bounded, FIFO eviction).
    ws_events: RwLock<WsEventBuffer>,
    /// Broadcast channel for real-time WS event streaming to browser.
    ws_sse_tx: broadcast::Sender<Arc<WsEvent>>,
    /// Active session ID for tagging requests.
    session_id: SyncRwLock<Option<String>>,
    /// The local endpoint being tunneled and replayed.
    local_target: SyncRwLock<lpm_common::LocalTarget>,
    /// The tunnel URL (set after connection).
    pub tunnel_url: RwLock<Option<String>>,
    /// Per-process random auth token gating every `/api/*` route — closes
    /// the same-UID attacker on shared hosts (loopback bind alone is not
    /// enough on CI runners / dev containers).
    auth_token: String,
}

fn generate_auth_token() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let mut hex = String::with_capacity(64);
    for b in bytes {
        hex.push_str(&format!("{b:02x}"));
    }
    hex
}

impl InspectorState {
    /// Create inspector state whose local endpoint is not resolved yet.
    pub fn pending() -> Self {
        Self::new(0)
    }

    /// Create a new inspector state without persistence.
    pub fn new(local_port: u16) -> Self {
        Self::new_for_target(lpm_common::LocalTarget::loopback(
            lpm_common::LocalScheme::Http,
            local_port,
        ))
    }

    /// Create in-memory inspector state for a complete local endpoint.
    pub fn new_for_target(local_target: lpm_common::LocalTarget) -> Self {
        let (sse_tx, _) = broadcast::channel(SSE_BROADCAST_CAPACITY);
        let (ws_sse_tx, _) = broadcast::channel(SSE_BROADCAST_CAPACITY);
        Self {
            inner: Arc::new(Inner {
                buffer: RwLock::new(WebhookBuffer::with_limits(
                    DEFAULT_BUFFER_CAPACITY,
                    DEFAULT_BUFFER_BYTES,
                )),
                sse_tx,
                db: None,
                observe_database: false,
                ws_events: RwLock::new(WsEventBuffer::new()),
                ws_sse_tx,
                session_id: SyncRwLock::new(None),
                local_target: SyncRwLock::new(local_target),
                tunnel_url: RwLock::new(None),
                auth_token: generate_auth_token(),
            }),
        }
    }

    /// Create a new inspector state with SQLite persistence.
    pub fn with_db(local_port: u16, db: InspectorDb) -> Self {
        Self::with_db_for_target(
            lpm_common::LocalTarget::loopback(lpm_common::LocalScheme::Http, local_port),
            db,
        )
    }

    /// Create persistent inspector state whose local endpoint is not resolved yet.
    pub fn with_db_pending(db: InspectorDb) -> Self {
        Self::with_db(0, db)
    }

    /// Create persistent inspector state for a complete local endpoint.
    pub fn with_db_for_target(local_target: lpm_common::LocalTarget, db: InspectorDb) -> Self {
        Self::with_database(local_target, db, false)
    }

    /// Create read-oriented state that observes captures written by another process.
    pub fn with_db_observer(local_port: u16, db: InspectorDb) -> Self {
        Self::with_db_observer_for_target(
            lpm_common::LocalTarget::loopback(lpm_common::LocalScheme::Http, local_port),
            db,
        )
    }

    /// Create read-oriented state for a complete replay endpoint.
    pub fn with_db_observer_for_target(
        local_target: lpm_common::LocalTarget,
        db: InspectorDb,
    ) -> Self {
        Self::with_database(local_target, db, true)
    }

    fn with_database(
        local_target: lpm_common::LocalTarget,
        db: InspectorDb,
        observe_database: bool,
    ) -> Self {
        let (sse_tx, _) = broadcast::channel(SSE_BROADCAST_CAPACITY);
        let (ws_sse_tx, _) = broadcast::channel(SSE_BROADCAST_CAPACITY);
        Self {
            inner: Arc::new(Inner {
                buffer: RwLock::new(WebhookBuffer::with_limits(
                    DEFAULT_BUFFER_CAPACITY,
                    DEFAULT_BUFFER_BYTES,
                )),
                sse_tx,
                db: Some(db),
                observe_database,
                ws_events: RwLock::new(WsEventBuffer::new()),
                ws_sse_tx,
                session_id: SyncRwLock::new(None),
                local_target: SyncRwLock::new(local_target),
                tunnel_url: RwLock::new(None),
                auth_token: generate_auth_token(),
            }),
        }
    }

    /// Per-process auth token required on every `/api/*` request.
    pub fn auth_token(&self) -> &str {
        &self.inner.auth_token
    }

    /// Push a captured request into the buffer, broadcast to SSE, and persist to SQLite.
    pub async fn push(&self, webhook: CapturedWebhook) {
        self.push_shared(Arc::new(webhook)).await;
    }

    /// Push an already shared request without copying its headers and bodies.
    pub async fn push_shared(&self, webhook: Arc<CapturedWebhook>) {
        let session_id = self
            .inner
            .session_id
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();

        // Persist to SQLite (non-blocking — queued for batch write).
        if let Some(ref db) = self.inner.db {
            db.insert_shared_request(Arc::clone(&webhook), session_id.clone());
        }

        // Broadcast to SSE subscribers (best-effort — if no subscribers, this is a no-op).
        // If the channel is full, lagged subscribers will get an error on next recv.
        let _ = self
            .inner
            .sse_tx
            .send(Arc::new(crate::api::RequestSummary::from_live(
                &webhook, session_id,
            )));

        // Store in ring buffer (evicts oldest if at capacity).
        let mut buf = self.inner.buffer.write().await;
        buf.push_shared(webhook);
    }

    /// Get all requests currently in the buffer (oldest first).
    pub async fn get_all(&self) -> Vec<CapturedWebhook> {
        let buf = self.inner.buffer.read().await;
        buf.iter().cloned().collect()
    }

    /// Get a single request by ID.
    pub async fn get_by_id(&self, id: &str) -> Option<CapturedWebhook> {
        let buf = self.inner.buffer.read().await;
        buf.find_by_id(id).cloned()
    }

    /// Get a request from SQLite, falling back only to the pending live buffer.
    pub async fn get_by_id_persisted(
        &self,
        id: &str,
    ) -> Result<Option<CapturedWebhook>, rusqlite::Error> {
        if let Some(ref db) = self.inner.db
            && let Some(webhook) = db.get_webhook(id).await?
        {
            return Ok(Some(webhook));
        }
        Ok(self.get_by_id(id).await)
    }

    /// Get persisted requests newest first, or the live buffer when persistence is disabled.
    pub async fn get_all_persisted(&self) -> Result<Vec<CapturedWebhook>, rusqlite::Error> {
        if let Some(ref db) = self.inner.db {
            return db.list_webhooks(DEFAULT_BUFFER_CAPACITY, 0).await;
        }
        let mut requests = self.get_all().await;
        requests.reverse();
        Ok(requests)
    }

    /// Get the number of requests in the buffer.
    pub async fn count(&self) -> usize {
        let buf = self.inner.buffer.read().await;
        buf.len()
    }

    /// Subscribe to the SSE broadcast channel.
    pub fn subscribe(&self) -> broadcast::Receiver<Arc<crate::api::RequestSummary>> {
        self.inner.sse_tx.subscribe()
    }

    /// Set the tunnel URL after connection is established.
    pub async fn set_tunnel_url(&self, url: String) {
        let mut tunnel_url = self.inner.tunnel_url.write().await;
        *tunnel_url = Some(url);
    }

    /// Get the tunnel URL.
    pub async fn get_tunnel_url(&self) -> Option<String> {
        let tunnel_url = self.inner.tunnel_url.read().await;
        tunnel_url.clone()
    }

    /// Get the local port being tunneled.
    pub fn local_port(&self) -> u16 {
        self.local_target().port
    }

    /// Replace the replay endpoint with a plain IPv4-loopback port.
    pub fn set_local_port(&self, local_port: u16) {
        self.set_local_target(lpm_common::LocalTarget::loopback(
            lpm_common::LocalScheme::Http,
            local_port,
        ));
    }

    /// Return the endpoint currently used for replay.
    pub fn local_target(&self) -> lpm_common::LocalTarget {
        self.inner
            .local_target
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Replace the endpoint used for replay after child discovery completes.
    pub fn set_local_target(&self, local_target: lpm_common::LocalTarget) {
        *self
            .inner
            .local_target
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = local_target;
    }

    /// Push a WebSocket event into the buffer and broadcast to SSE subscribers.
    pub async fn push_ws_event(&self, event: WsEvent) {
        let event = Arc::new(event);
        let mut buf = self.inner.ws_events.write().await;
        if buf.push(Arc::clone(&event)) {
            let _ = self.inner.ws_sse_tx.send(event);
        }
    }

    /// Get all WS events (oldest first).
    pub async fn get_ws_events(&self) -> Vec<WsEvent> {
        let buf = self.inner.ws_events.read().await;
        buf.events.iter().map(|event| (**event).clone()).collect()
    }

    /// Get WS events for a specific connection.
    pub async fn get_ws_connection_events(&self, connection_id: &str) -> Vec<WsEvent> {
        let buf = self.inner.ws_events.read().await;
        buf.events
            .iter()
            .filter(|e| e.connection_id() == connection_id)
            .map(|event| (**event).clone())
            .collect()
    }

    /// Subscribe to the WS SSE broadcast channel.
    pub fn subscribe_ws(&self) -> broadcast::Receiver<Arc<WsEvent>> {
        self.inner.ws_sse_tx.subscribe()
    }

    /// Get a reference to the database (if persistence is enabled).
    pub fn db(&self) -> Option<&InspectorDb> {
        self.inner.db.as_ref()
    }

    /// Whether this state should poll SQLite for writes from another process.
    pub fn observes_database(&self) -> bool {
        self.inner.observe_database
    }

    /// Return the current database revision fingerprint.
    pub async fn database_revision(&self) -> Result<Option<i64>, rusqlite::Error> {
        match self.inner.db.as_ref() {
            Some(db) => db.revision().await.map(Some),
            None => Ok(None),
        }
    }

    /// Wait for all queued persistent writes to commit.
    pub async fn flush(&self) -> Result<(), String> {
        match self.inner.db.as_ref() {
            Some(db) => db.flush_pending_writes().await,
            None => Ok(()),
        }
    }

    /// Start a new tunnel session.
    pub async fn start_session(
        &self,
        id: String,
        domain: Option<String>,
        local_port: u16,
        name: Option<String>,
    ) -> Result<(), rusqlite::Error> {
        self.start_session_immediate(id, domain, local_port, name)
    }

    /// Start a session synchronously before the relay can deliver its first request.
    pub fn start_session_immediate(
        &self,
        id: String,
        domain: Option<String>,
        local_port: u16,
        name: Option<String>,
    ) -> Result<(), rusqlite::Error> {
        if let Some(ref db) = self.inner.db {
            db.start_session_named(id.clone(), domain, local_port, name)?;
        }
        let mut session_id = self
            .inner
            .session_id
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *session_id = Some(id);
        Ok(())
    }

    /// End the current tunnel session.
    pub async fn end_session(&self) -> Result<(), rusqlite::Error> {
        let mut session_id = self
            .inner
            .session_id
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(id) = session_id.take()
            && let Some(ref db) = self.inner.db
        {
            db.end_session(id)?;
        }
        Ok(())
    }
}
