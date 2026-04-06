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
use std::sync::Arc;
use tokio::sync::{RwLock, broadcast};

/// Maximum number of requests held in the in-memory ring buffer.
const DEFAULT_BUFFER_CAPACITY: usize = 1000;

/// Maximum number of WebSocket events held in memory.
const WS_EVENT_CAPACITY: usize = 5000;

/// Capacity of the SSE broadcast channel.
/// Slow consumers that fall behind this many events will receive a lagged error
/// and must re-fetch via the REST API.
///
/// Set to 512 to handle burst scenarios (e.g., Stripe batch actions sending
/// 150+ webhooks/sec). Since events use `Arc<CapturedWebhook>`, each slot
/// costs only a pointer — the memory overhead of a larger buffer is negligible.
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
    sse_tx: broadcast::Sender<Arc<CapturedWebhook>>,
    /// SQLite database for persistent storage and full-text search.
    /// `None` when running without persistence (e.g., `inspect --ui` with no project dir).
    db: Option<InspectorDb>,
    /// WebSocket events ring buffer (bounded, FIFO eviction).
    ws_events: RwLock<VecDeque<WsEvent>>,
    /// Broadcast channel for real-time WS event streaming to browser.
    ws_sse_tx: broadcast::Sender<Arc<WsEvent>>,
    /// Active session ID for tagging requests.
    session_id: RwLock<Option<String>>,
    /// The local port being tunneled (for display purposes).
    pub local_port: u16,
    /// The tunnel URL (set after connection).
    pub tunnel_url: RwLock<Option<String>>,
}

impl InspectorState {
    /// Create a new inspector state without persistence.
    pub fn new(local_port: u16) -> Self {
        let (sse_tx, _) = broadcast::channel(SSE_BROADCAST_CAPACITY);
        let (ws_sse_tx, _) = broadcast::channel(SSE_BROADCAST_CAPACITY);
        Self {
            inner: Arc::new(Inner {
                buffer: RwLock::new(WebhookBuffer::new(DEFAULT_BUFFER_CAPACITY)),
                sse_tx,
                db: None,
                ws_events: RwLock::new(VecDeque::with_capacity(WS_EVENT_CAPACITY)),
                ws_sse_tx,
                session_id: RwLock::new(None),
                local_port,
                tunnel_url: RwLock::new(None),
            }),
        }
    }

    /// Create a new inspector state with SQLite persistence.
    pub fn with_db(local_port: u16, db: InspectorDb) -> Self {
        let (sse_tx, _) = broadcast::channel(SSE_BROADCAST_CAPACITY);
        let (ws_sse_tx, _) = broadcast::channel(SSE_BROADCAST_CAPACITY);
        Self {
            inner: Arc::new(Inner {
                buffer: RwLock::new(WebhookBuffer::new(DEFAULT_BUFFER_CAPACITY)),
                sse_tx,
                db: Some(db),
                ws_events: RwLock::new(VecDeque::with_capacity(WS_EVENT_CAPACITY)),
                ws_sse_tx,
                session_id: RwLock::new(None),
                local_port,
                tunnel_url: RwLock::new(None),
            }),
        }
    }

    /// Push a captured request into the buffer, broadcast to SSE, and persist to SQLite.
    pub async fn push(&self, webhook: CapturedWebhook) {
        let webhook = Arc::new(webhook);

        // Broadcast to SSE subscribers (best-effort — if no subscribers, this is a no-op).
        // If the channel is full, lagged subscribers will get an error on next recv.
        let _ = self.inner.sse_tx.send(Arc::clone(&webhook));

        // Persist to SQLite (non-blocking — queued for batch write)
        if let Some(ref db) = self.inner.db {
            let session_id = self.inner.session_id.read().await.clone();
            db.insert_request(CapturedWebhook::clone(&webhook), session_id);
        }

        // Store in ring buffer (evicts oldest if at capacity).
        let mut buf = self.inner.buffer.write().await;
        buf.push(CapturedWebhook::clone(&webhook));
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

    /// Get the number of requests in the buffer.
    pub async fn count(&self) -> usize {
        let buf = self.inner.buffer.read().await;
        buf.len()
    }

    /// Subscribe to the SSE broadcast channel.
    pub fn subscribe(&self) -> broadcast::Receiver<Arc<CapturedWebhook>> {
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
        self.inner.local_port
    }

    /// Push a WebSocket event into the buffer and broadcast to SSE subscribers.
    pub async fn push_ws_event(&self, event: WsEvent) {
        let event = Arc::new(event);
        let _ = self.inner.ws_sse_tx.send(Arc::clone(&event));

        let mut buf = self.inner.ws_events.write().await;
        if buf.len() >= WS_EVENT_CAPACITY {
            buf.pop_front();
        }
        buf.push_back(WsEvent::clone(&event));
    }

    /// Get all WS events (oldest first).
    pub async fn get_ws_events(&self) -> Vec<WsEvent> {
        let buf = self.inner.ws_events.read().await;
        buf.iter().cloned().collect()
    }

    /// Get WS events for a specific connection.
    pub async fn get_ws_connection_events(&self, connection_id: &str) -> Vec<WsEvent> {
        let buf = self.inner.ws_events.read().await;
        buf.iter()
            .filter(|e| e.connection_id() == connection_id)
            .cloned()
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

    /// Start a new tunnel session.
    pub async fn start_session(
        &self,
        id: String,
        domain: Option<String>,
        local_port: u16,
        name: Option<String>,
    ) {
        if let Some(ref db) = self.inner.db {
            db.start_session(id.clone(), domain, local_port);
            // Apply the session name if provided
            if let Some(ref name) = name {
                let _ = db.rename_session(&id, name).await;
            }
        }
        let mut session_id = self.inner.session_id.write().await;
        *session_id = Some(id);
    }

    /// End the current tunnel session.
    pub async fn end_session(&self) {
        let mut session_id = self.inner.session_id.write().await;
        if let Some(id) = session_id.take()
            && let Some(ref db) = self.inner.db
        {
            db.end_session(id);
        }
    }
}
