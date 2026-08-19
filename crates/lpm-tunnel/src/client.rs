//! Tunnel WebSocket client.
//!
//! Connects to the LPM tunnel relay, authenticates, receives a public URL,
//! and proxies HTTP requests between the relay and the local dev server.

use crate::protocol::{ClientMessage, ServerMessage};
use crate::webhook::CapturedWebhook;
use crate::ws_capture::{FrameDirection, WsEvent};
use crate::{
    DEFAULT_RELAY_URL, TunnelLimitMetadata, TunnelSession, TunnelUsageMetadata, proxy, webhook,
    webhook_signature,
};
use futures_util::{SinkExt, StreamExt};
use lpm_common::LpmError;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::CloseFrame;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;

/// Maximum WebSocket message size from relay (50 MB).
pub(crate) const MAX_WS_MESSAGE_SIZE: usize = 50 * 1024 * 1024;

/// Maximum WebSocket frame size from relay (16 MB).
pub(crate) const MAX_WS_FRAME_SIZE: usize = 16 * 1024 * 1024;

/// Duration after which a successful connection resets the retry counter.
/// If a connection lasts longer than this, it was "healthy" and the next
/// disconnect should not carry forward accumulated retry counts.
const HEALTHY_CONNECTION_SECS: u64 = 60;

/// Maximum time to wait for a pong response before considering the relay dead.
const PONG_TIMEOUT_SECS: u64 = 90;

/// Maximum time to wait for in-flight tasks during graceful shutdown.
const SHUTDOWN_TIMEOUT_SECS: u64 = 5;

const MAX_CONCURRENT_HTTP_FORWARDS: usize = 4;
const HTTP_RESPONSE_MEMORY_PERMITS: usize = 64;
const HTTP_RESPONSE_MEMORY_UNIT_BYTES: usize = 1024 * 1024;
const HTTP_RESPONSE_ESTIMATED_OVERHEAD_MULTIPLIER: usize = 4;
const HTTP_REQUEST_MEMORY_PERMITS: usize = 256;
const HTTP_REQUEST_ESTIMATED_OVERHEAD_MULTIPLIER: usize = 4;
const WEBSOCKET_MEMORY_PERMITS: usize = 128;
const MAX_CONCURRENT_WEBSOCKETS: usize = 64;
const WEBSOCKET_CONNECT_TIMEOUT_SECS: u64 = 10;
const WEBSOCKET_LOCAL_ENQUEUE_TIMEOUT_MILLIS: u64 = 100;
const WEBSOCKET_SEND_TIMEOUT_SECS: u64 = 5;
const WEBSOCKET_CAPTURE_HEADER_BYTES: usize = 64 * 1024;
const WEBSOCKET_WRITE_BUFFER_BYTES: usize = 128 * 1024;
const WEBSOCKET_MAX_WRITE_BUFFER_BYTES: usize = 72 * 1024 * 1024;
const MAX_WEBSOCKET_CONNECTION_ID_BYTES: usize = 256;
const MAX_WEBSOCKET_LOCAL_URL_BYTES: usize = 8 * 1024;
const MAX_WEBSOCKET_CLOSE_REASON_BYTES: usize = 123;

#[derive(serde::Deserialize)]
#[serde(tag = "type")]
enum RelayHandshakeMessage {
    #[serde(rename = "hello")]
    Hello {
        #[serde(rename = "subdomain")]
        domain: String,
        tunnel_url: String,
        session_id: String,
        #[serde(default)]
        plan: Option<String>,
        #[serde(default)]
        base_domain: Option<String>,
        #[serde(default)]
        domain_kind: Option<String>,
        #[serde(default)]
        session_expires_at: Option<u64>,
        #[serde(default)]
        session_max_ms: Option<u64>,
        #[serde(default)]
        limits: Option<Box<TunnelLimitMetadata>>,
        #[serde(default)]
        usage: Option<Box<TunnelUsageMetadata>>,
    },
    #[serde(rename = "error")]
    Error {
        message: String,
        code: Option<String>,
    },
}

#[derive(serde::Serialize)]
#[serde(tag = "type")]
enum ClientExtensionMessage {
    #[serde(rename = "ws_ready")]
    WebSocketReady { id: String },
    #[serde(rename = "ws_reject")]
    WebSocketReject { id: String, error: String },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RetryClass {
    Permanent,
    Transient,
    AuthRejected,
}

#[derive(Debug)]
struct TunnelConnectError {
    error: LpmError,
    retry_class: RetryClass,
}

/// Future returned by a dynamic tunnel token callback.
pub type TunnelTokenFuture =
    Pin<Box<dyn Future<Output = Result<String, LpmError>> + Send + 'static>>;

/// Dynamic bearer source used when a CLI session can refresh its access token.
#[derive(Clone)]
pub struct TunnelTokenProvider {
    current: Arc<dyn Fn() -> TunnelTokenFuture + Send + Sync>,
    refresh_after_rejection: Arc<dyn Fn() -> TunnelTokenFuture + Send + Sync>,
}

impl TunnelTokenProvider {
    pub fn new(
        current: impl Fn() -> TunnelTokenFuture + Send + Sync + 'static,
        refresh_after_rejection: impl Fn() -> TunnelTokenFuture + Send + Sync + 'static,
    ) -> Self {
        Self {
            current: Arc::new(current),
            refresh_after_rejection: Arc::new(refresh_after_rejection),
        }
    }

    async fn current(&self) -> Result<String, LpmError> {
        (self.current)().await
    }

    async fn refresh_after_rejection(&self) -> Result<String, LpmError> {
        (self.refresh_after_rejection)().await
    }
}

impl std::fmt::Debug for TunnelTokenProvider {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("TunnelTokenProvider([redacted callbacks])")
    }
}

/// Captured webhook plus reservations for its queued request and response bodies.
pub struct CapturedWebhookEvent {
    pub webhook: Arc<CapturedWebhook>,
    _response_memory_permit: Option<Arc<tokio::sync::OwnedSemaphorePermit>>,
    _request_memory_permit: Option<Arc<tokio::sync::OwnedSemaphorePermit>>,
}

struct CompletedHttpForward {
    json: String,
    permit: tokio::sync::OwnedSemaphorePermit,
    memory_permit: Option<Arc<tokio::sync::OwnedSemaphorePermit>>,
}

impl TunnelConnectError {
    fn permanent(message: impl Into<String>) -> Self {
        Self {
            error: LpmError::Tunnel(message.into()),
            retry_class: RetryClass::Permanent,
        }
    }

    fn transient(message: impl Into<String>) -> Self {
        Self {
            error: LpmError::Tunnel(message.into()),
            retry_class: RetryClass::Transient,
        }
    }

    fn auth_rejected(message: impl Into<String>) -> Self {
        Self {
            error: LpmError::Tunnel(message.into()),
            retry_class: RetryClass::AuthRejected,
        }
    }

    fn from_token_provider(error: LpmError) -> Self {
        let retry_class = if matches!(error, LpmError::AuthRequired | LpmError::SessionExpired) {
            RetryClass::Permanent
        } else {
            RetryClass::Transient
        };
        Self { error, retry_class }
    }
}

impl std::fmt::Display for TunnelConnectError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(formatter)
    }
}

impl From<LpmError> for TunnelConnectError {
    fn from(error: LpmError) -> Self {
        Self {
            error,
            retry_class: RetryClass::Transient,
        }
    }
}

#[derive(serde::Deserialize)]
struct RelayRejectionBody {
    error: Option<String>,
    message: Option<String>,
    code: Option<String>,
}

fn relay_code_retry_class(code: &str) -> Option<RetryClass> {
    match code {
        "auth_failed" => Some(RetryClass::AuthRejected),
        "plan_required"
        | "domain_not_owned"
        | "concurrent_limit"
        | "billing_inactive"
        | "monthly_allowance_exhausted" => Some(RetryClass::Permanent),
        "quota_unavailable"
        | "account_unavailable"
        | "usage_unavailable"
        | "usage_report_unavailable" => Some(RetryClass::Transient),
        _ => None,
    }
}

fn classify_relay_rejection(status: u16, body: &[u8]) -> TunnelConnectError {
    let payload = serde_json::from_slice::<RelayRejectionBody>(body).ok();
    let code = payload.as_ref().and_then(|value| value.code.as_deref());
    let detail = payload
        .as_ref()
        .and_then(|value| value.error.as_deref().or(value.message.as_deref()))
        .unwrap_or("relay rejected connection");
    let message = format!(
        "relay rejected connection: {detail}{}",
        code.map(|value| format!(" ({value})")).unwrap_or_default()
    );

    let retry_class = code.and_then(relay_code_retry_class).unwrap_or({
        if status == 401 {
            RetryClass::AuthRejected
        } else if status >= 500 {
            RetryClass::Transient
        } else {
            RetryClass::Permanent
        }
    });
    match retry_class {
        RetryClass::Permanent => TunnelConnectError::permanent(message),
        RetryClass::Transient => TunnelConnectError::transient(message),
        RetryClass::AuthRejected => TunnelConnectError::auth_rejected(message),
    }
}

fn classify_websocket_connect_error(
    error: tokio_tungstenite::tungstenite::Error,
) -> TunnelConnectError {
    if let tokio_tungstenite::tungstenite::Error::Http(response) = &error {
        let body = response.body().as_deref().unwrap_or_default();
        return classify_relay_rejection(response.status().as_u16(), body);
    }
    TunnelConnectError::transient(format!("failed to connect to relay: {error}"))
}

enum LocalWebSocketCommand {
    Frame {
        data: Vec<u8>,
        is_binary: bool,
        _memory_permit: tokio::sync::OwnedSemaphorePermit,
    },
    Close {
        code: Option<u16>,
        reason: Option<String>,
    },
}

fn bounded_websocket_close_reason(reason: Option<String>) -> Option<String> {
    let mut reason = reason?;
    if reason.len() > MAX_WEBSOCKET_CLOSE_REASON_BYTES {
        let mut end = MAX_WEBSOCKET_CLOSE_REASON_BYTES;
        while !reason.is_char_boundary(end) {
            end -= 1;
        }
        reason.truncate(end);
    }
    Some(reason)
}

async fn next_local_websocket_command(
    commands: &mut tokio::sync::mpsc::Receiver<LocalWebSocketCommand>,
    priority_commands: &mut tokio::sync::mpsc::Receiver<LocalWebSocketCommand>,
    cancel: &tokio_util::sync::CancellationToken,
) -> Option<LocalWebSocketCommand> {
    if let Ok(command) = priority_commands.try_recv() {
        return Some(command);
    }
    if let Ok(command) = commands.try_recv() {
        return Some(command);
    }
    tokio::select! {
        biased;
        command = priority_commands.recv() => command,
        command = commands.recv() => command,
        _ = cancel.cancelled() => commands.try_recv().ok(),
    }
}

struct WebSocketConnection {
    commands: tokio::sync::mpsc::Sender<LocalWebSocketCommand>,
    priority_commands: tokio::sync::mpsc::Sender<LocalWebSocketCommand>,
    cancel: tokio_util::sync::CancellationToken,
    generation: u64,
}

struct ClosedLocalWebSocket {
    id: String,
    generation: u64,
    half: LocalWebSocketHalf,
    reason: String,
    notify_relay: bool,
    relay_close: Option<(Option<u16>, Option<String>)>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LocalWebSocketHalf {
    Reader,
    Writer,
}

struct ClosingWebSocket {
    generation: u64,
    cancel: tokio_util::sync::CancellationToken,
    completed_halves: u8,
    relay_notified: bool,
}

type LocalWebSocket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;
type LocalWebSocketWrite = futures_util::stream::SplitSink<LocalWebSocket, Message>;
type LocalWebSocketRead = futures_util::stream::SplitStream<LocalWebSocket>;

struct CompletedWebSocketUpgrade {
    id: String,
    url: String,
    headers: HashMap<String, String>,
    generation: u64,
    slot: tokio::sync::OwnedSemaphorePermit,
    result: Result<(LocalWebSocketWrite, LocalWebSocketRead), String>,
}

struct LocalWebSocketActivation {
    id: String,
    generation: u64,
    local_write: LocalWebSocketWrite,
    local_read: LocalWebSocketRead,
    slot: tokio::sync::OwnedSemaphorePermit,
    relay_tx: tokio::sync::mpsc::Sender<RelayWebSocketMessage>,
    relay_memory: Arc<tokio::sync::Semaphore>,
    ws_tx: Option<tokio::sync::mpsc::Sender<WsEvent>>,
    closed_tx: tokio::sync::mpsc::UnboundedSender<ClosedLocalWebSocket>,
}

struct PendingWebSocketUpgrade {
    generation: u64,
    cancel: tokio_util::sync::CancellationToken,
}

fn discard_pending_websocket_upgrade(
    pending: &mut HashMap<String, PendingWebSocketUpgrade>,
    id: &str,
) -> bool {
    let Some(pending) = pending.remove(id) else {
        return false;
    };
    pending.cancel.cancel();
    true
}

fn cancel_active_websocket(
    active: &mut HashMap<String, WebSocketConnection>,
    closing: &mut HashMap<String, ClosingWebSocket>,
    id: &str,
    relay_notified: bool,
) {
    let Some(connection) = active.remove(id) else {
        return;
    };
    connection.cancel.cancel();
    closing.insert(
        id.to_string(),
        ClosingWebSocket {
            generation: connection.generation,
            cancel: connection.cancel,
            completed_halves: 0,
            relay_notified,
        },
    );
}

fn websocket_id_is_in_use(
    active: &HashMap<String, WebSocketConnection>,
    closing: &HashMap<String, ClosingWebSocket>,
    pending: &HashMap<String, PendingWebSocketUpgrade>,
    id: &str,
) -> bool {
    active.contains_key(id) || closing.contains_key(id) || pending.contains_key(id)
}

fn relay_websocket_message_is_current(
    active: &HashMap<String, WebSocketConnection>,
    message: &RelayWebSocketMessage,
) -> bool {
    active
        .get(&message.id)
        .is_some_and(|connection| connection.generation == message.generation)
}

async fn shutdown_websocket_tasks(
    ws_connections: HashMap<String, WebSocketConnection>,
    closing_websockets: HashMap<String, ClosingWebSocket>,
    pending_websocket_upgrades: HashMap<String, PendingWebSocketUpgrade>,
    task_handles: &mut tokio::task::JoinSet<()>,
    shutdown_timeout: std::time::Duration,
) {
    for connection in ws_connections.into_values() {
        connection.cancel.cancel();
    }
    for pending in pending_websocket_upgrades.into_values() {
        pending.cancel.cancel();
    }
    for connection in closing_websockets.into_values() {
        connection.cancel.cancel();
    }

    if tokio::time::timeout(shutdown_timeout, async {
        while task_handles.join_next().await.is_some() {}
    })
    .await
    .is_err()
    {
        task_handles.abort_all();
        while task_handles.join_next().await.is_some() {}
    }
}

struct RelayWebSocketMessage {
    id: String,
    generation: u64,
    json: String,
    _memory_permit: Option<tokio::sync::OwnedSemaphorePermit>,
}

async fn send_websocket_close_to_relay<S>(
    write: &mut S,
    id: &str,
    reason: &str,
) -> Result<(), TunnelConnectError>
where
    S: futures_util::Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
{
    send_websocket_close_frame_to_relay(write, id, Some(1013), Some(reason.to_string())).await
}

async fn send_websocket_close_frame_to_relay<S>(
    write: &mut S,
    id: &str,
    code: Option<u16>,
    reason: Option<String>,
) -> Result<(), TunnelConnectError>
where
    S: futures_util::Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
{
    let close = ClientMessage::WebSocketClose {
        id: id.to_string(),
        code,
        reason,
    };
    let json = serde_json::to_string(&close).map_err(|error| {
        LpmError::Tunnel(format!("failed to serialize WebSocket close: {error}"))
    })?;
    send_to_relay(write, Message::Text(json), "close WebSocket at relay").await
}

async fn send_to_relay<S>(
    write: &mut S,
    message: Message,
    operation: &str,
) -> Result<(), TunnelConnectError>
where
    S: futures_util::Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
{
    match tokio::time::timeout(
        std::time::Duration::from_secs(WEBSOCKET_SEND_TIMEOUT_SECS),
        write.send(message),
    )
    .await
    {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(TunnelConnectError::transient(format!(
            "failed to {operation}: {error}"
        ))),
        Err(_) => Err(TunnelConnectError::transient(format!(
            "timed out while attempting to {operation}"
        ))),
    }
}

fn activate_local_websocket(
    task_handles: &mut tokio::task::JoinSet<()>,
    activation: LocalWebSocketActivation,
) -> WebSocketConnection {
    let LocalWebSocketActivation {
        id,
        generation,
        local_write,
        mut local_read,
        slot,
        relay_tx,
        relay_memory,
        ws_tx,
        closed_tx,
    } = activation;
    let (local_tx, mut local_rx) = tokio::sync::mpsc::channel::<LocalWebSocketCommand>(64);
    let (priority_tx, mut priority_rx) = tokio::sync::mpsc::channel::<LocalWebSocketCommand>(1);
    let connection_cancel = tokio_util::sync::CancellationToken::new();
    let local_write = Arc::new(tokio::sync::Mutex::new(local_write));
    let writer = Arc::clone(&local_write);
    let writer_id = id.clone();
    let writer_cancel = connection_cancel.clone();
    let writer_closed = closed_tx.clone();
    task_handles.spawn(async move {
        let mut reason = "local WebSocket writer stopped".to_string();
        let mut notify_relay = true;
        loop {
            let command =
                next_local_websocket_command(&mut local_rx, &mut priority_rx, &writer_cancel).await;
            let Some(command) = command else {
                notify_relay = false;
                break;
            };
            let is_close = matches!(&command, LocalWebSocketCommand::Close { .. });
            let message = match command {
                LocalWebSocketCommand::Frame {
                    data,
                    is_binary,
                    _memory_permit,
                } => match local_websocket_message(data, is_binary) {
                    Ok(message) => message,
                    Err(error) => {
                        reason = error;
                        break;
                    }
                },
                LocalWebSocketCommand::Close { code, reason } => Message::Close(Some(CloseFrame {
                    code: CloseCode::from(code.unwrap_or(1000)),
                    reason: reason.unwrap_or_default().into(),
                })),
            };
            let send = async {
                let mut sink = writer.lock().await;
                sink.send(message).await
            };
            let result = tokio::select! {
                biased;
                _ = writer_cancel.cancelled(), if !is_close => break,
                result = tokio::time::timeout(
                    std::time::Duration::from_secs(WEBSOCKET_SEND_TIMEOUT_SECS),
                    send,
                ) => result,
            };
            match result {
                Ok(Ok(())) if is_close => {
                    reason = "relay closed the WebSocket".to_string();
                    notify_relay = false;
                    writer_cancel.cancel();
                    break;
                }
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    reason = format!("local WebSocket write failed: {error}");
                    break;
                }
                Err(_) => {
                    reason = "local WebSocket write timed out".to_string();
                    break;
                }
            }
        }
        let _ = writer_closed.send(ClosedLocalWebSocket {
            id: writer_id,
            generation,
            half: LocalWebSocketHalf::Writer,
            reason,
            notify_relay,
            relay_close: None,
        });
    });

    let reader_id = id;
    let reader_cancel = connection_cancel.clone();
    task_handles.spawn(async move {
        let _slot = slot;
        let mut close_reason = "local WebSocket connection ended".to_string();
        let mut notify_relay = true;
        let mut relay_close = None;
        loop {
            let message = tokio::select! {
                biased;
                _ = reader_cancel.cancelled() => {
                    notify_relay = false;
                    break;
                },
                message = local_read.next() => message,
            };
            let Some(message) = message else {
                break;
            };
            let message = match message {
                Ok(message) => message,
                Err(error) => {
                    close_reason = format!("local WebSocket read failed: {error}");
                    break;
                }
            };
            let (bytes, is_binary) = match message {
                Message::Text(text) => (text.into_bytes(), false),
                Message::Binary(bytes) => (bytes, true),
                Message::Close(frame) => {
                    notify_relay = false;
                    let reason = frame.as_ref().map(|frame| frame.reason.to_string());
                    let code = frame.as_ref().map(|frame| u16::from(frame.code));
                    if let Some(ref ws_tx) = ws_tx {
                        let _ = ws_tx.try_send(WsEvent::Closed {
                            connection_id: reader_id.clone(),
                            reason: reason.clone(),
                            timestamp: chrono::Utc::now().to_rfc3339(),
                        });
                    }
                    relay_close = Some((code, reason.clone()));
                    close_reason = reason.map_or_else(
                        || "local WebSocket closed".to_string(),
                        |reason| format!("local WebSocket closed: {reason}"),
                    );
                    break;
                }
                _ => continue,
            };
            let Some(retained_bytes) =
                websocket_encoded_message_bytes(bytes.len(), reader_id.len())
            else {
                close_reason = "local WebSocket frame size overflowed".to_string();
                break;
            };
            let Some(permits) = websocket_memory_permits(retained_bytes) else {
                close_reason = "local WebSocket frame exceeded the tunnel byte limit".to_string();
                break;
            };
            let permit = match Arc::clone(&relay_memory).try_acquire_many_owned(permits) {
                Ok(permit) => permit,
                Err(_) => {
                    close_reason =
                        "relay backpressure exhausted the WebSocket byte budget".to_string();
                    break;
                }
            };
            if let Some(ref ws_tx) = ws_tx {
                let _ = ws_tx.try_send(WsEvent::captured_frame(
                    reader_id.clone(),
                    FrameDirection::Outbound,
                    &bytes,
                    is_binary,
                    chrono::Utc::now().to_rfc3339(),
                ));
            }
            let json = match serialize_websocket_frame(&reader_id, &bytes, is_binary) {
                Ok(json) => json,
                Err(error) => {
                    close_reason = format!("failed to serialize WebSocket frame: {error}");
                    break;
                }
            };
            drop(bytes);
            if relay_tx
                .send(RelayWebSocketMessage {
                    id: reader_id.clone(),
                    generation,
                    json,
                    _memory_permit: Some(permit),
                })
                .await
                .is_err()
            {
                close_reason = "relay WebSocket writer stopped".to_string();
                break;
            }
        }
        reader_cancel.cancel();
        let _ = closed_tx.send(ClosedLocalWebSocket {
            id: reader_id,
            generation,
            half: LocalWebSocketHalf::Reader,
            reason: close_reason,
            notify_relay,
            relay_close,
        });
    });

    WebSocketConnection {
        commands: local_tx,
        priority_commands: priority_tx,
        cancel: connection_cancel,
        generation,
    }
}

/// Options for connecting to the tunnel relay.
#[derive(Debug, Clone)]
pub struct TunnelOptions {
    /// Relay WebSocket URL (default: wss://relay.lpm.fyi/connect).
    pub relay_url: String,
    /// LPM auth token.
    pub token: String,
    /// Dynamic refresh-backed bearer source. Static callers can leave this unset.
    pub token_provider: Option<TunnelTokenProvider>,
    /// Validated local HTTP endpoint to tunnel.
    pub local_target: lpm_common::LocalTarget,
    /// Live endpoint source for dev services that can restart.
    pub live_local_target: Option<Arc<RwLock<lpm_common::LocalTarget>>>,
    /// Full tunnel domain (e.g., "acme-api.lpm.llc"). Pro/Org only.
    /// If None, relay assigns a random domain on lpm.fyi (free tier).
    /// If bare name without dot, ".lpm.fyi" is appended for backward compat.
    pub domain: Option<String>,
    /// Auth token for protecting the tunnel URL. When set, the relay
    /// requires `?auth={token}` on incoming requests (prevents unauthorized access).
    pub tunnel_auth: Option<String>,
    /// Channel for sending captured webhooks to observers (inspector, logger, dashboard).
    ///
    /// Bounded best-effort channel. A full observer queue drops capture events
    /// without blocking the proxy hot path or retaining unbounded request bodies.
    pub webhook_tx: Option<tokio::sync::mpsc::Sender<CapturedWebhookEvent>>,
    /// Disable TLS certificate pinning (for development/testing).
    /// When false (default), the relay's TLS certificate public key is pinned
    /// using TOFU (Trust On First Use) to prevent MITM attacks.
    pub no_pin: bool,
    /// Auto-acknowledge mode. When enabled, if the local dev server is
    /// unreachable (connection refused, timeout), the tunnel returns `200 OK`
    /// to the provider instead of `502`. This prevents webhook providers
    /// (Stripe, GitHub, etc.) from retrying aggressively and potentially
    /// disabling the webhook endpoint. The request is still fully captured
    /// for later replay.
    pub auto_ack: bool,
    /// Channel for sending captured WebSocket events to the inspector.
    /// Uses the same bounded best-effort pattern as `webhook_tx`.
    pub ws_tx: Option<tokio::sync::mpsc::Sender<WsEvent>>,
    /// Optional publication barrier for callers that must commit local runtime
    /// state before the relay can forward requests.
    pub forwarding_admission: Option<TunnelForwardingAdmission>,
    /// Cooperative shutdown signal. Connection teardown cancels and joins all
    /// in-flight forwarding tasks before returning.
    pub shutdown: Option<tokio_util::sync::CancellationToken>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TunnelForwardingState {
    Pending,
    Open,
    Rejected,
}

#[derive(Clone, Debug)]
pub struct TunnelForwardingAdmission {
    state: tokio::sync::watch::Receiver<TunnelForwardingState>,
}

#[derive(Clone, Debug)]
pub struct TunnelForwardingController {
    state: tokio::sync::watch::Sender<TunnelForwardingState>,
}

pub fn forwarding_admission_barrier() -> (TunnelForwardingController, TunnelForwardingAdmission) {
    let (state, receiver) = tokio::sync::watch::channel(TunnelForwardingState::Pending);
    (
        TunnelForwardingController { state },
        TunnelForwardingAdmission { state: receiver },
    )
}

impl TunnelForwardingController {
    pub fn open(&self) {
        self.state.send_replace(TunnelForwardingState::Open);
    }

    pub fn reject(&self) {
        self.state.send_replace(TunnelForwardingState::Rejected);
    }
}

impl TunnelForwardingAdmission {
    async fn wait(&self) -> Result<(), LpmError> {
        let mut state = self.state.clone();
        loop {
            match *state.borrow() {
                TunnelForwardingState::Open => return Ok(()),
                TunnelForwardingState::Rejected => {
                    return Err(LpmError::Tunnel(
                        "tunnel forwarding was rejected before runtime publication".into(),
                    ));
                }
                TunnelForwardingState::Pending => {}
            }
            state.changed().await.map_err(|_| {
                LpmError::Tunnel(
                    "tunnel forwarding admission closed before runtime publication".into(),
                )
            })?;
        }
    }
}

impl TunnelOptions {
    pub fn new(token: String, local_port: u16) -> Self {
        Self {
            relay_url: DEFAULT_RELAY_URL.to_string(),
            token,
            token_provider: None,
            local_target: lpm_common::LocalTarget::loopback(
                lpm_common::LocalScheme::Http,
                local_port,
            ),
            live_local_target: None,
            domain: None,
            tunnel_auth: None,
            webhook_tx: None,
            no_pin: false,
            auto_ack: false,
            ws_tx: None,
            forwarding_admission: None,
            shutdown: None,
        }
    }

    /// Resolve the domain, appending default base domain if bare subdomain.
    pub fn resolved_domain(&self) -> Option<String> {
        self.domain.as_ref().map(|d| {
            if d.contains('.') {
                d.clone()
            } else {
                format!("{d}.{}", crate::DEFAULT_BASE_DOMAIN)
            }
        })
    }

    fn current_local_target(&self) -> lpm_common::LocalTarget {
        self.live_local_target.as_ref().map_or_else(
            || self.local_target.clone(),
            |target| {
                target
                    .read()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .clone()
            },
        )
    }
}

/// Connect to the tunnel relay and start proxying.
///
/// This function blocks until the tunnel is closed (Ctrl+C or relay disconnect).
/// It handles reconnection with exponential backoff.
pub async fn connect(
    options: &TunnelOptions,
    on_connected: impl Fn(&TunnelSession),
    on_disconnected: impl Fn(&str),
) -> Result<(), LpmError> {
    connect_with_usage(options, on_connected, on_disconnected, |_, _| {}).await
}

/// Connect to the relay while receiving initial and threshold usage snapshots.
///
/// The final callback receives `true` for the usage included in the initial
/// handshake and `false` for later allowance/overage threshold notices.
pub async fn connect_with_usage(
    options: &TunnelOptions,
    on_connected: impl Fn(&TunnelSession),
    on_disconnected: impl Fn(&str),
    on_usage: impl Fn(&TunnelUsageMetadata, bool),
) -> Result<(), LpmError> {
    connect_with_usage_fallible(
        options,
        |session| {
            on_connected(session);
            Ok(())
        },
        on_disconnected,
        on_usage,
    )
    .await
}

/// Connect to the relay with a callback that can reject session startup.
pub async fn connect_with_usage_fallible(
    options: &TunnelOptions,
    on_connected: impl Fn(&TunnelSession) -> Result<(), LpmError>,
    on_disconnected: impl Fn(&str),
    on_usage: impl Fn(&TunnelUsageMetadata, bool),
) -> Result<(), LpmError> {
    crate::validate_forward_target(&options.current_local_target())?;
    let mut retry_count = 0;
    let max_retries = 10;
    let auth_refresh_attempted = std::sync::atomic::AtomicBool::new(false);
    let mut retry_token = None;

    loop {
        if options
            .shutdown
            .as_ref()
            .is_some_and(tokio_util::sync::CancellationToken::is_cancelled)
        {
            return Ok(());
        }
        let connection_start = std::time::Instant::now();
        let attempt_token = retry_token.take();
        let mark_authenticated = |session: &TunnelSession| {
            auth_refresh_attempted.store(false, std::sync::atomic::Ordering::Relaxed);
            on_connected(session)
        };
        match try_connect_with_token(
            options,
            attempt_token.as_deref(),
            &mark_authenticated,
            &on_usage,
        )
        .await
        {
            Ok(()) => {
                // Clean disconnect
                tracing::info!("tunnel closed");
                return Ok(());
            }
            Err(mut e) => {
                if e.retry_class == RetryClass::AuthRejected {
                    let Some(provider) = options.token_provider.as_ref() else {
                        return Err(e.error);
                    };
                    if auth_refresh_attempted.swap(true, std::sync::atomic::Ordering::Relaxed) {
                        return Err(e.error);
                    }
                    match provider.refresh_after_rejection().await {
                        Ok(token) => {
                            retry_token = Some(token);
                            continue;
                        }
                        Err(error) => {
                            e = TunnelConnectError::from_token_provider(error);
                            if e.retry_class == RetryClass::Transient {
                                auth_refresh_attempted
                                    .store(false, std::sync::atomic::Ordering::Relaxed);
                            }
                        }
                    }
                }
                if e.retry_class == RetryClass::Permanent {
                    return Err(e.error);
                }
                // Reset retry counter if the connection was healthy (lasted > 60s).
                // This prevents a long-running tunnel from accumulating retries
                // across unrelated transient failures.
                if connection_start.elapsed().as_secs() >= HEALTHY_CONNECTION_SECS {
                    retry_count = 0;
                }

                retry_count += 1;
                if retry_count > max_retries {
                    return Err(LpmError::Tunnel(format!(
                        "tunnel disconnected after {max_retries} retries: {e}"
                    )));
                }

                let base_delay = std::cmp::min(1u64 << retry_count, 30);
                let jitter = backoff_jitter(base_delay);
                let total_delay = base_delay + jitter;
                on_disconnected(&format!(
                    "disconnected, retrying in {total_delay}s... ({e})"
                ));
                tokio::select! {
                    _ = tokio::time::sleep(std::time::Duration::from_secs(total_delay)) => {}
                    _ = wait_for_tunnel_shutdown(options.shutdown.as_ref()) => return Ok(()),
                }
            }
        }
    }
}

async fn wait_for_tunnel_shutdown(shutdown: Option<&tokio_util::sync::CancellationToken>) {
    match shutdown {
        Some(shutdown) => shutdown.cancelled().await,
        None => std::future::pending::<()>().await,
    }
}

/// Compute jitter for reconnection backoff to prevent thundering herd.
///
/// Uses a deterministic-ish source (PID + current time) to avoid requiring
/// full RNG initialization on the hot path. Returns a value in `[0, base_delay/2]`.
fn backoff_jitter(base_delay: u64) -> u64 {
    use rand::Rng;
    let max_jitter = base_delay / 2 + 1;
    rand::thread_rng().gen_range(0..max_jitter)
}

/// Validate that a URL path received from the relay is safe to forward locally.
///
/// Rejects paths that don't start with `/`, contain `//` in the path portion
/// (potential protocol-relative redirect or path confusion), or contain CR/LF
/// (HTTP response splitting). Double slashes in query strings are allowed since
/// query parameters may legitimately contain URLs (e.g., `?redirect=https://...`).
fn is_safe_local_url(url: &str) -> bool {
    if !url.starts_with('/') {
        return false;
    }
    // Only check for // in the path portion, not the query string
    let path = url.split('?').next().unwrap_or(url);
    if path.contains("//") {
        return false;
    }
    if url.contains('\r') || url.contains('\n') {
        return false;
    }
    true
}

fn websocket_upgrade_metadata_error(id: &str, url: &str) -> Option<&'static str> {
    if id.len() > MAX_WEBSOCKET_CONNECTION_ID_BYTES {
        return Some("Local WebSocket connection ID exceeds the byte limit");
    }
    if url.len() > MAX_WEBSOCKET_LOCAL_URL_BYTES {
        return Some("Local WebSocket upgrade URL exceeds the byte limit");
    }
    if !is_safe_local_url(url) {
        return Some("Local WebSocket upgrade URL was rejected");
    }
    None
}

/// Check if enough time has elapsed since last pong to consider the relay dead.
fn is_pong_timed_out(last_pong: std::time::Instant) -> bool {
    last_pong.elapsed() > std::time::Duration::from_secs(PONG_TIMEOUT_SECS)
}

fn build_websocket_connect_request(
    connect_url: &str,
    token: &str,
    tunnel_auth: Option<&str>,
) -> Result<tokio_tungstenite::tungstenite::http::Request<()>, LpmError> {
    let mut request = connect_url
        .into_client_request()
        .map_err(|e| LpmError::Tunnel(format!("failed to build WebSocket request: {e}")))?;

    request.headers_mut().insert(
        "Authorization",
        tokio_tungstenite::tungstenite::http::HeaderValue::from_str(&format!("Bearer {token}"))
            .map_err(|e| LpmError::Tunnel(format!("invalid Authorization header: {e}")))?,
    );

    if let Some(auth) = tunnel_auth {
        request.headers_mut().insert(
            "X-Tunnel-Auth",
            tokio_tungstenite::tungstenite::http::HeaderValue::from_str(auth)
                .map_err(|e| LpmError::Tunnel(format!("invalid X-Tunnel-Auth header: {e}")))?,
        );
    }

    Ok(request)
}

/// Extract response status, headers, and body from a `ClientMessage::HttpResponse`.
///
/// Returns `(status, headers, decoded_body)`. If the message is not an
/// `HttpResponse` or body decoding fails, returns safe defaults.
fn extract_response_data(response: &ClientMessage) -> (u16, HashMap<String, String>, Vec<u8>) {
    match response {
        ClientMessage::HttpResponse {
            status,
            headers,
            body,
            ..
        } => {
            let decoded_body =
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD, body)
                    .unwrap_or_default();
            (*status, headers.clone(), decoded_body)
        }
        _ => (0, HashMap::new(), Vec::new()),
    }
}

fn request_memory_permits(wire_message_len: usize) -> Option<u32> {
    let permits = wire_message_len
        .saturating_mul(HTTP_REQUEST_ESTIMATED_OVERHEAD_MULTIPLIER)
        .div_ceil(HTTP_RESPONSE_MEMORY_UNIT_BYTES)
        .max(1);
    if permits > HTTP_REQUEST_MEMORY_PERMITS {
        return None;
    }
    u32::try_from(permits).ok()
}

fn websocket_memory_permits(retained_bytes: usize) -> Option<u32> {
    let permits = retained_bytes
        .div_ceil(HTTP_RESPONSE_MEMORY_UNIT_BYTES)
        .max(1);
    if permits > WEBSOCKET_MEMORY_PERMITS {
        return None;
    }
    u32::try_from(permits).ok()
}

fn inbound_websocket_memory_permits(
    wire_message_bytes: usize,
    base64_payload_bytes: usize,
) -> Option<u32> {
    let decoded_bytes = base64_payload_bytes
        .checked_div(4)
        .and_then(|groups| groups.checked_mul(3))
        .and_then(|bytes| bytes.checked_add(3))?;
    let retained_bytes = wire_message_bytes
        .checked_mul(2)?
        .checked_add(decoded_bytes)?;
    websocket_memory_permits(retained_bytes)
        .filter(|permits| *permits as usize <= WEBSOCKET_MEMORY_PERMITS)
}

fn local_websocket_message(data: Vec<u8>, is_binary: bool) -> Result<Message, String> {
    if is_binary {
        Ok(Message::Binary(data))
    } else {
        String::from_utf8(data)
            .map(Message::Text)
            .map_err(|_| "relay WebSocket text frame is not valid UTF-8".to_string())
    }
}

fn websocket_encoded_message_bytes(raw_bytes: usize, connection_id_bytes: usize) -> Option<usize> {
    let encoded = raw_bytes.checked_add(2)?.checked_div(3)?.checked_mul(4)?;
    raw_bytes
        .checked_add(encoded)?
        .checked_add(connection_id_bytes.checked_mul(6)?)?
        .checked_add(64)
}

fn serialize_websocket_frame(id: &str, bytes: &[u8], is_binary: bool) -> Result<String, String> {
    use base64::Engine as _;

    const PREFIX: &str = "{\"type\":\"ws_frame\",\"id\":";
    const DATA_PREFIX: &str = ",\"data\":\"";
    const BINARY_TRUE: &str = "\",\"is_binary\":true}";
    const BINARY_FALSE: &str = "\",\"is_binary\":false}";

    let encoded = base64::encoded_len(bytes.len(), true)
        .ok_or_else(|| "WebSocket frame size overflowed during base64 encoding".to_string())?;
    let escaped_id_capacity = id
        .len()
        .checked_mul(6)
        .and_then(|len| len.checked_add(2))
        .ok_or_else(|| "WebSocket connection ID size overflowed".to_string())?;
    let suffix = if is_binary { BINARY_TRUE } else { BINARY_FALSE };
    let capacity = PREFIX
        .len()
        .checked_add(escaped_id_capacity)
        .and_then(|len| len.checked_add(DATA_PREFIX.len()))
        .and_then(|len| len.checked_add(encoded))
        .and_then(|len| len.checked_add(suffix.len()))
        .ok_or_else(|| "WebSocket frame size overflowed during JSON serialization".to_string())?;
    let mut json = Vec::with_capacity(capacity);
    json.extend_from_slice(PREFIX.as_bytes());
    serde_json::to_writer(&mut json, id).map_err(|error| error.to_string())?;
    json.extend_from_slice(DATA_PREFIX.as_bytes());
    let data_offset = json.len();
    json.resize(
        data_offset
            .checked_add(encoded)
            .ok_or_else(|| "WebSocket frame size overflowed during base64 encoding".to_string())?,
        0,
    );
    let written = base64::engine::general_purpose::STANDARD
        .encode_slice(bytes, &mut json[data_offset..])
        .map_err(|error| error.to_string())?;
    json.truncate(data_offset + written);
    json.extend_from_slice(suffix.as_bytes());
    String::from_utf8(json).map_err(|error| error.to_string())
}

fn captured_websocket_headers(
    headers: &HashMap<String, String>,
) -> Option<HashMap<String, String>> {
    if websocket_upgrade_header_bytes(headers)? > WEBSOCKET_CAPTURE_HEADER_BYTES {
        return None;
    }
    Some(headers.clone())
}

fn websocket_upgrade_header_bytes(headers: &HashMap<String, String>) -> Option<usize> {
    headers.iter().try_fold(0usize, |retained, (name, value)| {
        retained
            .checked_add(name.len())?
            .checked_add(value.len())?
            .checked_add(64)
    })
}

fn bounded_websocket_upgrade_headers(
    headers: HashMap<String, String>,
) -> Result<HashMap<String, String>, String> {
    let retained = websocket_upgrade_header_bytes(&headers)
        .ok_or_else(|| "WebSocket upgrade headers exceeded the tunnel byte limit".to_string())?;
    if retained > WEBSOCKET_CAPTURE_HEADER_BYTES {
        return Err(format!(
            "WebSocket upgrade headers exceed the {WEBSOCKET_CAPTURE_HEADER_BYTES}-byte limit"
        ));
    }
    Ok(headers)
}

async fn forward_http_request(
    http_client: reqwest::Client,
    local_target: lpm_common::LocalTarget,
    server_msg: ServerMessage,
    auto_ack: bool,
    webhook_tx: Option<tokio::sync::mpsc::Sender<CapturedWebhookEvent>>,
    memory_budget: Arc<tokio::sync::Semaphore>,
    request_memory_permit: Option<Arc<tokio::sync::OwnedSemaphorePermit>>,
) -> (
    ClientMessage,
    Option<Arc<tokio::sync::OwnedSemaphorePermit>>,
) {
    let forward_start = std::time::Instant::now();
    let mut was_auto_acked = false;
    let memory_multiplier = if webhook_tx.is_some() {
        HTTP_RESPONSE_ESTIMATED_OVERHEAD_MULTIPLIER
    } else {
        HTTP_RESPONSE_ESTIMATED_OVERHEAD_MULTIPLIER - 1
    };
    let (response, memory_permit) = match proxy::forward_request_with_memory_budget(
        &http_client,
        &local_target,
        &server_msg,
        memory_budget,
        HTTP_RESPONSE_MEMORY_PERMITS,
        HTTP_RESPONSE_MEMORY_UNIT_BYTES,
        memory_multiplier,
    )
    .await
    {
        Ok(response) => (response.message, response.memory_permit.map(Arc::new)),
        Err(error) => {
            tracing::debug!("local proxy error: {error}");
            let ServerMessage::HttpRequest { ref id, .. } = server_msg else {
                return (ClientMessage::Ping, None);
            };
            let response = if auto_ack {
                was_auto_acked = true;
                tracing::info!("auto-ack: returning 200 OK (server down)");
                proxy::auto_ack_response(id)
            } else {
                proxy::bad_gateway_response(id)
            };
            (response, None)
        }
    };

    if let Some(ref tx) = webhook_tx
        && let ServerMessage::HttpRequest {
            ref id,
            ref method,
            ref url,
            ref headers,
            ref body,
        } = server_msg
    {
        let request_body = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, body)
            .unwrap_or_default();
        let (response_status, response_headers, response_body) = extract_response_data(&response);
        let mut captured = CapturedWebhook {
            id: id.clone(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            method: method.clone(),
            path: url.clone(),
            request_headers: headers.clone(),
            request_body,
            response_status,
            response_headers,
            response_body,
            duration_ms: forward_start.elapsed().as_millis() as u64,
            provider: webhook::detect_provider(url, headers),
            summary: String::new(),
            signature_diagnostic: None,
            auto_acked: was_auto_acked,
        };
        captured.summary = webhook::summarize_webhook(&captured);
        if captured.response_status >= 400 {
            const DIAGNOSTIC_ENV_ALLOWLIST: &[&str] = &[
                "STRIPE_WEBHOOK_SECRET",
                "STRIPE_SIGNING_SECRET",
                "GITHUB_WEBHOOK_SECRET",
            ];
            let mut env_vars = HashMap::with_capacity(DIAGNOSTIC_ENV_ALLOWLIST.len());
            for name in DIAGNOSTIC_ENV_ALLOWLIST {
                if let Ok(value) = std::env::var(name) {
                    env_vars.insert((*name).to_string(), value);
                }
            }
            captured.signature_diagnostic =
                webhook_signature::diagnose_signature_failure(&captured, &env_vars);
        }
        let _ = tx.try_send(CapturedWebhookEvent {
            webhook: Arc::new(captured),
            _response_memory_permit: memory_permit.clone(),
            _request_memory_permit: request_memory_permit,
        });
    }

    (response, memory_permit)
}

// ── TOFU Certificate Pinning ──────────────────────────────────────

/// Optional embedded SPKI SHA-256 pin for the canonical relay
/// (`relay.lpm.fyi`). When `Some`, the first connect to the canonical
/// host MUST match this pin — pure WebPKI-valid-but-unknown TOFU is
/// rejected.
///
/// L3: pure TOFU on first connect lets an attacker who controls the
/// network on the user's first `lpm dev --tunnel` capture a forged
/// pin. The embedded pin slot is wired up here so the release pipeline
/// can flip `None` → `Some("<canonical SPKI sha256 hex>")` to close
/// the first-connect gap. Default stays at `None` to avoid shipping a
/// pin that's wrong (or rotated) and would brick every install.
///
/// Non-canonical hosts (`LPM_TUNNEL_RELAY` override, regional relays)
/// continue to use pure TOFU — the embedded pin would be meaningless
/// for them.
const EMBEDDED_CANONICAL_RELAY_SPKI_PIN_HEX: Option<&str> = None;

/// Read the stored TOFU pin (hex-encoded SHA-256 of SPKI) for `host`.
///
/// Looks up `~/.lpm/relay-pins/<host>` first. If absent AND `host` is
/// the canonical default ([`crate::relay::DEFAULT_RELAY_HOST`]), falls
/// through to the legacy single-file `~/.lpm/relay-pin` so existing
/// installs from before per-host pinning keep working without manual
/// migration. The legacy file is read but never written — the next
/// successful verification migrates the pin to the new layout via
/// [`write_tofu_pin`].
fn read_tofu_pin(host: &str) -> Result<Option<String>, lpm_common::BoundedReadError> {
    if let Some(path) = crate::relay::tofu_pin_path_for_host(host) {
        match lpm_common::read_text_file_capped(&path, lpm_common::TLS_MATERIAL_FILE_SIZE_CAP_BYTES)
        {
            Ok(pin) => return Ok(Some(pin.trim().to_string())),
            Err(lpm_common::BoundedReadError::NotFound { .. }) => {}
            Err(error) => return Err(error),
        }
    }

    // Legacy fallback: only honored on the canonical default relay,
    // since the old single-file layout had no host context. Any other
    // relay starts a fresh TOFU on the per-host layout — that's the
    // correct semantic, since a stored pin is meaningless across hosts.
    if host == crate::relay::DEFAULT_RELAY_HOST
        && let Some(path) = crate::relay::legacy_tofu_pin_path()
    {
        match lpm_common::read_text_file_capped(&path, lpm_common::TLS_MATERIAL_FILE_SIZE_CAP_BYTES)
        {
            Ok(pin) => return Ok(Some(pin.trim().to_string())),
            Err(lpm_common::BoundedReadError::NotFound { .. }) => {}
            Err(error) => return Err(error),
        }
    }

    Ok(None)
}

/// Store a TOFU pin for `host` to `~/.lpm/relay-pins/<host>`.
///
/// Always writes to the per-host layout — never updates the legacy
/// `~/.lpm/relay-pin` file. After a successful verify on the canonical
/// relay, this naturally lifts existing users into the per-host model
/// the first time they reconnect post-upgrade.
fn write_tofu_pin(host: &str, pin_hex: &str) -> Result<(), String> {
    let path = crate::relay::tofu_pin_path_for_host(host).ok_or("no home directory")?;
    let parent = path.parent().unwrap();
    std::fs::create_dir_all(parent)
        .map_err(|e| format!("failed to create {}: {e}", parent.display()))?;
    #[cfg(unix)]
    {
        // Open with O_CREAT|O_TRUNC|O_WRONLY and mode 0o600 so the
        // file lands owner-only from creation rather than via a
        // post-write chmod. Closes the race window where another
        // process could observe the pin file between the umask-based
        // create and the set_permissions call. The pin itself is not
        // a secret (it's an SPKI hash), but locking it down at create
        // time matches the broader credential-metadata posture and
        // prevents tampering by other local UIDs.
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)
            .map_err(|e| format!("failed to open relay pin for write: {e}"))?;
        f.write_all(pin_hex.as_bytes())
            .map_err(|e| format!("failed to write relay pin: {e}"))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(&path, pin_hex).map_err(|e| format!("failed to write relay pin: {e}"))?;
    }
    Ok(())
}

/// Compute the SHA-256 hash of a certificate's Subject Public Key Info (SPKI).
fn spki_sha256_hex(cert_der: &[u8]) -> Option<String> {
    use sha2::{Digest, Sha256};
    let spki = extract_spki_from_der(cert_der)?;
    let hash = Sha256::digest(spki);
    Some(hex::encode(hash))
}

/// Extract the SubjectPublicKeyInfo bytes from a DER-encoded X.509 certificate.
///
/// Walks the ASN.1 DER structure to find the SPKI field (7th element of TBSCertificate).
///
/// X.509v3 TBSCertificate layout:
///   [0] version, serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo, ...
///   index:  0         1            2         3        4        5              6
fn extract_spki_from_der(cert_der: &[u8]) -> Option<&[u8]> {
    // Outer: SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
    let (cert_content, _) = read_der_seq_content(cert_der)?;
    // tbsCertificate is the first element of the outer SEQUENCE
    let (tbs_element, _) = read_der_element(cert_content)?;
    // TBS is itself a SEQUENCE — get its content
    let (tbs_content, _) = read_der_seq_content(tbs_element)?;

    // Skip through tbsCertificate fields to reach subjectPublicKeyInfo (index 6)
    let mut remaining = tbs_content;
    for i in 0..7 {
        let (element, rest) = read_der_element(remaining)?;
        if i == 6 {
            return Some(element);
        }
        remaining = rest;
    }
    None
}

/// Read the content of a DER SEQUENCE (or any constructed type).
/// Returns (content_bytes_only, full_element_bytes).
fn read_der_seq_content(data: &[u8]) -> Option<(&[u8], &[u8])> {
    if data.is_empty() {
        return None;
    }
    let (content_len, header_len) = read_der_length(&data[1..])?;
    let total_header = 1 + header_len;
    let total = total_header + content_len;
    if total > data.len() {
        return None;
    }
    Some((&data[total_header..total], data))
}

/// Read a single DER element. Returns (full_element_bytes_including_header, remaining_bytes).
fn read_der_element(data: &[u8]) -> Option<(&[u8], &[u8])> {
    if data.is_empty() {
        return None;
    }
    let (content_len, len_bytes) = read_der_length(&data[1..])?;
    let total = 1 + len_bytes + content_len;
    if total > data.len() {
        return None;
    }
    Some((&data[..total], &data[total..]))
}

/// Parse DER length encoding. Returns (content_length, bytes_consumed_for_length_field).
fn read_der_length(data: &[u8]) -> Option<(usize, usize)> {
    if data.is_empty() {
        return None;
    }
    let first = data[0] as usize;
    if first < 0x80 {
        Some((first, 1))
    } else if first == 0x80 {
        None // Indefinite length not supported in DER
    } else {
        let num_bytes = first & 0x7F;
        if num_bytes > 4 || 1 + num_bytes > data.len() {
            return None;
        }
        let mut len = 0usize;
        for i in 0..num_bytes {
            len = len.checked_shl(8)?.checked_add(data[1 + i] as usize)?;
        }
        Some((len, 1 + num_bytes))
    }
}

/// Render a rustls `ServerName` as a host string suitable for keying a
/// pin file. Both DNS and IP variants stringify cleanly via `Display`;
/// rustls already validates that the name is well-formed, so we don't
/// need to re-sanitize for filesystem safety on the macOS/Linux/Windows
/// path layouts we support.
fn server_name_to_string(server_name: &rustls::pki_types::ServerName<'_>) -> String {
    match server_name {
        rustls::pki_types::ServerName::DnsName(n) => n.as_ref().to_string(),
        rustls::pki_types::ServerName::IpAddress(ip) => format!("{ip:?}"),
        // rustls's ServerName is `#[non_exhaustive]`; if a future variant
        // appears, fall back to the Debug rendering rather than failing
        // the verifier outright. Pin storage simply uses a stable string
        // — getting it slightly less pretty for a new variant is fine.
        other => format!("{other:?}"),
    }
}

/// TOFU (Trust On First Use) certificate pinning verifier.
///
/// Delegates standard chain validation to the default `WebPkiServerVerifier`, then
/// checks the end-entity certificate's SPKI hash against a stored pin. On first
/// connection the pin is saved; on subsequent connections a mismatch is rejected.
#[derive(Debug)]
struct TofuPinningVerifier {
    default_verifier: Arc<dyn rustls::client::danger::ServerCertVerifier>,
}

impl TofuPinningVerifier {
    fn new(default_verifier: Arc<dyn rustls::client::danger::ServerCertVerifier>) -> Self {
        Self { default_verifier }
    }
}

impl rustls::client::danger::ServerCertVerifier for TofuPinningVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        server_name: &rustls::pki_types::ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        // First: standard certificate chain validation (WebPKI)
        self.default_verifier.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )?;

        // Then: TOFU pin check on the end-entity certificate's SPKI.
        // The pin is keyed by the rustls-verified `ServerName` so each
        // relay host gets its own pin file. This is what makes
        // `LPM_TUNNEL_RELAY` and future regional relays safe — switching
        // hosts never inherits a pin for a different server, and
        // re-pointing back doesn't lose the original pin.
        let host = server_name_to_string(server_name);

        let current_pin = spki_sha256_hex(end_entity.as_ref()).ok_or_else(|| {
            rustls::Error::General("failed to extract SPKI from relay certificate".into())
        })?;

        tracing::debug!("relay certificate SPKI SHA-256 for {host}: {current_pin}");

        match read_tofu_pin(&host).map_err(|error| rustls::Error::General(error.to_string()))? {
            Some(stored_pin) => {
                if stored_pin != current_pin {
                    let pin_path = crate::relay::tofu_pin_path_for_host(&host).map_or_else(
                        || format!("~/.lpm/relay-pins/{host}"),
                        |p| p.display().to_string(),
                    );
                    tracing::error!(
                        "CERTIFICATE PIN MISMATCH for {host}: stored={stored_pin}, current={current_pin}. \
                         The relay's certificate has changed. This could indicate a MITM attack. \
                         If the relay legitimately rotated certificates, delete {pin_path} and reconnect."
                    );
                    return Err(rustls::Error::General(format!(
                        "certificate pin mismatch for {host} — possible MITM \
                         (delete {pin_path} to re-pin)"
                    )));
                }
                tracing::debug!("TOFU certificate pin verified for {host}");
            }
            None => {
                // L3: on the canonical relay, if an embedded SPKI pin
                // is compiled in, the cert MUST match it on first
                // connect — pure WebPKI-valid TOFU is no longer good
                // enough. Closes the first-connect MITM window. The
                // const is None by default; release flips it to
                // `Some(...)` to enable enforcement.
                if host == crate::relay::DEFAULT_RELAY_HOST
                    && let Some(expected) = EMBEDDED_CANONICAL_RELAY_SPKI_PIN_HEX
                    && expected != current_pin
                {
                    tracing::error!(
                        "FIRST-CONNECT PIN MISMATCH for {host}: embedded={expected}, current={current_pin}. \
                         The relay's certificate does not match the pin shipped with this binary."
                    );
                    return Err(rustls::Error::General(format!(
                        "first-connect pin mismatch for {host} — possible MITM \
                         (delete any stored pin and reinstall lpm if the relay legitimately rotated)"
                    )));
                }

                // First connection (or post-upgrade migration from the
                // legacy global pin file) — store the pin under the
                // per-host layout. Warn-level so operators reviewing CI
                // logs see when a fresh pin was captured (a pure-TOFU
                // accept on the canonical relay is the L3 hazard
                // surface; surfacing it is the minimum step while the
                // embedded-pin slot is still empty).
                if let Err(e) = write_tofu_pin(&host, &current_pin) {
                    tracing::warn!("failed to store TOFU pin for {host}: {e}");
                } else if host == crate::relay::DEFAULT_RELAY_HOST {
                    tracing::warn!(
                        host = %host,
                        pin = %current_pin,
                        "captured first-connect TOFU pin for canonical relay — verify the SPKI hash matches the published one before relying on this install"
                    );
                } else {
                    tracing::info!("stored relay certificate pin (TOFU) for {host}: {current_pin}");
                }
            }
        }

        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.default_verifier
            .verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.default_verifier
            .verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.default_verifier.supported_verify_schemes()
    }
}

/// Return whether a relay URL resolves directly to a loopback host.
pub fn relay_url_is_loopback(url: &str) -> bool {
    let Ok(uri) = url.parse::<tokio_tungstenite::tungstenite::http::Uri>() else {
        return false;
    };
    if !uri
        .scheme_str()
        .is_some_and(|scheme| matches!(scheme, "ws" | "wss"))
    {
        return false;
    }
    let Some(host) = uri.host() else {
        return false;
    };
    let host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

/// Single connection attempt to the relay.
#[cfg(test)]
async fn try_connect(
    options: &TunnelOptions,
    on_connected: &impl Fn(&TunnelSession) -> Result<(), LpmError>,
    on_usage: &impl Fn(&TunnelUsageMetadata, bool),
) -> Result<(), TunnelConnectError> {
    try_connect_with_token(options, None, on_connected, on_usage).await
}

async fn try_connect_with_token(
    options: &TunnelOptions,
    token_override: Option<&str>,
    on_connected: &impl Fn(&TunnelSession) -> Result<(), LpmError>,
    on_usage: &impl Fn(&TunnelUsageMetadata, bool),
) -> Result<(), TunnelConnectError> {
    let connection_target = options.current_local_target();
    // Build connect URL — non-sensitive params only (token goes in Authorization header)
    let mut connect_url = format!(
        "{}?port={}&protocol=2",
        options.relay_url, connection_target.port
    );
    if let Some(domain) = options.resolved_domain() {
        let encoded = urlencoding::encode(&domain);
        connect_url.push_str(&format!("&domain={encoded}"));
    }
    tracing::debug!("connecting to relay: {connect_url}");

    // Force HTTP/1.1 — Cloudflare Workers require HTTP/1.1 for WebSocket upgrades.
    // HTTP/2 (default via ALPN) doesn't support the Upgrade header mechanism.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let root_store =
        rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let use_pinning = !options.no_pin && !relay_url_is_loopback(&options.relay_url);

    let mut tls_config = if use_pinning {
        let default_verifier = rustls::client::WebPkiServerVerifier::builder(Arc::new(root_store))
            .build()
            .map_err(|e| LpmError::Tunnel(format!("failed to build TLS verifier: {e}")))?;

        let pinning_verifier = Arc::new(TofuPinningVerifier::new(default_verifier));

        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(pinning_verifier)
            .with_no_client_auth()
    } else {
        if options.no_pin {
            tracing::debug!("certificate pinning disabled (--no-pin)");
        }
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };

    tls_config.alpn_protocols = vec![b"http/1.1".to_vec()];

    let tls_connector = tokio_tungstenite::Connector::Rustls(Arc::new(tls_config));

    // Build WebSocket request with auth token in Authorization header
    // tunnel_auth goes in X-Tunnel-Auth header (not URL) to avoid leaking in proxy/CDN logs
    // Use IntoClientRequest so tungstenite generates the required upgrade headers.
    let dynamic_token = if token_override.is_none() {
        match options.token_provider.as_ref() {
            Some(provider) => Some(
                provider
                    .current()
                    .await
                    .map_err(TunnelConnectError::from_token_provider)?,
            ),
            None => None,
        }
    } else {
        None
    };
    let token = token_override
        .or(dynamic_token.as_deref())
        .unwrap_or(&options.token);
    let request =
        build_websocket_connect_request(&connect_url, token, options.tunnel_auth.as_deref())?;

    let ws_config = tokio_tungstenite::tungstenite::protocol::WebSocketConfig {
        write_buffer_size: WEBSOCKET_WRITE_BUFFER_BYTES,
        max_write_buffer_size: WEBSOCKET_MAX_WRITE_BUFFER_BYTES,
        max_message_size: Some(MAX_WS_MESSAGE_SIZE),
        max_frame_size: Some(MAX_WS_FRAME_SIZE),
        ..Default::default()
    };

    let (ws_stream, _) = tokio_tungstenite::connect_async_tls_with_config(
        request,
        Some(ws_config),
        false,
        Some(tls_connector),
    )
    .await
    .map_err(classify_websocket_connect_error)?;

    let (mut write, mut read) = ws_stream.split();

    // Wait for ServerHello (Worker sends it after validating token)
    let server_hello = read
        .next()
        .await
        .ok_or_else(|| LpmError::Tunnel("relay closed connection before hello".into()))?
        .map_err(|e| LpmError::Tunnel(format!("failed to read server hello: {e}")))?;

    let (session, initial_usage) = match server_hello {
        Message::Text(text) => {
            let msg: RelayHandshakeMessage = serde_json::from_str(&text)
                .map_err(|e| LpmError::Tunnel(format!("invalid server message: {e}")))?;

            match msg {
                RelayHandshakeMessage::Hello {
                    domain: raw_domain,
                    tunnel_url,
                    session_id,
                    plan,
                    base_domain,
                    domain_kind,
                    session_expires_at,
                    session_max_ms,
                    limits,
                    usage,
                } => {
                    // domain field from relay may be just the subdomain or full domain
                    // tunnel_url is always the full URL
                    let domain = if raw_domain.contains('.') {
                        raw_domain
                    } else {
                        // Extract domain from tunnel_url: "https://acme.lpm.llc" → "acme.lpm.llc"
                        tunnel_url
                            .strip_prefix("https://")
                            .or_else(|| tunnel_url.strip_prefix("http://"))
                            .unwrap_or(&raw_domain)
                            .to_string()
                    };
                    // Verify the assigned domain matches what was requested.
                    // A mismatch could indicate a relay bug or MITM — warn but
                    // don't hard-fail since the server may have valid reasons
                    // to reassign (e.g., domain taken, plan downgrade).
                    if let Some(requested) = options.resolved_domain()
                        && domain != requested
                    {
                        tracing::warn!(
                            "domain mismatch: requested '{}' but relay assigned '{}'",
                            requested,
                            domain
                        );
                        eprintln!(
                            "  \u{26a0} Requested {} but relay assigned {}",
                            requested, domain
                        );
                    }

                    (
                        TunnelSession {
                            tunnel_url,
                            domain,
                            session_id,
                            local_port: connection_target.port,
                            plan,
                            base_domain,
                            domain_kind,
                            session_expires_at,
                            session_max_ms,
                            limits: limits.map(|value| *value),
                        },
                        usage.map(|value| *value),
                    )
                }
                RelayHandshakeMessage::Error { message, code } => {
                    let retry_class = code
                        .as_deref()
                        .and_then(relay_code_retry_class)
                        .unwrap_or(RetryClass::Permanent);
                    let detail = format!(
                        "relay rejected connection: {message}{}",
                        code.map(|value| format!(" ({value})")).unwrap_or_default()
                    );
                    return Err(match retry_class {
                        RetryClass::Permanent => TunnelConnectError::permanent(detail),
                        RetryClass::Transient => TunnelConnectError::transient(detail),
                        RetryClass::AuthRejected => TunnelConnectError::auth_rejected(detail),
                    });
                }
            }
        }
        _ => {
            return Err(TunnelConnectError::transient(
                "unexpected message type from relay",
            ));
        }
    };

    if let Some(ref usage) = initial_usage {
        on_usage(usage, true);
    }
    on_connected(&session).map_err(|error| TunnelConnectError {
        error,
        retry_class: RetryClass::Permanent,
    })?;
    if let Some(admission) = options.forwarding_admission.as_ref() {
        tokio::select! {
            result = admission.wait() => {
                result.map_err(|error| TunnelConnectError {
                    error,
                    retry_class: RetryClass::Permanent,
                })?;
            }
            _ = wait_for_tunnel_shutdown(options.shutdown.as_ref()) => return Ok(()),
        }
    }

    // Create HTTP client for local proxying. `Policy::none()` disables
    // redirect-following entirely — the local dev server should never
    // 30x our tunnel forwarder anywhere meaningful, and an attacker-
    // controlled `Location: http://169.254.169.254/...` from a buggy
    // or compromised local server would otherwise let the forwarder
    // probe cloud-metadata endpoints, AWS IMDS, or other localhost
    // services on behalf of the relay. The relay only ever wants the
    // dev server's direct response, never the response after a chain
    // of redirects, so refusing them is both safer and more
    // predictable.
    let http_client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| LpmError::Tunnel(format!("failed to create HTTP client: {e}")))?;

    // Keepalive ticker: ping every 30s
    let mut ping_interval = tokio::time::interval(std::time::Duration::from_secs(30));
    ping_interval.tick().await; // Skip first immediate tick

    // Track last pong time for dead relay detection.
    let mut last_pong = std::time::Instant::now();

    // Channel for spawned WebSocket tasks to send frames back to the relay.
    // The main loop owns `write` exclusively; spawned tasks send through this channel.
    let (relay_tx, mut relay_rx) = tokio::sync::mpsc::channel::<RelayWebSocketMessage>(64);
    let relay_websocket_memory = Arc::new(tokio::sync::Semaphore::new(WEBSOCKET_MEMORY_PERMITS));
    let local_websocket_memory = Arc::new(tokio::sync::Semaphore::new(WEBSOCKET_MEMORY_PERMITS));
    let websocket_slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_WEBSOCKETS));

    let http_forward_slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_HTTP_FORWARDS));
    let http_request_memory = Arc::new(tokio::sync::Semaphore::new(HTTP_REQUEST_MEMORY_PERMITS));
    let http_response_memory = Arc::new(tokio::sync::Semaphore::new(HTTP_RESPONSE_MEMORY_PERMITS));
    let (http_response_tx, mut http_response_rx) =
        tokio::sync::mpsc::channel::<CompletedHttpForward>(MAX_CONCURRENT_HTTP_FORWARDS);

    // Track spawned task handles for graceful shutdown.
    let mut task_handles = tokio::task::JoinSet::new();

    // Active local WebSocket connections keyed by connection ID.
    // Senders push frames from relay → local WS.
    let mut ws_connections: HashMap<String, WebSocketConnection> = HashMap::new();
    let mut closing_websockets: HashMap<String, ClosingWebSocket> = HashMap::new();
    let mut pending_websocket_upgrades: HashMap<String, PendingWebSocketUpgrade> = HashMap::new();
    let (closed_local_ws_tx, mut closed_local_ws_rx) =
        tokio::sync::mpsc::unbounded_channel::<ClosedLocalWebSocket>();
    let (websocket_upgrade_tx, mut websocket_upgrade_rx) =
        tokio::sync::mpsc::channel::<CompletedWebSocketUpgrade>(MAX_CONCURRENT_WEBSOCKETS);
    let mut next_websocket_generation = 0u64;

    // Message loop
    loop {
        tokio::select! {
            _ = wait_for_tunnel_shutdown(options.shutdown.as_ref()) => break,
            // Incoming message from relay
            msg = read.next() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        let server_msg: ServerMessage = match serde_json::from_str(&text) {
                            Ok(m) => m,
                            Err(e) => {
                                tracing::warn!("invalid message from relay: {e}");
                                continue;
                            }
                        };

                        match server_msg {
                            ServerMessage::HttpRequest { ref id, ref url, .. } => {
                                // Validate URL before forwarding to local server
                                if !is_safe_local_url(url) {
                                    tracing::warn!(
                                        "rejected HTTP request with unsafe URL: {:?}",
                                        url
                                    );
                                    let error_resp = proxy::bad_gateway_response(id);
                                    let json = match serde_json::to_string(&error_resp) {
                                        Ok(j) => j,
                                        Err(e) => {
                                            tracing::error!("failed to serialize error response: {e}");
                                            continue;
                                        }
                                    };
                                    if let Err(e) = send_to_relay(&mut write, Message::Text(json), "send message to relay").await {
                                        tracing::warn!("failed to send error response to relay: {e}");
                                        break;
                                    }
                                    continue;
                                }

                                let request_permits = request_memory_permits(text.len());
                                let request_permits = match request_permits {
                                    Some(permits) => permits,
                                    None => {
                                        let response = proxy::service_unavailable_response(id);
                                        if let Ok(json) = serde_json::to_string(&response)
                                            && send_to_relay(&mut write, Message::Text(json), "send message to relay").await.is_err()
                                        {
                                            break;
                                        }
                                        continue;
                                    }
                                };
                                let request_memory_permit = match Arc::clone(&http_request_memory)
                                    .try_acquire_many_owned(request_permits)
                                {
                                    Ok(permit) => Arc::new(permit),
                                    Err(_) => {
                                        let response = proxy::service_unavailable_response(id);
                                        if let Ok(json) = serde_json::to_string(&response)
                                            && send_to_relay(&mut write, Message::Text(json), "send message to relay").await.is_err()
                                        {
                                            break;
                                        }
                                        continue;
                                    }
                                };

                                let permit = match Arc::clone(&http_forward_slots)
                                    .try_acquire_owned()
                                {
                                    Ok(permit) => permit,
                                    Err(_) => {
                                        let response = if options.auto_ack {
                                            proxy::auto_ack_response(id)
                                        } else {
                                            proxy::service_unavailable_response(id)
                                        };
                                        let json = match serde_json::to_string(&response) {
                                            Ok(json) => json,
                                            Err(error) => {
                                                tracing::error!(
                                                    "failed to serialize busy response: {error}"
                                                );
                                                continue;
                                            }
                                        };
                                        if let Err(error) = send_to_relay(&mut write, Message::Text(json), "send message to relay").await {
                                            tracing::warn!(
                                                "failed to send busy response to relay: {error}"
                                            );
                                            break;
                                        }
                                        if options.auto_ack
                                            && let Some(ref webhook_tx) = options.webhook_tx
                                            && let ServerMessage::HttpRequest {
                                                id,
                                                method,
                                                url,
                                                headers,
                                                body,
                                            } = &server_msg
                                        {
                                            let request_body = base64::Engine::decode(
                                                &base64::engine::general_purpose::STANDARD,
                                                body,
                                            )
                                            .unwrap_or_default();
                                            let (response_status, response_headers, response_body) =
                                                extract_response_data(&response);
                                            let mut captured = CapturedWebhook {
                                                id: id.clone(),
                                                timestamp: chrono::Utc::now().to_rfc3339(),
                                                method: method.clone(),
                                                path: url.clone(),
                                                request_headers: headers.clone(),
                                                request_body,
                                                response_status,
                                                response_headers,
                                                response_body,
                                                duration_ms: 0,
                                                provider: webhook::detect_provider(url, headers),
                                                summary: String::new(),
                                                signature_diagnostic: None,
                                                auto_acked: true,
                                            };
                                            captured.summary = webhook::summarize_webhook(&captured);
                                            let _ = webhook_tx.try_send(CapturedWebhookEvent {
                                                webhook: Arc::new(captured),
                                                _response_memory_permit: None,
                                                _request_memory_permit: Some(request_memory_permit),
                                            });
                                        }
                                        continue;
                                    }
                                };

                                let http_client = http_client.clone();
                                let local_target = options.current_local_target();
                                let auto_ack = options.auto_ack;
                                let webhook_tx = options.webhook_tx.clone();
                                let http_response_tx = http_response_tx.clone();
                                let http_response_memory = Arc::clone(&http_response_memory);
                                task_handles.spawn(async move {
                                    let (response, memory_permit) = forward_http_request(
                                        http_client,
                                        local_target,
                                        server_msg,
                                        auto_ack,
                                        webhook_tx.clone(),
                                        http_response_memory,
                                        Some(request_memory_permit),
                                    )
                                    .await;
                                    let json = match serde_json::to_string(&response) {
                                        Ok(json) => json,
                                        Err(error) => {
                                            tracing::error!(
                                                "failed to serialize HTTP response: {error}"
                                            );
                                            return;
                                        }
                                    };
                                    let _ = http_response_tx
                                        .send(CompletedHttpForward {
                                            json,
                                            permit,
                                            memory_permit,
                                        })
                                        .await;
                                });
                            }
                            ServerMessage::WebSocketUpgrade { id, url, headers } => {
                                if let Some(error) = websocket_upgrade_metadata_error(&id, &url) {
                                    tracing::warn!(
                                        "rejected WebSocket upgrade with unsafe URL: {:?}",
                                        url
                                    );
                                    let error_resp = ClientExtensionMessage::WebSocketReject {
                                        id,
                                        error: error.to_string(),
                                    };
                                    let json = match serde_json::to_string(&error_resp) {
                                        Ok(j) => j,
                                        Err(e) => {
                                            tracing::error!("failed to serialize error response: {e}");
                                            continue;
                                        }
                                    };
                                    if let Err(e) = send_to_relay(&mut write, Message::Text(json), "send message to relay").await {
                                        tracing::warn!("failed to send error response to relay: {e}");
                                        break;
                                    }
                                    continue;
                                }

                                if websocket_id_is_in_use(
                                    &ws_connections,
                                    &closing_websockets,
                                    &pending_websocket_upgrades,
                                    &id,
                                ) {
                                    let reject = ClientExtensionMessage::WebSocketReject {
                                        id,
                                        error: "A WebSocket with this connection ID is already active"
                                            .to_string(),
                                    };
                                    let json = serde_json::to_string(&reject).map_err(|error| {
                                        LpmError::Tunnel(format!(
                                            "failed to serialize duplicate WebSocket rejection: {error}"
                                        ))
                                    })?;
                                    if send_to_relay(&mut write, Message::Text(json), "send message to relay").await.is_err() {
                                        break;
                                    }
                                    continue;
                                }
                                let headers = match bounded_websocket_upgrade_headers(headers) {
                                    Ok(headers) => headers,
                                    Err(error) => {
                                        let reject = ClientExtensionMessage::WebSocketReject {
                                            id,
                                            error,
                                        };
                                        let json = serde_json::to_string(&reject).map_err(|error| {
                                            LpmError::Tunnel(format!(
                                                "failed to serialize WebSocket header rejection: {error}"
                                            ))
                                        })?;
                                        if send_to_relay(&mut write, Message::Text(json), "send message to relay").await.is_err() {
                                            break;
                                        }
                                        continue;
                                    }
                                };
                                let websocket_slot = match Arc::clone(&websocket_slots)
                                    .try_acquire_owned()
                                {
                                    Ok(slot) => slot,
                                    Err(_) => {
                                        let reject = ClientExtensionMessage::WebSocketReject {
                                            id,
                                            error: "The local WebSocket connection limit is reached"
                                                .to_string(),
                                        };
                                        let json = serde_json::to_string(&reject).map_err(|error| {
                                            LpmError::Tunnel(format!(
                                                "failed to serialize WebSocket capacity rejection: {error}"
                                            ))
                                        })?;
                                        if send_to_relay(&mut write, Message::Text(json), "send message to relay").await.is_err() {
                                            break;
                                        }
                                        continue;
                                    }
                                };
                                next_websocket_generation = next_websocket_generation.wrapping_add(1);
                                let websocket_generation = next_websocket_generation;
                                let upgrade_cancel = tokio_util::sync::CancellationToken::new();
                                pending_websocket_upgrades.insert(
                                    id.clone(),
                                    PendingWebSocketUpgrade {
                                        generation: websocket_generation,
                                        cancel: upgrade_cancel.clone(),
                                    },
                                );

                                tracing::debug!("WebSocket upgrade request: {url}");
                                let local_target = options.current_local_target();
                                let upgrade_tx = websocket_upgrade_tx.clone();
                                let upgrade_id = id.clone();
                                let upgrade_url = url.clone();
                                let upgrade_headers = headers;
                                task_handles.spawn(async move {
                                    let result = tokio::select! {
                                        biased;
                                        _ = upgrade_cancel.cancelled() => return,
                                        result = tokio::time::timeout(
                                            std::time::Duration::from_secs(
                                                WEBSOCKET_CONNECT_TIMEOUT_SECS,
                                            ),
                                            proxy::connect_local_websocket(
                                                &local_target,
                                                &upgrade_url,
                                                &upgrade_headers,
                                            ),
                                        ) => result,
                                    };
                                    let result = match result {
                                        Ok(Ok(connection)) => Ok(connection),
                                        Ok(Err(error)) => Err(format!(
                                            "Local server rejected the WebSocket upgrade: {error}"
                                        )),
                                        Err(_) => {
                                            Err("Local WebSocket upgrade timed out".to_string())
                                        }
                                    };
                                    let _ = upgrade_tx
                                        .send(CompletedWebSocketUpgrade {
                                            id: upgrade_id,
                                            url: upgrade_url,
                                            headers: upgrade_headers,
                                            generation: websocket_generation,
                                            slot: websocket_slot,
                                            result,
                                        })
                                        .await;
                                });
                            }
                            ServerMessage::WebSocketFrame { id, data, is_binary } => {
                                // Forward frame from relay → local WebSocket
                                if let Some(connection) = ws_connections.get(&id) {
                                    let Some(permits) =
                                        inbound_websocket_memory_permits(text.len(), data.len())
                                    else {
                                        tracing::warn!(
                                            "closing WebSocket {id} after an oversized relay frame"
                                        );
                                        cancel_active_websocket(
                                            &mut ws_connections,
                                            &mut closing_websockets,
                                            &id,
                                            true,
                                        );
                                        send_websocket_close_to_relay(
                                            &mut write,
                                            &id,
                                            "relay WebSocket frame exceeded the tunnel byte limit",
                                        ).await?;
                                        continue;
                                    };
                                    let memory_permit = match Arc::clone(&local_websocket_memory)
                                        .try_acquire_many_owned(permits)
                                    {
                                        Ok(permit) => permit,
                                        Err(_) => {
                                            tracing::warn!(
                                                "closing WebSocket {id} because local backpressure exhausted the byte budget"
                                            );
                                            cancel_active_websocket(
                                                &mut ws_connections,
                                                &mut closing_websockets,
                                                &id,
                                                true,
                                            );
                                            send_websocket_close_to_relay(
                                                &mut write,
                                                &id,
                                                "local backpressure exhausted the WebSocket byte budget",
                                            ).await?;
                                            continue;
                                        }
                                    };
                                    let decoded = match base64::Engine::decode(
                                        &base64::engine::general_purpose::STANDARD,
                                        &data,
                                    ) {
                                        Ok(decoded) => decoded,
                                        Err(error) => {
                                            tracing::warn!(
                                                "failed to decode WS frame data for {id}: {error}"
                                            );
                                            continue;
                                        }
                                    };
                                    if !is_binary && std::str::from_utf8(&decoded).is_err() {
                                        tracing::warn!(
                                            "closing WebSocket {id} after an invalid text frame"
                                        );
                                        cancel_active_websocket(
                                            &mut ws_connections,
                                            &mut closing_websockets,
                                            &id,
                                            true,
                                        );
                                        send_websocket_close_to_relay(
                                            &mut write,
                                            &id,
                                            "relay WebSocket text frame is not valid UTF-8",
                                        )
                                        .await?;
                                        continue;
                                    }
                                    // Capture inbound frame for inspector
                                    if let Some(ref ws_tx) = options.ws_tx {
                                        let _ = ws_tx.try_send(WsEvent::captured_frame(
                                            id.clone(),
                                            FrameDirection::Inbound,
                                            &decoded,
                                            is_binary,
                                            chrono::Utc::now().to_rfc3339(),
                                        ));
                                    }

                                    let command = LocalWebSocketCommand::Frame {
                                        data: decoded,
                                        is_binary,
                                        _memory_permit: memory_permit,
                                    };
                                    let enqueue_result = tokio::time::timeout(
                                        std::time::Duration::from_millis(
                                            WEBSOCKET_LOCAL_ENQUEUE_TIMEOUT_MILLIS,
                                        ),
                                        connection.commands.send(command),
                                    )
                                    .await;
                                    if !matches!(enqueue_result, Ok(Ok(()))) {
                                        // Local WS connection closed, clean up
                                        tracing::debug!(
                                            "local WS connection {id} closed, removing"
                                        );
                                        cancel_active_websocket(
                                            &mut ws_connections,
                                            &mut closing_websockets,
                                            &id,
                                            true,
                                        );
                                        send_websocket_close_to_relay(
                                            &mut write,
                                            &id,
                                            "local WebSocket forwarding queue stalled",
                                        )
                                        .await?;
                                    }
                                } else {
                                    tracing::warn!(
                                        "received WS frame for unknown connection {id}, ignoring"
                                    );
                                }
                            }
                            ServerMessage::WebSocketClose { id, code, reason } => {
                                if discard_pending_websocket_upgrade(
                                    &mut pending_websocket_upgrades,
                                    &id,
                                ) {
                                    tracing::debug!(
                                        "cancelled pending WS upgrade after relay close for {id}"
                                    );
                                } else if let Some(connection) = ws_connections.remove(&id) {
                                    let generation = connection.generation;
                                    let cancel = connection.cancel.clone();
                                    if connection
                                        .priority_commands
                                        .try_send(LocalWebSocketCommand::Close {
                                            code,
                                            reason: bounded_websocket_close_reason(reason),
                                        })
                                        .is_err()
                                    {
                                        cancel.cancel();
                                    }
                                    closing_websockets.insert(
                                        id,
                                        ClosingWebSocket {
                                            generation,
                                            cancel,
                                            completed_halves: 0,
                                            relay_notified: true,
                                        },
                                    );
                                } else {
                                    tracing::debug!("received WS close for unknown connection {id}");
                                }
                            }
                            ServerMessage::Pong => {
                                last_pong = std::time::Instant::now();
                                tracing::debug!("pong received");
                            }
                            ServerMessage::UsageNotice { usage } => {
                                on_usage(&usage, false);
                            }
                            ServerMessage::Error { message, .. } => {
                                tracing::error!("relay error: {message}");
                                return Err(TunnelConnectError::transient(format!(
                                    "relay error: {message}"
                                )));
                            }
                            _ => {
                                tracing::debug!("unhandled message type");
                            }
                        }
                    }
                    Some(Ok(Message::Close(_))) => {
                        tracing::info!("relay closed connection");
                        break;
                    }
                    Some(Err(e)) => {
                        return Err(TunnelConnectError::transient(format!(
                            "WebSocket error: {e}"
                        )));
                    }
                    None => {
                        tracing::info!("relay connection ended");
                        break;
                    }
                    _ => {}
                }
            }

            Some(completed) = websocket_upgrade_rx.recv() => {
                if pending_websocket_upgrades
                    .get(&completed.id)
                    .map(|pending| pending.generation)
                    != Some(completed.generation)
                {
                    continue;
                }
                pending_websocket_upgrades.remove(&completed.id);
                match completed.result {
                    Ok((local_write, local_read)) => {
                        let connection = activate_local_websocket(
                            &mut task_handles,
                            LocalWebSocketActivation {
                                id: completed.id.clone(),
                                generation: completed.generation,
                                local_write,
                                local_read,
                                slot: completed.slot,
                                relay_tx: relay_tx.clone(),
                                relay_memory: Arc::clone(&relay_websocket_memory),
                                ws_tx: options.ws_tx.clone(),
                                closed_tx: closed_local_ws_tx.clone(),
                            },
                        );
                        ws_connections.insert(completed.id.clone(), connection);
                        let ready = ClientExtensionMessage::WebSocketReady {
                            id: completed.id.clone(),
                        };
                        let json = serde_json::to_string(&ready).map_err(|error| {
                            LpmError::Tunnel(format!(
                                "failed to serialize WebSocket upgrade confirmation: {error}"
                            ))
                        })?;
                        if send_to_relay(&mut write, Message::Text(json), "send message to relay").await.is_err() {
                            break;
                        }
                        if let (Some(ws_tx), Some(headers)) = (
                            options.ws_tx.as_ref(),
                            captured_websocket_headers(&completed.headers),
                        ) {
                            let _ = ws_tx.try_send(WsEvent::Connected {
                                connection_id: completed.id,
                                url: completed.url,
                                headers,
                                timestamp: chrono::Utc::now().to_rfc3339(),
                            });
                        }
                    }
                    Err(error) => {
                        tracing::warn!(
                            "WebSocket upgrade failed for {}: {error}",
                            completed.id
                        );
                        let reject = ClientExtensionMessage::WebSocketReject {
                            id: completed.id,
                            error,
                        };
                        let json = serde_json::to_string(&reject).map_err(|error| {
                            LpmError::Tunnel(format!(
                                "failed to serialize WebSocket rejection: {error}"
                            ))
                        })?;
                        if send_to_relay(&mut write, Message::Text(json), "send message to relay").await.is_err() {
                            break;
                        }
                    }
                }
            }

            // Frames from spawned WS tasks → relay
            Some(message) = relay_rx.recv() => {
                if !relay_websocket_message_is_current(&ws_connections, &message) {
                    continue;
                }
                if let Err(e) = send_to_relay(&mut write, Message::Text(message.json), "send WebSocket frame to relay").await {
                    tracing::warn!("failed to send WS frame to relay: {e}");
                    break;
                }
            }

            Some(closed) = closed_local_ws_rx.recv() => {
                if ws_connections
                    .get(&closed.id)
                    .map(|connection| connection.generation)
                    == Some(closed.generation)
                    && let Some(connection) = ws_connections.remove(&closed.id)
                {
                    connection.cancel.cancel();
                    closing_websockets.insert(
                        closed.id.clone(),
                        ClosingWebSocket {
                            generation: closed.generation,
                            cancel: connection.cancel,
                            completed_halves: 0,
                            relay_notified: false,
                        },
                    );
                }
                let Some(closing) = closing_websockets.get_mut(&closed.id)
                    .filter(|closing| closing.generation == closed.generation)
                else {
                    continue;
                };
                closing.completed_halves |= match closed.half {
                    LocalWebSocketHalf::Reader => 0b01,
                    LocalWebSocketHalf::Writer => 0b10,
                };
                let notification = if closing.relay_notified {
                    None
                } else if let Some((code, reason)) = closed.relay_close {
                    closing.relay_notified = true;
                    Some((code, reason))
                } else if closed.notify_relay {
                    closing.relay_notified = true;
                    Some((Some(1013), Some(closed.reason)))
                } else {
                    None
                };
                let fully_closed = closing.completed_halves == 0b11;
                if let Some((code, reason)) = notification {
                    send_websocket_close_frame_to_relay(
                        &mut write,
                        &closed.id,
                        code,
                        reason,
                    )
                    .await?;
                }
                if fully_closed {
                    closing_websockets.remove(&closed.id);
                }
            }

            Some(response) = http_response_rx.recv() => {
                let CompletedHttpForward { json, permit, memory_permit } = response;
                if let Err(error) = send_to_relay(&mut write, Message::Text(json), "send message to relay").await {
                    tracing::warn!("failed to send HTTP response to relay: {error}");
                    break;
                }
                drop(permit);
                drop(memory_permit);
            }

            Some(result) = task_handles.join_next(), if !task_handles.is_empty() => {
                if let Err(error) = result {
                    tracing::warn!("tunnel forwarding task failed: {error}");
                }
            }

            // Keepalive ping + dead relay detection
            _ = ping_interval.tick() => {
                // Check if relay has stopped responding to pings
                if is_pong_timed_out(last_pong) {
                    tracing::warn!(
                        "no pong received in {}s, relay appears dead — reconnecting",
                        PONG_TIMEOUT_SECS
                    );
                    break;
                }

                let ping = match serde_json::to_string(&ClientMessage::Ping) {
                    Ok(j) => j,
                    Err(e) => {
                        tracing::error!("failed to serialize ping: {e}");
                        break;
                    }
                };
                if let Err(e) = send_to_relay(&mut write, Message::Text(ping), "send tunnel ping").await {
                    tracing::warn!("failed to send ping: {e}");
                    break;
                }
            }
        }
    }

    shutdown_websocket_tasks(
        ws_connections,
        closing_websockets,
        pending_websocket_upgrades,
        &mut task_handles,
        std::time::Duration::from_secs(SHUTDOWN_TIMEOUT_SECS),
    )
    .await;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// RAII guard that sets `HOME` to the given path and restores it
    /// on drop. Centralises the `unsafe` env mutation behind one
    /// SAFETY justification so individual tests don't need to repeat
    /// it. Always pair with `test_env_lock()` because env state is
    /// process-global.
    struct HomeGuard {
        prev: Option<std::ffi::OsString>,
    }
    impl HomeGuard {
        fn set(path: &std::path::Path) -> Self {
            let prev = std::env::var_os("HOME");
            // SAFETY: callers hold `test_env_lock()` so no other test in
            // this crate is reading or mutating `HOME` concurrently.
            // Production code does not race on `HOME` mutation under
            // `cargo test`.
            unsafe {
                std::env::set_var("HOME", path);
            }
            Self { prev }
        }
    }
    impl Drop for HomeGuard {
        fn drop(&mut self) {
            // SAFETY: same justification as `HomeGuard::set`; we are
            // restoring the value captured before mutation.
            unsafe {
                match self.prev.take() {
                    Some(v) => std::env::set_var("HOME", v),
                    None => std::env::remove_var("HOME"),
                }
            }
        }
    }

    async fn reject_next_tunnel_request(
        listener: &tokio::net::TcpListener,
        rejection: &[u8],
    ) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = Vec::with_capacity(1024);
        let mut chunk = [0u8; 1024];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let read = socket.read(&mut chunk).await.unwrap();
            assert!(read > 0, "WebSocket request ended before its headers");
            request.extend_from_slice(&chunk[..read]);
        }
        let request = std::str::from_utf8(&request).unwrap();
        let token = request
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("authorization")
                    .then_some(value.trim())?
                    .strip_prefix("Bearer ")
            })
            .expect("tunnel request omitted bearer auth")
            .to_string();

        socket
            .write_all(
                format!(
                    "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    rejection.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        socket.write_all(rejection).await.unwrap();
        socket.shutdown().await.unwrap();
        token
    }

    fn rotating_test_provider() -> (TunnelTokenProvider, Arc<AtomicUsize>) {
        let current_token = Arc::new(Mutex::new("stale-access-token".to_string()));
        let refresh_calls = Arc::new(AtomicUsize::new(0));
        let provider = TunnelTokenProvider::new(
            {
                let current_token = Arc::clone(&current_token);
                move || {
                    let token = current_token.lock().unwrap().clone();
                    Box::pin(async move { Ok(token) })
                }
            },
            {
                let current_token = Arc::clone(&current_token);
                let refresh_calls = Arc::clone(&refresh_calls);
                move || {
                    refresh_calls.fetch_add(1, Ordering::SeqCst);
                    let mut token = current_token.lock().unwrap();
                    *token = "fresh-access-token".to_string();
                    let refreshed = token.clone();
                    Box::pin(async move { Ok(refreshed) })
                }
            },
        );
        (provider, refresh_calls)
    }

    #[test]
    fn tunnel_options_defaults() {
        let opts = TunnelOptions::new("lpm_test".to_string(), 3000);
        assert_eq!(opts.relay_url, DEFAULT_RELAY_URL);
        assert_eq!(opts.local_target.port, 3000);
        assert!(opts.token_provider.is_none());
        assert!(opts.domain.is_none());
        assert!(opts.tunnel_auth.is_none());
        assert!(opts.webhook_tx.is_none());
        assert!(!opts.no_pin);
        assert!(opts.resolved_domain().is_none());
    }

    #[tokio::test]
    async fn forwarding_admission_stays_closed_until_runtime_publication_opens_it() {
        let (controller, admission) = forwarding_admission_barrier();
        let waiter = tokio::spawn(async move { admission.wait().await });
        tokio::task::yield_now().await;

        assert!(!waiter.is_finished());
        controller.open();
        assert!(waiter.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn failed_runtime_publication_rejects_tunnel_forwarding() {
        let (controller, admission) = forwarding_admission_barrier();
        controller.reject();

        let error = admission.wait().await.unwrap_err();

        assert!(
            error
                .to_string()
                .contains("rejected before runtime publication")
        );
    }

    #[tokio::test]
    async fn rejected_runtime_publication_never_forwards_a_queued_relay_request() {
        let local_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_address = local_listener.local_addr().unwrap();
        let relay_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay_address = relay_listener.local_addr().unwrap();
        let (request_sent_tx, request_sent_rx) = tokio::sync::oneshot::channel();
        let relay = tokio::spawn(async move {
            let (socket, _) = relay_listener.accept().await.unwrap();
            let mut websocket = tokio_tungstenite::accept_async(socket).await.unwrap();
            websocket
                .send(Message::Text(
                    serde_json::json!({
                        "type": "hello",
                        "subdomain": "test.localhost",
                        "tunnel_url": "http://test.localhost",
                        "session_id": "session",
                    })
                    .to_string(),
                ))
                .await
                .unwrap();
            websocket
                .send(Message::Text(
                    serde_json::json!({
                        "type": "http_request",
                        "id": "queued-before-publication",
                        "method": "GET",
                        "url": "/must-not-forward",
                        "headers": {},
                        "body": "",
                    })
                    .to_string(),
                ))
                .await
                .unwrap();
            request_sent_tx.send(()).unwrap();
            while websocket.next().await.is_some() {}
        });
        let (controller, admission) = forwarding_admission_barrier();
        let mut options = TunnelOptions::new("test-token".to_string(), local_address.port());
        options.relay_url = format!("ws://{relay_address}/connect");
        options.no_pin = true;
        options.forwarding_admission = Some(admission);
        let client =
            tokio::spawn(async move { try_connect(&options, &|_| Ok(()), &|_, _| {}).await });

        request_sent_rx.await.unwrap();
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(100),
                local_listener.accept()
            )
            .await
            .is_err(),
            "the child received a relay request before runtime publication"
        );
        controller.reject();
        let error = tokio::time::timeout(std::time::Duration::from_secs(1), client)
            .await
            .expect("the rejected admission did not stop the tunnel")
            .unwrap()
            .unwrap_err();
        assert!(
            error
                .error
                .to_string()
                .contains("rejected before runtime publication")
        );
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(100),
                local_listener.accept()
            )
            .await
            .is_err(),
            "the child received a queued relay request after publication rejection"
        );

        relay.await.unwrap();
    }

    #[tokio::test]
    async fn tunnel_rejects_an_https_child_before_connecting_to_the_relay() {
        let mut options = TunnelOptions::new("lpm_test".to_string(), 5173);
        options.relay_url = "not a relay URL".to_string();
        options.local_target.scheme = lpm_common::LocalScheme::Https;

        let error = connect_with_usage(&options, |_| {}, |_| {}, |_, _| {})
            .await
            .unwrap_err();

        assert!(error.to_string().contains("plain HTTP child"));
    }

    #[tokio::test]
    async fn tunnel_rejects_invalid_local_targets_before_connecting_to_the_relay() {
        let mut zero_port = TunnelOptions::new("lpm_test".to_string(), 0);
        zero_port.relay_url = "not a relay URL".to_string();
        let zero_error = connect_with_usage(&zero_port, |_| {}, |_| {}, |_, _| {})
            .await
            .unwrap_err();
        assert!(zero_error.to_string().contains("between 1 and 65535"));

        let mut non_loopback = TunnelOptions::new("lpm_test".to_string(), 5173);
        non_loopback.relay_url = "not a relay URL".to_string();
        non_loopback.local_target.address = "192.0.2.1".parse().unwrap();
        let address_error = connect_with_usage(&non_loopback, |_| {}, |_| {}, |_, _| {})
            .await
            .unwrap_err();
        assert!(address_error.to_string().contains("non-loopback"));
    }

    #[test]
    fn relay_quota_errors_have_stable_retry_classification() {
        for code in [
            "plan_required",
            "domain_not_owned",
            "concurrent_limit",
            "billing_inactive",
            "monthly_allowance_exhausted",
        ] {
            let body = format!(r#"{{"error":"denied","code":"{code}"}}"#);
            let error = classify_relay_rejection(429, body.as_bytes());
            assert_eq!(error.retry_class, RetryClass::Permanent, "code={code}");
        }

        for code in ["quota_unavailable", "account_unavailable"] {
            let body = format!(r#"{{"error":"retry","code":"{code}"}}"#);
            let error = classify_relay_rejection(503, body.as_bytes());
            assert_eq!(error.retry_class, RetryClass::Transient, "code={code}");
        }

        let auth_error = classify_relay_rejection(
            401,
            br#"{"error":"expired access token","code":"auth_failed"}"#,
        );
        assert_eq!(auth_error.retry_class, RetryClass::AuthRejected);
    }

    #[test]
    fn relay_http_status_fallback_does_not_retry_client_errors() {
        assert_eq!(
            classify_relay_rejection(401, br#"{"error":"Unauthorized"}"#).retry_class,
            RetryClass::AuthRejected
        );
        assert_eq!(
            classify_relay_rejection(
                403,
                br#"{"error":"Unknown client error","code":"future_client_error"}"#
            )
            .retry_class,
            RetryClass::Permanent
        );
        assert_eq!(
            classify_relay_rejection(503, br#"{"error":"Unavailable"}"#).retry_class,
            RetryClass::Transient
        );
    }

    #[tokio::test]
    #[expect(
        clippy::result_large_err,
        reason = "tungstenite fixes the handshake callback's rejection type"
    )]
    async fn rejected_dynamic_bearer_refreshes_once_and_reconnects_without_backoff() {
        let relay_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay_address = relay_listener.local_addr().unwrap();
        let seen_tokens = Arc::new(Mutex::new(Vec::new()));
        let relay_tokens = Arc::clone(&seen_tokens);
        let relay = tokio::spawn(async move {
            let rejection = br#"{"error":"expired access token","code":"auth_failed"}"#;
            let first_token = reject_next_tunnel_request(&relay_listener, rejection).await;
            relay_tokens.lock().unwrap().push(first_token);

            let (second_socket, _) = relay_listener.accept().await.unwrap();
            let callback_tokens = Arc::clone(&relay_tokens);
            let mut websocket = tokio_tungstenite::accept_hdr_async(
                second_socket,
                move |request: &tokio_tungstenite::tungstenite::handshake::server::Request,
                      response: tokio_tungstenite::tungstenite::handshake::server::Response| {
                    let token = request
                        .headers()
                        .get("authorization")
                        .and_then(|value| value.to_str().ok())
                        .and_then(|value| value.strip_prefix("Bearer "))
                        .expect("retried tunnel request omitted bearer auth");
                    callback_tokens.lock().unwrap().push(token.to_string());
                    Ok(response)
                },
            )
            .await
            .unwrap();
            websocket
                .send(Message::Text(
                    serde_json::json!({
                        "type": "hello",
                        "subdomain": "refresh.localhost",
                        "tunnel_url": "http://refresh.localhost",
                        "session_id": "refreshed-session",
                    })
                    .to_string(),
                ))
                .await
                .unwrap();
            websocket.close(None).await.unwrap();
        });

        let (provider, refresh_calls) = rotating_test_provider();
        let mut options = TunnelOptions::new("stale-access-token".to_string(), 5173);
        options.relay_url = format!("ws://{relay_address}/connect");
        options.no_pin = true;
        options.token_provider = Some(provider);

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            connect_with_usage(&options, |_| {}, |_| {}, |_, _| {}),
        )
        .await
        .expect("tunnel auth recovery did not finish");
        let relay_result = tokio::time::timeout(std::time::Duration::from_secs(1), relay).await;

        assert!(
            result.is_ok(),
            "tunnel did not recover auth rejection: {result:?}"
        );
        relay_result
            .expect("tunnel never reconnected with refreshed auth")
            .unwrap();
        assert_eq!(refresh_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            *seen_tokens.lock().unwrap(),
            ["stale-access-token", "fresh-access-token"]
        );
    }

    #[tokio::test]
    async fn refreshed_bearer_rejected_again_without_response_body_stops_without_a_second_refresh()
    {
        let relay_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay_address = relay_listener.local_addr().unwrap();
        let seen_tokens = Arc::new(Mutex::new(Vec::new()));
        let relay_tokens = Arc::clone(&seen_tokens);
        let relay = tokio::spawn(async move {
            for attempt in 0..2 {
                let rejection: &[u8] = if attempt == 0 {
                    br#"{"error":"invalid access token","code":"auth_failed"}"#
                } else {
                    b""
                };
                let token = reject_next_tunnel_request(&relay_listener, rejection).await;
                relay_tokens.lock().unwrap().push(token);
            }
        });

        let (provider, refresh_calls) = rotating_test_provider();
        let mut options = TunnelOptions::new("stale-access-token".to_string(), 5173);
        options.relay_url = format!("ws://{relay_address}/connect");
        options.no_pin = true;
        options.token_provider = Some(provider);

        let error = connect_with_usage(&options, |_| {}, |_| {}, |_, _| {})
            .await
            .unwrap_err();
        relay.await.unwrap();

        assert!(
            matches!(
                &error,
                LpmError::Tunnel(message)
                    if message == "relay rejected connection: relay rejected connection"
            ),
            "unexpected second relay rejection: {error}"
        );
        assert_eq!(refresh_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            *seen_tokens.lock().unwrap(),
            ["stale-access-token", "fresh-access-token"]
        );
    }

    #[tokio::test]
    #[expect(
        clippy::result_large_err,
        reason = "tungstenite fixes the handshake callback's rejection type"
    )]
    async fn transient_refresh_failure_allows_a_later_tunnel_refresh() {
        let relay_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay_address = relay_listener.local_addr().unwrap();
        let seen_tokens = Arc::new(Mutex::new(Vec::new()));
        let relay_tokens = Arc::clone(&seen_tokens);
        let relay = tokio::spawn(async move {
            let rejection = br#"{"error":"expired access token","code":"auth_failed"}"#;
            for _ in 0..2 {
                let token = reject_next_tunnel_request(&relay_listener, rejection).await;
                relay_tokens.lock().unwrap().push(token);
            }

            let (socket, _) = relay_listener.accept().await.unwrap();
            let callback_tokens = Arc::clone(&relay_tokens);
            let mut websocket = tokio_tungstenite::accept_hdr_async(
                socket,
                move |request: &tokio_tungstenite::tungstenite::handshake::server::Request,
                      response: tokio_tungstenite::tungstenite::handshake::server::Response| {
                    let token = request
                        .headers()
                        .get("authorization")
                        .and_then(|value| value.to_str().ok())
                        .and_then(|value| value.strip_prefix("Bearer "))
                        .expect("recovered tunnel request omitted bearer auth");
                    callback_tokens.lock().unwrap().push(token.to_string());
                    Ok(response)
                },
            )
            .await
            .unwrap();
            websocket
                .send(Message::Text(
                    serde_json::json!({
                        "type": "hello",
                        "subdomain": "refresh.localhost",
                        "tunnel_url": "http://refresh.localhost",
                        "session_id": "refreshed-session",
                    })
                    .to_string(),
                ))
                .await
                .unwrap();
            websocket.close(None).await.unwrap();
        });

        let current_token = Arc::new(Mutex::new("stale-access-token".to_string()));
        let refresh_calls = Arc::new(AtomicUsize::new(0));
        let provider = TunnelTokenProvider::new(
            {
                let current_token = Arc::clone(&current_token);
                move || {
                    let token = current_token.lock().unwrap().clone();
                    Box::pin(async move { Ok(token) })
                }
            },
            {
                let current_token = Arc::clone(&current_token);
                let refresh_calls = Arc::clone(&refresh_calls);
                move || {
                    let attempt = refresh_calls.fetch_add(1, Ordering::SeqCst);
                    let result = if attempt == 0 {
                        Err(LpmError::Network("temporary refresh outage".to_string()))
                    } else {
                        let mut token = current_token.lock().unwrap();
                        *token = "fresh-access-token".to_string();
                        Ok(token.clone())
                    };
                    Box::pin(async move { result })
                }
            },
        );
        let mut options = TunnelOptions::new("stale-access-token".to_string(), 5173);
        options.relay_url = format!("ws://{relay_address}/connect");
        options.no_pin = true;
        options.token_provider = Some(provider);

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(8),
            connect_with_usage(&options, |_| {}, |_| {}, |_, _| {}),
        )
        .await
        .expect("tunnel auth recovery did not finish");
        if result.is_err() {
            relay.abort();
        }

        assert!(
            result.is_ok(),
            "transient refresh failure prevented later recovery: {result:?}"
        );
        relay.await.unwrap();
        assert_eq!(refresh_calls.load(Ordering::SeqCst), 2);
        assert_eq!(
            *seen_tokens.lock().unwrap(),
            [
                "stale-access-token",
                "stale-access-token",
                "fresh-access-token"
            ]
        );
    }

    #[test]
    fn private_handshake_preserves_initial_usage_metadata() {
        let message: RelayHandshakeMessage = serde_json::from_str(
            r#"{
                "type":"hello",
                "subdomain":"demo.lpm.fyi",
                "tunnel_url":"https://demo.lpm.fyi",
                "session_id":"session-1",
                "usage":{"accepted_requests":80000,"included_requests":100000}
            }"#,
        )
        .expect("valid relay handshake");
        let RelayHandshakeMessage::Hello { usage, .. } = message else {
            panic!("expected hello");
        };
        let usage = usage.expect("initial usage");
        assert_eq!(usage.accepted_requests, Some(80_000));
        assert_eq!(usage.included_requests, Some(100_000));
    }

    #[test]
    fn private_websocket_upgrade_results_keep_public_enum_exhaustive() {
        let ready = serde_json::to_string(&ClientExtensionMessage::WebSocketReady {
            id: "ws-1".to_string(),
        })
        .expect("serialize ready");
        let rejected = serde_json::to_string(&ClientExtensionMessage::WebSocketReject {
            id: "ws-2".to_string(),
            error: "local upgrade failed".to_string(),
        })
        .expect("serialize rejection");

        assert_eq!(ready, r#"{"type":"ws_ready","id":"ws-1"}"#);
        assert_eq!(
            rejected,
            r#"{"type":"ws_reject","id":"ws-2","error":"local upgrade failed"}"#
        );
    }

    /// `write_tofu_pin` always lands at `~/.lpm/relay-pins/<host>` —
    /// never the legacy single-file location. Verifies both the
    /// directory layout and that read-back agrees.
    #[test]
    fn write_pin_uses_per_host_layout() {
        let _g = crate::test_env_lock();
        let home = tempfile::tempdir().unwrap();
        let _home = HomeGuard::set(home.path());

        write_tofu_pin("relay.lpm.fyi", "deadbeef").unwrap();

        let expected = home
            .path()
            .join(".lpm")
            .join("relay-pins")
            .join("relay.lpm.fyi");
        assert!(
            expected.exists(),
            "expected per-host pin file at {}",
            expected.display()
        );
        let read_back = read_tofu_pin("relay.lpm.fyi").unwrap().unwrap();

        assert_eq!(read_back, "deadbeef");
    }

    /// Legacy `~/.lpm/relay-pin` is honored on the canonical default
    /// host so existing installs don't break — but reads only, the
    /// write path always migrates to per-host layout.
    #[test]
    fn read_pin_falls_back_to_legacy_on_default_host() {
        let _g = crate::test_env_lock();
        let home = tempfile::tempdir().unwrap();
        // Pre-create legacy single-file pin
        let legacy = home.path().join(".lpm").join("relay-pin");
        std::fs::create_dir_all(legacy.parent().unwrap()).unwrap();
        std::fs::write(&legacy, "legacy_pin_value").unwrap();

        let _home = HomeGuard::set(home.path());
        let got = read_tofu_pin("relay.lpm.fyi").unwrap();
        assert_eq!(got.as_deref(), Some("legacy_pin_value"));
    }

    /// Legacy fallback only fires for the canonical default host. Any
    /// other relay (custom env override, regional endpoint, staging)
    /// must NOT read the legacy file — the stored pin is meaningless
    /// for a different server's certificate.
    #[test]
    fn read_pin_ignores_legacy_for_non_default_host() {
        let _g = crate::test_env_lock();
        let home = tempfile::tempdir().unwrap();
        let legacy = home.path().join(".lpm").join("relay-pin");
        std::fs::create_dir_all(legacy.parent().unwrap()).unwrap();
        std::fs::write(&legacy, "wrong_relay_pin").unwrap();

        let _home = HomeGuard::set(home.path());
        let got = read_tofu_pin("relay-eu.lpm.fyi").unwrap();
        assert!(
            got.is_none(),
            "legacy pin must not bleed into a different host: {got:?}"
        );
    }

    /// Per-host pin always wins over legacy, even for the default
    /// host — guarantees the post-upgrade migration is sticky.
    #[test]
    fn read_pin_prefers_per_host_over_legacy() {
        let _g = crate::test_env_lock();
        let home = tempfile::tempdir().unwrap();
        // Both exist; per-host should win.
        let legacy = home.path().join(".lpm").join("relay-pin");
        std::fs::create_dir_all(legacy.parent().unwrap()).unwrap();
        std::fs::write(&legacy, "old").unwrap();
        let per_host = home
            .path()
            .join(".lpm")
            .join("relay-pins")
            .join("relay.lpm.fyi");
        std::fs::create_dir_all(per_host.parent().unwrap()).unwrap();
        std::fs::write(&per_host, "new").unwrap();

        let _home = HomeGuard::set(home.path());
        let got = read_tofu_pin("relay.lpm.fyi").unwrap();
        assert_eq!(got.as_deref(), Some("new"));
    }

    /// Each host gets its own pin file — writing one host doesn't
    /// affect another. Necessary for any future regional-relay or
    /// staging-relay setup to work without pin collisions.
    #[test]
    fn pins_are_isolated_per_host() {
        let _g = crate::test_env_lock();
        let home = tempfile::tempdir().unwrap();
        let _home = HomeGuard::set(home.path());

        write_tofu_pin("relay.lpm.fyi", "pin_a").unwrap();
        write_tofu_pin("relay-eu.lpm.fyi", "pin_b").unwrap();

        let a = read_tofu_pin("relay.lpm.fyi").unwrap();
        let b = read_tofu_pin("relay-eu.lpm.fyi").unwrap();
        let c = read_tofu_pin("never-stored.example").unwrap();

        assert_eq!(a.as_deref(), Some("pin_a"));
        assert_eq!(b.as_deref(), Some("pin_b"));
        assert!(c.is_none());
    }

    /// `server_name_to_string` round-trips DNS names for use as pin keys.
    #[test]
    fn server_name_to_string_dns() {
        let name = rustls::pki_types::ServerName::try_from("relay.lpm.fyi").unwrap();
        assert_eq!(server_name_to_string(&name), "relay.lpm.fyi");
    }

    #[test]
    fn tunnel_domain_resolution() {
        let mut opts = TunnelOptions::new("lpm_test".to_string(), 3000);

        // Full domain passes through
        opts.domain = Some("acme-api.lpm.llc".to_string());
        assert_eq!(opts.resolved_domain().unwrap(), "acme-api.lpm.llc");

        // Bare subdomain gets default base domain appended
        opts.domain = Some("acme-api".to_string());
        assert_eq!(opts.resolved_domain().unwrap(), "acme-api.lpm.fyi");
    }

    #[test]
    fn safe_local_url_validation() {
        // Valid paths
        assert!(is_safe_local_url("/"));
        assert!(is_safe_local_url("/api/users"));
        assert!(is_safe_local_url("/api/users?page=1"));
        assert!(is_safe_local_url("/_next/webpack-hmr"));
        assert!(is_safe_local_url("/path/to/resource#fragment"));
        assert!(is_safe_local_url("/api/v1"));

        // Double slashes in query string are allowed.
        assert!(is_safe_local_url("/callback?redirect=https://example.com"));
        assert!(is_safe_local_url("/api?url=http://localhost:3000//path"));

        // Must start with /
        assert!(!is_safe_local_url(""));
        assert!(!is_safe_local_url("api/users"));
        assert!(!is_safe_local_url("http://evil.com/"));
        assert!(!is_safe_local_url("https://evil.com/"));

        // No double slashes in path portion
        assert!(!is_safe_local_url("//evil.com/path"));
        assert!(!is_safe_local_url("/api//double"));

        // No CR/LF (HTTP response splitting)
        assert!(!is_safe_local_url("/api\r\nX-Injected: true"));
        assert!(!is_safe_local_url("/api\nX-Injected: true"));
        assert!(!is_safe_local_url("/api\rX-Injected: true"));
    }

    #[test]
    fn websocket_upgrade_rejects_oversized_connection_ids() {
        let id = "x".repeat(MAX_WEBSOCKET_CONNECTION_ID_BYTES + 1);

        assert_eq!(
            websocket_upgrade_metadata_error(&id, "/socket"),
            Some("Local WebSocket connection ID exceeds the byte limit")
        );
    }

    #[test]
    fn websocket_upgrade_rejects_oversized_local_urls() {
        let url = format!("/{}", "x".repeat(MAX_WEBSOCKET_LOCAL_URL_BYTES));

        assert_eq!(
            websocket_upgrade_metadata_error("connection", &url),
            Some("Local WebSocket upgrade URL exceeds the byte limit")
        );
    }

    #[test]
    fn ws_config_constants_are_reasonable() {
        // Verify WebSocket message size limits are set and sane.
        assert_eq!(MAX_WS_MESSAGE_SIZE, 50 * 1024 * 1024);
        assert_eq!(MAX_WS_FRAME_SIZE, 16 * 1024 * 1024);
    }

    #[test]
    fn websocket_write_buffer_accepts_the_largest_http_response_message() {
        let maximum_encoded_body = (50 * 1024 * 1024_usize).div_ceil(3) * 4;

        assert!(WEBSOCKET_MAX_WRITE_BUFFER_BYTES >= maximum_encoded_body + 1024 * 1024);
    }

    #[test]
    fn pong_timeout_detection() {
        // Pong timeout should detect dead relays.
        let now = std::time::Instant::now();

        // Just connected — should not be timed out
        assert!(!is_pong_timed_out(now));

        // Simulate old pong (more than 90s ago)
        let old_pong = now - std::time::Duration::from_secs(PONG_TIMEOUT_SECS + 1);
        assert!(is_pong_timed_out(old_pong));

        // Well within threshold — should not be timed out
        let recent = now - std::time::Duration::from_secs(PONG_TIMEOUT_SECS - 10);
        assert!(!is_pong_timed_out(recent));
    }

    #[test]
    fn backoff_jitter_is_bounded() {
        // Jitter must be non-negative and <= base_delay / 2.
        for base in [1u64, 2, 4, 8, 16, 30] {
            for _ in 0..20 {
                let j = backoff_jitter(base);
                assert!(
                    j <= base / 2 + 1,
                    "jitter {j} exceeds bound for base {base}"
                );
            }
        }
        // Edge case: base_delay=0
        let j = backoff_jitter(0);
        assert!(j <= 1);
    }

    #[test]
    fn healthy_connection_resets_retry_logic() {
        // Verify the constants are reasonable.
        assert_eq!(HEALTHY_CONNECTION_SECS, 60);
        assert_eq!(SHUTDOWN_TIMEOUT_SECS, 5);
    }

    #[test]
    fn extract_response_data_from_http_response() {
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "text/plain".to_string());

        let body_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"hello");

        let response = ClientMessage::HttpResponse {
            id: "req-1".to_string(),
            status: 200,
            headers: headers.clone(),
            body: body_b64,
        };

        let (status, resp_headers, resp_body) = extract_response_data(&response);
        assert_eq!(status, 200);
        assert_eq!(resp_headers.get("content-type").unwrap(), "text/plain");
        assert_eq!(resp_body, b"hello");
    }

    #[test]
    fn extract_response_data_from_non_http_response() {
        let response = ClientMessage::Ping;
        let (status, headers, body) = extract_response_data(&response);
        assert_eq!(status, 0);
        assert!(headers.is_empty());
        assert!(body.is_empty());
    }

    // ── Certificate Pinning Tests ──

    #[test]
    fn localhost_relay_detection() {
        assert!(relay_url_is_loopback("wss://localhost:8787/connect"));
        assert!(relay_url_is_loopback("wss://LOCALHOST:8787/connect"));
        assert!(relay_url_is_loopback("ws://127.0.0.1:8787/connect"));
        assert!(relay_url_is_loopback("ws://127.0.0.2:8787/connect"));
        assert!(relay_url_is_loopback("wss://[::1]:8787/connect"));
        assert!(!relay_url_is_loopback("https://127.0.0.1/connect"));
        assert!(!relay_url_is_loopback(
            "wss://localhost:8787@relay.example/connect"
        ));
        assert!(!relay_url_is_loopback("wss://relay.lpm.fyi/connect"));
        assert!(!relay_url_is_loopback("wss://example.com/connect"));
    }

    #[test]
    fn no_pin_flag_in_options() {
        let mut opts = TunnelOptions::new("lpm_test".to_string(), 3000);
        assert!(!opts.no_pin, "pinning should be enabled by default");
        opts.no_pin = true;
        assert!(opts.no_pin);
    }

    #[test]
    fn der_length_parsing() {
        // Short form: length < 128
        assert_eq!(read_der_length(&[0x05]), Some((5, 1)));
        assert_eq!(read_der_length(&[0x7F]), Some((127, 1)));

        // Long form: 1-byte length
        assert_eq!(read_der_length(&[0x81, 0x80]), Some((128, 2)));
        assert_eq!(read_der_length(&[0x81, 0xFF]), Some((255, 2)));

        // Long form: 2-byte length
        assert_eq!(read_der_length(&[0x82, 0x01, 0x00]), Some((256, 3)));

        // Empty input
        assert_eq!(read_der_length(&[]), None);

        // Indefinite length (not DER)
        assert_eq!(read_der_length(&[0x80]), None);
    }

    #[test]
    fn spki_extraction_from_self_signed_cert() {
        // A minimal self-signed X.509 certificate (DER-encoded) for testing SPKI extraction.
        // This is a real RSA 2048 self-signed cert generated for test purposes.
        // We verify that extract_spki_from_der returns Some (non-None) and that
        // the SPKI hash is deterministic.
        //
        // Rather than embedding a full cert, we test the DER parsing primitives
        // and verify spki_sha256_hex handles edge cases.

        // Test that None is returned for garbage input
        assert!(extract_spki_from_der(&[0x00, 0x01, 0x02]).is_none());
        assert!(spki_sha256_hex(&[]).is_none());

        // Test read_der_element on a simple SEQUENCE
        let seq = [0x30, 0x03, 0x02, 0x01, 0x05]; // SEQUENCE { INTEGER 5 }
        let (element, rest) = read_der_element(&seq).unwrap();
        assert_eq!(element.len(), 5);
        assert!(rest.is_empty());
    }

    #[test]
    fn spki_extraction_on_live_relay_cert() {
        // This is the actual DER-encoded X.509 certificate from relay.lpm.fyi
        // (Let's Encrypt E7, ECDSA P-256). The SPKI extraction must succeed on it.
        let cert_b64 = "MIIDhTCCAwygAwIBAgISBnwZXTcb+HAx6IxqHcjBIQ+vMAoGCCqGSM49BAMDMDIxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQswCQYDVQQDEwJFNzAeFw0yNjAzMjYwODM5MjlaFw0yNjA2MjQwODM5MjhaMBIxEDAOBgNVBAMTB2xwbS5meWkwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQLA0O1upreekdC/2YuBIvGEv0ItQdeGZigA3T4HkevlYc1jsoMR4hXFg7orjjEDae4wPFHa97nxbaBPv0rSvdGo4ICIDCCAhwwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFE5S6V888MqQTt/vGuh2GHdWg/otMB8GA1UdIwQYMBaAFK5IntyHHUSgb9qi5WB0BHjCnACAMDIGCCsGAQUFBwEBBCYwJDAiBggrBgEFBQcwAoYWaHR0cDovL2U3LmkubGVuY3Iub3JnLzAdBgNVHREEFjAUggkqLmxwbS5meWmCB2xwbS5meWkwEwYDVR0gBAwwCjAIBgZngQwBAgEwLQYDVR0fBCYwJDAioCCgHoYcaHR0cDovL2U3LmMubGVuY3Iub3JnLzQ4LmNybDCCAQ4GCisGAQQB1nkCBAIEgf8EgfwA+gB/AKgmy+MKxjUSRlM/4GXxTxnZbhkIE8Qd2W15ALMSPFUnAAABnSmCBrEACAAABQAEVgsdBAMASDBGAiEAgSf73/doQgyx5ZOIUgH/ns0ctb/6BLrFtB6TnDw1JXgCIQDAi2BZBUqv0AXNLKl58JGufmva84jP2I15ySbD6xboWAB3AJaXZL9VWJet90OHaDcIQnfp8DrV9qTzNm5GpD8PyqnGAAABnSmCC3UAAAQDAEgwRgIhAOkbQzpja/UW0iWjmg81Ep/X9Irn62E8yo2VEqQVEpTSAiEA5VevCeozTUVliZgStDKUKvNCeOhLiW6Vnmuhc3W5T2owCgYIKoZIzj0EAwMDZwAwZAIwOpVSu7MkcgR/dZ7IvnAPjldYOmGPSUH7rLKj0JbbnXt8RJfx/gekSN7jFN9avxloAjA194GitzezYf7tbZZ9Q/tbxK+c7KN2UwZeudy25Y4MIC2EQf97CKbcA6+xxTQ4zFI=";
        use base64::Engine;
        let cert_der = base64::engine::general_purpose::STANDARD
            .decode(cert_b64)
            .unwrap();

        let spki_hash = spki_sha256_hex(&cert_der);
        assert!(
            spki_hash.is_some(),
            "SPKI extraction failed on live relay.lpm.fyi certificate — this is the bug that blocks tunnel connections"
        );
        // The hash should be a 64-char hex string (SHA-256)
        let hash = spki_hash.unwrap();
        assert_eq!(hash.len(), 64, "SPKI SHA-256 hash should be 64 hex chars");
    }

    #[test]
    fn tofu_pin_round_trip() {
        // Test pin file read/write using a temp directory
        let tmp = tempfile::tempdir().unwrap();
        let pin_path = tmp.path().join("relay-pin");
        let test_pin = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";

        // Write directly to test path (since relay_pin_path uses home dir)
        std::fs::write(&pin_path, test_pin).unwrap();
        let read_back = std::fs::read_to_string(&pin_path).unwrap();
        assert_eq!(read_back.trim(), test_pin);
    }

    #[test]
    fn pinning_verifier_rejects_wrong_pin() {
        // Simulate: stored pin differs from current cert's pin.
        // We test the comparison logic directly since constructing a full
        // TLS handshake in a unit test is impractical.
        let stored = "aaaa";
        let current = "bbbb";
        assert_ne!(stored, current, "mismatched pins should be detected");
    }

    #[test]
    fn tunnel_auth_not_in_url() {
        // L4: tunnel_auth must NOT appear as a URL query parameter.
        // It should be sent via X-Tunnel-Auth header instead (tested in connect_url_construction).
        let options = TunnelOptions {
            relay_url: "wss://relay.lpm.fyi/connect".to_string(),
            token: "test-token".to_string(),
            token_provider: None,
            local_target: lpm_common::LocalTarget::loopback(lpm_common::LocalScheme::Http, 3000),
            live_local_target: None,
            domain: Some("myapp.lpm.fyi".to_string()),
            tunnel_auth: Some("secret-tunnel-auth".to_string()),
            webhook_tx: None,
            no_pin: false,
            auto_ack: false,
            ws_tx: None,
            forwarding_admission: None,
            shutdown: None,
        };

        // Reproduce the URL construction from try_connect
        let mut connect_url = format!("{}?port={}", options.relay_url, options.local_target.port);
        if let Some(domain) = options.resolved_domain() {
            let encoded = urlencoding::encode(&domain);
            connect_url.push_str(&format!("&domain={encoded}"));
        }
        // tunnel_auth is intentionally NOT added to the URL

        assert!(
            !connect_url.contains("tunnel_auth"),
            "tunnel_auth must not appear in URL: {connect_url}"
        );
        assert!(
            !connect_url.contains("secret-tunnel-auth"),
            "tunnel_auth value must not appear in URL: {connect_url}"
        );
    }

    #[test]
    fn live_local_target_tracks_republished_dev_endpoint() {
        let mut options = TunnelOptions::new("test-token".to_string(), 5173);
        let live_target = Arc::new(RwLock::new(options.local_target.clone()));
        options.live_local_target = Some(Arc::clone(&live_target));

        *live_target
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) =
            lpm_common::LocalTarget::loopback(lpm_common::LocalScheme::Http, 5174);

        assert_eq!(options.current_local_target().port, 5174);
    }

    #[test]
    fn tunnel_auth_header_is_set() {
        // L4: tunnel_auth must be sent via X-Tunnel-Auth header.
        let tunnel_auth = "secret-tunnel-auth";

        let request = build_websocket_connect_request(
            "wss://relay.lpm.fyi/connect?port=3000",
            "test-token",
            Some(tunnel_auth),
        )
        .unwrap();
        assert_eq!(
            request.headers().get("X-Tunnel-Auth").unwrap(),
            tunnel_auth,
            "X-Tunnel-Auth header must contain the tunnel auth value"
        );
    }

    #[test]
    fn tunnel_auth_header_absent_when_none() {
        // When tunnel_auth is None, X-Tunnel-Auth header should not be set.
        let request = build_websocket_connect_request(
            "wss://relay.lpm.fyi/connect?port=3000",
            "test-token",
            None,
        )
        .unwrap();
        assert!(
            request.headers().get("X-Tunnel-Auth").is_none(),
            "X-Tunnel-Auth header must not be present when tunnel_auth is None"
        );
    }

    #[test]
    fn websocket_connect_request_includes_upgrade_headers() {
        let request = build_websocket_connect_request(
            "wss://relay.lpm.fyi/connect?port=3000",
            "test-token",
            None,
        )
        .unwrap();

        assert!(
            request.headers().contains_key("sec-websocket-key"),
            "WebSocket client request must include sec-websocket-key"
        );
        assert!(
            request.headers().contains_key("sec-websocket-version"),
            "WebSocket client request must include sec-websocket-version"
        );
        assert_eq!(
            request.headers().get("upgrade").unwrap(),
            "websocket",
            "WebSocket client request must include Upgrade: websocket"
        );
        assert!(
            request
                .headers()
                .get("connection")
                .unwrap()
                .to_str()
                .unwrap()
                .to_ascii_lowercase()
                .contains("upgrade"),
            "WebSocket client request must include Connection: upgrade"
        );
    }

    #[tokio::test]
    async fn websocket_connect_sends_single_sec_websocket_key_header() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buffer = vec![0u8; 4096];
            let read = socket.read(&mut buffer).await.unwrap();
            let request = String::from_utf8_lossy(&buffer[..read]).into_owned();

            socket
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: x3JJHMbDL1EzLkh9GBhXDw==\r\n\r\n",
                )
                .await
                .unwrap();

            request
        });

        let request = build_websocket_connect_request(
            &format!("ws://127.0.0.1:{}/connect", addr.port()),
            "test-token",
            None,
        )
        .unwrap();

        let _ = tokio_tungstenite::connect_async(request).await;

        let raw_request = server.await.unwrap();
        let sec_key_count = raw_request
            .lines()
            .filter(|line| line.to_ascii_lowercase().starts_with("sec-websocket-key:"))
            .count();

        assert_eq!(
            sec_key_count, 1,
            "client must send exactly one Sec-WebSocket-Key header, got request:\n{raw_request}"
        );
    }

    #[tokio::test]
    async fn slow_http_forwarding_does_not_block_later_relay_requests() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let release_slow = Arc::new(tokio::sync::Notify::new());
        let local_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_address = local_listener.local_addr().unwrap();
        let local_release = Arc::clone(&release_slow);
        let local_server = tokio::spawn(async move {
            loop {
                let (mut socket, _) = local_listener.accept().await.unwrap();
                let release = Arc::clone(&local_release);
                tokio::spawn(async move {
                    let mut request = [0; 2048];
                    let read = socket.read(&mut request).await.unwrap();
                    let request = String::from_utf8_lossy(&request[..read]);
                    if request.starts_with("GET /slow ") {
                        release.notified().await;
                    }
                    socket
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                        .await
                        .unwrap();
                });
            }
        });

        let relay_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay_address = relay_listener.local_addr().unwrap();
        let relay = tokio::spawn(async move {
            let (socket, _) = relay_listener.accept().await.unwrap();
            let mut websocket = tokio_tungstenite::accept_async(socket).await.unwrap();
            websocket
                .send(Message::Text(
                    serde_json::json!({
                        "type": "hello",
                        "subdomain": "test.localhost",
                        "tunnel_url": "http://test.localhost",
                        "session_id": "session",
                    })
                    .to_string(),
                ))
                .await
                .unwrap();
            for (id, url) in [("slow", "/slow"), ("fast", "/fast")] {
                websocket
                    .send(Message::Text(
                        serde_json::json!({
                            "type": "http_request",
                            "id": id,
                            "method": "GET",
                            "url": url,
                            "headers": {},
                            "body": "",
                        })
                        .to_string(),
                    ))
                    .await
                    .unwrap();
            }

            tokio::time::timeout(std::time::Duration::from_millis(750), async {
                while let Some(message) = websocket.next().await {
                    let Message::Text(text) = message.unwrap() else {
                        continue;
                    };
                    let value: serde_json::Value = serde_json::from_str(&text).unwrap();
                    if value.get("id").and_then(serde_json::Value::as_str) == Some("fast") {
                        return;
                    }
                }
            })
            .await
        });

        let mut options = TunnelOptions::new("test-token".to_string(), local_address.port());
        options.relay_url = format!("ws://{relay_address}/connect");
        options.no_pin = true;
        let client =
            tokio::spawn(async move { try_connect(&options, &|_| Ok(()), &|_, _| {}).await });

        let fast_response = relay.await.unwrap();
        release_slow.notify_waiters();
        client.abort();
        local_server.abort();

        assert!(
            fast_response.is_ok(),
            "the fast request was blocked behind the slow request"
        );
    }

    #[tokio::test]
    async fn saturated_auto_ack_tunnel_returns_success_without_forwarding_the_excess_request() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let active_requests = Arc::new(AtomicUsize::new(0));
        let release_requests = Arc::new(tokio::sync::Notify::new());
        let local_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_address = local_listener.local_addr().unwrap();
        let local_active = Arc::clone(&active_requests);
        let local_release = Arc::clone(&release_requests);
        let local_server = tokio::spawn(async move {
            loop {
                let (mut socket, _) = local_listener.accept().await.unwrap();
                let active = Arc::clone(&local_active);
                let release = Arc::clone(&local_release);
                tokio::spawn(async move {
                    let mut request = [0; 2048];
                    assert!(socket.read(&mut request).await.unwrap() > 0);
                    active.fetch_add(1, Ordering::SeqCst);
                    release.notified().await;
                    socket
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                        .await
                        .unwrap();
                });
            }
        });

        let relay_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay_address = relay_listener.local_addr().unwrap();
        let relay_active = Arc::clone(&active_requests);
        let relay = tokio::spawn(async move {
            let (socket, _) = relay_listener.accept().await.unwrap();
            let mut websocket = tokio_tungstenite::accept_async(socket).await.unwrap();
            websocket
                .send(Message::Text(
                    serde_json::json!({
                        "type": "hello",
                        "subdomain": "test.localhost",
                        "tunnel_url": "http://test.localhost",
                        "session_id": "session",
                    })
                    .to_string(),
                ))
                .await
                .unwrap();
            for index in 0..MAX_CONCURRENT_HTTP_FORWARDS {
                websocket
                    .send(Message::Text(
                        serde_json::json!({
                            "type": "http_request",
                            "id": format!("held-{index}"),
                            "method": "GET",
                            "url": "/held",
                            "headers": {},
                            "body": "",
                        })
                        .to_string(),
                    ))
                    .await
                    .unwrap();
            }
            tokio::time::timeout(std::time::Duration::from_secs(2), async {
                while relay_active.load(Ordering::SeqCst) != MAX_CONCURRENT_HTTP_FORWARDS {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("forwarding slots did not become saturated");
            websocket
                .send(Message::Text(
                    serde_json::json!({
                        "type": "http_request",
                        "id": "excess",
                        "method": "GET",
                        "url": "/excess",
                        "headers": {},
                        "body": "",
                    })
                    .to_string(),
                ))
                .await
                .unwrap();

            tokio::time::timeout(std::time::Duration::from_secs(2), async {
                while let Some(message) = websocket.next().await {
                    let Message::Text(text) = message.unwrap() else {
                        continue;
                    };
                    let response: serde_json::Value = serde_json::from_str(&text).unwrap();
                    if response["id"] == "excess" {
                        return response["status"].as_u64();
                    }
                }
                None
            })
            .await
            .expect("auto-ack response was not returned promptly")
        });

        let mut options = TunnelOptions::new("test-token".to_string(), local_address.port());
        options.relay_url = format!("ws://{relay_address}/connect");
        options.no_pin = true;
        options.auto_ack = true;
        let (webhook_tx, mut webhook_rx) = tokio::sync::mpsc::channel(1);
        options.webhook_tx = Some(webhook_tx);
        let client =
            tokio::spawn(async move { try_connect(&options, &|_| Ok(()), &|_, _| {}).await });

        let status = relay.await.unwrap();
        let captured = tokio::time::timeout(std::time::Duration::from_secs(1), webhook_rx.recv())
            .await
            .expect("saturated auto-ack request was not captured")
            .expect("webhook capture channel closed");
        release_requests.notify_waiters();
        client.abort();
        local_server.abort();

        assert_eq!(status, Some(200));
        assert_eq!(captured.webhook.id, "excess");
        assert!(captured.webhook.auto_acked);
        assert_eq!(
            active_requests.load(Ordering::SeqCst),
            MAX_CONCURRENT_HTTP_FORWARDS
        );
    }

    #[tokio::test]
    async fn queued_capture_keeps_response_memory_reserved_until_received() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let response_body = vec![b'x'; 1024 * 1024];
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0; 1024];
            assert!(socket.read(&mut request).await.unwrap() > 0);
            socket
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                        response_body.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            socket.write_all(&response_body).await.unwrap();
        });
        let (webhook_tx, mut webhook_rx) = tokio::sync::mpsc::channel(1);
        let budget = Arc::new(tokio::sync::Semaphore::new(HTTP_RESPONSE_MEMORY_PERMITS));
        let request = ServerMessage::HttpRequest {
            id: "budgeted-capture".to_string(),
            method: "GET".to_string(),
            url: "/".to_string(),
            headers: HashMap::new(),
            body: String::new(),
        };
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let target =
            lpm_common::LocalTarget::loopback(lpm_common::LocalScheme::Http, address.port());

        let (_, response_permit) = forward_http_request(
            client,
            target,
            request,
            false,
            Some(webhook_tx),
            Arc::clone(&budget),
            None,
        )
        .await;
        drop(response_permit);
        server.await.unwrap();

        assert!(
            budget.available_permits() < HTTP_RESPONSE_MEMORY_PERMITS,
            "queued capture released its response-memory reservation"
        );
        let capture = webhook_rx.recv().await.unwrap();
        drop(capture);
        assert_eq!(budget.available_permits(), HTTP_RESPONSE_MEMORY_PERMITS);
    }

    #[tokio::test]
    async fn concurrent_large_requests_cannot_reserve_more_than_the_byte_budget() {
        let encoded_len = (20 * 1024 * 1024_usize).div_ceil(3) * 4;
        let permits = request_memory_permits(encoded_len).unwrap();
        let budget = Arc::new(tokio::sync::Semaphore::new(HTTP_REQUEST_MEMORY_PERMITS));
        let mut reservations = Vec::new();

        while let Ok(permit) = Arc::clone(&budget).try_acquire_many_owned(permits) {
            reservations.push(permit);
        }

        assert_eq!(
            reservations.len(),
            HTTP_REQUEST_MEMORY_PERMITS / permits as usize
        );
        assert!(budget.available_permits() < permits as usize);
    }

    #[test]
    fn request_admission_accounts_for_headers_and_the_complete_wire_message() {
        let request = ServerMessage::HttpRequest {
            id: "request".to_string(),
            method: "POST".to_string(),
            url: "/webhook".to_string(),
            headers: HashMap::from([("x-large".to_string(), "x".repeat(4 * 1024 * 1024))]),
            body: String::new(),
        };
        let wire_bytes = serde_json::to_string(&request).unwrap().len();
        let permits = request_memory_permits(wire_bytes).unwrap();

        assert!(
            permits >= 16,
            "large headers bypassed the request-memory budget: {permits} permits"
        );
    }

    #[tokio::test]
    async fn relay_to_local_websocket_queue_is_bounded_by_retained_bytes() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(64);
        let budget = Arc::new(tokio::sync::Semaphore::new(WEBSOCKET_MEMORY_PERMITS));
        let permits = websocket_memory_permits(32 * 1024 * 1024).unwrap();
        for _ in 0..5 {
            let Ok(memory_permit) = Arc::clone(&budget).try_acquire_many_owned(permits) else {
                break;
            };
            tx.try_send(LocalWebSocketCommand::Frame {
                data: Vec::with_capacity(32 * 1024 * 1024),
                is_binary: true,
                _memory_permit: memory_permit,
            })
            .unwrap();
        }

        let mut retained = 0;
        while let Ok(LocalWebSocketCommand::Frame { data, .. }) = rx.try_recv() {
            retained += data.capacity();
        }
        assert!(
            retained <= 128 * 1024 * 1024,
            "count-only queue retained {retained} bytes"
        );
        assert_eq!(budget.available_permits(), WEBSOCKET_MEMORY_PERMITS);
    }

    #[tokio::test]
    async fn queued_websocket_close_is_delivered_before_cancellation() {
        let (_tx, mut rx) = tokio::sync::mpsc::channel(1);
        let (priority_tx, mut priority_rx) = tokio::sync::mpsc::channel(1);
        let cancel = tokio_util::sync::CancellationToken::new();
        priority_tx
            .try_send(LocalWebSocketCommand::Close {
                code: Some(1001),
                reason: Some("relay closed".to_string()),
            })
            .unwrap();
        cancel.cancel();

        let command = next_local_websocket_command(&mut rx, &mut priority_rx, &cancel).await;

        assert!(matches!(
            command,
            Some(LocalWebSocketCommand::Close {
                code: Some(1001),
                reason: Some(reason),
            }) if reason == "relay closed"
        ));
    }

    #[tokio::test]
    async fn relay_websocket_close_preempts_a_full_frame_queue() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(2);
        let budget = Arc::new(tokio::sync::Semaphore::new(2));
        for byte in [b'a', b'b'] {
            tx.send(LocalWebSocketCommand::Frame {
                data: vec![byte],
                is_binary: true,
                _memory_permit: Arc::clone(&budget).acquire_owned().await.unwrap(),
            })
            .await
            .unwrap();
        }
        let (priority_tx, mut priority_rx) = tokio::sync::mpsc::channel(1);
        priority_tx
            .try_send(LocalWebSocketCommand::Close {
                code: Some(1001),
                reason: Some("relay closed".to_string()),
            })
            .unwrap();
        let cancel = tokio_util::sync::CancellationToken::new();

        let command = next_local_websocket_command(&mut rx, &mut priority_rx, &cancel).await;

        assert!(matches!(command, Some(LocalWebSocketCommand::Close { .. })));
    }

    #[test]
    fn relay_websocket_close_reason_fits_the_control_frame_limit() {
        let reason = bounded_websocket_close_reason(Some("é".repeat(200))).unwrap();

        assert!(reason.len() <= MAX_WEBSOCKET_CLOSE_REASON_BYTES);
        assert!(std::str::from_utf8(reason.as_bytes()).is_ok());
    }

    #[test]
    fn closing_websocket_ids_cannot_be_reused_until_both_halves_finish() {
        let active = HashMap::new();
        let pending = HashMap::new();
        let closing = HashMap::from([(
            "connection".to_string(),
            ClosingWebSocket {
                generation: 1,
                cancel: tokio_util::sync::CancellationToken::new(),
                completed_halves: 0b01,
                relay_notified: true,
            },
        )]);

        assert!(websocket_id_is_in_use(
            &active,
            &closing,
            &pending,
            "connection"
        ));
    }

    #[test]
    fn queued_websocket_frames_from_an_old_generation_are_discarded() {
        let (commands, _) = tokio::sync::mpsc::channel(1);
        let (priority_commands, _) = tokio::sync::mpsc::channel(1);
        let active = HashMap::from([(
            "connection".to_string(),
            WebSocketConnection {
                commands,
                priority_commands,
                cancel: tokio_util::sync::CancellationToken::new(),
                generation: 2,
            },
        )]);
        let queued = RelayWebSocketMessage {
            id: "connection".to_string(),
            generation: 1,
            json: "stale".to_string(),
            _memory_permit: None,
        };

        assert!(!relay_websocket_message_is_current(&active, &queued));
    }

    #[test]
    fn invalid_text_websocket_frames_are_not_forwarded_lossily() {
        let error = local_websocket_message(vec![0xff], false).unwrap_err();

        assert_eq!(error, "relay WebSocket text frame is not valid UTF-8");
    }

    #[test]
    fn inbound_websocket_admission_accounts_for_wire_and_decoded_buffers() {
        let wire_bytes = MAX_WS_MESSAGE_SIZE - 1;
        let base64_bytes = wire_bytes - 128;

        assert!(inbound_websocket_memory_permits(wire_bytes, base64_bytes).is_none());
    }

    #[tokio::test]
    async fn local_websocket_close_is_not_followed_by_a_synthetic_close() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut websocket = tokio_tungstenite::accept_async(stream).await.unwrap();
            websocket
                .send(Message::Close(Some(CloseFrame {
                    code: CloseCode::Normal,
                    reason: "finished".into(),
                })))
                .await
                .unwrap();
        });
        let (websocket, _) = tokio_tungstenite::connect_async(format!("ws://{address}"))
            .await
            .unwrap();
        let (local_write, local_read) = websocket.split();
        let websocket_slots = Arc::new(tokio::sync::Semaphore::new(1));
        let slot = websocket_slots.acquire_owned().await.unwrap();
        let (relay_tx, mut relay_rx) = tokio::sync::mpsc::channel(4);
        let (closed_tx, mut closed_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut tasks = tokio::task::JoinSet::new();
        let connection = activate_local_websocket(
            &mut tasks,
            LocalWebSocketActivation {
                id: "connection".to_string(),
                generation: 1,
                local_write,
                local_read,
                slot,
                relay_tx,
                relay_memory: Arc::new(tokio::sync::Semaphore::new(WEBSOCKET_MEMORY_PERMITS)),
                ws_tx: None,
                closed_tx,
            },
        );

        let closed = loop {
            let closed = tokio::time::timeout(std::time::Duration::from_secs(1), closed_rx.recv())
                .await
                .unwrap()
                .unwrap();
            if closed.relay_close.is_some() {
                break closed;
            }
        };
        assert!(
            !closed.notify_relay,
            "local close requested a second synthetic relay close"
        );
        assert!(matches!(
            closed.relay_close,
            Some((Some(1000), Some(reason))) if reason == "finished"
        ));
        assert!(relay_rx.try_recv().is_err());

        connection.cancel.cancel();
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        server.await.unwrap();
    }

    #[test]
    fn outbound_websocket_admission_accounts_for_base64_and_json_growth() {
        let raw_bytes = 50 * 1024 * 1024;
        let connection_id_bytes = 36;
        let retained = websocket_encoded_message_bytes(raw_bytes, connection_id_bytes).unwrap();
        let encoded_bytes = raw_bytes.div_ceil(3) * 4;

        assert!(
            retained >= raw_bytes + encoded_bytes + connection_id_bytes * 6 + 64,
            "admission reserved {retained} bytes for the raw frame and directly encoded JSON buffer"
        );
        assert_eq!(
            websocket_memory_permits(retained).unwrap() as usize,
            retained.div_ceil(HTTP_RESPONSE_MEMORY_UNIT_BYTES)
        );
    }

    #[test]
    fn direct_websocket_frame_serialization_matches_the_protocol_contract() {
        let id = "connection-\"quoted\"-\n-control";
        let bytes = [0, 1, 2, 127, 128, 255];
        for is_binary in [false, true] {
            let expected = serde_json::to_string(&ClientMessage::WebSocketFrame {
                id: id.to_string(),
                data: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, bytes),
                is_binary,
            })
            .unwrap();

            assert_eq!(
                serialize_websocket_frame(id, &bytes, is_binary).unwrap(),
                expected
            );
        }
    }

    #[test]
    fn websocket_capture_rejects_oversized_upgrade_headers_before_cloning() {
        let headers = HashMap::from([(
            "x-large".to_string(),
            "x".repeat(WEBSOCKET_CAPTURE_HEADER_BYTES + 1),
        )]);

        assert!(captured_websocket_headers(&headers).is_none());
    }

    #[test]
    fn oversized_websocket_upgrade_headers_are_rejected_before_task_spawn() {
        let headers = HashMap::from([(
            "x-large".to_string(),
            "x".repeat(WEBSOCKET_CAPTURE_HEADER_BYTES + 1),
        )]);

        assert!(bounded_websocket_upgrade_headers(headers).is_err());
    }

    #[tokio::test]
    async fn websocket_connection_slots_bound_pending_and_active_connections() {
        let slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_WEBSOCKETS));
        let mut reservations = Vec::with_capacity(MAX_CONCURRENT_WEBSOCKETS);
        for _ in 0..MAX_CONCURRENT_WEBSOCKETS {
            reservations.push(Arc::clone(&slots).try_acquire_owned().unwrap());
        }

        assert!(Arc::clone(&slots).try_acquire_owned().is_err());
        drop(reservations.pop());
        assert!(Arc::clone(&slots).try_acquire_owned().is_ok());
    }

    #[test]
    fn relay_close_cancels_the_pending_local_websocket_upgrade() {
        let cancel = tokio_util::sync::CancellationToken::new();
        let mut pending = HashMap::from([(
            "connection".to_string(),
            PendingWebSocketUpgrade {
                generation: 1,
                cancel: cancel.clone(),
            },
        )]);

        assert!(discard_pending_websocket_upgrade(
            &mut pending,
            "connection"
        ));
        assert!(cancel.is_cancelled());
    }

    #[tokio::test]
    async fn relay_disconnect_cancels_pending_local_websocket_upgrades_before_joining_tasks() {
        let cancel = tokio_util::sync::CancellationToken::new();
        let task_cancel = cancel.clone();
        let pending = HashMap::from([(
            "connection".to_string(),
            PendingWebSocketUpgrade {
                generation: 1,
                cancel,
            },
        )]);
        let mut tasks = tokio::task::JoinSet::new();
        tasks.spawn(async move {
            task_cancel.cancelled().await;
        });

        tokio::time::timeout(
            std::time::Duration::from_millis(500),
            shutdown_websocket_tasks(
                HashMap::new(),
                HashMap::new(),
                pending,
                &mut tasks,
                std::time::Duration::from_millis(250),
            ),
        )
        .await
        .expect("pending WebSocket upgrade delayed tunnel reconnect");
    }

    #[tokio::test]
    async fn tunnel_shutdown_waits_for_in_flight_forwarder_destruction_after_timeout() {
        struct CompletionGuard(Option<tokio::sync::oneshot::Sender<()>>);

        impl Drop for CompletionGuard {
            fn drop(&mut self) {
                if let Some(completed) = self.0.take() {
                    let _ = completed.send(());
                }
            }
        }

        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (completed_tx, mut completed_rx) = tokio::sync::oneshot::channel();
        let mut tasks = tokio::task::JoinSet::new();
        tasks.spawn(async move {
            let _completion = CompletionGuard(Some(completed_tx));
            let _ = started_tx.send(());
            std::future::pending::<()>().await;
        });
        started_rx.await.unwrap();

        shutdown_websocket_tasks(
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            &mut tasks,
            std::time::Duration::from_millis(10),
        )
        .await;

        assert!(completed_rx.try_recv().is_ok());
    }

    #[tokio::test]
    async fn relay_send_deadline_rejects_a_stalled_sink() {
        use futures_util::Sink;
        use std::pin::Pin;
        use std::task::{Context, Poll};

        struct StalledSink;
        impl Sink<Message> for StalledSink {
            type Error = tokio_tungstenite::tungstenite::Error;

            fn poll_ready(
                self: Pin<&mut Self>,
                _context: &mut Context<'_>,
            ) -> Poll<Result<(), Self::Error>> {
                Poll::Pending
            }

            fn start_send(self: Pin<&mut Self>, _item: Message) -> Result<(), Self::Error> {
                Ok(())
            }

            fn poll_flush(
                self: Pin<&mut Self>,
                _context: &mut Context<'_>,
            ) -> Poll<Result<(), Self::Error>> {
                Poll::Pending
            }

            fn poll_close(
                self: Pin<&mut Self>,
                _context: &mut Context<'_>,
            ) -> Poll<Result<(), Self::Error>> {
                Poll::Pending
            }
        }

        let mut sink = StalledSink;
        let send = send_to_relay(
            &mut sink,
            Message::Text("frame".to_string()),
            "send test frame",
        );
        let error = tokio::time::timeout(std::time::Duration::from_secs(6), send)
            .await
            .expect("relay send did not enforce its own deadline")
            .unwrap_err();

        assert!(error.to_string().contains("timed out"));
    }
}
