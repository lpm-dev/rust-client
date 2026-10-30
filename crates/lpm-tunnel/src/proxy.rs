//! Local HTTP proxy.
//!
//! Forwards incoming tunnel requests to the local dev server running
//! at a verified loopback endpoint. Preserves headers and handles
//! connection errors gracefully (returns 502 if the local server is down).

use crate::protocol::{ClientMessage, ServerMessage};
use lpm_common::LpmError;
use std::collections::HashMap;
use std::sync::Arc;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

/// Maximum local response body size before returning 502 (50 MB).
const MAX_RESPONSE_BODY_SIZE: usize = 50 * 1024 * 1024;

pub(crate) struct ForwardedResponse {
    pub(crate) message: ClientMessage,
    pub(crate) stream_end: Option<ClientMessage>,
    pub(crate) capture_incomplete: bool,
    pub(crate) memory_permit: Option<tokio::sync::OwnedSemaphorePermit>,
}

struct ResponseMemoryReservation {
    budget: Arc<tokio::sync::Semaphore>,
    total_permits: usize,
    unit_bytes: usize,
    multiplier: usize,
    permit: Option<tokio::sync::OwnedSemaphorePermit>,
}

impl ResponseMemoryReservation {
    fn try_reserve(&mut self, capacity: usize) -> Result<bool, LpmError> {
        let needed = capacity
            .saturating_mul(self.multiplier)
            .div_ceil(self.unit_bytes)
            .max(1)
            .min(self.total_permits);
        let held = self
            .permit
            .as_ref()
            .map_or(0, |permit| permit.num_permits());
        if needed <= held {
            return Ok(true);
        }
        let additional = u32::try_from(needed - held)
            .map_err(|_| LpmError::Tunnel("response memory budget is too large".into()))?;
        // Waiting while retaining a partial reservation can deadlock concurrent bodies.
        let extra = match Arc::clone(&self.budget).try_acquire_many_owned(additional) {
            Ok(permit) => permit,
            Err(tokio::sync::TryAcquireError::NoPermits) => return Ok(false),
            Err(tokio::sync::TryAcquireError::Closed) => {
                return Err(LpmError::Tunnel("response memory budget was closed".into()));
            }
        };
        if let Some(permit) = &mut self.permit {
            permit.merge(extra);
        } else {
            self.permit = Some(extra);
        }
        Ok(true)
    }
}

/// Allowed request headers (whitelist). Only these headers are forwarded from
/// the relay to the local dev server. Any header starting with `x-` is also
/// allowed to support custom webhook headers.
const ALLOWED_HEADERS: &[&str] = &[
    "content-type",
    "content-length",
    "content-encoding",
    "accept",
    "accept-encoding",
    "accept-language",
    "user-agent",
    "cache-control",
    "pragma",
    "if-none-match",
    "if-modified-since",
    "last-event-id",
    "range",
    "cookie",
    "authorization",
    "origin",
    "referer",
    "stripe-signature",
];

/// Check if a header name is allowed through the proxy whitelist.
///
/// Allows explicitly whitelisted headers plus any `x-` prefixed header
/// (for webhook signatures, forwarded-for, etc.). Always blocks `host`
/// and `transfer-encoding` regardless.
fn is_header_allowed(name: &str) -> bool {
    let lower = name.to_lowercase();

    // Always block these — host is set to the verified target authority, transfer-encoding
    // is hop-by-hop and must not be forwarded.
    if lower == "host" || lower == "transfer-encoding" {
        return false;
    }

    // Allow all x- prefixed headers (x-forwarded-for, x-requested-with,
    // x-github-event, x-hub-signature-256, x-webhook-id, etc.)
    if lower.starts_with("x-") {
        return true;
    }

    ALLOWED_HEADERS.contains(&lower.as_str())
}

/// Forward an HTTP request to the local dev server and return the response.
pub async fn forward_request(
    http_client: &reqwest::Client,
    local_target: &lpm_common::LocalTarget,
    request: &ServerMessage,
) -> Result<ClientMessage, LpmError> {
    Ok(
        forward_request_inner(http_client, local_target, None, request, None, None)
            .await?
            .message,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn forward_request_with_memory_budget(
    http_client: &reqwest::Client,
    local_target: &lpm_common::LocalTarget,
    live_target: Option<&std::sync::RwLock<lpm_common::LocalTarget>>,
    request: &ServerMessage,
    memory_budget: Arc<tokio::sync::Semaphore>,
    memory_budget_permits: usize,
    memory_unit_bytes: usize,
    memory_multiplier: usize,
    stream: Option<crate::http_stream::StreamOutput>,
) -> Result<ForwardedResponse, LpmError> {
    forward_request_inner(
        http_client,
        local_target,
        live_target,
        request,
        Some((
            memory_budget,
            memory_budget_permits,
            memory_unit_bytes,
            memory_multiplier,
        )),
        stream,
    )
    .await
}

async fn forward_request_inner(
    http_client: &reqwest::Client,
    local_target: &lpm_common::LocalTarget,
    live_target: Option<&std::sync::RwLock<lpm_common::LocalTarget>>,
    request: &ServerMessage,
    memory_budget: Option<(Arc<tokio::sync::Semaphore>, usize, usize, usize)>,
    stream: Option<crate::http_stream::StreamOutput>,
) -> Result<ForwardedResponse, LpmError> {
    crate::validate_forward_target(local_target)?;
    let (id, method, url, headers, body) = match request {
        ServerMessage::HttpRequest {
            id,
            method,
            url,
            headers,
            body,
        } => (id, method, url, headers, body),
        _ => return Err(LpmError::Tunnel("expected HttpRequest message".into())),
    };

    let local_request = LocalRequest {
        http_client,
        method: method
            .parse::<reqwest::Method>()
            .map_err(|e| LpmError::Tunnel(format!("invalid HTTP method '{method}': {e}")))?,
        url,
        headers,
        body,
        streaming: stream.is_some(),
        deadline: tokio::time::Instant::now() + std::time::Duration::from_secs(30),
    };
    // A refused connection never reached the server, so retrying it on the
    // other loopback family is safe for every method.
    let response = match local_request.send(local_target).await? {
        Ok(response) => response,
        Err(error) if error.is_connect() => match local_target.loopback_sibling() {
            Some(sibling) => match local_request.send(&sibling).await? {
                Ok(response) => {
                    if let Some(live_target) = live_target {
                        crate::adopt_loopback_sibling(live_target, local_target, sibling);
                    }
                    response
                }
                Err(error) if error.is_connect() => {
                    return Err(local_request.error(local_target, error));
                }
                Err(error) => return Err(local_request.error(&sibling, error)),
            },
            None => return Err(local_request.error(local_target, error)),
        },
        Err(error) => return Err(local_request.error(local_target, error)),
    };

    let status = response.status().as_u16();

    // Collect response headers
    let mut resp_headers = HashMap::new();
    for (key, value) in response.headers() {
        if let Ok(v) = value.to_str() {
            resp_headers.insert(key.to_string(), v.to_string());
        }
    }

    let is_event_stream = resp_headers.get("content-type").is_some_and(|value| {
        value
            .split(';')
            .next()
            .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("text/event-stream"))
    });
    if is_event_stream && let Some(output) = stream {
        let capture = output.forward(id, status, &resp_headers, response).await?;
        return Ok(ForwardedResponse {
            message: ClientMessage::HttpResponse {
                id: id.clone(),
                status,
                headers: resp_headers,
                body: base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    capture.body,
                ),
            },
            stream_end: Some(ClientMessage::HttpResponseEnd {
                id: id.clone(),
                failed: capture.failed,
            }),
            capture_incomplete: capture.incomplete,
            memory_permit: None,
        });
    }

    // Check content-length header first for early rejection of oversized responses.
    // Fall back to reading bytes and checking after for chunked/streaming responses.
    if let Some(cl) = response.content_length()
        && cl > MAX_RESPONSE_BODY_SIZE as u64
    {
        return Ok(ForwardedResponse {
            message: response_too_large(id, cl),
            stream_end: None,
            capture_incomplete: false,
            memory_permit: None,
        });
    }

    let initial_capacity = response
        .content_length()
        .and_then(|length| usize::try_from(length).ok())
        .unwrap_or(0)
        .min(MAX_RESPONSE_BODY_SIZE);
    let mut reservation = memory_budget.map(|(budget, total_permits, unit_bytes, multiplier)| {
        ResponseMemoryReservation {
            budget,
            total_permits,
            unit_bytes,
            multiplier,
            permit: None,
        }
    });
    if let Some(reservation) = &mut reservation
        && !reservation.try_reserve(initial_capacity)?
    {
        return Ok(busy_response(id));
    }
    let mut body_bytes = Vec::with_capacity(initial_capacity);
    let mut response = response;
    while let Some(chunk) = tokio::time::timeout_at(local_request.deadline, response.chunk())
        .await
        .map_err(|_| LpmError::Tunnel("local response body timed out".into()))?
        .map_err(|e| LpmError::Tunnel(format!("failed to read response body: {e}")))?
    {
        let next_len = body_bytes.len().saturating_add(chunk.len());
        if next_len > MAX_RESPONSE_BODY_SIZE {
            return Ok(ForwardedResponse {
                message: response_too_large(id, next_len as u64),
                stream_end: None,
                capture_incomplete: false,
                memory_permit: reservation.and_then(|reservation| reservation.permit),
            });
        }
        if next_len > body_bytes.capacity() {
            let capacity = next_len
                .max(body_bytes.capacity().saturating_mul(2))
                .min(MAX_RESPONSE_BODY_SIZE);
            if let Some(reservation) = &mut reservation
                && !reservation.try_reserve(capacity)?
            {
                return Ok(busy_response(id));
            }
            body_bytes.reserve_exact(capacity - body_bytes.len());
        }
        body_bytes.extend_from_slice(&chunk);
    }

    let body_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &body_bytes);

    Ok(ForwardedResponse {
        message: ClientMessage::HttpResponse {
            id: id.clone(),
            status,
            headers: resp_headers,
            body: body_b64,
        },
        memory_permit: reservation.and_then(|reservation| reservation.permit),
        stream_end: None,
        capture_incomplete: false,
    })
}

fn busy_response(id: &str) -> ForwardedResponse {
    ForwardedResponse {
        message: service_unavailable_response(id),
        stream_end: None,
        capture_incomplete: false,
        memory_permit: None,
    }
}

/// One relayed request, sendable to either loopback family of its target.
struct LocalRequest<'a> {
    http_client: &'a reqwest::Client,
    method: reqwest::Method,
    url: &'a str,
    headers: &'a HashMap<String, String>,
    body: &'a str,
    streaming: bool,
    deadline: tokio::time::Instant,
}

impl LocalRequest<'_> {
    /// Send to `target`. The outer error ends forwarding; the inner one is the
    /// HTTP client's, which a connect failure lets the caller retry.
    async fn send(
        &self,
        target: &lpm_common::LocalTarget,
    ) -> Result<Result<reqwest::Response, reqwest::Error>, LpmError> {
        let local_url = format!(
            "{}://{}{}",
            target.scheme,
            target.authority(),
            target.upstream_path(self.url)
        );
        let mut builder = self.http_client.request(self.method.clone(), &local_url);

        // Forward headers using a whitelist — only known-safe headers are forwarded
        // to the local dev server. This prevents relay-injected or attacker-controlled
        // headers from reaching the local service.
        for (key, value) in self.headers {
            if is_header_allowed(key) {
                builder = builder.header(key.as_str(), value.as_str());
            }
        }
        builder = builder.header("host", target.authority());

        if !self.body.is_empty() {
            let body_bytes =
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD, self.body)
                    .map_err(|e| LpmError::Tunnel(format!("failed to decode request body: {e}")))?;
            builder = builder.body(body_bytes);
        }
        if !self.streaming {
            builder = builder.timeout(std::time::Duration::from_secs(30));
        }
        tokio::time::timeout_at(self.deadline, builder.send())
            .await
            .map_err(|_| LpmError::Tunnel("local response headers timed out".into()))
    }

    fn error(&self, target: &lpm_common::LocalTarget, error: reqwest::Error) -> LpmError {
        if error.is_connect() {
            LpmError::Tunnel(format!(
                "local server not reachable at {} — is it running?",
                describe_endpoint(target)
            ))
        } else if error.is_timeout() {
            LpmError::Tunnel(format!(
                "request to {}{} timed out",
                target.authority(),
                target.upstream_path(self.url)
            ))
        } else {
            LpmError::Tunnel(format!("failed to forward request: {error}"))
        }
    }
}

/// Name the endpoint a failed connection tried, including both loopback
/// families when either one would have done.
fn describe_endpoint(target: &lpm_common::LocalTarget) -> String {
    match target.loopback_sibling() {
        Some(sibling) => format!("{} or {}", target.url(), sibling.url()),
        None => target.url(),
    }
}

/// Create an HTTP response for when the local server is unreachable.
pub fn bad_gateway_response(request_id: &str) -> ClientMessage {
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "text/plain".to_string());

    ClientMessage::HttpResponse {
        id: request_id.to_string(),
        status: 502,
        headers,
        body: base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            b"502 Bad Gateway: local dev server is not running",
        ),
    }
}

/// Create an HTTP response when the bounded local-forwarding pool is busy.
pub fn service_unavailable_response(request_id: &str) -> ClientMessage {
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "text/plain".to_string());
    headers.insert("retry-after".to_string(), "1".to_string());

    ClientMessage::HttpResponse {
        id: request_id.to_string(),
        status: 503,
        headers,
        body: base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            b"Tunnel local forwarding is busy; retry shortly",
        ),
    }
}

/// Create a 200 OK response for auto-ack mode.
///
/// Returned to the webhook provider when the local dev server is unreachable
/// and `--auto-ack` is enabled. This prevents the provider from retrying
/// aggressively or disabling the webhook endpoint.
pub fn auto_ack_response(request_id: &str) -> ClientMessage {
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());

    ClientMessage::HttpResponse {
        id: request_id.to_string(),
        status: 200,
        headers,
        body: base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            br#"{"ok":true}"#,
        ),
    }
}

/// Create a 502 response for when the local server response is too large to relay.
fn response_too_large(request_id: &str, size: u64) -> ClientMessage {
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "text/plain".to_string());

    let body_text = format!(
        "502 Bad Gateway: response body too large ({} bytes, max {} bytes)",
        size, MAX_RESPONSE_BODY_SIZE
    );

    ClientMessage::HttpResponse {
        id: request_id.to_string(),
        status: 502,
        headers,
        body: base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            body_text.as_bytes(),
        ),
    }
}

type LocalWebSocketStream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// A local WebSocket connection, split for frame forwarding.
pub struct LocalWebSocketConnection {
    pub write: futures_util::stream::SplitSink<
        LocalWebSocketStream,
        tokio_tungstenite::tungstenite::Message,
    >,
    pub read: futures_util::stream::SplitStream<LocalWebSocketStream>,
    /// Set when the target's other loopback family accepted the connection.
    pub sibling_target: Option<lpm_common::LocalTarget>,
}

/// Establish a WebSocket connection to the local dev server for upgrade passthrough.
///
/// Connects to the target's complete WebSocket endpoint, including its address
/// and base path, falling back to the other loopback family when the target
/// allows either, and returns the split stream used for HMR frame forwarding.
pub async fn connect_local_websocket(
    local_target: &lpm_common::LocalTarget,
    url: &str,
    headers: &HashMap<String, String>,
) -> Result<LocalWebSocketConnection, LpmError> {
    crate::validate_forward_target(local_target)?;
    let (socket, sibling_target) = connect_loopback(local_target).await?;
    let connected = sibling_target.as_ref().unwrap_or(local_target);
    let request = build_local_websocket_request(connected, url, headers)?;

    let ws_config = tokio_tungstenite::tungstenite::protocol::WebSocketConfig {
        write_buffer_size: 128 * 1024,
        max_write_buffer_size: 4 * 1024 * 1024,
        max_message_size: Some(crate::client::MAX_WS_MESSAGE_SIZE),
        max_frame_size: Some(crate::client::MAX_WS_FRAME_SIZE),
        ..Default::default()
    };
    let (stream, _) = tokio_tungstenite::client_async_with_config(
        request,
        tokio_tungstenite::MaybeTlsStream::Plain(socket),
        Some(ws_config),
    )
    .await
    .map_err(|e| LpmError::Tunnel(format!("failed to connect local WebSocket: {e}")))?;

    use futures_util::StreamExt;
    let (write, read) = stream.split();
    Ok(LocalWebSocketConnection {
        write,
        read,
        sibling_target,
    })
}

/// How long [`probe_local_target`] waits for each address to accept.
const LOCAL_PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(300);

/// Find where `target` is listening right now.
///
/// Returns `target` when its own address accepts a connection, its other
/// loopback family when only that one does, and `None` when nothing accepts.
pub async fn probe_local_target(
    target: &lpm_common::LocalTarget,
) -> Option<lpm_common::LocalTarget> {
    async fn accepts(target: &lpm_common::LocalTarget) -> bool {
        matches!(
            tokio::time::timeout(
                LOCAL_PROBE_TIMEOUT,
                tokio::net::TcpStream::connect((target.address, target.port)),
            )
            .await,
            Ok(Ok(_))
        )
    }

    match target.loopback_sibling() {
        None => accepts(target).await.then(|| target.clone()),
        Some(sibling) => match tokio::join!(accepts(target), accepts(&sibling)) {
            (true, _) => Some(target.clone()),
            (false, true) => Some(sibling),
            (false, false) => None,
        },
    }
}

/// Open a TCP connection to `target`, or to its other loopback family when
/// the target allows either and its own address refuses.
async fn connect_loopback(
    target: &lpm_common::LocalTarget,
) -> Result<(tokio::net::TcpStream, Option<lpm_common::LocalTarget>), LpmError> {
    let unreachable = |error: std::io::Error| {
        LpmError::Tunnel(format!(
            "failed to connect local WebSocket: nothing accepted {} ({error})",
            describe_endpoint(target)
        ))
    };
    match tokio::net::TcpStream::connect((target.address, target.port)).await {
        Ok(socket) => Ok((socket, None)),
        Err(error) => {
            let Some(sibling) = target.loopback_sibling() else {
                return Err(unreachable(error));
            };
            let socket = tokio::net::TcpStream::connect((sibling.address, sibling.port))
                .await
                .map_err(unreachable)?;
            Ok((socket, Some(sibling)))
        }
    }
}

fn build_local_websocket_request(
    local_target: &lpm_common::LocalTarget,
    url: &str,
    headers: &HashMap<String, String>,
) -> Result<tokio_tungstenite::tungstenite::http::Request<()>, LpmError> {
    let local_path = local_target.upstream_path(url);
    let ws_url = format!(
        "{}://{}{}",
        local_target.scheme.websocket(),
        local_target.authority(),
        local_path
    );
    tracing::debug!("connecting local WebSocket: {ws_url}");

    // Use IntoClientRequest so tungstenite generates the required upgrade headers.
    let mut request = ws_url
        .into_client_request()
        .map_err(|e| LpmError::Tunnel(format!("failed to build WebSocket request: {e}")))?;

    request.headers_mut().insert(
        "host",
        tokio_tungstenite::tungstenite::http::HeaderValue::from_str(&local_target.authority())
            .map_err(|e| LpmError::Tunnel(format!("invalid Host header: {e}")))?,
    );

    for (key, value) in headers {
        if is_header_allowed(key) {
            let header_name = tokio_tungstenite::tungstenite::http::header::HeaderName::from_bytes(
                key.as_bytes(),
            )
            .map_err(|e| LpmError::Tunnel(format!("invalid WebSocket header name '{key}': {e}")))?;
            let header_value = tokio_tungstenite::tungstenite::http::HeaderValue::from_str(value)
                .map_err(|e| {
                LpmError::Tunnel(format!("invalid WebSocket header value for '{key}': {e}"))
            })?;
            request.headers_mut().insert(header_name, header_value);
        }
    }

    Ok(request)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_ack_response_returns_200() {
        let resp = auto_ack_response("req_ack");
        match resp {
            ClientMessage::HttpResponse {
                id, status, body, ..
            } => {
                assert_eq!(id, "req_ack");
                assert_eq!(status, 200);
                let decoded =
                    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &body)
                        .unwrap();
                let text = String::from_utf8(decoded).unwrap();
                assert!(text.contains("ok"));
            }
            _ => panic!("expected HttpResponse"),
        }
    }

    #[test]
    fn bad_gateway_response_has_correct_status() {
        let resp = bad_gateway_response("req_001");
        match resp {
            ClientMessage::HttpResponse { id, status, .. } => {
                assert_eq!(id, "req_001");
                assert_eq!(status, 502);
            }
            _ => panic!("expected HttpResponse"),
        }
    }

    #[test]
    fn header_whitelist_allows_known_headers() {
        assert!(is_header_allowed("content-type"));
        assert!(is_header_allowed("Content-Type"));
        assert!(is_header_allowed("authorization"));
        assert!(is_header_allowed("cookie"));
        assert!(is_header_allowed("accept"));
        assert!(is_header_allowed("stripe-signature"));
        assert!(is_header_allowed("user-agent"));
        assert!(is_header_allowed("content-encoding"));
    }

    #[test]
    fn header_whitelist_allows_x_prefix() {
        assert!(is_header_allowed("x-forwarded-for"));
        assert!(is_header_allowed("x-forwarded-proto"));
        assert!(is_header_allowed("x-real-ip"));
        assert!(is_header_allowed("x-requested-with"));
        assert!(is_header_allowed("x-github-event"));
        assert!(is_header_allowed("x-hub-signature-256"));
        assert!(is_header_allowed("x-webhook-id"));
        assert!(is_header_allowed("x-webhook-signature"));
        assert!(is_header_allowed("x-webhook-timestamp"));
        assert!(is_header_allowed("X-Custom-Header"));
    }

    #[test]
    fn response_too_large_returns_502() {
        let resp = response_too_large("req_big", 100_000_000);
        match resp {
            ClientMessage::HttpResponse {
                id, status, body, ..
            } => {
                assert_eq!(id, "req_big");
                assert_eq!(status, 502);
                let decoded =
                    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &body)
                        .unwrap();
                let text = String::from_utf8(decoded).unwrap();
                assert!(text.contains("too large"));
                assert!(text.contains("100000000"));
            }
            _ => panic!("expected HttpResponse"),
        }
    }

    #[test]
    fn max_response_body_size_is_reasonable() {
        assert_eq!(MAX_RESPONSE_BODY_SIZE, 50 * 1024 * 1024);
    }

    #[tokio::test]
    async fn event_stream_reconnect_preserves_last_event_id() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut bytes = Vec::new();
            let mut chunk = [0; 1024];
            while !bytes.ends_with(b"\r\n\r\n") {
                let count = socket.read(&mut chunk).await.unwrap();
                assert!(count > 0);
                bytes.extend_from_slice(&chunk[..count]);
            }
            let request = String::from_utf8(bytes).unwrap();
            let resumed = request
                .lines()
                .any(|line| line.eq_ignore_ascii_case("last-event-id: event-1230"));
            let body = if resumed {
                "id: event-1231\ndata: new\n\n"
            } else {
                "id: event-1\ndata: old\n\n"
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            );
            socket.write_all(response.as_bytes()).await.unwrap();
            request
        });
        let request = ServerMessage::HttpRequest {
            id: "resume".into(),
            method: "GET".into(),
            url: "/events".into(),
            headers: HashMap::from([("Last-Event-ID".into(), "event-1230".into())]),
            body: String::new(),
        };
        let response = forward_request(
            &reqwest::Client::builder().no_proxy().build().unwrap(),
            &lpm_common::LocalTarget::loopback(lpm_common::LocalScheme::Http, address.port()),
            &request,
        )
        .await
        .unwrap();
        let captured = server.await.unwrap();
        assert!(
            captured
                .to_ascii_lowercase()
                .contains("last-event-id: event-1230")
        );
        let ClientMessage::HttpResponse { status, body, .. } = response else {
            panic!("expected HTTP response")
        };
        assert_eq!(status, 200);
        let decoded =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, body).unwrap();
        assert_eq!(decoded, b"id: event-1231\ndata: new\n\n");
    }

    #[tokio::test]
    async fn event_stream_chunks_and_inspector_capture_are_bounded() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0; 1024];
            assert!(socket.read(&mut request).await.unwrap() > 0);
            socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream; charset=utf-8\r\nContent-Length: 131072\r\n\r\n").await.unwrap();
            socket.write_all(&vec![b'x'; 128 * 1024]).await.unwrap();
        });
        let (messages, mut output) = tokio::sync::mpsc::channel(1);
        let (credits, credit_rx) = tokio::sync::mpsc::channel(1);
        let forward = tokio::spawn(async move {
            let request = ServerMessage::HttpRequest {
                id: "stream".into(),
                method: "GET".into(),
                url: "/events".into(),
                headers: HashMap::new(),
                body: String::new(),
            };
            forward_request_inner(
                &reqwest::Client::builder().no_proxy().build().unwrap(),
                &lpm_common::LocalTarget::loopback(lpm_common::LocalScheme::Http, address.port()),
                None,
                &request,
                None,
                Some(crate::http_stream::StreamOutput {
                    messages,
                    credits: credit_rx,
                    cancel: tokio_util::sync::CancellationToken::new(),
                }),
            )
            .await
            .unwrap()
        });
        let mut received = 0;
        while let Some(message) = output.recv().await {
            match message {
                ClientMessage::HttpResponseStart { status: 200, .. } => {}
                ClientMessage::HttpResponseChunk { body, .. } => {
                    let bytes =
                        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, body)
                            .unwrap();
                    assert!(bytes.len() <= 64 * 1024);
                    received += bytes.len();
                }
                _ => panic!("unexpected stream message"),
            }
            credits.send(()).await.unwrap();
        }
        let response = forward.await.unwrap();
        server.await.unwrap();
        assert_eq!(received, 128 * 1024);
        assert!(response.capture_incomplete);
        assert!(matches!(
            response.stream_end,
            Some(ClientMessage::HttpResponseEnd { failed: false, .. })
        ));
        let ClientMessage::HttpResponse { body, .. } = response.message else {
            panic!("missing inspector response")
        };
        assert_eq!(
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, body)
                .unwrap()
                .len(),
            64 * 1024
        );
    }

    #[tokio::test]
    async fn chunked_response_stops_at_the_body_limit_without_waiting_for_eof() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0; 1024];
            let read = socket.read(&mut request).await.unwrap();
            assert!(read > 0);
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
                .await
                .unwrap();
            let chunk = vec![b'x'; 1024 * 1024];
            for _ in 0..=MAX_RESPONSE_BODY_SIZE / chunk.len() {
                socket
                    .write_all(format!("{:x}\r\n", chunk.len()).as_bytes())
                    .await
                    .unwrap();
                socket.write_all(&chunk).await.unwrap();
                socket.write_all(b"\r\n").await.unwrap();
            }
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        });
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let target =
            lpm_common::LocalTarget::loopback(lpm_common::LocalScheme::Http, address.port());
        let request = ServerMessage::HttpRequest {
            id: "chunked-large".to_string(),
            method: "GET".to_string(),
            url: "/large".to_string(),
            headers: HashMap::new(),
            body: String::new(),
        };

        let response = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            forward_request(&client, &target, &request),
        )
        .await
        .expect("oversized response waited for EOF")
        .unwrap();
        server.abort();

        assert!(matches!(
            response,
            ClientMessage::HttpResponse { status: 502, .. }
        ));
    }

    #[tokio::test]
    async fn chunked_response_completes_while_another_response_holds_memory() {
        let budget = Arc::new(tokio::sync::Semaphore::new(64));
        let held = Arc::clone(&budget).acquire_owned().await.unwrap();
        let response = budgeted_test_response(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n",
            Arc::clone(&budget),
            64,
            1024 * 1024,
        )
        .await;
        assert!(matches!(
            response.message,
            ClientMessage::HttpResponse { status: 200, .. }
        ));
        assert_eq!(budget.available_permits(), 62);
        drop(response);
        drop(held);
        assert_eq!(budget.available_permits(), 64);
    }

    #[tokio::test]
    async fn response_memory_saturation_returns_retryable_busy_without_waiting() {
        let budget = Arc::new(tokio::sync::Semaphore::new(4));
        let held = Arc::clone(&budget).acquire_many_owned(4).await.unwrap();
        let response = budgeted_test_response(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
            Arc::clone(&budget),
            4,
            1024,
        )
        .await;
        let ClientMessage::HttpResponse {
            status, headers, ..
        } = response.message
        else {
            panic!("expected HTTP response")
        };
        assert_eq!(status, 503);
        assert_eq!(headers.get("retry-after").map(String::as_str), Some("1"));
        drop(held);
        assert_eq!(budget.available_permits(), 4);
    }

    #[tokio::test]
    async fn growing_chunked_response_releases_its_reservation_when_memory_is_busy() {
        let budget = Arc::new(tokio::sync::Semaphore::new(4));
        let held = Arc::clone(&budget).acquire_owned().await.unwrap();
        let response = budgeted_test_response(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\ne\r\n0123456789abcd\r\n0\r\n\r\n",
            Arc::clone(&budget),
            4,
            4,
        )
        .await;
        assert!(matches!(
            response.message,
            ClientMessage::HttpResponse { status: 503, .. }
        ));
        assert_eq!(budget.available_permits(), 3);
        drop(held);
        assert_eq!(budget.available_permits(), 4);
    }

    async fn budgeted_test_response(
        raw: &'static [u8],
        budget: Arc<tokio::sync::Semaphore>,
        permits: usize,
        unit_bytes: usize,
    ) -> ForwardedResponse {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0; 1024];
            assert!(socket.read(&mut request).await.unwrap() > 0);
            socket.write_all(raw).await.unwrap();
        });
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let target =
            lpm_common::LocalTarget::loopback(lpm_common::LocalScheme::Http, address.port());
        let request = ServerMessage::HttpRequest {
            id: "budgeted".into(),
            method: "GET".into(),
            url: "/health".into(),
            headers: HashMap::new(),
            body: String::new(),
        };
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            forward_request_with_memory_budget(
                &client, &target, None, &request, budget, permits, unit_bytes, 4, None,
            ),
        )
        .await;
        server.await.unwrap();
        result
            .expect("response waited for unrelated memory reservations")
            .unwrap()
    }

    #[tokio::test]
    async fn chunked_response_keeps_its_grown_memory_reservation_until_dropped() {
        let budget = Arc::new(tokio::sync::Semaphore::new(4));
        let response = budgeted_test_response(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\ne\r\n0123456789abcd\r\n0\r\n\r\n",
            Arc::clone(&budget),
            4,
            16,
        )
        .await;
        let ClientMessage::HttpResponse {
            status, ref body, ..
        } = response.message
        else {
            panic!("expected HTTP response")
        };
        assert_eq!(status, 200);
        assert_eq!(
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, body).unwrap(),
            b"ok0123456789abcd"
        );
        assert_eq!(budget.available_permits(), 0);
        drop(response);
        assert_eq!(budget.available_permits(), 4);
    }

    #[tokio::test]
    async fn near_limit_response_reserves_the_full_memory_budget_before_body_buffering() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let release_body = Arc::new(tokio::sync::Notify::new());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server_release = Arc::clone(&release_body);
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0; 1024];
            assert!(socket.read(&mut request).await.unwrap() > 0);
            socket
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                        49 * 1024 * 1024
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            server_release.notified().await;
        });
        let budget = Arc::new(tokio::sync::Semaphore::new(64));
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let target =
            lpm_common::LocalTarget::loopback(lpm_common::LocalScheme::Http, address.port());
        let request = ServerMessage::HttpRequest {
            id: "near-limit".to_string(),
            method: "GET".to_string(),
            url: "/large".to_string(),
            headers: HashMap::new(),
            body: String::new(),
        };
        let forward_budget = Arc::clone(&budget);
        let forward = tokio::spawn(async move {
            forward_request_with_memory_budget(
                &client,
                &target,
                None,
                &request,
                forward_budget,
                64,
                1024 * 1024,
                4,
                None,
            )
            .await
        });

        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while budget.available_permits() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("near-limit response did not reserve the memory budget");

        forward.abort();
        release_body.notify_waiters();
        server.await.unwrap();
        assert_eq!(budget.available_permits(), 64);
    }

    #[test]
    fn header_whitelist_blocks_dangerous_headers() {
        assert!(!is_header_allowed("host"));
        assert!(!is_header_allowed("Host"));
        assert!(!is_header_allowed("transfer-encoding"));
        assert!(!is_header_allowed("Transfer-Encoding"));
        // Unknown headers not in whitelist are blocked
        assert!(!is_header_allowed("connection"));
        assert!(!is_header_allowed("upgrade"));
        assert!(!is_header_allowed("proxy-authorization"));
        assert!(!is_header_allowed("te"));
        assert!(!is_header_allowed("trailer"));
        assert!(!is_header_allowed("keep-alive"));
    }

    #[test]
    fn local_websocket_request_includes_upgrade_headers() {
        let target = lpm_common::LocalTarget::loopback(lpm_common::LocalScheme::Http, 3005);
        let request = build_local_websocket_request(&target, "/ws-test", &HashMap::new()).unwrap();

        assert!(
            request.headers().contains_key("sec-websocket-key"),
            "local WebSocket request must include sec-websocket-key"
        );
        assert!(
            request.headers().contains_key("sec-websocket-version"),
            "local WebSocket request must include sec-websocket-version"
        );
        assert_eq!(
            request.headers().get("upgrade").unwrap(),
            "websocket",
            "local WebSocket request must include Upgrade: websocket"
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
            "local WebSocket request must include Connection: upgrade"
        );
    }

    #[test]
    fn target_base_path_is_not_duplicated_when_request_already_contains_it() {
        let target = lpm_common::LocalTarget::loopback(lpm_common::LocalScheme::Http, 5173)
            .with_base_path("/app/");

        assert_eq!(
            target.upstream_path("/app/assets/main.js"),
            "/app/assets/main.js"
        );
    }

    #[tokio::test]
    async fn local_websocket_connect_sends_single_sec_websocket_key_header() {
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

        let target = lpm_common::LocalTarget::loopback(lpm_common::LocalScheme::Http, addr.port());
        let request = build_local_websocket_request(&target, "/ws-test", &HashMap::new()).unwrap();

        let _ = tokio_tungstenite::connect_async(request).await;

        let raw_request = server.await.unwrap();
        let sec_key_count = raw_request
            .lines()
            .filter(|line| line.to_ascii_lowercase().starts_with("sec-websocket-key:"))
            .count();

        assert_eq!(
            sec_key_count, 1,
            "local websocket client must send exactly one Sec-WebSocket-Key header, got request:\n{raw_request}"
        );
    }

    /// An IPv6-only listener on a port whose IPv4 loopback address refuses
    /// connections, as `npm run dev` leaves Vite on macOS.
    async fn ipv6_only_listener() -> (tokio::net::TcpListener, tokio::net::TcpSocket) {
        for _ in 0..16 {
            let listener = tokio::net::TcpListener::bind((std::net::Ipv6Addr::LOCALHOST, 0))
                .await
                .unwrap();
            let port = listener.local_addr().unwrap().port();
            let refused = tokio::net::TcpSocket::new_v4().unwrap();
            if refused
                .bind((std::net::Ipv4Addr::LOCALHOST, port).into())
                .is_ok()
            {
                return (listener, refused);
            }
        }
        panic!("no port was free on both loopback families");
    }

    fn serve_one_response(listener: tokio::net::TcpListener, body: &'static str) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0; 1024];
            assert!(socket.read(&mut request).await.unwrap() > 0);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            socket.write_all(response.as_bytes()).await.unwrap();
        });
    }

    fn get_root(id: &str) -> ServerMessage {
        ServerMessage::HttpRequest {
            id: id.into(),
            method: "POST".into(),
            url: "/".into(),
            headers: HashMap::new(),
            body: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"{}"),
        }
    }

    #[tokio::test]
    async fn port_only_forward_reaches_the_ipv6_listener_and_remembers_it() {
        let (listener, _refused) = ipv6_only_listener().await;
        let port = listener.local_addr().unwrap().port();
        serve_one_response(listener, "over ipv6");
        let target = lpm_common::LocalTarget::loopback_port(lpm_common::LocalScheme::Http, port);
        let live_target = std::sync::RwLock::new(target.clone());

        let response = forward_request_inner(
            &reqwest::Client::builder().no_proxy().build().unwrap(),
            &target,
            Some(&live_target),
            &get_root("ipv6"),
            None,
            None,
        )
        .await
        .unwrap();

        let ClientMessage::HttpResponse { status, body, .. } = response.message else {
            panic!("expected HTTP response")
        };
        let body =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, body).unwrap();
        assert_eq!((status, body.as_slice()), (200, b"over ipv6".as_slice()));
        assert_eq!(
            live_target.read().unwrap().url(),
            format!("http://[::1]:{port}/")
        );
    }

    #[tokio::test]
    async fn a_verified_target_does_not_fall_back_to_the_other_loopback_family() {
        let (listener, _refused) = ipv6_only_listener().await;
        let port = listener.local_addr().unwrap().port();
        serve_one_response(listener, "over ipv6");
        let target = lpm_common::LocalTarget::loopback(lpm_common::LocalScheme::Http, port);

        let error = forward_request(
            &reqwest::Client::builder().no_proxy().build().unwrap(),
            &target,
            &get_root("verified"),
        )
        .await
        .unwrap_err();

        assert_eq!(
            error.to_string(),
            format!(
                "tunnel error: local server not reachable at http://127.0.0.1:{port}/ — is it running?"
            )
        );
    }

    #[tokio::test]
    async fn a_port_only_forward_with_no_listener_names_both_loopback_addresses() {
        let (listener, refused) = ipv6_only_listener().await;
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let target = lpm_common::LocalTarget::loopback_port(lpm_common::LocalScheme::Http, port);

        let error = forward_request(
            &reqwest::Client::builder().no_proxy().build().unwrap(),
            &target,
            &get_root("nobody"),
        )
        .await
        .unwrap_err();
        drop(refused);

        assert_eq!(
            error.to_string(),
            format!(
                "tunnel error: local server not reachable at http://127.0.0.1:{port}/ or http://[::1]:{port}/ — is it running?"
            )
        );
    }

    #[tokio::test]
    async fn port_only_websocket_upgrade_connects_on_the_ipv6_listener() {
        let (listener, _refused) = ipv6_only_listener().await;
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            tokio_tungstenite::accept_async(socket).await.unwrap();
        });
        let target = lpm_common::LocalTarget::loopback_port(lpm_common::LocalScheme::Http, port);

        let connection = connect_local_websocket(&target, "/hmr", &HashMap::new())
            .await
            .unwrap();

        server.await.unwrap();
        assert_eq!(
            connection.sibling_target.map(|target| target.url()),
            Some(format!("http://[::1]:{port}/"))
        );
    }

    #[tokio::test]
    async fn probe_prefers_the_targets_own_family_and_falls_back_to_its_sibling() {
        let (listener, refused) = ipv6_only_listener().await;
        let port = listener.local_addr().unwrap().port();
        let target = lpm_common::LocalTarget::loopback_port(lpm_common::LocalScheme::Http, port);

        let ipv6_only = probe_local_target(&target).await;
        drop(refused);
        let ipv4 = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        let both = probe_local_target(&target).await;
        drop((listener, ipv4));

        assert_eq!(
            ipv6_only.map(|target| target.url()),
            Some(format!("http://[::1]:{port}/"))
        );
        assert_eq!(both, Some(target));
    }

    #[tokio::test]
    async fn probe_finds_nothing_when_neither_loopback_family_listens() {
        let (listener, _refused) = ipv6_only_listener().await;
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let target = lpm_common::LocalTarget::loopback_port(lpm_common::LocalScheme::Http, port);

        assert_eq!(probe_local_target(&target).await, None);
    }
}
