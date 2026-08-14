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
    pub(crate) memory_permit: Option<tokio::sync::OwnedSemaphorePermit>,
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
        forward_request_inner(http_client, local_target, request, None)
            .await?
            .message,
    )
}

pub(crate) async fn forward_request_with_memory_budget(
    http_client: &reqwest::Client,
    local_target: &lpm_common::LocalTarget,
    request: &ServerMessage,
    memory_budget: Arc<tokio::sync::Semaphore>,
    memory_budget_permits: usize,
    memory_unit_bytes: usize,
    memory_multiplier: usize,
) -> Result<ForwardedResponse, LpmError> {
    forward_request_inner(
        http_client,
        local_target,
        request,
        Some((
            memory_budget,
            memory_budget_permits,
            memory_unit_bytes,
            memory_multiplier,
        )),
    )
    .await
}

async fn forward_request_inner(
    http_client: &reqwest::Client,
    local_target: &lpm_common::LocalTarget,
    request: &ServerMessage,
    memory_budget: Option<(Arc<tokio::sync::Semaphore>, usize, usize, usize)>,
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

    let local_path = local_target.upstream_path(url);
    let local_url = format!(
        "{}://{}{}",
        local_target.scheme,
        local_target.authority(),
        local_path
    );

    // Build the request
    let req_method = method
        .parse::<reqwest::Method>()
        .map_err(|e| LpmError::Tunnel(format!("invalid HTTP method '{method}': {e}")))?;

    let mut builder = http_client.request(req_method, &local_url);

    // Forward headers using a whitelist — only known-safe headers are forwarded
    // to the local dev server. This prevents relay-injected or attacker-controlled
    // headers from reaching the local service.
    for (key, value) in headers {
        if is_header_allowed(key) {
            builder = builder.header(key.as_str(), value.as_str());
        }
    }
    builder = builder.header("host", local_target.authority());

    // Decode and attach body
    if !body.is_empty() {
        let body_bytes =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, body)
                .map_err(|e| LpmError::Tunnel(format!("failed to decode request body: {e}")))?;
        builder = builder.body(body_bytes);
    }

    // Send with timeout
    let response = builder
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| {
            if e.is_connect() {
                LpmError::Tunnel(format!(
                    "local server not reachable at {} — is it running?",
                    local_target.url()
                ))
            } else if e.is_timeout() {
                LpmError::Tunnel(format!(
                    "request to {}{local_path} timed out",
                    local_target.authority()
                ))
            } else {
                LpmError::Tunnel(format!("failed to forward request: {e}"))
            }
        })?;

    let status = response.status().as_u16();

    // Collect response headers
    let mut resp_headers = HashMap::new();
    for (key, value) in response.headers() {
        if let Ok(v) = value.to_str() {
            resp_headers.insert(key.to_string(), v.to_string());
        }
    }

    // Check content-length header first for early rejection of oversized responses.
    // Fall back to reading bytes and checking after for chunked/streaming responses.
    if let Some(cl) = response.content_length()
        && cl > MAX_RESPONSE_BODY_SIZE as u64
    {
        return Ok(ForwardedResponse {
            message: response_too_large(id, cl),
            memory_permit: None,
        });
    }

    let memory_permit =
        if let Some((budget, budget_permits, unit_bytes, multiplier)) = memory_budget {
            let raw_bytes = response
                .content_length()
                .and_then(|length| usize::try_from(length).ok())
                .unwrap_or(MAX_RESPONSE_BODY_SIZE)
                .min(MAX_RESPONSE_BODY_SIZE);
            let estimated_bytes = raw_bytes.saturating_mul(multiplier);
            let permits = estimated_bytes.div_ceil(unit_bytes).max(1);
            let permits = u32::try_from(permits.min(budget_permits).max(1))
                .map_err(|_| LpmError::Tunnel("response memory budget is too large".into()))?;
            Some(
                budget
                    .acquire_many_owned(permits)
                    .await
                    .map_err(|_| LpmError::Tunnel("response memory budget was closed".into()))?,
            )
        } else {
            None
        };

    let mut body_bytes = Vec::with_capacity(
        response
            .content_length()
            .map_or(0, |length| length as usize)
            .min(MAX_RESPONSE_BODY_SIZE),
    );
    let mut response = response;
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| LpmError::Tunnel(format!("failed to read response body: {e}")))?
    {
        let next_len = body_bytes.len().saturating_add(chunk.len());
        if next_len > MAX_RESPONSE_BODY_SIZE {
            return Ok(ForwardedResponse {
                message: response_too_large(id, next_len as u64),
                memory_permit,
            });
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
        memory_permit,
    })
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

/// Establish a WebSocket connection to the local dev server for upgrade passthrough.
///
/// Connects to the target's complete WebSocket endpoint, including its address
/// and base path, and returns the split stream used for HMR frame forwarding.
pub async fn connect_local_websocket(
    local_target: &lpm_common::LocalTarget,
    url: &str,
    headers: &HashMap<String, String>,
) -> Result<
    (
        futures_util::stream::SplitSink<
            tokio_tungstenite::WebSocketStream<
                tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
            >,
            tokio_tungstenite::tungstenite::Message,
        >,
        futures_util::stream::SplitStream<
            tokio_tungstenite::WebSocketStream<
                tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
            >,
        >,
    ),
    LpmError,
> {
    crate::validate_forward_target(local_target)?;
    let request = build_local_websocket_request(local_target, url, headers)?;

    let ws_config = tokio_tungstenite::tungstenite::protocol::WebSocketConfig {
        write_buffer_size: 128 * 1024,
        max_write_buffer_size: 4 * 1024 * 1024,
        max_message_size: Some(crate::client::MAX_WS_MESSAGE_SIZE),
        max_frame_size: Some(crate::client::MAX_WS_FRAME_SIZE),
        ..Default::default()
    };
    let (stream, _) = tokio_tungstenite::connect_async_with_config(request, Some(ws_config), false)
        .await
        .map_err(|e| LpmError::Tunnel(format!("failed to connect local WebSocket: {e}")))?;

    use futures_util::StreamExt;
    Ok(stream.split())
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
                &request,
                forward_budget,
                64,
                1024 * 1024,
                4,
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
}
