//! Webhook replay mechanism.
//!
//! Re-sends a previously captured webhook to the local dev server,
//! preserving the original headers (including signatures) so the
//! handler processes it identically to the original request.

use crate::webhook::CapturedWebhook;
use futures_util::StreamExt;
use lpm_common::LpmError;

/// Cap on replay response bodies. Matches the proxy's
/// `MAX_RESPONSE_BODY_SIZE` so replay can't accept anything the
/// tunnel itself would already have refused.
const MAX_REPLAY_RESPONSE_BYTES: usize = 50 * 1024 * 1024;

/// Result of replaying a webhook against the local server.
#[derive(Debug)]
pub struct ReplayResult {
    /// HTTP status code from the local server.
    pub status: u16,
    /// Round-trip time in milliseconds.
    pub duration_ms: u64,
    /// Response body from the local server.
    pub response_body: Vec<u8>,
}

/// Validate that a path is safe to use in a replay URL.
///
/// Prevents SSRF attacks where a crafted path like `@evil.com/path` would make
/// `http://localhost:3000@evil.com/path` resolve to `evil.com` (localhost becomes
/// the userinfo). Also rejects `//` which could be interpreted as authority.
fn is_safe_replay_path(path: &str) -> bool {
    path.starts_with('/')
        && !path.starts_with("//")
        && !path.contains('@')
        && !path.contains('\n')
        && !path.contains('\r')
}

/// Replay a captured webhook against the local dev server.
///
/// Sends the original request (method, path, headers, body) to
/// `localhost:{local_port}`. Headers like `host`, `content-length`,
/// and `transfer-encoding` are excluded since they are hop-by-hop
/// or will be set by the HTTP client automatically.
///
/// Accepts a shared `reqwest::Client` to avoid creating a new client per replay
/// (connection pool reuse, TLS session caching, etc.).
pub async fn replay_webhook(
    client: &reqwest::Client,
    webhook: &CapturedWebhook,
    local_port: u16,
) -> Result<ReplayResult, LpmError> {
    if !is_safe_replay_path(&webhook.path) {
        return Err(LpmError::Tunnel(format!(
            "unsafe replay path rejected: {:?}",
            webhook.path
        )));
    }

    let url = format!("http://localhost:{local_port}{}", webhook.path);
    let method: reqwest::Method = webhook
        .method
        .parse()
        .map_err(|e| LpmError::Tunnel(format!("invalid method '{}': {e}", webhook.method)))?;

    let mut builder = client.request(method, &url);

    // Preserve original headers (including signatures) — skip hop-by-hop
    // headers that would conflict with the new connection.
    for (key, value) in &webhook.request_headers {
        let k = key.to_lowercase();
        if k != "host" && k != "content-length" && k != "transfer-encoding" {
            builder = builder.header(key.as_str(), value.as_str());
        }
    }

    if !webhook.request_body.is_empty() {
        builder = builder.body(webhook.request_body.clone());
    }

    let start = std::time::Instant::now();
    let resp = builder
        .send()
        .await
        .map_err(|e| LpmError::Tunnel(format!("replay failed: {}", lpm_http::display_error(&e))))?;

    let status = resp.status().as_u16();
    let body = read_capped_replay_body(resp).await?;

    Ok(ReplayResult {
        status,
        duration_ms: start.elapsed().as_millis() as u64,
        response_body: body,
    })
}

/// Two-stage size cap on the local server's replay response.
///
/// Stage 1 rejects pre-stream when the server's declared
/// `Content-Length` exceeds `MAX_REPLAY_RESPONSE_BYTES`. Stage 2
/// streams `bytes_stream()` and aborts the moment another chunk
/// would cross the cap, so a chunked / undeclared-length response
/// cannot exhaust CLI memory.
async fn read_capped_replay_body(resp: reqwest::Response) -> Result<Vec<u8>, LpmError> {
    if let Some(declared) = resp.content_length()
        && declared > MAX_REPLAY_RESPONSE_BYTES as u64
    {
        return Err(LpmError::Tunnel(format!(
            "replay response too large: declared body length {declared} exceeds cap {MAX_REPLAY_RESPONSE_BYTES}"
        )));
    }

    let mut buf: Vec<u8> = Vec::with_capacity(16 * 1024);
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk =
            chunk.map_err(|e| LpmError::Tunnel(format!("failed to read replay response: {e}")))?;
        if buf.len().saturating_add(chunk.len()) > MAX_REPLAY_RESPONSE_BYTES {
            return Err(LpmError::Tunnel(format!(
                "replay response too large: streamed body exceeded cap {MAX_REPLAY_RESPONSE_BYTES}"
            )));
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_result_fields() {
        let result = ReplayResult {
            status: 200,
            duration_ms: 42,
            response_body: b"ok".to_vec(),
        };
        assert_eq!(result.status, 200);
        assert_eq!(result.duration_ms, 42);
        assert_eq!(result.response_body, b"ok");
    }

    #[test]
    fn safe_replay_path_validation() {
        // Valid paths
        assert!(is_safe_replay_path("/api/webhook"));
        assert!(is_safe_replay_path("/callback?url=https://example.com"));
        assert!(is_safe_replay_path("/a/b/c"));
        assert!(is_safe_replay_path("/"));

        // SSRF vectors
        assert!(!is_safe_replay_path("@evil.com/path"));
        assert!(!is_safe_replay_path("//evil.com/path"));
        assert!(!is_safe_replay_path(""));
        assert!(!is_safe_replay_path("/path\nX-Injected: true"));
        assert!(!is_safe_replay_path("/path\r\nX-Injected: true"));
        assert!(!is_safe_replay_path("/api@evil.com"));
    }

    #[test]
    fn replay_result_error_status() {
        let result = ReplayResult {
            status: 500,
            duration_ms: 100,
            response_body: b"internal server error".to_vec(),
        };
        assert_eq!(result.status, 500);
        assert!(result.status >= 400);
    }

    /// Replay against a local listener whose `Content-Length` header
    /// claims more bytes than the cap allows. The stage-1 pre-stream
    /// check rejects before any body bytes are read.
    #[tokio::test]
    async fn replay_rejects_oversized_declared_content_length() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request_buf = [0u8; 1024];
            let _ = stream.read(&mut request_buf).await;
            let oversized = MAX_REPLAY_RESPONSE_BYTES as u64 + 1;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {oversized}\r\n\r\n"
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.shutdown().await;
        });

        let captured = CapturedWebhook {
            id: "test".into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            method: "POST".into(),
            path: "/api/webhook".into(),
            request_headers: std::collections::HashMap::new(),
            request_body: vec![],
            response_status: 0,
            response_headers: std::collections::HashMap::new(),
            response_body: vec![],
            duration_ms: 0,
            provider: None,
            summary: String::new(),
            signature_diagnostic: None,
            auto_acked: false,
        };

        let client = reqwest::Client::new();
        let result = replay_webhook(&client, &captured, port).await;
        server.await.unwrap();

        let err = result.expect_err("oversized declared length must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("declared body length"),
            "expected pre-stream rejection, got: {msg}"
        );
    }

    /// Replay against a local listener that sends no `Content-Length`
    /// (chunked-style) and streams body bytes past the cap. The
    /// stage-2 mid-stream check aborts before the body finishes.
    #[tokio::test]
    async fn replay_rejects_streamed_body_exceeding_cap() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request_buf = [0u8; 1024];
            let _ = stream.read(&mut request_buf).await;
            let header = b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\n\r\n";
            let _ = stream.write_all(header).await;
            let chunk_size = 1024 * 1024;
            let payload = vec![b'x'; chunk_size];
            let chunk_header = format!("{:x}\r\n", chunk_size);
            let total_chunks = (MAX_REPLAY_RESPONSE_BYTES / chunk_size) + 2;
            for _ in 0..total_chunks {
                if stream.write_all(chunk_header.as_bytes()).await.is_err() {
                    break;
                }
                if stream.write_all(&payload).await.is_err() {
                    break;
                }
                if stream.write_all(b"\r\n").await.is_err() {
                    break;
                }
            }
            let _ = stream.shutdown().await;
        });

        let captured = CapturedWebhook {
            id: "test".into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            method: "POST".into(),
            path: "/api/webhook".into(),
            request_headers: std::collections::HashMap::new(),
            request_body: vec![],
            response_status: 0,
            response_headers: std::collections::HashMap::new(),
            response_body: vec![],
            duration_ms: 0,
            provider: None,
            summary: String::new(),
            signature_diagnostic: None,
            auto_acked: false,
        };

        let client = reqwest::Client::new();
        let result = replay_webhook(&client, &captured, port).await;
        let _ = server.await;

        let err = result.expect_err("streamed body past cap must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("streamed body exceeded cap"),
            "expected mid-stream rejection, got: {msg}"
        );
    }
}
