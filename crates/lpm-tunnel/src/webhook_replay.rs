//! Webhook replay mechanism.
//!
//! Re-sends a previously captured webhook to the local dev server,
//! preserving the original headers (including signatures) so the
//! handler processes it identically to the original request.

use crate::webhook::CapturedWebhook;
use lpm_common::LpmError;

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
        .map_err(|e| LpmError::Tunnel(format!("replay failed: {e}")))?;

    let status = resp.status().as_u16();
    let body = resp
        .bytes()
        .await
        .map_err(|e| LpmError::Tunnel(format!("failed to read replay response: {e}")))?
        .to_vec();

    Ok(ReplayResult {
        status,
        duration_ms: start.elapsed().as_millis() as u64,
        response_body: body,
    })
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
}
