use futures::StreamExt;

use super::SyncError;
use super::envelope::{
    AuthenticatedSyncResponse, REQUEST_NONCE_HEADER, SyncScope, generate_request_nonce,
};
use crate::signature;

/// Hard cap on a single vault-sync response body. Encrypted envelopes
/// are small (kilobytes); a multi-MB cap leaves multiple orders of
/// magnitude of headroom while stopping a malicious / compromised
/// platform endpoint from OOM-ing the CLI on the signed-read path
/// that runs before any signature verification.
const MAX_VAULT_RESPONSE_BYTES: usize = 10 * 1024 * 1024;

/// Drain a response body with the vault size cap applied in two stages.
///
/// Stage 1 (pre-stream): refuse when the server's declared
/// `Content-Length` exceeds `MAX_VAULT_RESPONSE_BYTES`. Stage 2
/// (mid-stream): accumulate `bytes_stream()` chunks and abort the
/// moment another chunk would cross the cap. Closing the response
/// at that point drops the underlying connection.
async fn read_capped_body(response: reqwest::Response) -> Result<Vec<u8>, String> {
    if let Some(declared) = response.content_length()
        && declared as usize > MAX_VAULT_RESPONSE_BYTES
    {
        return Err(format!(
            "response too large: declared length {declared} exceeds cap {MAX_VAULT_RESPONSE_BYTES}"
        ));
    }

    let mut buf: Vec<u8> = Vec::with_capacity(16 * 1024);
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| format!("response read error: {e}"))?;
        if buf.len().saturating_add(chunk.len()) > MAX_VAULT_RESPONSE_BYTES {
            return Err(format!(
                "response too large: streamed body exceeded cap {MAX_VAULT_RESPONSE_BYTES}"
            ));
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

/// Read a (typically error) response body as UTF-8 text under the
/// vault cap. Mirrors the previous `response.text().await.unwrap_or_default()`
/// shape — failures become empty strings so error formatting still
/// produces a usable message — but the buffer is now bounded.
pub(super) async fn read_capped_error_text(response: reqwest::Response) -> String {
    match read_capped_body(response).await {
        Ok(buf) => String::from_utf8_lossy(&buf).into_owned(),
        Err(_) => String::new(),
    }
}

/// Read a vault sync response and verify its `X-LPM-Signature` header
/// against the body. Only 2xx responses are signed by the server, so
/// error responses are returned unverified for the caller to format.
///
/// Returning `(status, body)` rather than the parsed response gives every
/// call site identical verification semantics and keeps the parse step
/// downstream — so a failed signature can never reach decryption.
pub(super) async fn read_verified_response(
    response: reqwest::Response,
    auth_token: &str,
) -> Result<(reqwest::StatusCode, Vec<u8>), String> {
    let status = response.status();
    // Snapshot the signature header first — body-drain consumes
    // `self`, so we cannot read headers afterwards.
    let signature_header = response
        .headers()
        .get(signature::SIGNATURE_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

    let body = read_capped_body(response).await?;

    if status.is_success() {
        signature::verify_response_body(&body, auth_token, signature_header.as_deref())
            .map_err(|e| e.to_string())?;
    }

    Ok((status, body))
}

pub(super) enum SyncHttpResponse {
    Success(Box<AuthenticatedSyncResponse>),
    Error {
        status: reqwest::StatusCode,
        body: Vec<u8>,
    },
}

pub(super) async fn send_authenticated_sync_request(
    request: reqwest::RequestBuilder,
    auth_token: &str,
    vault_id: &str,
    scope: SyncScope<'_>,
) -> Result<SyncHttpResponse, SyncError> {
    let request_nonce = generate_request_nonce()?;
    let response = request
        .header(REQUEST_NONCE_HEADER, &request_nonce)
        .send()
        .await
        .map_err(network_error)?;
    let (status, body) = read_verified_response(response, auth_token).await?;
    if !status.is_success() {
        return Ok(SyncHttpResponse::Error { status, body });
    }

    let response: AuthenticatedSyncResponse =
        serde_json::from_slice(&body).map_err(|error| format!("response parse error: {error}"))?;
    response.validate(vault_id, scope, &request_nonce)?;
    Ok(SyncHttpResponse::Success(Box::new(response)))
}

pub(super) fn sync_request_timeout(default: std::time::Duration) -> std::time::Duration {
    if !cfg!(debug_assertions) {
        return default;
    }
    match std::env::var("LPM_TEST_SYNC_TIMEOUT_MS") {
        Ok(value) => value
            .parse::<u64>()
            .map_or(default, std::time::Duration::from_millis),
        Err(_) => default,
    }
}

pub(super) fn sync_http_client_builder() -> reqwest::ClientBuilder {
    lpm_http::client_builder()
}

pub(super) fn network_error(error: reqwest::Error) -> String {
    format!("network error: {}", lpm_http::display_error(&error))
}

/// Percent-encode a URL path segment.
///
/// Vault sync calls interpolate `vault_id`, `org_slug`, and `code`
/// directly into request paths. Raw `/`, `?`, `#`, `..`, `&` etc. in
/// any of those would alter the route — e.g.,
/// `/api/orgs/{org}/vaults/{vault}` with `vault = "foo/../bar"` would
/// hit a different endpoint server-side. Routing all path components
/// through this helper closes the request-confusion shape.
pub(super) fn url_path_segment(s: &str) -> String {
    urlencoding::encode(s).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `read_capped_body` rejects pre-stream when the server declares a
    /// `Content-Length` over the vault cap. A malicious / compromised
    /// platform endpoint must not be able to coerce
    /// `read_verified_response` into allocating a multi-GB buffer
    /// before any signature check runs.
    #[tokio::test]
    async fn read_capped_body_rejects_oversized_declared_length() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let declared = MAX_VAULT_RESPONSE_BYTES + 1;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\n\
                     Content-Length: {declared}\r\n\
                     Content-Type: application/json\r\n\
                     Connection: close\r\n\
                     \r\n",
                );
                let _ = socket.write_all(resp.as_bytes()).await;
                let _ = socket.shutdown().await;
            }
        });

        let response = reqwest::get(format!("http://{addr}/"))
            .await
            .expect("connect");
        let err = read_capped_body(response)
            .await
            .expect_err("oversized declared length must reject pre-stream");
        assert!(
            err.contains("declared length"),
            "expected pre-stream rejection, got: {err}"
        );
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn sync_request_timeout_ignores_env_in_release_builds() {
        let _guard = crate::test_env_lock::acquire_env_lock();
        let original_timeout = std::env::var_os("LPM_TEST_SYNC_TIMEOUT_MS");
        unsafe { std::env::set_var("LPM_TEST_SYNC_TIMEOUT_MS", "50") };

        let timeout = sync_request_timeout(std::time::Duration::from_secs(30));

        match original_timeout {
            Some(value) => unsafe { std::env::set_var("LPM_TEST_SYNC_TIMEOUT_MS", value) },
            None => unsafe { std::env::remove_var("LPM_TEST_SYNC_TIMEOUT_MS") },
        }

        assert_eq!(timeout, std::time::Duration::from_secs(30));
    }
}
