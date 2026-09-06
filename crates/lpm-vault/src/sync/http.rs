use futures::StreamExt;
use std::sync::OnceLock;

use super::SyncError;
use super::envelope::{
    AuthenticatedSyncResponse, REQUEST_NONCE_HEADER, SyncEnvelopePolicy, SyncScope,
    generate_request_nonce, parse_vault_response,
};
use crate::signature;

/// Hard cap on a single vault-sync response body. Encrypted envelopes
/// are small (kilobytes); a multi-MB cap leaves multiple orders of
/// magnitude of headroom while stopping a malicious / compromised
/// platform endpoint from OOM-ing the CLI on the signed-read path
/// that runs before any signature verification.
pub(super) const MAX_VAULT_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const MAX_VAULT_ERROR_RESPONSE_BYTES: usize = 64 * 1024;

/// Drain a response body with the vault size cap applied in two stages.
///
/// Stage 1 (pre-stream): refuse when the server's declared
/// `Content-Length` exceeds `MAX_VAULT_RESPONSE_BYTES`. Stage 2
/// (mid-stream): accumulate `bytes_stream()` chunks and abort the
/// moment another chunk would cross the cap. Closing the response
/// at that point drops the underlying connection.
async fn read_capped_body_with_limit(
    response: reqwest::Response,
    max_bytes: usize,
) -> Result<Vec<u8>, String> {
    let declared_length = response
        .headers()
        .get(reqwest::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .or_else(|| response.content_length());
    if let Some(declared) = declared_length
        && declared_length_exceeds_cap_for_target(declared, max_bytes, usize::MAX as u64)
    {
        return Err(format!(
            "response too large: declared length {declared} exceeds cap {max_bytes}"
        ));
    }

    let initial_capacity = declared_length
        .and_then(|length| usize::try_from(length).ok())
        .unwrap_or(16 * 1024)
        .min(max_bytes);
    let mut buf: Vec<u8> = Vec::with_capacity(initial_capacity);
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| format!("response read error: {e}"))?;
        let required_capacity = buf
            .len()
            .checked_add(chunk.len())
            .filter(|required| *required <= max_bytes)
            .ok_or_else(|| format!("response too large: streamed body exceeded cap {max_bytes}"))?;
        if required_capacity > buf.capacity() {
            let next_capacity = buf
                .capacity()
                .saturating_mul(2)
                .max(required_capacity)
                .min(max_bytes);
            buf.reserve_exact(next_capacity - buf.len());
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

fn declared_length_exceeds_cap_for_target(
    declared: u64,
    max_bytes: usize,
    target_usize_max: u64,
) -> bool {
    declared > target_usize_max || declared > max_bytes as u64
}

#[cfg(test)]
async fn read_capped_body(response: reqwest::Response) -> Result<Vec<u8>, String> {
    read_capped_body_with_limit(response, MAX_VAULT_RESPONSE_BYTES).await
}

pub(super) async fn read_capped_json<T>(response: reqwest::Response) -> Result<T, String>
where
    T: serde::de::DeserializeOwned,
{
    read_capped_json_with_size(response)
        .await
        .map(|(value, _)| value)
}

pub(super) async fn read_capped_json_with_size<T>(
    response: reqwest::Response,
) -> Result<(T, usize), String>
where
    T: serde::de::DeserializeOwned,
{
    read_capped_json_with_size_limit(response, MAX_VAULT_RESPONSE_BYTES).await
}

pub(super) async fn read_capped_json_with_size_limit<T>(
    response: reqwest::Response,
    max_bytes: usize,
) -> Result<(T, usize), String>
where
    T: serde::de::DeserializeOwned,
{
    let body = read_capped_body_with_limit(response, max_bytes).await?;
    let body_len = body.len();
    serde_json::from_slice(&body)
        .map(|value| (value, body_len))
        .map_err(|error| format!("response parse error: {error}"))
}

/// Read a (typically error) response body as UTF-8 text under the
/// vault cap. Mirrors the previous `response.text().await.unwrap_or_default()`
/// shape — failures become empty strings so error formatting still
/// produces a usable message — but the buffer is now bounded.
pub(super) async fn read_capped_error_text(response: reqwest::Response) -> String {
    match read_capped_body_with_limit(response, MAX_VAULT_ERROR_RESPONSE_BYTES).await {
        Ok(buf) => match String::from_utf8(buf) {
            Ok(text) => text,
            Err(error) => String::from_utf8_lossy(error.as_bytes()).into_owned(),
        },
        Err(_) => String::new(),
    }
}

/// Read a vault sync response and verify its origin-authentication headers
/// against the body. Unsigned unauthorized responses discard their body;
/// every other response requires a trusted signature before parsing.
///
/// Returning `(status, body)` rather than the parsed response gives every
/// call site identical verification semantics and keeps the parse step
/// downstream — so a failed signature can never reach decryption.
pub(super) async fn read_verified_response(
    response: reqwest::Response,
) -> Result<(reqwest::StatusCode, Vec<u8>), String> {
    let status = response.status();
    let key_id_header = response
        .headers()
        .get(signature::KEY_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let signature_header = response
        .headers()
        .get(signature::SIGNATURE_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

    let max_bytes = if status.is_success() {
        MAX_VAULT_RESPONSE_BYTES
    } else {
        MAX_VAULT_ERROR_RESPONSE_BYTES
    };
    #[cfg(all(debug_assertions, not(test)))]
    let local_development =
        signature::is_local_development_key(response.url(), key_id_header.as_deref());
    let mut body = read_capped_body_with_limit(response, max_bytes).await?;
    let has_signature_headers = key_id_header.is_some() || signature_header.is_some();

    if status != reqwest::StatusCode::UNAUTHORIZED || has_signature_headers {
        #[cfg(not(test))]
        let verification = {
            #[cfg(debug_assertions)]
            if local_development {
                signature::verify_response_with_test_key(
                    status.as_u16(),
                    &body,
                    key_id_header.as_deref(),
                    signature_header.as_deref(),
                )
            } else {
                signature::verify_response(
                    status.as_u16(),
                    &body,
                    key_id_header.as_deref(),
                    signature_header.as_deref(),
                )
            }
            #[cfg(not(debug_assertions))]
            signature::verify_response(
                status.as_u16(),
                &body,
                key_id_header.as_deref(),
                signature_header.as_deref(),
            )
        };
        #[cfg(test)]
        let verification = signature::verify_response_with_test_key(
            status.as_u16(),
            &body,
            key_id_header.as_deref(),
            signature_header.as_deref(),
        );
        verification.map_err(|error| error.to_string())?;
    }
    if status == reqwest::StatusCode::UNAUTHORIZED && !has_signature_headers {
        body.clear();
    }

    Ok((status, body))
}

pub(super) enum SyncHttpResponse {
    Success(Box<AuthenticatedSyncResponse>),
    Error {
        status: reqwest::StatusCode,
        response: Box<AuthenticatedSyncResponse>,
    },
}

pub(super) async fn send_authenticated_sync_request(
    request: reqwest::RequestBuilder,
    vault_id: &str,
    scope: SyncScope<'_>,
    policy: SyncEnvelopePolicy,
) -> Result<SyncHttpResponse, SyncError> {
    let request_nonce = generate_request_nonce()?;
    let response = request
        .header(REQUEST_NONCE_HEADER, &request_nonce)
        .send()
        .await
        .map_err(network_error)?;
    let (status, body) = read_verified_response(response).await?;
    if status == reqwest::StatusCode::UNAUTHORIZED && body.is_empty() {
        return Err(SyncError::http(status, "authentication failed".into()));
    }
    let response = Box::new(parse_vault_response(
        &body,
        status.as_u16(),
        vault_id,
        scope,
        &request_nonce,
        policy,
    )?);
    if status.is_success() {
        Ok(SyncHttpResponse::Success(response))
    } else {
        Ok(SyncHttpResponse::Error { status, response })
    }
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

pub(super) fn sync_http_client() -> Result<&'static reqwest::Client, SyncError> {
    static CLIENT: OnceLock<Result<reqwest::Client, String>> = OnceLock::new();
    CLIENT
        .get_or_init(|| {
            sync_http_client_builder()
                .build()
                .map_err(|error| format!("failed to build http client: {error}"))
        })
        .as_ref()
        .map_err(|error| SyncError::from(error.clone()))
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

    #[test]
    fn vault_response_cap_covers_every_registry_accepted_request_body() {
        assert_eq!(MAX_VAULT_RESPONSE_BYTES, 16 * 1024 * 1024);
    }

    #[test]
    fn declared_length_above_target_usize_is_rejected_before_narrowing() {
        let first_unrepresentable_32_bit_length = u64::from(u32::MAX) + 1;

        assert!(declared_length_exceeds_cap_for_target(
            first_unrepresentable_32_bit_length,
            MAX_VAULT_RESPONSE_BYTES,
            u64::from(u32::MAX),
        ));
    }

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

    #[tokio::test]
    async fn read_capped_body_rejects_oversized_chunked_body() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 1024];
            let _ = socket.read(&mut request).await;
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
                .await
                .unwrap();
            let chunk = vec![b'x'; 1024 * 1024];
            for _ in 0..=(MAX_VAULT_RESPONSE_BYTES / chunk.len()) {
                socket.write_all(b"100000\r\n").await.unwrap();
                socket.write_all(&chunk).await.unwrap();
                socket.write_all(b"\r\n").await.unwrap();
            }
        });

        let response = reqwest::get(format!("http://{addr}/"))
            .await
            .expect("connect");
        let error = read_capped_body(response)
            .await
            .expect_err("an oversized streamed response must be rejected");

        assert!(error.contains("streamed body exceeded cap"));
    }

    #[tokio::test]
    async fn read_capped_body_keeps_unknown_length_capacity_within_the_wire_cap() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let body_size = MAX_VAULT_RESPONSE_BYTES - 1;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 1024];
            let _ = socket.read(&mut request).await;
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
                .await
                .unwrap();
            let chunk = vec![b'x'; 64 * 1024];
            let mut remaining = body_size;
            while remaining > 0 {
                let length = remaining.min(chunk.len());
                socket
                    .write_all(format!("{length:x}\r\n").as_bytes())
                    .await
                    .unwrap();
                socket.write_all(&chunk[..length]).await.unwrap();
                socket.write_all(b"\r\n").await.unwrap();
                remaining -= length;
            }
            socket.write_all(b"0\r\n\r\n").await.unwrap();
        });

        let response = reqwest::get(format!("http://{addr}/"))
            .await
            .expect("connect");
        assert_eq!(response.content_length(), None);
        let body = read_capped_body(response)
            .await
            .expect("near-cap chunked body should be accepted");

        assert_eq!(body.len(), body_size);
        assert!(
            body.capacity() <= MAX_VAULT_RESPONSE_BYTES,
            "unknown-length response retained {} bytes of capacity for a {}-byte body",
            body.capacity(),
            body.len()
        );
    }

    #[tokio::test]
    async fn read_capped_error_text_rejects_declared_body_over_error_cap() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let body = vec![b'x'; 64 * 1024 + 1];
        let body_length = body.len();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 1024];
            let _ = socket.read(&mut request).await;
            socket
                .write_all(
                    format!("HTTP/1.1 400 Bad Request\r\nContent-Length: {body_length}\r\n\r\n")
                        .as_bytes(),
                )
                .await
                .unwrap();
            socket.write_all(&body).await.unwrap();
        });

        let response = reqwest::get(format!("http://{addr}/"))
            .await
            .expect("connect");
        assert!(read_capped_error_text(response).await.is_empty());
    }

    #[tokio::test]
    async fn read_verified_response_rejects_chunked_error_body_over_error_cap() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 1024];
            let _ = socket.read(&mut request).await;
            socket
                .write_all(b"HTTP/1.1 400 Bad Request\r\nTransfer-Encoding: chunked\r\n\r\n")
                .await
                .unwrap();
            let chunk = vec![b'x'; 1024];
            for _ in 0..65 {
                socket.write_all(b"400\r\n").await.unwrap();
                socket.write_all(&chunk).await.unwrap();
                socket.write_all(b"\r\n").await.unwrap();
            }
            socket.write_all(b"0\r\n\r\n").await.unwrap();
        });

        let response = reqwest::get(format!("http://{addr}/"))
            .await
            .expect("connect");
        let error = read_verified_response(response)
            .await
            .expect_err("oversized chunked error response must reject");
        assert!(error.contains("streamed body exceeded cap 65536"));
    }

    #[tokio::test]
    async fn read_verified_response_rejects_an_invalid_signed_unauthorized_response() {
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let (key_id, response_signature) =
            signature::sign_response_for_test(401, b"original unauthorized body");
        Mock::given(wiremock::matchers::method("GET"))
            .respond_with(
                ResponseTemplate::new(401)
                    .insert_header(signature::KEY_ID_HEADER, key_id.as_str())
                    .insert_header(signature::SIGNATURE_HEADER, response_signature.as_str())
                    .set_body_string("tampered unauthorized body"),
            )
            .mount(&server)
            .await;

        let response = reqwest::get(server.uri()).await.expect("request succeeds");
        let error = read_verified_response(response)
            .await
            .expect_err("a signed unauthorized response must verify before use");

        assert!(error.contains("does not match"), "{error}");
    }

    #[tokio::test]
    async fn read_verified_response_discards_an_unsigned_unauthorized_body() {
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(wiremock::matchers::method("GET"))
            .respond_with(ResponseTemplate::new(401).set_body_string("attacker-controlled body"))
            .mount(&server)
            .await;

        let response = reqwest::get(server.uri()).await.expect("request succeeds");
        let (status, body) = read_verified_response(response)
            .await
            .expect("unsigned pre-authentication rejection is allowed");

        assert_eq!(status, reqwest::StatusCode::UNAUTHORIZED);
        assert!(body.is_empty());
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
