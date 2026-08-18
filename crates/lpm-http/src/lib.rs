//! Shared construction and error handling for LPM's outbound HTTP clients.

use std::error::Error as _;
use std::fmt;

use reqwest::redirect::Policy;

/// Reqwest's default maximum number of automatically followed redirects.
pub const DEFAULT_REDIRECT_LIMIT: usize = 10;

/// Stable user-facing error for a redirect that would weaken transport security.
pub const HTTPS_DOWNGRADE_REFUSAL: &str = "refused HTTPS-to-HTTP redirect";

/// Failure returned while draining a response under a byte limit.
#[derive(Debug)]
pub enum ResponseBodyError {
    DeclaredTooLarge { declared: u64, cap: usize },
    StreamedTooLarge { cap: usize },
    Read(reqwest::Error),
}

impl fmt::Display for ResponseBodyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DeclaredTooLarge { declared, cap } => {
                write!(
                    formatter,
                    "declared body length {declared} exceeds cap {cap}"
                )
            }
            Self::StreamedTooLarge { cap } => {
                write!(formatter, "streamed body exceeds cap {cap}")
            }
            Self::Read(error) => write!(formatter, "body read error: {error}"),
        }
    }
}

impl std::error::Error for ResponseBodyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Read(error) => Some(error),
            Self::DeclaredTooLarge { .. } | Self::StreamedTooLarge { .. } => None,
        }
    }
}

#[derive(Debug)]
struct HttpsDowngrade;

impl fmt::Display for HttpsDowngrade {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(HTTPS_DOWNGRADE_REFUSAL)
    }
}

impl std::error::Error for HttpsDowngrade {}

/// Build an asynchronous reqwest client with the workspace redirect policy.
pub fn client_builder() -> reqwest::ClientBuilder {
    client_builder_with_redirect_limit(DEFAULT_REDIRECT_LIMIT)
}

/// Build an asynchronous reqwest client with a caller-selected redirect limit.
pub fn client_builder_with_redirect_limit(limit: usize) -> reqwest::ClientBuilder {
    reqwest::Client::builder().redirect(redirect_policy(limit))
}

/// Build a blocking reqwest client with the workspace redirect policy.
pub fn blocking_client_builder() -> reqwest::blocking::ClientBuilder {
    reqwest::blocking::Client::builder().redirect(redirect_policy(DEFAULT_REDIRECT_LIMIT))
}

/// Read a response body while enforcing declared-length and streamed-byte caps.
pub async fn read_body_capped(
    mut response: reqwest::Response,
    cap: usize,
) -> Result<Vec<u8>, ResponseBodyError> {
    if let Some(declared) = response.content_length()
        && declared > cap as u64
    {
        return Err(ResponseBodyError::DeclaredTooLarge { declared, cap });
    }

    let initial_capacity = response
        .content_length()
        .and_then(|length| usize::try_from(length).ok())
        .unwrap_or(64 * 1024)
        .min(cap);
    let mut body = Vec::with_capacity(initial_capacity);
    while let Some(chunk) = response.chunk().await.map_err(ResponseBodyError::Read)? {
        if chunk.len() > cap.saturating_sub(body.len()) {
            return Err(ResponseBodyError::StreamedTooLarge { cap });
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Build a bounded redirect policy that refuses cleartext after any HTTPS hop.
pub fn redirect_policy(limit: usize) -> Policy {
    let bounded = Policy::limited(limit);
    Policy::custom(move |attempt| {
        let target_is_http = attempt.url().scheme() == "http";
        let chain_used_https = attempt.previous().iter().any(|url| url.scheme() == "https");
        if target_is_http && chain_used_https {
            attempt.error(HttpsDowngrade)
        } else {
            bounded.redirect(attempt)
        }
    })
}

/// Return whether a reqwest failure was caused by the HTTPS downgrade policy.
pub fn is_https_downgrade(error: &reqwest::Error) -> bool {
    let mut source = error.source();
    while let Some(current) = source {
        if current.downcast_ref::<HttpsDowngrade>().is_some() {
            return true;
        }
        source = current.source();
    }
    false
}

fn refusal_message(error: &reqwest::Error) -> Option<&'static str> {
    let mut source = error.source();
    while let Some(current) = source {
        if current.downcast_ref::<HttpsDowngrade>().is_some() {
            return Some(HTTPS_DOWNGRADE_REFUSAL);
        }
        source = current.source();
    }
    None
}

/// Display a request error without exposing URLs from a downgrade refusal.
pub fn display_error(error: &reqwest::Error) -> ErrorDisplay<'_> {
    ErrorDisplay { error }
}

/// A redacting display adapter for outbound HTTP errors.
pub struct ErrorDisplay<'a> {
    error: &'a reqwest::Error,
}

impl fmt::Display for ErrorDisplay<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(message) = refusal_message(self.error) {
            formatter.write_str(message)
        } else {
            self.error.fmt(formatter)
        }
    }
}

/// Render a full error chain while redacting downgrade-refusal URLs.
pub fn error_chain(error: &reqwest::Error) -> String {
    if let Some(message) = refusal_message(error) {
        return message.to_string();
    }

    let mut messages = Vec::with_capacity(4);
    let mut source: Option<&dyn std::error::Error> = Some(error);
    while let Some(current) = source {
        messages.push(current.to_string());
        source = current.source();
    }
    messages.join(" <- ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    async fn response_from_raw(raw_response: Vec<u8>) -> reqwest::Response {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test server");
        let address = listener.local_addr().expect("test server address");
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept request");
            let mut request = [0u8; 1024];
            let _ = socket.read(&mut request).await.expect("read request");
            socket
                .write_all(&raw_response)
                .await
                .expect("write response");
            socket.shutdown().await.expect("close response");
        });

        reqwest::get(format!("http://{address}/"))
            .await
            .expect("request test server")
    }

    #[test]
    fn default_redirect_limit_matches_reqwest_default() {
        assert_eq!(DEFAULT_REDIRECT_LIMIT, 10);
    }

    #[tokio::test]
    async fn capped_body_rejects_oversized_declared_length_before_reading() {
        let response = response_from_raw(
            b"HTTP/1.1 200 OK\r\nContent-Length: 33\r\nConnection: close\r\n\r\n".to_vec(),
        )
        .await;

        assert!(matches!(
            read_body_capped(response, 32).await,
            Err(ResponseBodyError::DeclaredTooLarge {
                declared: 33,
                cap: 32
            })
        ));
    }

    #[tokio::test]
    async fn capped_body_rejects_chunked_stream_when_aggregate_crosses_cap() {
        let mut raw =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n".to_vec();
        raw.extend_from_slice(b"14\r\n12345678901234567890\r\n");
        raw.extend_from_slice(b"14\r\n12345678901234567890\r\n0\r\n\r\n");
        let response = response_from_raw(raw).await;

        assert!(matches!(
            read_body_capped(response, 32).await,
            Err(ResponseBodyError::StreamedTooLarge { cap: 32 })
        ));
    }
}
