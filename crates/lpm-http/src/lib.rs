//! Shared construction and error handling for LPM's outbound HTTP clients.

use std::error::Error as _;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use base64::Engine as _;
use bytes::Bytes;
use futures::Stream;
use reqwest::header::{
    AUTHORIZATION, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, COOKIE, HOST, HeaderMap,
    PROXY_AUTHORIZATION, TRANSFER_ENCODING, WWW_AUTHENTICATE,
};
use reqwest::redirect::Policy;

/// Reqwest's default maximum number of automatically followed redirects.
pub const DEFAULT_REDIRECT_LIMIT: usize = 10;

/// Stable user-facing error for a redirect that would weaken transport security.
pub const HTTPS_DOWNGRADE_REFUSAL: &str = "refused HTTPS-to-HTTP redirect";

/// A streaming HTTP request body that can be reconstructed for retries.
#[derive(Debug)]
pub struct ReplayableRequestBody {
    prefix: Bytes,
    binary_attachment: Arc<Vec<u8>>,
    infix: Bytes,
    json_string_attachment: Option<Arc<str>>,
    suffix: Bytes,
    length: u64,
}

impl ReplayableRequestBody {
    /// Build a replayable body whose middle section is streamed as Base64.
    pub fn from_base64_json_parts(
        prefix: Vec<u8>,
        binary_attachment: Arc<Vec<u8>>,
        suffix: Vec<u8>,
    ) -> std::io::Result<Self> {
        let encoded_length = base64_encoded_length(binary_attachment.len())
            .ok_or_else(|| std::io::Error::other("request body length overflow"))?;
        let length = prefix
            .len()
            .checked_add(encoded_length)
            .and_then(|length| length.checked_add(suffix.len()))
            .and_then(|length| u64::try_from(length).ok())
            .ok_or_else(|| std::io::Error::other("request body length overflow"))?;
        Ok(Self {
            prefix: Bytes::from(prefix),
            binary_attachment,
            infix: Bytes::new(),
            json_string_attachment: None,
            suffix: Bytes::from(suffix),
            length,
        })
    }

    /// Build a replayable body with Base64 data followed by a streamed JSON string.
    pub fn from_base64_and_json_string_parts(
        prefix: Vec<u8>,
        binary_attachment: Arc<Vec<u8>>,
        infix: Vec<u8>,
        json_string_attachment: Arc<str>,
        suffix: Vec<u8>,
    ) -> std::io::Result<Self> {
        let encoded_length = base64_encoded_length(binary_attachment.len())
            .ok_or_else(|| std::io::Error::other("request body length overflow"))?;
        let json_string_length = json_string_encoded_length(&json_string_attachment)
            .ok_or_else(|| std::io::Error::other("request body length overflow"))?;
        let length = prefix
            .len()
            .checked_add(encoded_length)
            .and_then(|length| length.checked_add(infix.len()))
            .and_then(|length| length.checked_add(json_string_length))
            .and_then(|length| length.checked_add(suffix.len()))
            .and_then(|length| u64::try_from(length).ok())
            .ok_or_else(|| std::io::Error::other("request body length overflow"))?;
        Ok(Self {
            prefix: Bytes::from(prefix),
            binary_attachment,
            infix: Bytes::from(infix),
            json_string_attachment: Some(json_string_attachment),
            suffix: Bytes::from(suffix),
            length,
        })
    }

    /// Build a replayable body that contains no encoded binary section.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self {
            length: bytes.len() as u64,
            prefix: Bytes::from(bytes),
            binary_attachment: Arc::new(Vec::new()),
            infix: Bytes::new(),
            json_string_attachment: None,
            suffix: Bytes::new(),
        }
    }

    /// Return the exact request body length in bytes.
    #[inline]
    pub fn len(&self) -> u64 {
        self.length
    }

    /// Return whether the request body is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// Return bytes retained in already-encoded request segments.
    #[doc(hidden)]
    pub fn resident_encoded_bytes(&self) -> usize {
        self.prefix
            .len()
            .saturating_add(self.infix.len())
            .saturating_add(self.suffix.len())
    }

    /// Create a fresh stream at the first byte.
    pub fn body(&self) -> reqwest::Body {
        reqwest::Body::wrap_stream(self.stream())
    }

    fn stream(&self) -> ReplayableBodyStream {
        ReplayableBodyStream {
            prefix: Some(self.prefix.clone()),
            binary_attachment: Arc::clone(&self.binary_attachment),
            binary_offset: 0,
            infix: Some(self.infix.clone()),
            json_string_attachment: self.json_string_attachment.clone(),
            json_string_offset: 0,
            json_string_started: false,
            suffix: Some(self.suffix.clone()),
        }
    }
}

const BASE64_INPUT_CHUNK_BYTES: usize = 192 * 1024;
const JSON_STRING_OUTPUT_CHUNK_BYTES: usize = 256 * 1024;

fn base64_encoded_length(input_length: usize) -> Option<usize> {
    let complete_groups = input_length / 3;
    let trailing_group_length = usize::from(!input_length.is_multiple_of(3)) * 4;
    complete_groups
        .checked_mul(4)?
        .checked_add(trailing_group_length)
}

fn json_string_encoded_length(value: &str) -> Option<usize> {
    value.as_bytes().iter().try_fold(2usize, |length, byte| {
        let encoded_byte_length = match byte {
            b'"' | b'\\' | b'\x08' | b'\t' | b'\n' | b'\x0c' | b'\r' => 2,
            0x00..=0x1f => 6,
            _ => 1,
        };
        length.checked_add(encoded_byte_length)
    })
}

struct ReplayableBodyStream {
    prefix: Option<Bytes>,
    binary_attachment: Arc<Vec<u8>>,
    binary_offset: usize,
    infix: Option<Bytes>,
    json_string_attachment: Option<Arc<str>>,
    json_string_offset: usize,
    json_string_started: bool,
    suffix: Option<Bytes>,
}

impl Stream for ReplayableBodyStream {
    type Item = std::io::Result<bytes::Bytes>;

    fn poll_next(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let stream = self.get_mut();
        if let Some(prefix) = stream.prefix.take()
            && !prefix.is_empty()
        {
            return Poll::Ready(Some(Ok(prefix)));
        }
        if stream.binary_offset < stream.binary_attachment.len() {
            let end = stream
                .binary_offset
                .saturating_add(BASE64_INPUT_CHUNK_BYTES)
                .min(stream.binary_attachment.len());
            let input = &stream.binary_attachment[stream.binary_offset..end];
            let encoded_length = input.len().div_ceil(3) * 4;
            let mut encoded = vec![0; encoded_length];
            let written =
                match base64::engine::general_purpose::STANDARD.encode_slice(input, &mut encoded) {
                    Ok(written) => written,
                    Err(error) => {
                        return Poll::Ready(Some(Err(std::io::Error::other(format!(
                            "Base64 request encoding failed: {error}"
                        )))));
                    }
                };
            encoded.truncate(written);
            stream.binary_offset = end;
            return Poll::Ready(Some(Ok(Bytes::from(encoded))));
        }
        if let Some(infix) = stream.infix.take()
            && !infix.is_empty()
        {
            return Poll::Ready(Some(Ok(infix)));
        }
        if let Some(value) = stream.json_string_attachment.as_ref().map(Arc::clone) {
            let mut encoded = Vec::with_capacity(JSON_STRING_OUTPUT_CHUNK_BYTES);
            if !stream.json_string_started {
                encoded.push(b'"');
                stream.json_string_started = true;
            }
            let input = value.as_bytes();
            while stream.json_string_offset < input.len() {
                let byte = input[stream.json_string_offset];
                let escape: &[u8] = match byte {
                    b'"' => b"\\\"",
                    b'\\' => b"\\\\",
                    b'\x08' => b"\\b",
                    b'\t' => b"\\t",
                    b'\n' => b"\\n",
                    b'\x0c' => b"\\f",
                    b'\r' => b"\\r",
                    0x00..=0x1f => {
                        const HEX: &[u8; 16] = b"0123456789abcdef";
                        if encoded.len().saturating_add(6) > JSON_STRING_OUTPUT_CHUNK_BYTES {
                            break;
                        }
                        encoded.extend_from_slice(&[
                            b'\\',
                            b'u',
                            b'0',
                            b'0',
                            HEX[(byte >> 4) as usize],
                            HEX[(byte & 0x0f) as usize],
                        ]);
                        stream.json_string_offset += 1;
                        continue;
                    }
                    _ => std::slice::from_ref(&input[stream.json_string_offset]),
                };
                if encoded.len().saturating_add(escape.len()) > JSON_STRING_OUTPUT_CHUNK_BYTES {
                    break;
                }
                encoded.extend_from_slice(escape);
                stream.json_string_offset += 1;
            }
            if stream.json_string_offset == input.len() {
                encoded.push(b'"');
                stream.json_string_attachment = None;
            }
            return Poll::Ready(Some(Ok(Bytes::from(encoded))));
        }
        if let Some(suffix) = stream.suffix.take()
            && !suffix.is_empty()
        {
            return Poll::Ready(Some(Ok(suffix)));
        }
        Poll::Ready(None)
    }
}

/// Supplies a redirect-disabled client configured for each request origin.
///
/// Every returned client must use [`Policy::none`]. The explicit redirect
/// executor cannot enforce that setting after a client has been built. Clients
/// must also omit default credential and payload headers because reqwest merges
/// defaults after the executor sanitizes each redirected request.
pub trait ReplayableHttpClientProvider {
    type Error;

    fn client_for_url(
        &self,
        url: &reqwest::Url,
    ) -> impl Future<Output = Result<reqwest::Client, Self::Error>> + Send;
}

impl ReplayableHttpClientProvider for reqwest::Client {
    type Error = std::convert::Infallible;

    fn client_for_url(
        &self,
        _url: &reqwest::Url,
    ) -> impl Future<Output = Result<reqwest::Client, Self::Error>> + Send {
        std::future::ready(Ok(self.clone()))
    }
}

/// Failure while executing a request with explicit replay-safe redirects.
#[derive(Debug)]
pub enum ReplayableRequestError<E> {
    Client(E),
    Request(reqwest::Error),
    TooManyRedirects,
    Timeout,
    HttpsDowngrade,
    CleartextNonLoopback,
    UnsupportedRedirectScheme,
}

impl<E> ReplayableRequestError<E> {
    /// Convert a reqwest error while removing its request URL.
    pub fn request(error: reqwest::Error) -> Self {
        Self::Request(error.without_url())
    }
}

impl<E: fmt::Display> fmt::Display for ReplayableRequestError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Client(error) => error.fmt(formatter),
            Self::Request(error) => display_error(error).fmt(formatter),
            Self::TooManyRedirects => formatter.write_str("too many redirects"),
            Self::Timeout => formatter.write_str("request timed out"),
            Self::HttpsDowngrade => formatter.write_str(HTTPS_DOWNGRADE_REFUSAL),
            Self::CleartextNonLoopback => {
                formatter.write_str("refused cleartext redirect to a non-loopback host")
            }
            Self::UnsupportedRedirectScheme => {
                formatter.write_str("refused redirect to unsupported URL scheme")
            }
        }
    }
}

impl<E> std::error::Error for ReplayableRequestError<E>
where
    E: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Client(error) => Some(error),
            Self::Request(error) => Some(error),
            Self::TooManyRedirects
            | Self::Timeout
            | Self::HttpsDowngrade
            | Self::CleartextNonLoopback
            | Self::UnsupportedRedirectScheme => None,
        }
    }
}

/// Execute a request with replay-safe, credential-aware redirect handling.
pub async fn send_with_replayable_redirects<P>(
    provider: &P,
    mut request: reqwest::Request,
    replayable_body: Option<&ReplayableRequestBody>,
) -> Result<reqwest::Response, ReplayableRequestError<P::Error>>
where
    P: ReplayableHttpClientProvider + ?Sized,
{
    let timeout = request.timeout().copied();
    let deadline = timeout.and_then(|timeout| tokio::time::Instant::now().checked_add(timeout));
    let version = request.version();
    let mut method = request.method().clone();
    let mut url = request.url().clone();
    let mut headers = request.headers().clone();
    let mut send_body = replayable_body.is_some();
    let mut chain_used_https = url.scheme() == "https";
    let mut redirects_followed = 0usize;

    loop {
        *request.method_mut() = method.clone();
        *request.url_mut() = url.clone();
        *request.headers_mut() = headers.clone();
        *request.version_mut() = version;
        *request.body_mut() = if send_body {
            replayable_body.map(ReplayableRequestBody::body)
        } else {
            None
        };
        if send_body {
            request.headers_mut().insert(
                CONTENT_LENGTH,
                replayable_body.map_or(0, ReplayableRequestBody::len).into(),
            );
        }

        let client_future = provider.client_for_url(&url);
        let client = match deadline {
            Some(deadline) => tokio::time::timeout_at(deadline, client_future)
                .await
                .map_err(|_| ReplayableRequestError::Timeout)?
                .map_err(ReplayableRequestError::Client)?,
            None => client_future
                .await
                .map_err(ReplayableRequestError::Client)?,
        };
        *request.timeout_mut() = match deadline {
            Some(deadline) => {
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                if remaining.is_zero() {
                    return Err(ReplayableRequestError::Timeout);
                }
                Some(remaining)
            }
            None => None,
        };
        let response_future = client.execute(request);
        let response = match deadline {
            Some(deadline) => tokio::time::timeout_at(deadline, response_future)
                .await
                .map_err(|_| ReplayableRequestError::Timeout)?
                .map_err(ReplayableRequestError::request)?,
            None => response_future
                .await
                .map_err(ReplayableRequestError::request)?,
        };
        let Some((next_method, next_has_body)) =
            redirected_method_and_body(response.status(), &method, send_body)
        else {
            return Ok(response);
        };
        let Some(next_url) = response
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|location| location.to_str().ok())
            .and_then(|location| url.join(location).ok())
        else {
            return Ok(response);
        };

        if redirects_followed == DEFAULT_REDIRECT_LIMIT {
            return Err(ReplayableRequestError::TooManyRedirects);
        }
        if let Err(error) = validate_redirect_target(chain_used_https, &next_url) {
            return Err(match error {
                RedirectTargetError::HttpsDowngrade => ReplayableRequestError::HttpsDowngrade,
                RedirectTargetError::CleartextNonLoopback => {
                    ReplayableRequestError::CleartextNonLoopback
                }
                RedirectTargetError::UnsupportedScheme => {
                    ReplayableRequestError::UnsupportedRedirectScheme
                }
            });
        }
        if !same_origin(&url, &next_url) {
            remove_cross_origin_credentials(&mut headers);
        }
        if !next_has_body {
            remove_payload_headers(&mut headers);
        }
        headers.remove(HOST);

        redirects_followed += 1;
        chain_used_https |= next_url.scheme() == "https";
        method = next_method;
        url = next_url;
        send_body = next_has_body;
        request = reqwest::Request::new(method.clone(), url.clone());
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum RedirectTargetError {
    HttpsDowngrade,
    CleartextNonLoopback,
    UnsupportedScheme,
}

fn validate_redirect_target(
    chain_used_https: bool,
    next_url: &reqwest::Url,
) -> Result<(), RedirectTargetError> {
    if !matches!(next_url.scheme(), "http" | "https") {
        return Err(RedirectTargetError::UnsupportedScheme);
    }
    if chain_used_https && next_url.scheme() == "http" {
        return Err(RedirectTargetError::HttpsDowngrade);
    }
    if next_url.scheme() == "http" && !url_host_is_loopback(next_url) {
        return Err(RedirectTargetError::CleartextNonLoopback);
    }
    Ok(())
}

fn url_host_is_loopback(url: &reqwest::Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    let host = host.trim_start_matches('[').trim_end_matches(']');
    host.parse::<std::net::IpAddr>()
        .is_ok_and(|address| match address {
            std::net::IpAddr::V4(address) => address.is_loopback(),
            std::net::IpAddr::V6(address) => {
                address.is_loopback()
                    || address
                        .to_ipv4_mapped()
                        .is_some_and(|address| address.is_loopback())
            }
        })
}

fn redirected_method_and_body(
    status: reqwest::StatusCode,
    method: &reqwest::Method,
    has_body: bool,
) -> Option<(reqwest::Method, bool)> {
    match status {
        reqwest::StatusCode::MOVED_PERMANENTLY | reqwest::StatusCode::FOUND
            if *method == reqwest::Method::POST =>
        {
            Some((reqwest::Method::GET, false))
        }
        reqwest::StatusCode::MOVED_PERMANENTLY | reqwest::StatusCode::FOUND => {
            Some((method.clone(), has_body))
        }
        reqwest::StatusCode::SEE_OTHER if *method == reqwest::Method::HEAD => {
            Some((reqwest::Method::HEAD, false))
        }
        reqwest::StatusCode::SEE_OTHER => Some((reqwest::Method::GET, false)),
        reqwest::StatusCode::TEMPORARY_REDIRECT | reqwest::StatusCode::PERMANENT_REDIRECT => {
            Some((method.clone(), has_body))
        }
        _ => None,
    }
}

fn same_origin(previous: &reqwest::Url, next: &reqwest::Url) -> bool {
    previous.scheme() == next.scheme()
        && previous.host_str() == next.host_str()
        && previous.port_or_known_default() == next.port_or_known_default()
}

fn remove_cross_origin_credentials(headers: &mut HeaderMap) {
    for header in [
        AUTHORIZATION,
        COOKIE,
        PROXY_AUTHORIZATION,
        WWW_AUTHENTICATE,
        reqwest::header::HeaderName::from_static("cookie2"),
        reqwest::header::HeaderName::from_static("x-otp"),
        reqwest::header::HeaderName::from_static("npm-otp"),
    ] {
        headers.remove(header);
    }
}

fn remove_payload_headers(headers: &mut HeaderMap) {
    for header in [
        CONTENT_TYPE,
        CONTENT_LENGTH,
        CONTENT_ENCODING,
        TRANSFER_ENCODING,
    ] {
        headers.remove(header);
    }
}

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

    #[derive(Clone)]
    struct DelayedClientProvider {
        client: reqwest::Client,
        delay: std::time::Duration,
    }

    #[derive(Clone)]
    struct RecordingClientProvider {
        client: reqwest::Client,
        urls: Arc<std::sync::Mutex<Vec<String>>>,
    }

    impl ReplayableHttpClientProvider for DelayedClientProvider {
        type Error = std::convert::Infallible;

        fn client_for_url(
            &self,
            _url: &reqwest::Url,
        ) -> impl Future<Output = Result<reqwest::Client, Self::Error>> + Send {
            let client = self.client.clone();
            let delay = self.delay;
            async move {
                tokio::time::sleep(delay).await;
                Ok(client)
            }
        }
    }

    impl ReplayableHttpClientProvider for RecordingClientProvider {
        type Error = std::convert::Infallible;

        fn client_for_url(
            &self,
            url: &reqwest::Url,
        ) -> impl Future<Output = Result<reqwest::Client, Self::Error>> + Send {
            self.urls.lock().unwrap().push(url.to_string());
            std::future::ready(Ok(self.client.clone()))
        }
    }

    async fn response_from_raw(raw_response: Vec<u8>) -> reqwest::Response {
        response_from_raw_at_path(raw_response, "/").await
    }

    async fn response_from_raw_at_path(raw_response: Vec<u8>, path: &str) -> reqwest::Response {
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

        reqwest::get(format!("http://{address}{path}"))
            .await
            .expect("request test server")
    }

    async fn redirect_chain_server(
        redirect_responses: usize,
        finish_with_success: bool,
    ) -> (String, Arc<std::sync::atomic::AtomicUsize>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind redirect server");
        let address = listener.local_addr().expect("redirect server address");
        let request_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed_count = Arc::clone(&request_count);
        let total_responses = redirect_responses + usize::from(finish_with_success);
        tokio::spawn(async move {
            for index in 0..total_responses {
                let (mut socket, _) = listener.accept().await.expect("accept redirect request");
                let mut request = [0u8; 4096];
                let _ = socket
                    .read(&mut request)
                    .await
                    .expect("read redirect request");
                observed_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let response = if index < redirect_responses {
                    format!(
                        "HTTP/1.1 302 Found\r\nLocation: /hop/{}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        index + 1
                    )
                } else {
                    "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                        .to_string()
                };
                socket
                    .write_all(response.as_bytes())
                    .await
                    .expect("write redirect response");
                socket.shutdown().await.expect("close redirect response");
            }
        });
        (format!("http://{address}/start"), request_count)
    }

    #[test]
    fn default_redirect_limit_matches_reqwest_default() {
        assert_eq!(DEFAULT_REDIRECT_LIMIT, 10);
    }

    #[tokio::test]
    async fn replayable_request_body_streams_exact_base64_across_chunk_boundary() {
        use futures::StreamExt as _;

        let prefix = b"{\"data\":\"".to_vec();
        let binary = Arc::new(vec![0x5a; BASE64_INPUT_CHUNK_BYTES + 2]);
        let suffix = b"\"}".to_vec();
        let body = ReplayableRequestBody::from_base64_json_parts(
            prefix.clone(),
            Arc::clone(&binary),
            suffix.clone(),
        )
        .unwrap();
        let chunks = ReplayableBodyStream {
            prefix: Some(Bytes::from(prefix.clone())),
            binary_attachment: Arc::clone(&binary),
            binary_offset: 0,
            infix: Some(Bytes::new()),
            json_string_attachment: None,
            json_string_offset: 0,
            json_string_started: false,
            suffix: Some(Bytes::from(suffix.clone())),
        }
        .collect::<Vec<_>>()
        .await;
        let mut actual = Vec::with_capacity(body.len() as usize);
        for chunk in chunks {
            actual.extend_from_slice(&chunk.unwrap());
        }
        let mut expected = prefix;
        expected.extend_from_slice(
            base64::engine::general_purpose::STANDARD
                .encode(&*binary)
                .as_bytes(),
        );
        expected.extend_from_slice(&suffix);

        assert_eq!(actual, expected);
        assert_eq!(body.len(), expected.len() as u64);
        assert!(!body.is_empty());
    }

    #[test]
    fn base64_encoded_length_rejects_overflow() {
        assert_eq!(base64_encoded_length(usize::MAX), None);
    }

    #[tokio::test]
    async fn replayable_request_body_streams_exact_escape_heavy_json_string() {
        use futures::StreamExt as _;

        let prefix = b"{\"archive\":\"".to_vec();
        let binary = Arc::new(b"archive".to_vec());
        let infix = b"\",\"provenance\":".to_vec();
        let raw_unit = "\0\u{1}\u{8}\t\n\u{c}\r\"\\/é🦀";
        let value: Arc<str> = raw_unit.repeat(32 * 1024).into();
        let suffix = b"}".to_vec();
        let body = ReplayableRequestBody::from_base64_and_json_string_parts(
            prefix.clone(),
            Arc::clone(&binary),
            infix.clone(),
            Arc::clone(&value),
            suffix.clone(),
        )
        .unwrap();
        let chunks = body.stream().collect::<Vec<_>>().await;
        let mut actual = Vec::with_capacity(body.len() as usize);
        for chunk in chunks {
            let chunk = chunk.unwrap();
            assert!(chunk.len() <= JSON_STRING_OUTPUT_CHUNK_BYTES + 1);
            actual.extend_from_slice(&chunk);
        }
        let mut expected = prefix;
        expected.extend_from_slice(
            base64::engine::general_purpose::STANDARD
                .encode(&*binary)
                .as_bytes(),
        );
        expected.extend_from_slice(&infix);
        expected.extend_from_slice(&serde_json::to_vec(value.as_ref()).unwrap());
        expected.extend_from_slice(&suffix);

        assert_eq!(actual, expected);
        assert_eq!(body.len(), expected.len() as u64);
    }

    #[test]
    fn explicit_redirect_method_matrix_matches_reqwest_semantics() {
        use reqwest::Method;
        use reqwest::StatusCode;

        let cases = [
            (
                Method::PUT,
                StatusCode::MOVED_PERMANENTLY,
                Method::PUT,
                true,
            ),
            (Method::PUT, StatusCode::FOUND, Method::PUT, true),
            (Method::PUT, StatusCode::SEE_OTHER, Method::GET, false),
            (
                Method::PUT,
                StatusCode::TEMPORARY_REDIRECT,
                Method::PUT,
                true,
            ),
            (
                Method::PUT,
                StatusCode::PERMANENT_REDIRECT,
                Method::PUT,
                true,
            ),
            (
                Method::POST,
                StatusCode::MOVED_PERMANENTLY,
                Method::GET,
                false,
            ),
            (Method::POST, StatusCode::FOUND, Method::GET, false),
            (Method::POST, StatusCode::SEE_OTHER, Method::GET, false),
            (
                Method::POST,
                StatusCode::TEMPORARY_REDIRECT,
                Method::POST,
                true,
            ),
            (
                Method::POST,
                StatusCode::PERMANENT_REDIRECT,
                Method::POST,
                true,
            ),
        ];

        for (initial_method, status, expected_method, expected_body) in cases {
            assert_eq!(
                redirected_method_and_body(status, &initial_method, true),
                Some((expected_method, expected_body))
            );
        }
    }

    #[tokio::test]
    async fn explicit_redirect_method_matrix_preserves_or_drops_wire_body_and_headers() {
        use reqwest::{Method, StatusCode};
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let cases = [
            (
                Method::PUT,
                StatusCode::MOVED_PERMANENTLY,
                Method::PUT,
                true,
            ),
            (Method::PUT, StatusCode::FOUND, Method::PUT, true),
            (Method::PUT, StatusCode::SEE_OTHER, Method::GET, false),
            (
                Method::PUT,
                StatusCode::TEMPORARY_REDIRECT,
                Method::PUT,
                true,
            ),
            (
                Method::PUT,
                StatusCode::PERMANENT_REDIRECT,
                Method::PUT,
                true,
            ),
            (
                Method::POST,
                StatusCode::MOVED_PERMANENTLY,
                Method::GET,
                false,
            ),
            (Method::POST, StatusCode::FOUND, Method::GET, false),
            (Method::POST, StatusCode::SEE_OTHER, Method::GET, false),
            (
                Method::POST,
                StatusCode::TEMPORARY_REDIRECT,
                Method::POST,
                true,
            ),
            (
                Method::POST,
                StatusCode::PERMANENT_REDIRECT,
                Method::POST,
                true,
            ),
        ];

        for (initial_method, status, expected_method, expected_body) in cases {
            let server = MockServer::start().await;
            Mock::given(method(initial_method.as_str()))
                .and(path("/initial"))
                .respond_with(
                    ResponseTemplate::new(status.as_u16()).insert_header("location", "/redirected"),
                )
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method(expected_method.as_str()))
                .and(path("/redirected"))
                .respond_with(ResponseTemplate::new(200))
                .expect(1)
                .mount(&server)
                .await;
            let client = reqwest::Client::builder()
                .redirect(Policy::none())
                .build()
                .unwrap();
            let body = ReplayableRequestBody::from_bytes(b"exact-body".to_vec());
            let request = client
                .request(initial_method, format!("{}/initial", server.uri()))
                .header(CONTENT_TYPE, "application/json")
                .header(CONTENT_ENCODING, "identity")
                .header(AUTHORIZATION, "Bearer same-origin")
                .header("x-otp", "123456")
                .header("npm-otp", "654321")
                .body(body.body())
                .build()
                .unwrap();

            let response = send_with_replayable_redirects(&client, request, Some(&body))
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::OK);
            let requests = server.received_requests().await.unwrap();
            let redirected = requests
                .iter()
                .find(|request| request.url.path() == "/redirected")
                .unwrap();
            assert_eq!(redirected.method.as_str(), expected_method.as_str());
            assert_eq!(redirected.body == b"exact-body", expected_body);
            assert_eq!(
                redirected.headers.get(CONTENT_TYPE).is_some(),
                expected_body
            );
            assert_eq!(
                redirected.headers.get(CONTENT_LENGTH).is_some(),
                expected_body
            );
            assert_eq!(
                redirected.headers.get(CONTENT_ENCODING).is_some(),
                expected_body
            );
            assert_eq!(
                redirected
                    .headers
                    .get(AUTHORIZATION)
                    .and_then(|value| value.to_str().ok()),
                Some("Bearer same-origin")
            );
            assert_eq!(
                redirected
                    .headers
                    .get("x-otp")
                    .and_then(|value| value.to_str().ok()),
                Some("123456")
            );
            assert_eq!(
                redirected
                    .headers
                    .get("npm-otp")
                    .and_then(|value| value.to_str().ok()),
                Some("654321")
            );
        }
    }

    #[tokio::test]
    async fn cross_origin_307_replays_body_without_forwarding_credentials() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let target = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/capture"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&target)
            .await;
        let redirector = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/initial"))
            .respond_with(
                ResponseTemplate::new(307)
                    .insert_header("location", format!("{}/capture", target.uri())),
            )
            .expect(1)
            .mount(&redirector)
            .await;
        let client = reqwest::Client::builder()
            .redirect(Policy::none())
            .build()
            .unwrap();
        let body = ReplayableRequestBody::from_bytes(b"exact-body".to_vec());
        let request = client
            .put(format!("{}/initial", redirector.uri()))
            .header(CONTENT_TYPE, "application/json")
            .header(AUTHORIZATION, "Bearer secret")
            .header("x-otp", "123456")
            .header("npm-otp", "654321")
            .body(body.body())
            .build()
            .unwrap();

        send_with_replayable_redirects(&client, request, Some(&body))
            .await
            .unwrap();

        let requests = target.received_requests().await.unwrap();
        let redirected = requests.first().unwrap();
        assert_eq!(redirected.body, b"exact-body");
        assert!(redirected.headers.get(AUTHORIZATION).is_none());
        assert!(redirected.headers.get("x-otp").is_none());
        assert!(redirected.headers.get("npm-otp").is_none());
    }

    #[tokio::test]
    async fn redirect_without_valid_location_returns_original_response() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        for location in [None, Some("http://[")] {
            let server = MockServer::start().await;
            let response = match location {
                Some(location) => ResponseTemplate::new(302).insert_header("location", location),
                None => ResponseTemplate::new(302),
            };
            Mock::given(method("GET"))
                .and(path("/initial"))
                .respond_with(response)
                .expect(1)
                .mount(&server)
                .await;
            let client = reqwest::Client::builder()
                .redirect(Policy::none())
                .build()
                .unwrap();
            let request = client
                .get(format!("{}/initial", server.uri()))
                .build()
                .unwrap();

            let response = send_with_replayable_redirects(&client, request, None)
                .await
                .unwrap();

            assert_eq!(response.status(), reqwest::StatusCode::FOUND);
        }
    }

    #[test]
    fn redirect_origin_comparison_includes_scheme_host_and_effective_port() {
        let origin = reqwest::Url::parse("https://example.test/path").unwrap();

        assert!(same_origin(
            &origin,
            &reqwest::Url::parse("https://example.test:443/other").unwrap()
        ));
        assert!(!same_origin(
            &origin,
            &reqwest::Url::parse("http://example.test:443/other").unwrap()
        ));
        assert!(!same_origin(
            &origin,
            &reqwest::Url::parse("https://other.test/other").unwrap()
        ));
        assert!(!same_origin(
            &origin,
            &reqwest::Url::parse("https://example.test:444/other").unwrap()
        ));
    }

    #[test]
    fn cross_origin_redirect_removes_standard_and_otp_credentials() {
        let mut headers = HeaderMap::new();
        for name in [
            "authorization",
            "cookie",
            "proxy-authorization",
            "www-authenticate",
            "cookie2",
            "x-otp",
            "npm-otp",
        ] {
            headers.insert(
                reqwest::header::HeaderName::from_static(name),
                reqwest::header::HeaderValue::from_static("secret"),
            );
        }

        remove_cross_origin_credentials(&mut headers);

        assert!(headers.is_empty());
    }

    #[test]
    fn body_dropping_redirect_removes_all_payload_headers() {
        let mut headers = HeaderMap::new();
        for name in [
            CONTENT_TYPE,
            CONTENT_LENGTH,
            CONTENT_ENCODING,
            TRANSFER_ENCODING,
        ] {
            headers.insert(name, reqwest::header::HeaderValue::from_static("value"));
        }

        remove_payload_headers(&mut headers);

        assert!(headers.is_empty());
    }

    #[test]
    fn redirect_target_validation_refuses_https_chain_downgrade_without_url_details() {
        let target = reqwest::Url::parse("http://example.test/path?secret=value").unwrap();

        let error = validate_redirect_target(true, &target).unwrap_err();

        assert_eq!(error, RedirectTargetError::HttpsDowngrade);
        let display =
            ReplayableRequestError::<std::convert::Infallible>::HttpsDowngrade.to_string();
        assert_eq!(display, HTTPS_DOWNGRADE_REFUSAL);
        assert!(!display.contains("secret"));
    }

    #[test]
    fn redirect_target_validation_rejects_non_http_scheme() {
        let target = reqwest::Url::parse("file:///tmp/archive").unwrap();

        assert_eq!(
            validate_redirect_target(false, &target),
            Err(RedirectTargetError::UnsupportedScheme)
        );
    }

    #[test]
    fn redirect_target_validation_allows_cleartext_only_for_exact_loopback_hosts() {
        for target in [
            "http://example.test/upload",
            "http://localhost.evil.example/upload",
            "http://192.0.2.1/upload",
            "http://[::ffff:192.0.2.1]/upload",
        ] {
            let target = reqwest::Url::parse(target).unwrap();
            assert!(
                validate_redirect_target(false, &target).is_err(),
                "accepted cleartext redirect target {target}"
            );
        }

        for target in [
            "http://localhost/upload",
            "http://127.0.0.42/upload",
            "http://[::1]/upload",
            "http://[::ffff:127.0.0.42]/upload",
        ] {
            let target = reqwest::Url::parse(target).unwrap();
            assert_eq!(validate_redirect_target(false, &target), Ok(()));
        }
    }

    #[tokio::test]
    async fn cleartext_non_loopback_redirect_is_rejected_before_target_client_selection() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let redirector = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/initial"))
            .respond_with(
                ResponseTemplate::new(307)
                    .insert_header("location", "http://192.0.2.1/private-package"),
            )
            .expect(1)
            .mount(&redirector)
            .await;
        let urls = Arc::new(std::sync::Mutex::new(Vec::new()));
        let provider = RecordingClientProvider {
            client: reqwest::Client::builder()
                .redirect(Policy::none())
                .build()
                .unwrap(),
            urls: Arc::clone(&urls),
        };
        let body = ReplayableRequestBody::from_bytes(b"private package".to_vec());
        let request = reqwest::Request::new(
            reqwest::Method::PUT,
            reqwest::Url::parse(&format!("{}/initial", redirector.uri())).unwrap(),
        );

        let error = send_with_replayable_redirects(&provider, request, Some(&body))
            .await
            .expect_err("cleartext non-loopback redirect must be rejected");

        assert!(matches!(
            error,
            ReplayableRequestError::CleartextNonLoopback
        ));
        assert_eq!(
            urls.lock().unwrap().as_slice(),
            [redirector.uri() + "/initial"]
        );
    }

    #[tokio::test]
    async fn redirected_request_error_does_not_expose_url_credentials_or_query() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let unavailable_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let unavailable_address = unavailable_listener.local_addr().unwrap();
        drop(unavailable_listener);
        let redirector = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/initial"))
            .respond_with(ResponseTemplate::new(307).insert_header(
                "location",
                format!(
                    "http://upload-user:upload-password@{unavailable_address}/upload?token=query-secret#fragment-secret"
                ),
            ))
            .expect(1)
            .mount(&redirector)
            .await;
        let client = reqwest::Client::builder()
            .redirect(Policy::none())
            .build()
            .unwrap();
        let body = ReplayableRequestBody::from_bytes(b"body".to_vec());
        let request = client
            .put(format!("{}/initial", redirector.uri()))
            .body(body.body())
            .build()
            .unwrap();

        let error = send_with_replayable_redirects(&client, request, Some(&body))
            .await
            .expect_err("the redirect target should refuse the connection")
            .to_string();

        for secret in [
            "upload-user",
            "upload-password",
            "query-secret",
            "fragment-secret",
        ] {
            assert!(!error.contains(secret), "request error exposed {secret}");
        }
    }

    #[tokio::test]
    async fn redirect_timeout_includes_client_provider_latency() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/initial"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;
        let client = reqwest::Client::builder()
            .redirect(Policy::none())
            .build()
            .unwrap();
        let provider = DelayedClientProvider {
            client,
            delay: std::time::Duration::from_millis(100),
        };
        let mut request = reqwest::Request::new(
            reqwest::Method::GET,
            reqwest::Url::parse(&format!("{}/initial", server.uri())).unwrap(),
        );
        *request.timeout_mut() = Some(std::time::Duration::from_millis(40));

        let error = send_with_replayable_redirects(&provider, request, None)
            .await
            .expect_err("provider latency must consume the request timeout");

        assert!(
            matches!(error, ReplayableRequestError::Timeout)
                || matches!(error, ReplayableRequestError::Request(ref error) if error.is_timeout())
        );
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn redirect_timeout_uses_one_budget_for_provider_and_request_latency() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/initial"))
            .respond_with(
                ResponseTemplate::new(200).set_delay(std::time::Duration::from_millis(100)),
            )
            .expect(1)
            .mount(&server)
            .await;
        let client = reqwest::Client::builder()
            .redirect(Policy::none())
            .build()
            .unwrap();
        let provider = DelayedClientProvider {
            client,
            delay: std::time::Duration::from_millis(60),
        };
        let mut request = reqwest::Request::new(
            reqwest::Method::GET,
            reqwest::Url::parse(&format!("{}/initial", server.uri())).unwrap(),
        );
        *request.timeout_mut() = Some(std::time::Duration::from_millis(120));

        let error = send_with_replayable_redirects(&provider, request, None)
            .await
            .expect_err("provider and request latency must share one timeout budget");

        assert!(
            matches!(error, ReplayableRequestError::Timeout)
                || matches!(error, ReplayableRequestError::Request(ref error) if error.is_timeout())
        );
    }

    #[tokio::test]
    async fn explicit_redirects_follow_exactly_ten_hops() {
        let (url, request_count) = redirect_chain_server(DEFAULT_REDIRECT_LIMIT, true).await;
        let client = reqwest::Client::builder()
            .redirect(Policy::none())
            .build()
            .unwrap();
        let request = client.get(url).build().unwrap();

        let response = send_with_replayable_redirects(&client, request, None)
            .await
            .expect("ten redirects should be allowed");

        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert_eq!(
            request_count.load(std::sync::atomic::Ordering::SeqCst),
            DEFAULT_REDIRECT_LIMIT + 1
        );
    }

    #[tokio::test]
    async fn explicit_redirects_reject_the_eleventh_hop_before_contacting_its_target() {
        let (url, request_count) = redirect_chain_server(DEFAULT_REDIRECT_LIMIT + 1, false).await;
        let client = reqwest::Client::builder()
            .redirect(Policy::none())
            .build()
            .unwrap();
        let request = client.get(url).build().unwrap();

        let error = send_with_replayable_redirects(&client, request, None)
            .await
            .expect_err("an eleventh redirect should be rejected");

        assert!(matches!(error, ReplayableRequestError::TooManyRedirects));
        assert_eq!(
            request_count.load(std::sync::atomic::Ordering::SeqCst),
            DEFAULT_REDIRECT_LIMIT + 1
        );
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

    #[tokio::test]
    async fn body_read_error_does_not_expose_request_query() {
        let response = response_from_raw_at_path(
            b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nx".to_vec(),
            "/release?token=should-not-appear",
        )
        .await;

        let error = read_body_capped(response, 32)
            .await
            .expect_err("truncated body must fail");

        assert!(!error.to_string().contains("should-not-appear"));
    }
}
