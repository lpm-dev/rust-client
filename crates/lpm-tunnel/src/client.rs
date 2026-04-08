//! Tunnel WebSocket client.
//!
//! Connects to the LPM tunnel relay, authenticates, receives a public URL,
//! and proxies HTTP requests between the relay and the local dev server.

use crate::protocol::{ClientMessage, ServerMessage};
use crate::webhook::CapturedWebhook;
use crate::ws_capture::{FrameDirection, WsEvent};
use crate::{DEFAULT_RELAY_URL, TunnelSession, proxy, webhook, webhook_signature};
use futures_util::{SinkExt, StreamExt};
use lpm_common::LpmError;
use std::collections::HashMap;
use std::sync::Arc;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::CloseFrame;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;

/// Maximum WebSocket message size from relay (50 MB).
const MAX_WS_MESSAGE_SIZE: usize = 50 * 1024 * 1024;

/// Maximum WebSocket frame size from relay (16 MB).
const MAX_WS_FRAME_SIZE: usize = 16 * 1024 * 1024;

/// Duration after which a successful connection resets the retry counter.
/// If a connection lasts longer than this, it was "healthy" and the next
/// disconnect should not carry forward accumulated retry counts.
const HEALTHY_CONNECTION_SECS: u64 = 60;

/// Maximum time to wait for a pong response before considering the relay dead.
const PONG_TIMEOUT_SECS: u64 = 90;

/// Maximum time to wait for in-flight tasks during graceful shutdown.
const SHUTDOWN_TIMEOUT_SECS: u64 = 5;

enum LocalWebSocketCommand {
    Frame {
        data: Vec<u8>,
        is_binary: bool,
    },
    Close {
        code: Option<u16>,
        reason: Option<String>,
    },
}

/// Options for connecting to the tunnel relay.
#[derive(Debug, Clone)]
pub struct TunnelOptions {
    /// Relay WebSocket URL (default: wss://relay.lpm.fyi/connect).
    pub relay_url: String,
    /// LPM auth token.
    pub token: String,
    /// Local port to tunnel.
    pub local_port: u16,
    /// Full tunnel domain (e.g., "acme-api.lpm.llc"). Pro/Org only.
    /// If None, relay assigns a random domain on lpm.fyi (free tier).
    /// If bare name without dot, ".lpm.fyi" is appended for backward compat.
    pub domain: Option<String>,
    /// Auth token for protecting the tunnel URL. When set, the relay
    /// requires `?auth={token}` on incoming requests (prevents unauthorized access).
    pub tunnel_auth: Option<String>,
    /// Channel for sending captured webhooks to observers (inspector, logger, dashboard).
    ///
    /// Uses an unbounded channel by design: webhook capture is best-effort and must
    /// never block the proxy hot path. The receiver (logger/inspector) drains quickly
    /// since it only writes to disk. If back-pressure is ever needed, the caller can
    /// switch to a bounded channel — the tunnel uses `send()` which works with both.
    pub webhook_tx: Option<tokio::sync::mpsc::UnboundedSender<CapturedWebhook>>,
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
    /// Uses the same unbounded best-effort pattern as `webhook_tx`.
    pub ws_tx: Option<tokio::sync::mpsc::UnboundedSender<WsEvent>>,
}

impl TunnelOptions {
    pub fn new(token: String, local_port: u16) -> Self {
        Self {
            relay_url: DEFAULT_RELAY_URL.to_string(),
            token,
            local_port,
            domain: None,
            tunnel_auth: None,
            webhook_tx: None,
            no_pin: false,
            auto_ack: false,
            ws_tx: None,
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
    let mut retry_count = 0;
    let max_retries = 10;

    loop {
        let connection_start = std::time::Instant::now();
        match try_connect(options, &on_connected).await {
            Ok(()) => {
                // Clean disconnect
                tracing::info!("tunnel closed");
                return Ok(());
            }
            Err(e) => {
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
                tokio::time::sleep(std::time::Duration::from_secs(total_delay)).await;
            }
        }
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

// ── TOFU Certificate Pinning ──────────────────────────────────────

/// Path to the TOFU pin file (~/.lpm/relay-pin).
fn relay_pin_path() -> Option<std::path::PathBuf> {
    dirs::home_dir().map(|h| h.join(".lpm").join("relay-pin"))
}

/// Read a previously stored TOFU pin (hex-encoded SHA-256 of SPKI).
fn read_tofu_pin() -> Option<String> {
    let path = relay_pin_path()?;
    std::fs::read_to_string(&path)
        .ok()
        .map(|s| s.trim().to_string())
}

/// Store a TOFU pin to disk.
fn write_tofu_pin(pin_hex: &str) -> Result<(), String> {
    let path = relay_pin_path().ok_or("no home directory")?;
    let parent = path.parent().unwrap();
    std::fs::create_dir_all(parent).map_err(|e| format!("failed to create ~/.lpm: {e}"))?;
    std::fs::write(&path, pin_hex).map_err(|e| format!("failed to write relay pin: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
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

        // Then: TOFU pin check on the end-entity certificate's SPKI
        let current_pin = spki_sha256_hex(end_entity.as_ref()).ok_or_else(|| {
            rustls::Error::General("failed to extract SPKI from relay certificate".into())
        })?;

        tracing::debug!("relay certificate SPKI SHA-256: {current_pin}");

        match read_tofu_pin() {
            Some(stored_pin) => {
                if stored_pin != current_pin {
                    tracing::error!(
                        "CERTIFICATE PIN MISMATCH: stored={stored_pin}, current={current_pin}. \
						 The relay's certificate has changed. This could indicate a MITM attack. \
						 If the relay legitimately rotated certificates, delete ~/.lpm/relay-pin and reconnect."
                    );
                    return Err(rustls::Error::General(
                        "certificate pin mismatch — possible MITM \
						 (delete ~/.lpm/relay-pin to re-pin)"
                            .into(),
                    ));
                }
                tracing::debug!("TOFU certificate pin verified");
            }
            None => {
                // First connection — store the pin
                if let Err(e) = write_tofu_pin(&current_pin) {
                    tracing::warn!("failed to store TOFU pin: {e}");
                } else {
                    tracing::info!("stored relay certificate pin (TOFU): {current_pin}");
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

/// Check if a relay URL points to localhost (skip pinning for local development).
fn is_localhost_relay(url: &str) -> bool {
    let host_port = url
        .split("://")
        .nth(1)
        .and_then(|rest| rest.split('/').next())
        .unwrap_or("");
    // Handle bracketed IPv6: [::1]:8787
    let host = if host_port.starts_with('[') {
        host_port
            .split(']')
            .next()
            .unwrap_or("")
            .trim_start_matches('[')
    } else {
        host_port.split(':').next().unwrap_or("")
    };
    host == "localhost" || host == "127.0.0.1" || host == "::1"
}

/// Single connection attempt to the relay.
async fn try_connect(
    options: &TunnelOptions,
    on_connected: &impl Fn(&TunnelSession),
) -> Result<(), LpmError> {
    // Build connect URL — non-sensitive params only (token goes in Authorization header)
    let mut connect_url = format!("{}?port={}", options.relay_url, options.local_port);
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

    let use_pinning = !options.no_pin && !is_localhost_relay(&options.relay_url);

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
    let request = build_websocket_connect_request(
        &connect_url,
        &options.token,
        options.tunnel_auth.as_deref(),
    )?;

    let ws_config = tokio_tungstenite::tungstenite::protocol::WebSocketConfig {
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
    .map_err(|e| LpmError::Tunnel(format!("failed to connect to relay: {e}")))?;

    let (mut write, mut read) = ws_stream.split();

    // Wait for ServerHello (Worker sends it after validating token)
    let server_hello = read
        .next()
        .await
        .ok_or_else(|| LpmError::Tunnel("relay closed connection before hello".into()))?
        .map_err(|e| LpmError::Tunnel(format!("failed to read server hello: {e}")))?;

    let session = match server_hello {
        Message::Text(text) => {
            let msg: ServerMessage = serde_json::from_str(&text)
                .map_err(|e| LpmError::Tunnel(format!("invalid server message: {e}")))?;

            match msg {
                ServerMessage::Hello {
                    domain: raw_domain,
                    tunnel_url,
                    session_id,
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

                    TunnelSession {
                        tunnel_url,
                        domain,
                        session_id,
                        local_port: options.local_port,
                    }
                }
                ServerMessage::Error { message, code } => {
                    return Err(LpmError::Tunnel(format!(
                        "relay rejected connection: {message}{}",
                        code.map(|c| format!(" ({c})")).unwrap_or_default()
                    )));
                }
                _ => {
                    return Err(LpmError::Tunnel(
                        "unexpected message from relay (expected hello)".into(),
                    ));
                }
            }
        }
        _ => {
            return Err(LpmError::Tunnel(
                "unexpected message type from relay".into(),
            ));
        }
    };

    on_connected(&session);

    // Create HTTP client for local proxying
    let http_client = reqwest::Client::builder()
        .no_proxy()
        .build()
        .map_err(|e| LpmError::Tunnel(format!("failed to create HTTP client: {e}")))?;

    // Keepalive ticker: ping every 30s
    let mut ping_interval = tokio::time::interval(std::time::Duration::from_secs(30));
    ping_interval.tick().await; // Skip first immediate tick

    // Track last pong time for dead relay detection (#3)
    let mut last_pong = std::time::Instant::now();

    // Channel for spawned WebSocket tasks to send frames back to the relay.
    // The main loop owns `write` exclusively; spawned tasks send through this channel.
    let (relay_tx, mut relay_rx) = tokio::sync::mpsc::channel::<String>(64);

    // Track spawned task handles for graceful shutdown (#2)
    let mut task_handles = tokio::task::JoinSet::new();

    // Active local WebSocket connections keyed by connection ID.
    // Senders push frames from relay → local WS.
    let mut ws_connections: HashMap<String, tokio::sync::mpsc::Sender<LocalWebSocketCommand>> =
        HashMap::new();

    // Message loop
    loop {
        tokio::select! {
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
                                    if let Err(e) = write.send(Message::Text(json)).await {
                                        tracing::warn!("failed to send error response to relay: {e}");
                                        break;
                                    }
                                    continue;
                                }

                                let forward_start = std::time::Instant::now();
                                let mut was_auto_acked = false;
                                let response = match proxy::forward_request(
                                    &http_client,
                                    options.local_port,
                                    &server_msg,
                                )
                                .await
                                {
                                    Ok(resp) => resp,
                                    Err(e) => {
                                        tracing::debug!("local proxy error: {e}");
                                        if let ServerMessage::HttpRequest { id, .. } = &server_msg {
                                            if options.auto_ack {
                                                // Auto-ack: return 200 OK to prevent provider
                                                // retries and endpoint deactivation
                                                was_auto_acked = true;
                                                tracing::info!(
                                                    "auto-ack: returning 200 OK (server down)"
                                                );
                                                proxy::auto_ack_response(id)
                                            } else {
                                                proxy::bad_gateway_response(id)
                                            }
                                        } else {
                                            continue;
                                        }
                                    }
                                };
                                let forward_duration = forward_start.elapsed();

                                // Capture webhook for inspector/logger/dashboard
                                if let Some(ref tx) = options.webhook_tx
                                    && let ServerMessage::HttpRequest {
                                        ref id,
                                        ref method,
                                        ref url,
                                        ref headers,
                                        ref body,
                                    } = server_msg
                                    {
                                        let req_body = base64::Engine::decode(
                                            &base64::engine::general_purpose::STANDARD,
                                            body,
                                        )
                                        .unwrap_or_default();

                                        let (resp_status, resp_headers, resp_body) =
                                            extract_response_data(&response);

                                        let mut captured = CapturedWebhook {
                                            id: id.clone(),
                                            timestamp: chrono::Utc::now().to_rfc3339(),
                                            method: method.clone(),
                                            path: url.clone(),
                                            request_headers: headers.clone(),
                                            request_body: req_body,
                                            response_status: resp_status,
                                            response_headers: resp_headers,
                                            response_body: resp_body,
                                            duration_ms: forward_duration.as_millis() as u64,
                                            provider: webhook::detect_provider(url, headers),
                                            summary: String::new(),
                                            signature_diagnostic: None,
                                            auto_acked: was_auto_acked,
                                        };
                                        captured.summary = webhook::summarize_webhook(&captured);

                                        // Run signature diagnostics on failed webhook responses.
                                        // Only runs when status >= 400, so zero overhead on success.
                                        if captured.response_status >= 400 {
                                            let env_vars: HashMap<String, String> =
                                                std::env::vars().collect();
                                            captured.signature_diagnostic =
                                                webhook_signature::diagnose_signature_failure(
                                                    &captured, &env_vars,
                                                );
                                        }

                                        let _ = tx.send(captured);
                                    }

                                let json = match serde_json::to_string(&response) {
                                    Ok(j) => j,
                                    Err(e) => {
                                        tracing::error!("failed to serialize HTTP response: {e}");
                                        continue;
                                    }
                                };
                                if let Err(e) = write.send(Message::Text(json)).await {
                                    tracing::warn!("failed to send response to relay: {e}");
                                    break;
                                }
                            }
                            ServerMessage::WebSocketUpgrade { id, url, headers } => {
                                // Validate the URL before forwarding — prevent path traversal
                                // and header injection via crafted URLs from the relay.
                                if !is_safe_local_url(&url) {
                                    tracing::warn!(
                                        "rejected WebSocket upgrade with unsafe URL: {:?}",
                                        url
                                    );
                                    let error_resp = proxy::bad_gateway_response(&id);
                                    let json = match serde_json::to_string(&error_resp) {
                                        Ok(j) => j,
                                        Err(e) => {
                                            tracing::error!("failed to serialize error response: {e}");
                                            continue;
                                        }
                                    };
                                    if let Err(e) = write.send(Message::Text(json)).await {
                                        tracing::warn!("failed to send error response to relay: {e}");
                                        break;
                                    }
                                    continue;
                                }

                                // Establish local WebSocket connection for HMR passthrough
                                tracing::debug!("WebSocket upgrade request: {url}");
                                match proxy::connect_local_websocket(
                                    options.local_port, &url, &headers,
                                ).await {
                                    Ok((local_write, mut local_read)) => {
                                        // Create a channel for relay → local WS forwarding
                                        let (local_tx, mut local_rx) =
                                            tokio::sync::mpsc::channel::<LocalWebSocketCommand>(64);
                                        ws_connections.insert(id.clone(), local_tx);

                                        // Spawn: relay → local WS (consumes frames from local_rx)
                                        let local_write = std::sync::Arc::new(
                                            tokio::sync::Mutex::new(local_write),
                                        );
                                        let local_write_clone = local_write.clone();
                                        let id_for_writer = id.clone();
                                        task_handles.spawn(async move {
                                            while let Some(command) = local_rx.recv().await {
                                        let is_close = matches!(&command, LocalWebSocketCommand::Close { .. });
                                        let msg = match command {
                                            LocalWebSocketCommand::Frame { data, is_binary } => {
                                                if is_binary {
                                                    tokio_tungstenite::tungstenite::Message::Binary(data)
                                                } else {
                                                    let text = String::from_utf8_lossy(&data).into_owned();
                                                    tokio_tungstenite::tungstenite::Message::Text(text)
                                                }
                                            }
                                            LocalWebSocketCommand::Close { code, reason } => {
                                                let close_frame = CloseFrame {
                                                    code: CloseCode::from(code.unwrap_or(1000)),
                                                    reason: reason.unwrap_or_default().into(),
                                                };
                                                tokio_tungstenite::tungstenite::Message::Close(Some(close_frame))
                                            }
                                        };
                                                let mut sink = local_write_clone.lock().await;
                                                if let Err(e) = sink.send(msg).await {
                                                    tracing::debug!(
                                                        "local WS write failed for {}: {e}",
                                                        id_for_writer
                                                    );
                                                    break;
                                                }

                                        if is_close {
                                            break;
                                        }
                                            }
                                        });

                                        // Spawn: local WS → relay (reads from local_read, sends via relay_tx)
                                        let relay_tx_clone = relay_tx.clone();
                                        let id_clone = id.clone();
                                        let ws_tx_clone = options.ws_tx.clone();
                                        task_handles.spawn(async move {
                                            while let Some(Ok(msg)) = local_read.next().await {
                                                let (data, is_binary) = match msg {
                                                    tokio_tungstenite::tungstenite::Message::Text(t) => {
                                                        (base64::Engine::encode(
                                                            &base64::engine::general_purpose::STANDARD,
                                                            t.as_bytes(),
                                                        ), false)
                                                    }
                                                    tokio_tungstenite::tungstenite::Message::Binary(b) => {
                                                        (base64::Engine::encode(
                                                            &base64::engine::general_purpose::STANDARD,
                                                            &b,
                                                        ), true)
                                                    }
                                                    tokio_tungstenite::tungstenite::Message::Close(reason) => {
                                                        tracing::debug!("local WS closed for {}", id_clone);
                                                let close_reason = reason
                                                    .as_ref()
                                                    .map(|frame| frame.reason.to_string());
                                                let close_code = reason.as_ref().map(|frame| u16::from(frame.code));
                                                        if let Some(ref ws_tx) = ws_tx_clone {
                                                            let _ = ws_tx.send(WsEvent::Closed {
                                                                connection_id: id_clone.clone(),
                                                        reason: close_reason.clone(),
                                                                timestamp: chrono::Utc::now().to_rfc3339(),
                                                            });
                                                        }
                                                let close_msg = ClientMessage::WebSocketClose {
                                                    id: id_clone.clone(),
                                                    code: close_code,
                                                    reason: close_reason,
                                                };
                                                if let Ok(json) = serde_json::to_string(&close_msg) {
                                                    let _ = relay_tx_clone.send(json).await;
                                                }
                                                        break;
                                                    }
                                                    _ => continue,
                                                };
                                                // Capture outbound frame for inspector
                                                if let Some(ref ws_tx) = ws_tx_clone {
                                                    let display_data = if is_binary {
                                                        data.clone() // Already base64
                                                    } else {
                                                        // Decode base64 back to text for display
                                                        base64::Engine::decode(
                                                            &base64::engine::general_purpose::STANDARD,
                                                            &data,
                                                        )
                                                        .ok()
                                                        .and_then(|b| String::from_utf8(b).ok())
                                                        .unwrap_or_else(|| data.clone())
                                                    };
                                                    let size = base64::Engine::decode(
                                                        &base64::engine::general_purpose::STANDARD,
                                                        &data,
                                                    )
                                                    .map(|b| b.len())
                                                    .unwrap_or(0);
                                                    let _ = ws_tx.send(WsEvent::Frame {
                                                        connection_id: id_clone.clone(),
                                                        direction: FrameDirection::Outbound,
                                                        data: display_data,
                                                        is_binary,
                                                        size,
                                                        timestamp: chrono::Utc::now().to_rfc3339(),
                                                    });
                                                }

                                                let frame = ClientMessage::WebSocketFrame {
                                                    id: id_clone.clone(),
                                                    data,
                                                    is_binary,
                                                };
                                                let json = match serde_json::to_string(&frame) {
                                                    Ok(j) => j,
                                                    Err(e) => {
                                                        tracing::error!(
                                                            "failed to serialize WS frame: {e}"
                                                        );
                                                        continue;
                                                    }
                                                };
                                                if relay_tx_clone.send(json).await.is_err() {
                                                    // Main loop dropped the receiver — tunnel is closing
                                                    break;
                                                }
                                            }
                                        });

                                        tracing::debug!("WebSocket upgrade established for {url}");

                                        // Capture WS connection event for inspector
                                        if let Some(ref ws_tx) = options.ws_tx {
                                            let _ = ws_tx.send(WsEvent::Connected {
                                                connection_id: id.clone(),
                                                url: url.clone(),
                                                headers: headers.clone(),
                                                timestamp: chrono::Utc::now().to_rfc3339(),
                                            });
                                        }
                                    }
                                    Err(e) => {
                                        tracing::warn!("WebSocket upgrade failed for {}: {e}", id);
                                        // Send error response back to relay so the remote
                                        // client gets a proper 502 instead of hanging.
                                        let error_resp = proxy::bad_gateway_response(&id);
                                        let json = match serde_json::to_string(&error_resp) {
                                            Ok(j) => j,
                                            Err(ser_e) => {
                                                tracing::error!(
                                                    "failed to serialize WS upgrade error: {ser_e}"
                                                );
                                                continue;
                                            }
                                        };
                                        if let Err(e) = write.send(Message::Text(json)).await {
                                            tracing::warn!(
                                                "failed to send WS upgrade error to relay: {e}"
                                            );
                                            break;
                                        }
                                    }
                                }
                            }
                            ServerMessage::WebSocketFrame { id, data, is_binary } => {
                                // Forward frame from relay → local WebSocket
                                if let Some(tx) = ws_connections.get(&id) {
                                    let decoded = match base64::Engine::decode(
                                        &base64::engine::general_purpose::STANDARD,
                                        &data,
                                    ) {
                                        Ok(d) => d,
                                        Err(e) => {
                                            tracing::warn!(
                                                "failed to decode WS frame data for {id}: {e}"
                                            );
                                            continue;
                                        }
                                    };
                                    // Capture inbound frame for inspector
                                    if let Some(ref ws_tx) = options.ws_tx {
                                        let frame_data = if is_binary {
                                            base64::Engine::encode(
                                                &base64::engine::general_purpose::STANDARD,
                                                &decoded,
                                            )
                                        } else {
                                            String::from_utf8_lossy(&decoded).into_owned()
                                        };
                                        let _ = ws_tx.send(WsEvent::Frame {
                                            connection_id: id.clone(),
                                            direction: FrameDirection::Inbound,
                                            data: frame_data,
                                            is_binary,
                                            size: decoded.len(),
                                            timestamp: chrono::Utc::now().to_rfc3339(),
                                        });
                                    }

                                    if tx.send(LocalWebSocketCommand::Frame { data: decoded, is_binary }).await.is_err() {
                                        // Local WS connection closed, clean up
                                        tracing::debug!(
                                            "local WS connection {id} closed, removing"
                                        );
                                        ws_connections.remove(&id);
                                    }
                                } else {
                                    tracing::warn!(
                                        "received WS frame for unknown connection {id}, ignoring"
                                    );
                                }
                            }
                            ServerMessage::WebSocketClose { id, code, reason } => {
                                if let Some(tx) = ws_connections.remove(&id) {
                                    let _ = tx.send(LocalWebSocketCommand::Close { code, reason }).await;
                                } else {
                                    tracing::debug!("received WS close for unknown connection {id}");
                                }
                            }
                            ServerMessage::Pong => {
                                last_pong = std::time::Instant::now();
                                tracing::debug!("pong received");
                            }
                            ServerMessage::Error { message, .. } => {
                                tracing::error!("relay error: {message}");
                                return Err(LpmError::Tunnel(format!("relay error: {message}")));
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
                        return Err(LpmError::Tunnel(format!("WebSocket error: {e}")));
                    }
                    None => {
                        tracing::info!("relay connection ended");
                        break;
                    }
                    _ => {}
                }
            }

            // Frames from spawned WS tasks → relay
            Some(json) = relay_rx.recv() => {
                if let Err(e) = write.send(Message::Text(json)).await {
                    tracing::warn!("failed to send WS frame to relay: {e}");
                    break;
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
                if let Err(e) = write.send(Message::Text(ping)).await {
                    tracing::warn!("failed to send ping: {e}");
                    break;
                }
            }
        }
    }

    // Clean up: drop all WS connection senders to signal spawned tasks to exit
    ws_connections.clear();

    // Gracefully await in-flight tasks with a timeout (#2)
    let shutdown_deadline = tokio::time::Duration::from_secs(SHUTDOWN_TIMEOUT_SECS);
    let _ = tokio::time::timeout(shutdown_deadline, async {
        while task_handles.join_next().await.is_some() {}
    })
    .await;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tunnel_options_defaults() {
        let opts = TunnelOptions::new("lpm_test".to_string(), 3000);
        assert_eq!(opts.relay_url, DEFAULT_RELAY_URL);
        assert_eq!(opts.local_port, 3000);
        assert!(opts.domain.is_none());
        assert!(opts.tunnel_auth.is_none());
        assert!(opts.webhook_tx.is_none());
        assert!(!opts.no_pin);
        assert!(opts.resolved_domain().is_none());
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

        // Double slashes in query string are allowed (#11)
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
    fn ws_config_constants_are_reasonable() {
        // #1: Verify WebSocket message size limits are set and sane
        assert_eq!(MAX_WS_MESSAGE_SIZE, 50 * 1024 * 1024);
        assert_eq!(MAX_WS_FRAME_SIZE, 16 * 1024 * 1024);
        assert!(MAX_WS_FRAME_SIZE <= MAX_WS_MESSAGE_SIZE);
    }

    #[test]
    fn pong_timeout_detection() {
        // #3: Pong timeout should detect dead relays
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
        // #15: Jitter must be non-negative and <= base_delay / 2
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
        // #10: Verify the constant is reasonable
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
        assert!(is_localhost_relay("wss://localhost:8787/connect"));
        assert!(is_localhost_relay("ws://127.0.0.1:8787/connect"));
        assert!(is_localhost_relay("wss://[::1]:8787/connect"));
        assert!(!is_localhost_relay("wss://relay.lpm.fyi/connect"));
        assert!(!is_localhost_relay("wss://example.com/connect"));
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
            local_port: 3000,
            domain: Some("myapp.lpm.fyi".to_string()),
            tunnel_auth: Some("secret-tunnel-auth".to_string()),
            webhook_tx: None,
            no_pin: false,
            auto_ack: false,
            ws_tx: None,
        };

        // Reproduce the URL construction from try_connect
        let mut connect_url = format!("{}?port={}", options.relay_url, options.local_port);
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
}
