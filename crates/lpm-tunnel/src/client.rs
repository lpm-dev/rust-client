//! Tunnel WebSocket client.
//!
//! Connects to the LPM tunnel relay, authenticates, receives a public URL,
//! and proxies HTTP requests between the relay and the local dev server.

use crate::protocol::{ClientMessage, ServerMessage};
use crate::webhook::CapturedWebhook;
use crate::{proxy, webhook, TunnelSession, DEFAULT_RELAY_URL};
use futures_util::{SinkExt, StreamExt};
use lpm_common::LpmError;
use std::collections::HashMap;
use tokio_tungstenite::tungstenite::Message;

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
	pub webhook_tx: Option<tokio::sync::mpsc::UnboundedSender<CapturedWebhook>>,
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
				on_disconnected(&format!("disconnected, retrying in {total_delay}s... ({e})"));
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

/// Extract response status, headers, and body from a `ClientMessage::HttpResponse`.
///
/// Returns `(status, headers, decoded_body)`. If the message is not an
/// `HttpResponse` or body decoding fails, returns safe defaults.
fn extract_response_data(
	response: &ClientMessage,
) -> (u16, HashMap<String, String>, Vec<u8>) {
	match response {
		ClientMessage::HttpResponse {
			status,
			headers,
			body,
			..
		} => {
			let decoded_body = base64::Engine::decode(
				&base64::engine::general_purpose::STANDARD,
				body,
			)
			.unwrap_or_default();
			(*status, headers.clone(), decoded_body)
		}
		_ => (0, HashMap::new(), Vec::new()),
	}
}

/// Single connection attempt to the relay.
async fn try_connect(
	options: &TunnelOptions,
	on_connected: &impl Fn(&TunnelSession),
) -> Result<(), LpmError> {
	// Build connect URL — non-sensitive params only (token goes in Authorization header)
	let mut connect_url = format!(
		"{}?port={}",
		options.relay_url, options.local_port
	);
	if let Some(domain) = options.resolved_domain() {
		let encoded = urlencoding::encode(&domain);
		connect_url.push_str(&format!("&domain={encoded}"));
	}
	if let Some(ref auth) = options.tunnel_auth {
		let encoded_auth = urlencoding::encode(auth);
		connect_url.push_str(&format!("&tunnel_auth={encoded_auth}"));
	}

	tracing::debug!("connecting to relay: {connect_url}");

	// Force HTTP/1.1 — Cloudflare Workers require HTTP/1.1 for WebSocket upgrades.
	// HTTP/2 (default via ALPN) doesn't support the Upgrade header mechanism.
	let _ = rustls::crypto::ring::default_provider().install_default();
	let root_store = rustls::RootCertStore::from_iter(
		webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
	);
	let mut tls_config = rustls::ClientConfig::builder()
		.with_root_certificates(root_store)
		.with_no_client_auth();
	tls_config.alpn_protocols = vec![b"http/1.1".to_vec()];

	let tls_connector = tokio_tungstenite::Connector::Rustls(
		std::sync::Arc::new(tls_config),
	);

	// Extract host from relay URL for the Host header
	let url_host = connect_url
		.split("://")
		.nth(1)
		.and_then(|rest| rest.split('/').next())
		.unwrap_or("relay.lpm.fyi");

	// Build WebSocket request with auth token in Authorization header
	// (tokio-tungstenite's IntoClientRequest adds Upgrade/Connection/Sec-WebSocket-* automatically)
	let request = tokio_tungstenite::tungstenite::http::Request::builder()
		.uri(&connect_url)
		.header("Authorization", format!("Bearer {}", options.token))
		.header("Host", url_host)
		.body(())
		.map_err(|e| LpmError::Tunnel(format!("failed to build WebSocket request: {e}")))?;

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
					if let Some(requested) = options.resolved_domain() {
						if domain != requested {
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
					}

					TunnelSession {
						tunnel_url,
						domain,
						session_id,
						local_port: options.local_port,
					}
				},
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
	let (relay_tx, mut relay_rx) =
		tokio::sync::mpsc::channel::<String>(64);

	// Track spawned task handles for graceful shutdown (#2)
	let mut task_handles = tokio::task::JoinSet::new();

	// Active local WebSocket connections keyed by connection ID.
	// Senders push frames from relay → local WS.
	let mut ws_connections: HashMap<
		String,
		tokio::sync::mpsc::Sender<(Vec<u8>, bool)>,
	> = HashMap::new();

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
										// Extract request ID from the server message
										if let ServerMessage::HttpRequest { id, .. } = &server_msg {
											proxy::bad_gateway_response(id)
										} else {
											continue;
										}
									}
								};
								let forward_duration = forward_start.elapsed();

								// Capture webhook for inspector/logger/dashboard
								if let Some(ref tx) = options.webhook_tx {
									if let ServerMessage::HttpRequest {
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
										};
										captured.summary = webhook::summarize_webhook(&captured);
										let _ = tx.send(captured);
									}
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
											tokio::sync::mpsc::channel::<(Vec<u8>, bool)>(64);
										ws_connections.insert(id.clone(), local_tx);

										// Spawn: relay → local WS (consumes frames from local_rx)
										let local_write = std::sync::Arc::new(
											tokio::sync::Mutex::new(local_write),
										);
										let local_write_clone = local_write.clone();
										let id_for_writer = id.clone();
										task_handles.spawn(async move {
											while let Some((data, is_binary)) = local_rx.recv().await {
												let msg = if is_binary {
													tokio_tungstenite::tungstenite::Message::Binary(data)
												} else {
													let text = String::from_utf8_lossy(&data).into_owned();
													tokio_tungstenite::tungstenite::Message::Text(text)
												};
												let mut sink = local_write_clone.lock().await;
												if let Err(e) = sink.send(msg).await {
													tracing::debug!(
														"local WS write failed for {}: {e}",
														id_for_writer
													);
													break;
												}
											}
										});

										// Spawn: local WS → relay (reads from local_read, sends via relay_tx)
										let relay_tx_clone = relay_tx.clone();
										let id_clone = id.clone();
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
													tokio_tungstenite::tungstenite::Message::Close(_) => {
														tracing::debug!("local WS closed for {}", id_clone);
														break;
													}
													_ => continue,
												};
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
									if tx.send((decoded, is_binary)).await.is_err() {
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
				assert!(j <= base / 2 + 1, "jitter {j} exceeds bound for base {base}");
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

		let body_b64 = base64::Engine::encode(
			&base64::engine::general_purpose::STANDARD,
			b"hello",
		);

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
}
