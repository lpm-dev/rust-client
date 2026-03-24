use crate::{auth, output};
use lpm_common::LpmError;
use lpm_registry::RegistryClient;
use owo_colors::OwoColorize;
use std::sync::Arc;
use tokio::sync::oneshot;

/// Login flow:
/// 1. Start a local HTTP server on a random port
/// 2. Open browser to `{registry}/cli/login?port={port}`
/// 3. User authenticates in browser
/// 4. Browser redirects to `localhost:{port}/callback?token={token}`
/// 5. We capture the token, verify it with whoami, store it
pub async fn run(registry_url: &str, json_output: bool) -> Result<(), LpmError> {
	// Check if already logged in
	if let Some(existing) = auth::get_token(registry_url) {
		let client = lpm_registry::RegistryClient::new()
			.with_base_url(registry_url.to_string())
			.with_token(existing);
		if let Ok(info) = client.whoami().await {
			let name = info
				.profile_username
				.as_deref()
				.or(info.username.as_deref())
				.unwrap_or("unknown");
			if !json_output {
				output::info(&format!(
					"Already logged in as {}. Use {} to log out first.",
					name.bold(),
					"lpm-rs logout".dimmed()
				));
			}
			return Ok(());
		}
		// Token is invalid — proceed with login
	}

	if !json_output {
		output::info("Opening browser for authentication...");
	}

	// Create a oneshot channel to receive the token from the callback
	let (tx, rx) = oneshot::channel::<String>();
	let tx = Arc::new(tokio::sync::Mutex::new(Some(tx)));

	// Start local HTTP server on random port
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
		.await
		.map_err(|e| LpmError::Io(e))?;
	let port = listener
		.local_addr()
		.map_err(|e| LpmError::Io(e))?
		.port();

	// Open browser
	let login_url = format!("{registry_url}/cli/login?port={port}");
	if open::that(&login_url).is_err() {
		if !json_output {
			output::warn("Could not open browser automatically.");
			println!("  Open this URL manually: {}", login_url.bold());
		}
	}

	if !json_output {
		println!("  Waiting for authentication at {}", login_url.dimmed());
	}

	// Handle the callback
	let tx_clone = tx.clone();
	let server_handle = tokio::spawn(async move {
		// Accept one connection
		if let Ok((stream, _)) = listener.accept().await {
			handle_callback(stream, tx_clone).await;
		}
	});

	// Wait for token with timeout (2 minutes)
	let token = tokio::time::timeout(std::time::Duration::from_secs(120), rx)
		.await
		.map_err(|_| LpmError::Registry("login timed out after 2 minutes".to_string()))?
		.map_err(|_| LpmError::Registry("login callback channel closed".to_string()))?;

	server_handle.abort();

	// Verify the token via whoami
	let client = RegistryClient::new()
		.with_base_url(registry_url.to_string())
		.with_token(&token);

	let info = client.whoami().await.map_err(|e| {
		LpmError::Registry(format!("token verification failed: {e}"))
	})?;

	let username = info
		.profile_username
		.as_deref()
		.or(info.username.as_deref())
		.unwrap_or("unknown")
		.to_string();

	// Store the token
	auth::set_token(registry_url, &token)
		.map_err(|e| LpmError::Registry(format!("failed to store token: {e}")))?;

	if json_output {
		let json = serde_json::json!({
			"username": username,
			"registry": registry_url,
		});
		println!("{}", serde_json::to_string_pretty(&json).unwrap());
	} else {
		println!();
		output::success(&format!("Logged in as {}", username.bold()));
		println!();
	}

	Ok(())
}

/// Handle the OAuth callback HTTP request.
///
/// Expects: GET /callback?token=lpm_xxx
/// Responds with a simple HTML page that auto-closes.
async fn handle_callback(
	stream: tokio::net::TcpStream,
	tx: Arc<tokio::sync::Mutex<Option<oneshot::Sender<String>>>>,
) {
	use tokio::io::{AsyncReadExt, AsyncWriteExt};

	let mut stream = stream;
	let mut buf = vec![0u8; 4096];
	let n = match stream.read(&mut buf).await {
		Ok(n) => n,
		Err(_) => return,
	};

	let request = String::from_utf8_lossy(&buf[..n]);

	// Parse the GET request line
	let first_line = request.lines().next().unwrap_or("");
	let path = first_line
		.split_whitespace()
		.nth(1)
		.unwrap_or("/");

	// Extract token from query string
	let token = if path.starts_with("/callback") {
		path.split('?')
			.nth(1)
			.and_then(|query| {
				query.split('&').find_map(|param| {
					let mut parts = param.splitn(2, '=');
					let key = parts.next()?;
					let value = parts.next()?;
					if key == "token" {
						Some(value.to_string())
					} else {
						None
					}
				})
			})
	} else {
		None
	};

	let (status, body) = if let Some(ref token) = token {
		// Send token to main thread
		if let Some(sender) = tx.lock().await.take() {
			let _ = sender.send(token.clone());
		}

		(
			"200 OK",
			r#"<!DOCTYPE html>
<html>
<head><title>LPM Login</title></head>
<body style="font-family:system-ui;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;background:#0a0a0a;color:#fafafa">
<div style="text-align:center">
<h1 style="color:#22c55e">&#10004; Access Granted</h1>
<p>You can close this window and return to the terminal.</p>
</div>
</body>
</html>"#,
		)
	} else {
		(
			"400 Bad Request",
			r#"<!DOCTYPE html>
<html>
<head><title>LPM Login Error</title></head>
<body style="font-family:system-ui;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;background:#0a0a0a;color:#fafafa">
<div style="text-align:center">
<h1 style="color:#ef4444">&#10008; Login Failed</h1>
<p>No token received. Please try again.</p>
</div>
</body>
</html>"#,
		)
	};

	let response = format!(
		"HTTP/1.1 {status}\r\nContent-Type: text/html\r\nConnection: close\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\n\r\n{body}",
		body.len()
	);

	let _ = stream.write_all(response.as_bytes()).await;
	let _ = stream.flush().await;
}
