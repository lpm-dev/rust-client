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
	if !json_output {
		output::print_header();
	}

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

	// Generate CSRF state parameter
	let state: String = {
		use rand::RngCore;
		let mut bytes = [0u8; 16];
		rand::thread_rng().fill_bytes(&mut bytes);
		hex::encode(bytes)
	};

	// Open browser
	let login_url = format!("{registry_url}/cli/login?port={port}&state={state}");
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
	let expected_state = state.clone();
	let server_handle = tokio::spawn(async move {
		// Accept one connection
		if let Ok((stream, _)) = listener.accept().await {
			handle_callback(stream, tx_clone, &expected_state).await;
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
		// Server returns email in `username` field (npm compat) and display name in `profile_username`
		let email_str = info.username.as_deref().unwrap_or("");
		println!();
		if email_str.is_empty() || email_str == username {
			output::success(&format!("Logged in as {}", username.bold()));
		} else {
			output::success(&format!("Logged in as {} - {}", username.bold(), email_str.dimmed()));
		}
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
	expected_state: &str,
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

	// Extract token and state from query string
	let (token, received_state) = if path.starts_with("/callback") {
		let query = path.split('?').nth(1).unwrap_or("");
		let mut token = None;
		let mut state = None;
		for param in query.split('&') {
			let mut parts = param.splitn(2, '=');
			let key = parts.next().unwrap_or("");
			let value = parts.next().unwrap_or("");
			match key {
				"token" => token = Some(value.to_string()),
				"state" => state = Some(value.to_string()),
				_ => {}
			}
		}
		(token, state)
	} else {
		(None, None)
	};

	// Verify CSRF state parameter
	let token = token.filter(|_| {
		let state_ok = received_state.as_deref() == Some(expected_state);
		if !state_ok {
			tracing::warn!("login callback state mismatch — possible CSRF attack");
		}
		state_ok
	});

	let (status, body) = if let Some(ref token) = token {
		// Send token to main thread
		if let Some(sender) = tx.lock().await.take() {
			let _ = sender.send(token.clone());
		}

		("200 OK", render_login_page(true, None))
	} else {
		("400 Bad Request", render_login_page(false, None))
	};

	let response = format!(
		"HTTP/1.1 {status}\r\nContent-Type: text/html\r\nConnection: close\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\n\r\n{body}",
		body.len()
	);

	let _ = stream.write_all(response.as_bytes()).await;
	let _ = stream.flush().await;
}

/// Render the login callback HTML page.
/// Uses the same polished design as the JS CLI for consistent branding.
fn render_login_page(success: bool, _username: Option<&str>) -> String {
	let (title, subtitle, accent, icon_svg, footer_msg) = if success {
		(
			"Access Granted",
			"CLI authentication successful",
			"#22c55e",
			r#"<path class="checkmark-path" d="M5 12l5 5L19 7"/>"#,
			r#"Return to your terminal to continue using <code>lpm</code>"#,
		)
	} else {
		(
			"Login Failed",
			"No token received. Please try again.",
			"#ef4444",
			r#"<path class="checkmark-path" d="M6 6l12 12M6 18L18 6"/>"#,
			r#"Return to your terminal and run <code>lpm login</code> again"#,
		)
	};

	format!(r#"<!DOCTYPE html>
<html>
<head>
  <title>LPM - {title}</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&family=Outfit:wght@400;500;600&display=swap" rel="stylesheet">
  <style>
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    :root {{
      --bg-primary: #0a0a0b;
      --bg-card: #111113;
      --bg-subtle: #18181b;
      --border: #27272a;
      --text-primary: #fafafa;
      --text-secondary: #a1a1aa;
      --text-muted: #71717a;
      --accent: {accent};
      --accent-glow: rgba(34, 197, 94, 0.15);
    }}
    body {{
      font-family: 'Outfit', system-ui, sans-serif;
      min-height: 100vh;
      display: flex;
      justify-content: center;
      align-items: center;
      background: var(--bg-primary);
      background-image:
        radial-gradient(ellipse 80% 50% at 50% -20%, var(--accent-glow), transparent),
        radial-gradient(circle at 50% 50%, var(--bg-primary), var(--bg-primary));
      padding: 1.5rem;
    }}
    .container {{ width: 100%; max-width: 420px; animation: fadeInUp 0.6s cubic-bezier(0.16, 1, 0.3, 1); }}
    @keyframes fadeInUp {{ from {{ opacity: 0; transform: translateY(20px); }} to {{ opacity: 1; transform: translateY(0); }} }}
    .card {{
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 2.5rem 2rem;
      text-align: center;
      position: relative;
      overflow: hidden;
    }}
    .card::before {{
      content: '';
      position: absolute;
      top: 0; left: 50%;
      transform: translateX(-50%);
      width: 200px; height: 1px;
      background: linear-gradient(90deg, transparent, var(--accent), transparent);
      opacity: 0.6;
    }}
    .icon-wrapper {{
      width: 80px; height: 80px;
      margin: 0 auto 1.5rem;
      position: relative;
      display: flex; align-items: center; justify-content: center;
    }}
    .icon-ring {{
      position: absolute; inset: 0;
      border-radius: 50%;
      border: 2px solid var(--accent);
      opacity: 0;
      animation: ringPulse 2s ease-out 0.3s infinite;
    }}
    .icon-ring:nth-child(2) {{ animation-delay: 0.6s; }}
    @keyframes ringPulse {{ 0% {{ transform: scale(1); opacity: 0.6; }} 100% {{ transform: scale(1.8); opacity: 0; }} }}
    .icon-circle {{
      width: 64px; height: 64px;
      background: var(--accent);
      border-radius: 50%;
      display: flex; align-items: center; justify-content: center;
      box-shadow: 0 0 40px var(--accent-glow), 0 0 80px var(--accent-glow);
      animation: scaleIn 0.5s cubic-bezier(0.34, 1.56, 0.64, 1) 0.1s both;
    }}
    @keyframes scaleIn {{ from {{ transform: scale(0); }} to {{ transform: scale(1); }} }}
    .checkmark {{
      width: 32px; height: 32px;
      stroke: var(--bg-primary); stroke-width: 3;
      stroke-linecap: round; stroke-linejoin: round; fill: none;
    }}
    .checkmark-path {{
      stroke-dasharray: 50; stroke-dashoffset: 50;
      animation: drawCheck 0.4s ease-out 0.5s forwards;
    }}
    @keyframes drawCheck {{ to {{ stroke-dashoffset: 0; }} }}
    .title {{
      font-size: 1.5rem; font-weight: 600; color: var(--text-primary);
      margin-bottom: 0.5rem; letter-spacing: -0.02em;
      animation: fadeIn 0.5s ease-out 0.3s both;
    }}
    @keyframes fadeIn {{ from {{ opacity: 0; }} to {{ opacity: 1; }} }}
    .subtitle {{
      font-size: 0.9375rem; color: var(--text-secondary);
      margin-bottom: 1.5rem;
      animation: fadeIn 0.5s ease-out 0.4s both;
    }}
    .divider {{
      height: 1px; background: var(--border); margin: 1.25rem 0;
      animation: fadeIn 0.5s ease-out 0.6s both;
    }}
    .footer {{
      display: flex; align-items: center; justify-content: center; gap: 0.5rem;
      animation: fadeIn 0.5s ease-out 0.7s both;
    }}
    .footer-text {{ font-size: 0.8125rem; color: var(--text-muted); }}
    .countdown {{
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.75rem; font-weight: 500;
      color: var(--accent); background: var(--accent-glow);
      padding: 0.25rem 0.5rem; border-radius: 4px;
    }}
    .terminal-hint {{
      margin-top: 1.5rem; padding: 0.75rem 1rem;
      background: var(--bg-subtle); border-radius: 8px;
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.75rem; color: var(--text-muted);
      animation: fadeIn 0.5s ease-out 0.8s both;
    }}
    .terminal-hint code {{ color: var(--accent); }}
  </style>
</head>
<body>
  <div class="container">
    <div class="card">
      <div class="icon-wrapper">
        <div class="icon-ring"></div>
        <div class="icon-ring"></div>
        <div class="icon-circle">
          <svg class="checkmark" viewBox="0 0 24 24">
            {icon_svg}
          </svg>
        </div>
      </div>
      <h1 class="title">{title}</h1>
      <p class="subtitle">{subtitle}</p>
      <div class="divider"></div>
      <div class="footer" id="footer">
        <span class="footer-text">Closing in</span>
        <span class="countdown" id="countdown">5s</span>
      </div>
      <div class="terminal-hint" id="hint">
        {footer_msg}
      </div>
    </div>
  </div>
  <script>
    let seconds = 5;
    const countdown = document.getElementById('countdown');
    const footer = document.getElementById('footer');
    const hint = document.getElementById('hint');
    const interval = setInterval(() => {{
      seconds--;
      countdown.textContent = seconds + 's';
      if (seconds <= 0) {{
        clearInterval(interval);
        window.close();
        setTimeout(() => {{
          footer.innerHTML = '<span class="footer-text" style="color: var(--accent);">You can close this tab now</span>';
        }}, 100);
      }}
    }}, 1000);
  </script>
</body>
</html>"#)
}
