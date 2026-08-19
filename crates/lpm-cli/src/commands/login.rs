use crate::{auth, install_ui};
use lpm_auth::AuthRequirement;
use lpm_common::LpmError;
use lpm_registry::RegistryClient;
use std::sync::Arc;

const MAX_CLI_EXCHANGE_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_CONCURRENT_CALLBACKS: usize = 16;

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct CliExchangeSession {
    token: String,
    refresh_token: String,
    expires_in: u64,
    expires_at: String,
}

fn parse_cli_exchange_session(body: &[u8]) -> Result<CliExchangeSession, LpmError> {
    let session: CliExchangeSession = serde_json::from_slice(body)
        .map_err(|error| LpmError::Registry(format!("exchange response parse error: {error}")))?;
    if session.expires_in == 0
        || lpm_auth::validate_refresh_backed_session(
            &session.token,
            &session.refresh_token,
            &session.expires_at,
        )
        .is_err()
    {
        return Err(LpmError::Registry(
            "exchange response did not contain a complete refresh session".to_string(),
        ));
    }
    Ok(session)
}

async fn read_capped_exchange_body(mut response: reqwest::Response) -> Result<Vec<u8>, LpmError> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_CLI_EXCHANGE_RESPONSE_BYTES as u64)
    {
        return Err(LpmError::Registry(
            "exchange response exceeded the 64 KiB limit".to_string(),
        ));
    }

    let mut body = Vec::with_capacity(
        response
            .content_length()
            .unwrap_or(1024)
            .min(MAX_CLI_EXCHANGE_RESPONSE_BYTES as u64) as usize,
    );
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| LpmError::Registry(format!("exchange response read error: {error}")))?
    {
        if body.len().saturating_add(chunk.len()) > MAX_CLI_EXCHANGE_RESPONSE_BYTES {
            return Err(LpmError::Registry(
                "exchange response exceeded the 64 KiB limit".to_string(),
            ));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Login flow:
/// 1. Start a local HTTP server on a random port
/// 2. Open browser to `{registry}/cli/login?port={port}`
/// 3. User authenticates in browser
/// 4. Browser posts a short-lived exchange code to the loopback callback
/// 5. Redeem the PKCE-bound code, verify the token, and store the session
pub async fn run(
    client: &RegistryClient,
    registry_url: &str,
    json_output: bool,
) -> Result<(), LpmError> {
    let existing_session_client = match client.session() {
        Some(session) => {
            let stored_session = Arc::new(session.stored_session_only());
            match stored_session
                .bearer_string_for(AuthRequirement::SessionRequired)
                .await
            {
                Ok(_) => Some(client.clone_with_session_only(stored_session)),
                Err(LpmError::AuthRequired | LpmError::SessionExpired) => None,
                Err(error) => return Err(error),
            }
        }
        None => None,
    };
    if let Some(existing_session_client) = existing_session_client {
        match existing_session_client.whoami().await {
            Ok(info) => {
                let name = info
                    .profile_username
                    .as_deref()
                    .or(info.username.as_deref())
                    .unwrap_or("unknown");
                if !json_output {
                    install_ui::done_line(crate::install_ui::terminal_line!(
                        "Already logged in as {}. Use {} to log out first.",
                        install_ui::cyan(name),
                        install_ui::dim("lpm logout")
                    ));
                }
                return Ok(());
            }
            Err(LpmError::AuthRequired | LpmError::SessionExpired) => {}
            Err(error) => return Err(error),
        }
    }

    if !json_output {
        install_ui::phase("Opening browser for authentication");
    }

    // Start local HTTP server on random port
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(LpmError::Io)?;
    let port = listener.local_addr().map_err(LpmError::Io)?.port();

    // Generate CSRF state parameter
    let state: String = {
        use rand::RngCore;
        let mut bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut bytes);
        hex::encode(bytes)
    };

    // Bind the exchange code to this CLI invocation. The browser URL carries
    // only the challenge; the verifier is sent later, when the CLI redeems the
    // callback code.
    let (code_verifier, code_challenge) = generate_pkce_pair();

    // Per-install random fingerprint stored at ~/.lpm/device-id; see
    // `lpm_auth::compute_device_fingerprint` for the L13 rationale.
    let device_fingerprint = lpm_auth::compute_device_fingerprint();
    let device_name = std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "CLI".to_string());

    // Open browser
    let login_url = build_login_url(
        registry_url,
        port,
        &state,
        &device_fingerprint,
        &code_challenge,
        &device_name,
    );
    if open::that(&login_url).is_err() && !json_output {
        install_ui::warn("Could not open browser automatically");
        install_ui::detail_line(login_detail_row("url:", &install_ui::url(&login_url)));
    }

    if !json_output {
        install_ui::detail_line(login_detail_row("browser:", &install_ui::url(&login_url)));
    }

    let mut server_handle = tokio::spawn(wait_for_valid_callback(listener, state));
    let code =
        match tokio::time::timeout(std::time::Duration::from_secs(120), &mut server_handle).await {
            Ok(Ok(result)) => result?,
            Ok(Err(error)) => {
                return Err(LpmError::Registry(format!(
                    "login callback task failed: {error}"
                )));
            }
            Err(_) => {
                server_handle.abort();
                return Err(LpmError::Registry(
                    "login timed out after 2 minutes".to_string(),
                ));
            }
        };

    if !json_output {
        install_ui::phase("Exchanging authorization code");
    }
    let exchange_url = format!("{registry_url}/api/cli/exchange");
    let http_client = lpm_http::client_builder()
        .build()
        .map_err(|error| LpmError::Registry(format!("exchange client build failed: {error}")))?;
    let resp = http_client
        .post(&exchange_url)
        .json(&serde_json::json!({ "code": code, "code_verifier": code_verifier }))
        .send()
        .await
        .map_err(|error| {
            LpmError::Registry(format!(
                "exchange request failed: {}",
                lpm_http::display_error(&error)
            ))
        })?;

    let status = resp.status();
    let body = read_capped_exchange_body(resp).await?;
    if !status.is_success() {
        let detail = if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&body) {
            json["error"]
                .as_str()
                .unwrap_or("unknown error")
                .to_string()
        } else {
            format!("HTTP {status}")
        };
        return Err(LpmError::Registry(format!(
            "Failed to exchange authorization code: {detail}. It may have expired — please try again."
        )));
    }

    let session = parse_cli_exchange_session(&body)?;
    let token = session.token;
    let expires_at = session.expires_at;
    let refresh_token = session.refresh_token;

    // Verify the token via whoami
    let client = RegistryClient::new()
        .with_base_url(registry_url.to_string())
        .with_token(&token);

    let info = client
        .whoami()
        .await
        .map_err(|e| LpmError::Registry(format!("token verification failed: {e}")))?;

    let username = info
        .profile_username
        .as_deref()
        .or(info.username.as_deref())
        .unwrap_or("unknown")
        .to_string();

    let storage_status =
        auth::store_refresh_backed_session(registry_url, &token, &refresh_token, &expires_at)
            .await?;

    if json_output {
        let json = serde_json::json!({
            "success": true,
            "username": username,
            "registry": registry_url,
            "storage_backend": storage_status.backend_json_value(),
            "storage_degraded": storage_status.degraded,
        });
        println!("{}", serde_json::to_string_pretty(&json).unwrap());
    } else {
        let email_str = info.username.as_deref().unwrap_or("");
        emit_browser_login_success(&username, email_str, registry_url, storage_status);
    }

    Ok(())
}

fn emit_browser_login_success(
    username: &str,
    email: &str,
    registry_url: &str,
    storage_status: auth::AuthStorageStatus,
) {
    install_ui::done("Browser authentication complete");
    install_ui::detail_line(login_detail_row(
        "user:",
        &login_user_value(username, email),
    ));
    install_ui::detail_line(login_detail_row(
        "registry:",
        &install_ui::yellow(&install_ui::short_registry_host(registry_url)),
    ));
    if let Some(label) = storage_status.human_label() {
        install_ui::detail_line(login_detail_row(
            "secure storage backend:",
            &install_ui::field(label),
        ));
    }
    if storage_status.degraded {
        install_ui::warn(
            "Encrypted file fallback is active; unlock or repair the OS keychain and run `lpm login` again to use keychain storage.",
        );
    }
}

fn login_user_value(username: &str, email: &str) -> install_ui::TerminalLine {
    if email.is_empty() || email == username {
        return install_ui::terminal_line!("{}", install_ui::cyan(username));
    }
    install_ui::terminal_line!("{} {}", install_ui::cyan(username), install_ui::dim(email),)
}

fn login_detail_row<T: install_ui::TerminalValue + ?Sized>(
    label: &'static str,
    value: &T,
) -> install_ui::TerminalLine {
    install_ui::terminal_line!("    {:<9} {}", install_ui::dim(label), value)
}

fn build_login_url(
    registry_url: &str,
    port: u16,
    state: &str,
    device_fingerprint: &str,
    code_challenge: &str,
    device_name: &str,
) -> String {
    let registry_url = registry_url.trim_end_matches('/');
    format!(
        "{registry_url}/cli/login?port={port}&state={state}&fp={device_fingerprint}&code_challenge={code_challenge}&code_challenge_method=S256&dn={}",
        urlencoding::encode(device_name)
    )
}

fn is_valid_exchange_code(code: &str) -> bool {
    code.len() == 64
        && code
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

async fn wait_for_valid_callback(
    listener: tokio::net::TcpListener,
    expected_state: String,
) -> Result<String, LpmError> {
    let mut handlers = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept(), if handlers.len() < MAX_CONCURRENT_CALLBACKS => {
                let (stream, _) = accepted.map_err(LpmError::Io)?;
                let expected_state = expected_state.clone();
                handlers.spawn(async move { handle_callback(stream, &expected_state).await });
            }
            completed = handlers.join_next(), if !handlers.is_empty() => {
                if let Some(Ok(Some(code))) = completed {
                    return Ok(code);
                }
            }
        }
    }
}

/// Handle the OAuth callback HTTP request.
///
/// Expects: POST /callback with form body code=xxx&state=yyy
///   or:    GET  /callback?code=xxx&state=yyy
/// Responds with a simple HTML page that auto-closes.
async fn handle_callback(stream: tokio::net::TcpStream, expected_state: &str) -> Option<String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = stream;
    let mut buf = vec![0u8; 8192];

    let mut total = match tokio::time::timeout(
        std::time::Duration::from_secs(2),
        stream.read(&mut buf),
    )
    .await
    {
        Ok(Ok(n)) if n > 0 => n,
        _ => return None,
    };

    // For POST requests the body may arrive in a separate TCP segment.
    // Check if we have the full body by parsing Content-Length from headers.
    let request_so_far = String::from_utf8_lossy(&buf[..total]);
    if let Some(header_end) = request_so_far.find("\r\n\r\n") {
        let headers = &request_so_far[..header_end];
        // Extract Content-Length (case-insensitive)
        let content_length: usize = headers
            .lines()
            .find_map(|line| {
                let lower = line.to_ascii_lowercase();
                lower
                    .strip_prefix("content-length:")
                    .and_then(|v| v.trim().parse().ok())
            })
            .unwrap_or(0);

        let body_start = header_end + 4; // skip \r\n\r\n

        // Keep reading until we have the full body (with a short timeout)
        while total.saturating_sub(body_start) < content_length && total < buf.len() {
            match tokio::time::timeout(
                std::time::Duration::from_secs(2),
                stream.read(&mut buf[total..]),
            )
            .await
            {
                Ok(Ok(n)) if n > 0 => total += n,
                _ => break,
            }
        }
    }

    let request = String::from_utf8_lossy(&buf[..total]);

    // Parse request line
    let first_line = request.lines().next().unwrap_or("");
    let method = first_line.split_whitespace().next().unwrap_or("");
    let path = first_line.split_whitespace().nth(1).unwrap_or("/");

    // Parse key-value pairs from a query/form string
    fn parse_params(data: &str) -> (Option<String>, Option<String>) {
        let mut code = None;
        let mut state = None;
        for param in data.split('&') {
            let mut parts = param.splitn(2, '=');
            let key = parts.next().unwrap_or("");
            let value = parts.next().unwrap_or("");
            // URL-decode '+' → ' ' and %XX sequences for form-encoded bodies
            let decoded = urlencoding::decode(value).unwrap_or(std::borrow::Cow::Borrowed(value));
            match key {
                "code" => code = Some(decoded.into_owned()),
                "state" => state = Some(decoded.into_owned()),
                _ => {}
            }
        }
        (code, state)
    }

    let callback_path = path.split('?').next().unwrap_or("");
    let (code, received_state) = match (method, callback_path) {
        ("POST", "/callback") => {
            let body = request.split("\r\n\r\n").nth(1).unwrap_or("").trim();
            parse_params(body)
        }
        ("GET", "/callback") => {
            let query = path.split_once('?').map_or("", |(_, query)| query);
            parse_params(query)
        }
        _ => (None, None),
    };

    // Verify CSRF state parameter
    let state_ok = received_state.as_deref() == Some(expected_state);
    if !state_ok {
        tracing::warn!("login callback state mismatch — possible CSRF attack");
    }

    let credential = state_ok
        .then_some(code)
        .flatten()
        .filter(|code| is_valid_exchange_code(code));

    let (status, body) = if credential.is_some() {
        ("200 OK", render_login_page(true, None))
    } else {
        ("400 Bad Request", render_login_page(false, None))
    };

    let response = format_callback_response(status, &body);

    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.flush().await;

    credential
}

/// Render the HTTP response served back to the OAuth callback. The
/// callback is reached by direct browser navigation, not by a
/// cross-origin `fetch` from another tab, so it sends no
/// `Access-Control-Allow-Origin` header — that wildcard previously
/// let any web page the user had open probe the ephemeral callback
/// port and read the success/failure HTML body. The state check
/// still defeats forged callbacks; this removes the probe surface.
fn format_callback_response(status: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
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
            "No authorization code received. Please try again.",
            "#ef4444",
            r#"<path class="checkmark-path" d="M6 6l12 12M6 18L18 6"/>"#,
            r#"Return to your terminal and run <code>lpm login</code> again"#,
        )
    };

    format!(
        r#"<!DOCTYPE html>
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
</html>"#
    )
}

/// Derive the PKCE S256 `code_challenge` from a `code_verifier`:
/// `base64url-no-pad(sha256(verifier-bytes))`. Must match the server's
/// `createHash("sha256").update(verifier).digest("base64url")` exactly, or the
/// exchange-code redemption will reject the verifier.
fn pkce_challenge(verifier: &str) -> String {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use sha2::{Digest, Sha256};
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// Generate a fresh PKCE (`code_verifier`, `code_challenge`) pair. The verifier
/// is 32 CSPRNG bytes encoded as base64url-no-pad (43 chars, within the PKCE
/// 43–128-char range). Both values are URL-safe, so they pass through the login
/// URL query string and the exchange JSON body untouched.
fn generate_pkce_pair() -> (String, String) {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let verifier = URL_SAFE_NO_PAD.encode(bytes);
    let challenge = pkce_challenge(&verifier);
    (verifier, challenge)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_exchange_session() -> serde_json::Value {
        serde_json::json!({
            "token": "lpm_access_token",
            "refreshToken": "lpmrt_refresh_token",
            "expiresIn": 3600,
            "expiresAt": "2099-01-01T00:00:00Z",
        })
    }

    async fn send_callback_request(request: &str) -> (String, Option<String>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind callback test listener");
        let address = listener.local_addr().expect("read callback test address");
        let expected_state = "expected-state".to_string();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept test callback");
            handle_callback(stream, &expected_state).await
        });

        let mut client = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect callback test client");
        client
            .write_all(request.as_bytes())
            .await
            .expect("write callback test request");
        client
            .shutdown()
            .await
            .expect("finish callback test request");

        let mut response = String::new();
        client
            .read_to_string(&mut response)
            .await
            .expect("read callback test response");
        let credential = server.await.expect("join callback test server");
        (response, credential)
    }

    async fn send_request(address: std::net::SocketAddr, request: &str) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let mut client = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect callback test client");
        client
            .write_all(request.as_bytes())
            .await
            .expect("write callback test request");
        client
            .shutdown()
            .await
            .expect("finish callback test request");
        let mut response = String::new();
        client
            .read_to_string(&mut response)
            .await
            .expect("read callback test response");
        response
    }

    #[test]
    fn callback_response_has_no_cors_wildcard_header() {
        let resp = format_callback_response("200 OK", "<html>ok</html>");
        let lower = resp.to_ascii_lowercase();
        assert!(
            !lower.contains("access-control-allow-origin"),
            "callback must not emit any CORS header; got:\n{resp}"
        );
        assert!(
            resp.starts_with("HTTP/1.1 200 OK\r\n"),
            "status line preserved",
        );
        assert!(
            resp.contains("Content-Length: 15\r\n"),
            "Content-Length matches body length",
        );
    }

    #[test]
    fn exchange_response_requires_a_complete_refresh_session() {
        for field in ["token", "refreshToken", "expiresIn", "expiresAt"] {
            let mut response = valid_exchange_session();
            response
                .as_object_mut()
                .expect("session object")
                .remove(field);
            let body = serde_json::to_vec(&response).expect("serialize session response");

            assert!(
                parse_cli_exchange_session(&body).is_err(),
                "missing {field}"
            );
        }
    }

    #[test]
    fn exchange_response_rejects_invalid_refresh_session_values() {
        for (field, value) in [
            ("token", serde_json::json!("")),
            ("refreshToken", serde_json::json!("")),
            ("expiresIn", serde_json::json!(0)),
            ("expiresAt", serde_json::json!("not-a-timestamp")),
        ] {
            let mut response = valid_exchange_session();
            response[field] = value;
            let body = serde_json::to_vec(&response).expect("serialize session response");

            assert!(
                parse_cli_exchange_session(&body).is_err(),
                "invalid {field}"
            );
        }
    }

    #[test]
    fn exchange_response_rejects_an_already_expired_session() {
        let mut response = valid_exchange_session();
        response["expiresAt"] = serde_json::json!("2000-01-01T00:00:00Z");
        let body = serde_json::to_vec(&response).expect("serialize expired session response");

        assert!(
            parse_cli_exchange_session(&body).is_err(),
            "an already-expired exchange response must not become the active session"
        );
    }

    #[test]
    fn exchange_response_accepts_a_complete_refresh_session() {
        let body =
            serde_json::to_vec(&valid_exchange_session()).expect("serialize session response");
        let session = parse_cli_exchange_session(&body).expect("parse complete session");

        assert_eq!(session.token, "lpm_access_token");
        assert_eq!(session.refresh_token, "lpmrt_refresh_token");
        assert_eq!(session.expires_in, 3600);
        assert_eq!(session.expires_at, "2099-01-01T00:00:00Z");
    }

    #[test]
    fn callback_response_carries_failure_status_for_400() {
        let resp = format_callback_response("400 Bad Request", "");
        assert!(resp.starts_with("HTTP/1.1 400 Bad Request\r\n"));
        assert!(resp.contains("Content-Length: 0\r\n"));
    }

    #[tokio::test]
    async fn callback_rejects_legacy_raw_tokens() {
        let (response, credential) = send_callback_request(
            "GET /callback?token=lpm_attacker_token&state=expected-state HTTP/1.1\r\nHost: localhost\r\n\r\n",
        )
        .await;

        assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
        assert!(credential.is_none());
    }

    #[tokio::test]
    async fn callback_rejects_a_malformed_exchange_code() {
        let (response, credential) = send_callback_request(
            "GET /callback?code=not-hex&state=expected-state HTTP/1.1\r\nHost: localhost\r\n\r\n",
        )
        .await;

        assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
        assert!(credential.is_none());
    }

    #[tokio::test]
    async fn callback_listener_continues_after_wrong_state() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind callback listener");
        let address = listener.local_addr().expect("read callback address");
        let server = tokio::spawn(wait_for_valid_callback(
            listener,
            "expected-state".to_string(),
        ));

        let rejected = send_request(
            address,
            "GET /callback?code=attacker-code&state=wrong-state HTTP/1.1\r\nHost: localhost\r\n\r\n",
        )
        .await;
        assert!(rejected.starts_with("HTTP/1.1 400 Bad Request\r\n"));

        let accepted = send_request(
            address,
            &format!(
                "GET /callback?code={}&state=expected-state HTTP/1.1\r\nHost: localhost\r\n\r\n",
                "a".repeat(64)
            ),
        )
        .await;
        assert!(accepted.starts_with("HTTP/1.1 200 OK\r\n"));
        assert_eq!(
            server
                .await
                .expect("join callback listener")
                .expect("receive valid callback"),
            "a".repeat(64)
        );
    }

    #[tokio::test]
    async fn callback_listener_continues_after_an_idle_connection() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind callback listener");
        let address = listener.local_addr().expect("read callback address");
        let server = tokio::spawn(wait_for_valid_callback(
            listener,
            "expected-state".to_string(),
        ));

        let _idle = tokio::net::TcpStream::connect(address)
            .await
            .expect("open idle callback connection");
        let accepted = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            send_request(
                address,
                &format!(
                    "GET /callback?code={}&state=expected-state HTTP/1.1\r\nHost: localhost\r\n\r\n",
                    "a".repeat(64)
                ),
            ),
		)
		.await
		.expect("idle callback connection must not block a valid callback");

        assert!(accepted.starts_with("HTTP/1.1 200 OK\r\n"));
        assert_eq!(
            server
                .await
                .expect("join callback listener")
                .expect("receive valid callback"),
            "a".repeat(64)
        );
    }

    #[test]
    fn login_url_declares_s256_pkce() {
        let url = build_login_url(
            "https://lpm.dev",
            49152,
            "state",
            "fingerprint",
            "challenge",
            "Developer Mac",
        );

        assert!(url.contains("code_challenge_method=S256"));
        assert!(url.contains("dn=Developer%20Mac"));
    }

    #[test]
    fn pkce_challenge_matches_known_s256_vector() {
        // base64url-no-pad(sha256("test")).
        assert_eq!(
            pkce_challenge("test"),
            "n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg"
        );
    }

    #[test]
    fn generate_pkce_pair_is_s256_consistent_and_url_safe() {
        let (verifier, challenge) = generate_pkce_pair();
        // The challenge we send is the S256 hash of the verifier we keep.
        assert_eq!(challenge, pkce_challenge(&verifier));
        // Both are URL-safe (no +, /, =), so query-param / JSON transport is lossless.
        for s in [&verifier, &challenge] {
            assert!(!s.is_empty());
            assert!(!s.contains('+') && !s.contains('/') && !s.contains('='));
        }
        // Fresh CSPRNG verifier each call.
        let (verifier2, _) = generate_pkce_pair();
        assert_ne!(verifier, verifier2);
    }

    #[test]
    fn login_user_value_keeps_display_name_and_email_when_they_differ() {
        let value = login_user_value("alice", "alice@example.com");
        assert!(value.contains("alice"));
        assert!(value.contains("alice@example.com"));
    }

    #[test]
    fn login_detail_row_keeps_aligned_label_and_value() {
        let row = login_detail_row("registry:", &install_ui::field("lpm.dev"));
        assert!(row.contains("registry:"));
        assert!(row.ends_with("lpm.dev"));
    }
}
