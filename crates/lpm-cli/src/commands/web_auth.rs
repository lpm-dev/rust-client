use crate::install_ui;
use lpm_common::LpmError;
use reqwest::header::HeaderMap;
#[cfg(test)]
use reqwest::header::HeaderValue;
use std::io::IsTerminal;
use std::time::{Duration, Instant};

pub const NPM_AUTH_TYPE_HEADER: &str = "npm-auth-type";
pub const NPM_COMMAND_HEADER: &str = "npm-command";
pub const NPM_AUTH_TYPE_WEB: &str = "web";
pub const NPM_COMMAND_PUBLISH: &str = "publish";

const LOGIN_ENDPOINT: &str = "-/v1/login";
const NPM_WEB_AUTH_RESPONSE_MAX_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WebAuthChallenge {
    pub auth_url: String,
    pub done_url: String,
}

impl WebAuthChallenge {
    fn new(auth_url: &str, done_url: &str, registry_url: &str) -> Result<Self, LpmError> {
        let auth_url = validate_web_auth_url(auth_url, "authUrl")?;
        let done_url = validate_web_auth_url(done_url, "doneUrl")?;
        let registry_url = reqwest::Url::parse(registry_url)
            .map_err(|_| LpmError::Registry("registry returned invalid doneUrl".into()))?;
        if !same_origin(&done_url, &registry_url) {
            return Err(LpmError::Registry(
                "registry returned doneUrl outside the registry origin".into(),
            ));
        }
        Ok(Self {
            auth_url: auth_url.to_string(),
            done_url: done_url.to_string(),
        })
    }
}

pub fn terminal_is_interactive() -> bool {
    std::io::stdin().is_terminal() && std::io::stdout().is_terminal()
}

#[cfg(test)]
pub fn npm_web_auth_headers(npm_command: &str) -> HeaderMap {
    let mut headers = HeaderMap::with_capacity(2);
    headers.insert(
        NPM_AUTH_TYPE_HEADER,
        HeaderValue::from_static(NPM_AUTH_TYPE_WEB),
    );
    if let Ok(command) = HeaderValue::from_str(npm_command) {
        headers.insert(NPM_COMMAND_HEADER, command);
    }
    headers
}

pub fn add_npm_web_auth_headers(
    request: reqwest::RequestBuilder,
    npm_command: &str,
) -> reqwest::RequestBuilder {
    request
        .header(NPM_AUTH_TYPE_HEADER, NPM_AUTH_TYPE_WEB)
        .header(NPM_COMMAND_HEADER, npm_command)
}

pub fn parse_web_auth_challenge_from_body(
    body: &serde_json::Value,
    registry_url: &str,
) -> Option<WebAuthChallenge> {
    let auth_url = body.get("authUrl").and_then(|value| value.as_str())?;
    let done_url = body.get("doneUrl").and_then(|value| value.as_str())?;
    WebAuthChallenge::new(auth_url, done_url, registry_url).ok()
}

pub fn parse_web_login_response(
    body: &serde_json::Value,
    registry_url: &str,
) -> Result<WebAuthChallenge, LpmError> {
    let login_url = body.get("loginUrl").and_then(|value| value.as_str());
    let done_url = body.get("doneUrl").and_then(|value| value.as_str());

    match (login_url, done_url) {
        (Some(login_url), Some(done_url)) => {
            WebAuthChallenge::new(login_url, done_url, registry_url)
        }
        _ => Err(LpmError::Registry(
            "registry returned an invalid npm web-login response".into(),
        )),
    }
}

pub async fn fetch_npm_web_login_challenge(
    client: &reqwest::Client,
    registry_url: &str,
) -> Result<WebAuthChallenge, LpmError> {
    let login_url = registry_endpoint(registry_url, LOGIN_ENDPOINT)?;
    let response = client
        .post(login_url.clone())
        .header("content-type", "application/json")
        .header("accept", "application/json")
        .header(NPM_AUTH_TYPE_HEADER, NPM_AUTH_TYPE_WEB)
        .json(&serde_json::json!({}))
        .send()
        .await
        .map_err(|e| {
            LpmError::Registry(format!(
                "npm web login request failed: {}",
                lpm_http::display_error(&e)
            ))
        })?;

    if !same_origin(response.url(), &login_url) {
        return Err(LpmError::Registry(
            "npm web login redirected outside the registry origin".into(),
        ));
    }

    let status = response.status();
    let body = lpm_http::read_body_capped(response, NPM_WEB_AUTH_RESPONSE_MAX_BYTES)
        .await
        .map_err(web_auth_response_error)?;
    if !status.is_success() {
        return Err(LpmError::Registry(format!(
            "npm web login failed (HTTP {status}): {}",
            summarize_body(&String::from_utf8_lossy(&body))
        )));
    }

    let body: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|e| LpmError::Registry(format!("npm web login response parse error: {e}")))?;
    parse_web_login_response(&body, registry_url)
}

pub async fn complete_web_auth_challenge(
    challenge: &WebAuthChallenge,
    action: &str,
    json_output: bool,
    open_browser: bool,
    timeout: Duration,
    poll_interval: Duration,
) -> Result<String, LpmError> {
    if !json_output {
        install_ui::phase_untrusted(&format!("Authenticate with npm to {action}"));
        println!(
            "{}",
            crate::install_ui::terminal_line!("  {}", install_ui::bold(&challenge.auth_url))
        );
    }

    if open_browser
        && let Err(e) = open::that(&challenge.auth_url)
        && !json_output
    {
        install_ui::warn_untrusted(&format!(
            "Could not open browser automatically: {e}. Open the URL above manually."
        ));
    }

    if !json_output {
        install_ui::phase("Waiting for browser authentication");
    }

    poll_for_web_auth_token(&challenge.done_url, timeout, poll_interval).await
}

pub async fn poll_for_web_auth_token(
    done_url: &str,
    timeout: Duration,
    poll_interval: Duration,
) -> Result<String, LpmError> {
    let expected_url = validate_web_auth_url(done_url, "doneUrl")?;
    let client = build_web_auth_client(timeout)?;
    let started_at = Instant::now();

    loop {
        if started_at.elapsed() >= timeout {
            return Err(LpmError::Registry(format!(
                "npm web authentication timed out after {} seconds",
                timeout.as_secs()
            )));
        }

        let remaining = timeout.saturating_sub(started_at.elapsed());
        let response = tokio::time::timeout(
            remaining,
            client
                .get(done_url)
                .header("accept", "application/json")
                .send(),
        )
        .await
        .map_err(|_| web_auth_timeout(timeout))?;

        let sleep_for = match response {
            Ok(response) => {
                if response.status().is_redirection() {
                    return Err(LpmError::Registry(
                        "npm web authentication refused a redirect from doneUrl".into(),
                    ));
                }
                if !same_origin(response.url(), &expected_url) {
                    return Err(LpmError::Registry(
                        "npm web authentication response came from outside the registry origin"
                            .into(),
                    ));
                }
                if response.status() == reqwest::StatusCode::ACCEPTED {
                    retry_after_or_default(response.headers(), poll_interval)
                } else if response.status().is_success() {
                    let remaining = timeout.saturating_sub(started_at.elapsed());
                    let body = tokio::time::timeout(
                        remaining,
                        lpm_http::read_body_capped(response, NPM_WEB_AUTH_RESPONSE_MAX_BYTES),
                    )
                    .await
                    .map_err(|_| web_auth_timeout(timeout))?
                    .map_err(web_auth_response_error)?;
                    let body: serde_json::Value =
                        serde_json::from_slice(&body).map_err(|error| {
                            LpmError::Registry(format!(
                                "npm web authentication response parse error: {error}"
                            ))
                        })?;
                    if let Some(token) = body.get("token").and_then(|value| value.as_str())
                        && !token.is_empty()
                    {
                        return Ok(token.to_string());
                    }
                    poll_interval
                } else {
                    poll_interval
                }
            }
            Err(error) if lpm_http::is_https_downgrade(&error) => {
                return Err(LpmError::Registry(format!(
                    "npm web authentication failed: {}",
                    lpm_http::display_error(&error)
                )));
            }
            Err(_) => poll_interval,
        };

        let remaining = timeout.saturating_sub(started_at.elapsed());
        if remaining.is_zero() {
            continue;
        }
        tokio::time::sleep(std::cmp::min(sleep_for, remaining)).await;
    }
}

fn build_web_auth_client(timeout: Duration) -> Result<reqwest::Client, LpmError> {
    lpm_http::client_builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(timeout)
        .user_agent(format!("lpm-rs/{}", crate::build_version::version()))
        .build()
        .map_err(|error| {
            LpmError::Registry(format!("failed to create npm web-auth client: {error}"))
        })
}

fn validate_web_auth_url(raw: &str, field: &str) -> Result<reqwest::Url, LpmError> {
    let parsed = reqwest::Url::parse(raw)
        .map_err(|_| LpmError::Registry(format!("registry returned invalid {field}")))?;
    if parsed.username() != "" || parsed.password().is_some() {
        return Err(LpmError::Registry(format!(
            "registry returned {field} with embedded credentials"
        )));
    }
    match parsed.scheme() {
        "https" => Ok(parsed),
        "http" if url_host_is_loopback(&parsed) => Ok(parsed),
        "http" => Err(LpmError::Registry(format!(
            "registry returned cleartext {field} for a non-loopback host"
        ))),
        _ => Err(LpmError::Registry(format!(
            "registry returned unsupported {field} scheme"
        ))),
    }
}

fn url_host_is_loopback(url: &reqwest::Url) -> bool {
    url.host_str().is_some_and(lpm_common::is_loopback_host)
}

fn same_origin(left: &reqwest::Url, right: &reqwest::Url) -> bool {
    left.scheme() == right.scheme()
        && left.host() == right.host()
        && left.port_or_known_default() == right.port_or_known_default()
}

fn web_auth_timeout(timeout: Duration) -> LpmError {
    LpmError::Registry(format!(
        "npm web authentication timed out after {} seconds",
        timeout.as_secs()
    ))
}

fn web_auth_response_error(error: lpm_http::ResponseBodyError) -> LpmError {
    match error {
        lpm_http::ResponseBodyError::DeclaredTooLarge { .. }
        | lpm_http::ResponseBodyError::StreamedTooLarge { .. } => LpmError::Registry(format!(
            "npm web authentication response is too large (maximum {NPM_WEB_AUTH_RESPONSE_MAX_BYTES} bytes)"
        )),
        lpm_http::ResponseBodyError::Read(error) => LpmError::Registry(format!(
            "npm web authentication response read failed: {}",
            lpm_http::display_error(&error)
        )),
    }
}

fn registry_endpoint(registry_url: &str, endpoint: &str) -> Result<reqwest::Url, LpmError> {
    let mut base = registry_url.trim().to_string();
    if !base.ends_with('/') {
        base.push('/');
    }
    reqwest::Url::parse(&base)
        .and_then(|url| url.join(endpoint))
        .map_err(|e| LpmError::Registry(format!("invalid registry URL {registry_url}: {e}")))
}

fn retry_after_or_default(headers: &HeaderMap, default: Duration) -> Duration {
    headers
        .get("retry-after")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .map_or(default, Duration::from_secs)
}

fn summarize_body(body: &str) -> String {
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return "empty response".into();
    }

    const MAX_LEN: usize = 240;
    if trimmed.chars().count() <= MAX_LEN {
        trimmed.to_string()
    } else {
        format!("{}...", trimmed.chars().take(MAX_LEN).collect::<String>())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn parse_web_login_response_requires_login_and_done_urls() {
        let body = serde_json::json!({ "loginUrl": "https://www.npmjs.com/login" });

        let err = parse_web_login_response(&body, "https://registry.npmjs.org").unwrap_err();

        assert!(
            err.to_string().contains("invalid npm web-login response"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn parse_web_auth_challenge_rejects_non_http_urls() {
        let body = serde_json::json!({
            "authUrl": "file:///tmp/auth",
            "doneUrl": "https://registry.npmjs.org/-/v1/done"
        });

        assert!(parse_web_auth_challenge_from_body(&body, "https://registry.npmjs.org").is_none());
    }

    #[test]
    fn parse_web_auth_challenge_rejects_cleartext_non_loopback_urls() {
        let body = serde_json::json!({
            "authUrl": "http://login.example.test/auth",
            "doneUrl": "https://registry.example.test/-/v1/done"
        });

        assert!(
            parse_web_auth_challenge_from_body(&body, "https://registry.example.test").is_none()
        );
    }

    #[test]
    fn parse_web_auth_challenge_accepts_exact_loopback_http_origins() {
        for registry in ["http://localhost:4873", "http://[::1]:4873"] {
            let body = serde_json::json!({
                "authUrl": format!("{registry}/auth"),
                "doneUrl": format!("{registry}/done"),
            });

            assert!(
                parse_web_auth_challenge_from_body(&body, registry).is_some(),
                "unexpected rejected loopback challenge for {registry}"
            );
        }
    }

    #[tokio::test]
    async fn fetch_npm_web_login_challenge_rejects_a_done_url_outside_the_registry_origin() {
        let registry = MockServer::start().await;
        let polling_target = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/-/v1/login"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "loginUrl": "https://login.example.test/auth",
                "doneUrl": format!("{}/metadata", polling_target.uri()),
            })))
            .mount(&registry)
            .await;

        let error = fetch_npm_web_login_challenge(&reqwest::Client::new(), &registry.uri())
            .await
            .expect_err("the polling endpoint must remain on the registry origin");

        assert!(error.to_string().contains("doneUrl"));
    }

    #[test]
    fn npm_web_auth_headers_advertise_web_publish() {
        let headers = npm_web_auth_headers(NPM_COMMAND_PUBLISH);

        assert_eq!(
            headers
                .get(NPM_AUTH_TYPE_HEADER)
                .and_then(|value| value.to_str().ok()),
            Some(NPM_AUTH_TYPE_WEB)
        );
        assert_eq!(
            headers
                .get(NPM_COMMAND_HEADER)
                .and_then(|value| value.to_str().ok()),
            Some(NPM_COMMAND_PUBLISH)
        );
    }

    #[tokio::test]
    async fn fetch_npm_web_login_challenge_posts_web_auth_header() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/-/v1/login"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "loginUrl": format!("{}/login", server.uri()),
                "doneUrl": format!("{}/done", server.uri()),
            })))
            .mount(&server)
            .await;

        let client = reqwest::Client::new();
        let challenge = fetch_npm_web_login_challenge(&client, &server.uri())
            .await
            .expect("web login challenge should parse");

        assert_eq!(challenge.done_url, format!("{}/done", server.uri()));
        let requests = server.received_requests().await.unwrap();
        let request = requests.first().expect("login request should be recorded");
        assert_eq!(
            request
                .headers
                .get(NPM_AUTH_TYPE_HEADER)
                .and_then(|value| value.to_str().ok()),
            Some(NPM_AUTH_TYPE_WEB)
        );
    }

    #[tokio::test]
    async fn poll_for_web_auth_token_returns_token_response() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/done"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "token": "web-token-123",
            })))
            .mount(&server)
            .await;

        let token = poll_for_web_auth_token(
            &format!("{}/done", server.uri()),
            Duration::from_secs(1),
            Duration::from_millis(1),
        )
        .await
        .expect("poll should return token");

        assert_eq!(token, "web-token-123");
    }

    #[tokio::test]
    async fn poll_for_web_auth_token_does_not_follow_cross_origin_redirects() {
        let registry = MockServer::start().await;
        let redirect_target = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/done"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("location", format!("{}/token", redirect_target.uri())),
            )
            .mount(&registry)
            .await;
        Mock::given(method("GET"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "token": "redirected-token",
            })))
            .mount(&redirect_target)
            .await;

        let error = poll_for_web_auth_token(
            &format!("{}/done", registry.uri()),
            Duration::from_secs(1),
            Duration::from_millis(1),
        )
        .await
        .expect_err("web authentication must reject a cross-origin redirect");

        assert!(
            error.to_string().contains("redirect"),
            "unexpected error: {error}"
        );
        assert!(
            redirect_target
                .received_requests()
                .await
                .expect("redirect target request log should be available")
                .is_empty(),
            "the web-auth client must not contact the redirect target"
        );
    }

    #[tokio::test]
    async fn poll_for_web_auth_token_times_out_when_registry_keeps_waiting() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/done"))
            .respond_with(ResponseTemplate::new(202))
            .mount(&server)
            .await;

        let err = poll_for_web_auth_token(
            &format!("{}/done", server.uri()),
            Duration::from_millis(10),
            Duration::from_millis(1),
        )
        .await
        .unwrap_err();

        assert!(
            err.to_string().contains("timed out"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn poll_for_web_auth_token_rejects_an_oversized_response() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/done"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "token": "web-token-123",
                "padding": "x".repeat(128 * 1024),
            })))
            .mount(&server)
            .await;

        let error = poll_for_web_auth_token(
            &format!("{}/done", server.uri()),
            Duration::from_secs(1),
            Duration::from_millis(1),
        )
        .await
        .expect_err("an oversized web-auth response must be rejected");

        assert!(error.to_string().contains("too large"));
    }

    #[tokio::test]
    async fn poll_for_web_auth_token_enforces_the_deadline_during_a_request() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/done"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(Duration::from_millis(250))
                    .set_body_json(serde_json::json!({"token": "late-token"})),
            )
            .mount(&server)
            .await;

        let started = Instant::now();
        let error = poll_for_web_auth_token(
            &format!("{}/done", server.uri()),
            Duration::from_millis(25),
            Duration::from_millis(1),
        )
        .await
        .expect_err("a stalled request must not outlive the overall deadline");

        assert!(error.to_string().contains("timed out"));
        assert!(started.elapsed() < Duration::from_millis(200));
    }
}
