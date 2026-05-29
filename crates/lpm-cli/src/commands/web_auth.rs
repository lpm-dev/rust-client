use crate::output;
use lpm_common::LpmError;
use lpm_common::color::Painted;
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WebAuthChallenge {
    pub auth_url: String,
    pub done_url: String,
}

impl WebAuthChallenge {
    fn new(auth_url: &str, done_url: &str) -> Result<Self, LpmError> {
        Ok(Self {
            auth_url: validate_http_url(auth_url, "authUrl")?,
            done_url: validate_http_url(done_url, "doneUrl")?,
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

pub fn parse_web_auth_challenge_from_body(body: &serde_json::Value) -> Option<WebAuthChallenge> {
    let auth_url = body.get("authUrl").and_then(|value| value.as_str())?;
    let done_url = body.get("doneUrl").and_then(|value| value.as_str())?;
    WebAuthChallenge::new(auth_url, done_url).ok()
}

pub fn parse_web_login_response(body: &serde_json::Value) -> Result<WebAuthChallenge, LpmError> {
    let login_url = body.get("loginUrl").and_then(|value| value.as_str());
    let done_url = body.get("doneUrl").and_then(|value| value.as_str());

    match (login_url, done_url) {
        (Some(login_url), Some(done_url)) => WebAuthChallenge::new(login_url, done_url),
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
        .post(login_url)
        .header("content-type", "application/json")
        .header("accept", "application/json")
        .header(NPM_AUTH_TYPE_HEADER, NPM_AUTH_TYPE_WEB)
        .json(&serde_json::json!({}))
        .send()
        .await
        .map_err(|e| LpmError::Registry(format!("npm web login request failed: {e}")))?;

    let status = response.status();
    let body_text = response.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(LpmError::Registry(format!(
            "npm web login failed (HTTP {status}): {}",
            summarize_body(&body_text)
        )));
    }

    let body: serde_json::Value = serde_json::from_str(&body_text)
        .map_err(|e| LpmError::Registry(format!("npm web login response parse error: {e}")))?;
    parse_web_login_response(&body)
}

pub async fn complete_web_auth_challenge(
    client: &reqwest::Client,
    challenge: &WebAuthChallenge,
    action: &str,
    json_output: bool,
    open_browser: bool,
    timeout: Duration,
    poll_interval: Duration,
) -> Result<String, LpmError> {
    if !json_output {
        output::info(&format!("Authenticate with npm to {action}:"));
        println!("  {}", challenge.auth_url.bold());
    }

    if open_browser
        && let Err(e) = open::that(&challenge.auth_url)
        && !json_output
    {
        output::warn(&format!(
            "Could not open browser automatically: {e}. Open the URL above manually."
        ));
    }

    if !json_output {
        output::info("Waiting for browser authentication...");
    }

    poll_for_web_auth_token(client, &challenge.done_url, timeout, poll_interval).await
}

pub async fn poll_for_web_auth_token(
    client: &reqwest::Client,
    done_url: &str,
    timeout: Duration,
    poll_interval: Duration,
) -> Result<String, LpmError> {
    let started_at = Instant::now();

    loop {
        if started_at.elapsed() >= timeout {
            return Err(LpmError::Registry(format!(
                "npm web authentication timed out after {} seconds",
                timeout.as_secs()
            )));
        }

        let response = client
            .get(done_url)
            .header("accept", "application/json")
            .send()
            .await;

        let sleep_for = match response {
            Ok(response) => {
                if response.status() == reqwest::StatusCode::ACCEPTED {
                    retry_after_or_default(response.headers(), poll_interval)
                } else if response.status().is_success() {
                    match response.json::<serde_json::Value>().await {
                        Ok(body) => {
                            if let Some(token) = body.get("token").and_then(|value| value.as_str())
                                && !token.is_empty()
                            {
                                return Ok(token.to_string());
                            }
                            poll_interval
                        }
                        Err(_) => poll_interval,
                    }
                } else {
                    poll_interval
                }
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

fn validate_http_url(raw: &str, field: &str) -> Result<String, LpmError> {
    let parsed = reqwest::Url::parse(raw)
        .map_err(|_| LpmError::Registry(format!("registry returned invalid {field}")))?;
    match parsed.scheme() {
        "http" | "https" => Ok(parsed.to_string()),
        _ => Err(LpmError::Registry(format!(
            "registry returned unsupported {field} scheme"
        ))),
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

        let err = parse_web_login_response(&body).unwrap_err();

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

        assert!(parse_web_auth_challenge_from_body(&body).is_none());
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

        let client = reqwest::Client::new();
        let token = poll_for_web_auth_token(
            &client,
            &format!("{}/done", server.uri()),
            Duration::from_secs(1),
            Duration::from_millis(1),
        )
        .await
        .expect("poll should return token");

        assert_eq!(token, "web-token-123");
    }

    #[tokio::test]
    async fn poll_for_web_auth_token_times_out_when_registry_keeps_waiting() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/done"))
            .respond_with(ResponseTemplate::new(202))
            .mount(&server)
            .await;

        let client = reqwest::Client::new();
        let err = poll_for_web_auth_token(
            &client,
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
}
