use crate::commands::publish_npm::NPM_REGISTRY_URL;
use crate::{auth, oidc};
use futures::StreamExt;
use lpm_common::LpmError;
use reqwest::StatusCode;
use serde::Deserialize;
use std::time::Duration;

const NPM_OIDC_EXCHANGE_RESPONSE_CAP_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum NpmAuthSource {
    Token,
    Oidc,
}

impl NpmAuthSource {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Token => "token",
            Self::Oidc => "oidc",
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct NpmAuth {
    token: String,
    source: NpmAuthSource,
}

impl NpmAuth {
    pub(crate) fn token(&self) -> &str {
        &self.token
    }

    pub(crate) fn source(&self) -> NpmAuthSource {
        self.source
    }
}

pub(crate) async fn resolve_publish_auth(
    npm_name: &str,
    registry_url: &str,
) -> Result<NpmAuth, LpmError> {
    if oidc::npm_trusted_publish_jwt_available() {
        if registry_supports_npm_trusted_publishing(registry_url) {
            let oidc_error = match exchange_trusted_publish_token(npm_name, registry_url).await {
                Ok(token) => {
                    return Ok(NpmAuth {
                        token,
                        source: NpmAuthSource::Oidc,
                    });
                }
                Err(err) => err,
            };

            if let Some(token) = auth::get_npm_token() {
                tracing::warn!(
                    error = %oidc_error,
                    "npm Trusted Publishing exchange failed; falling back to npm token auth",
                );
                return Ok(NpmAuth {
                    token,
                    source: NpmAuthSource::Token,
                });
            }

            return Err(oidc_error);
        }

        tracing::warn!(
            registry_url = %registry_url,
            default_url = NPM_REGISTRY_URL,
            "npm Trusted Publishing is only attempted for registry.npmjs.org; using npm token auth",
        );
    }

    resolve_token_auth()
}

pub(crate) fn resolve_token_auth() -> Result<NpmAuth, LpmError> {
    auth::get_npm_token()
        .map(|token| NpmAuth {
            token,
            source: NpmAuthSource::Token,
        })
        .ok_or_else(missing_npm_token_error)
}

pub(crate) fn missing_npm_token_error() -> LpmError {
    LpmError::Registry(
        "no npm token found. Run `lpm login --npm` for browser login, pass `lpm login --npm --token <token>`, or set NPM_TOKEN.".into(),
    )
}

async fn exchange_trusted_publish_token(
    npm_name: &str,
    registry_url: &str,
) -> Result<String, LpmError> {
    let jwt = oidc::resolve_npm_trusted_publish_jwt().await?;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .user_agent(format!("lpm-rs/{}", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| LpmError::Registry(format!("npm OIDC client build failed: {e}")))?;
    let url = npm_oidc_exchange_url(registry_url, npm_name);

    let response = client
        .post(url)
        .bearer_auth(&jwt.token)
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await
        .map_err(|e| LpmError::Registry(format!("npm OIDC token exchange failed: {e}")))?;

    let status = response.status();
    let body = read_response_body_capped(response, "npm OIDC token exchange").await?;
    if !status.is_success() {
        return Err(LpmError::Registry(npm_oidc_error_message(status, &body)));
    }

    let payload: NpmOidcExchangeResponse = serde_json::from_slice(&body)
        .map_err(|e| LpmError::Registry(format!("npm OIDC response parse error: {e}")))?;
    if payload.token.trim().is_empty() {
        return Err(LpmError::Registry(
            "npm OIDC token exchange response missing token".into(),
        ));
    }

    tracing::debug!(
        source = ?jwt.source,
        package = %npm_name,
        "npm Trusted Publishing token exchange succeeded",
    );
    Ok(payload.token)
}

#[derive(Debug, Deserialize)]
struct NpmOidcExchangeResponse {
    token: String,
}

fn npm_oidc_exchange_url(registry_url: &str, npm_name: &str) -> String {
    format!(
        "{}/-/npm/v1/oidc/token/exchange/package/{}",
        registry_url.trim_end_matches('/'),
        urlencoding::encode(npm_name),
    )
}

fn registry_supports_npm_trusted_publishing(registry_url: &str) -> bool {
    let trimmed = registry_url.trim_end_matches('/');
    if trimmed.eq_ignore_ascii_case(NPM_REGISTRY_URL) {
        return true;
    }

    reqwest::Url::parse(trimmed)
        .ok()
        .and_then(|url| url.host_str().map(lpm_common::is_loopback_host))
        .unwrap_or(false)
}

async fn read_response_body_capped(
    response: reqwest::Response,
    label: &str,
) -> Result<Vec<u8>, LpmError> {
    if let Some(declared) = response.content_length()
        && declared > NPM_OIDC_EXCHANGE_RESPONSE_CAP_BYTES
    {
        return Err(LpmError::Registry(format!(
            "{label} response exceeds {} B cap (declared {declared} B)",
            NPM_OIDC_EXCHANGE_RESPONSE_CAP_BYTES
        )));
    }

    let mut bytes = Vec::with_capacity(8 * 1024);
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk =
            chunk.map_err(|e| LpmError::Registry(format!("{label} body read failed: {e}")))?;
        if bytes.len() as u64 + chunk.len() as u64 > NPM_OIDC_EXCHANGE_RESPONSE_CAP_BYTES {
            return Err(LpmError::Registry(format!(
                "{label} response exceeds {} B cap mid-stream",
                NPM_OIDC_EXCHANGE_RESPONSE_CAP_BYTES
            )));
        }
        bytes.extend_from_slice(&chunk);
    }

    Ok(bytes)
}

fn npm_oidc_error_message(status: StatusCode, body: &[u8]) -> String {
    let registry_message = serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|value| {
            value
                .get("message")
                .or_else(|| value.get("error"))
                .and_then(|field| field.as_str())
                .map(str::to_string)
        })
        .or_else(|| {
            std::str::from_utf8(body)
                .ok()
                .map(str::trim)
                .filter(|text| !text.is_empty())
                .map(str::to_string)
        })
        .unwrap_or_else(|| "unknown error".to_string());

    format!("npm OIDC token exchange failed ({status}): {registry_message}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_env::ScopedEnv;
    use std::ffi::OsString;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const NPM_ID_TOKEN: &str = "ci-oidc-id-token";

    fn scoped(set: &[(&'static str, &str)]) -> ScopedEnv {
        let keys = [
            "NPM_ID_TOKEN",
            "NPM_TOKEN",
            "ACTIONS_ID_TOKEN_REQUEST_URL",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
            "LPM_OIDC_TOKEN",
            "LPM_GITLAB_OIDC_TOKEN",
            "SIGSTORE_ID_TOKEN",
        ];
        let pairs: Vec<(&'static str, Option<OsString>)> = keys
            .into_iter()
            .map(|key| (key, None))
            .chain(
                set.iter()
                    .map(|(key, value)| (*key, Some(OsString::from(*value)))),
            )
            .collect();
        ScopedEnv::update(pairs)
    }

    #[test]
    fn npm_oidc_exchange_url_encodes_scoped_package_name() {
        assert_eq!(
            npm_oidc_exchange_url("https://registry.npmjs.org/", "@scope/pkg"),
            "https://registry.npmjs.org/-/npm/v1/oidc/token/exchange/package/%40scope%2Fpkg"
        );
    }

    #[test]
    fn trusted_publishing_registry_gate_accepts_npm_and_loopback_only() {
        assert!(registry_supports_npm_trusted_publishing(
            "https://registry.npmjs.org/"
        ));
        assert!(registry_supports_npm_trusted_publishing(
            "http://127.0.0.1:4873"
        ));
        assert!(registry_supports_npm_trusted_publishing(
            "http://localhost:4873"
        ));
        assert!(!registry_supports_npm_trusted_publishing(
            "https://npm.pkg.github.com"
        ));
        assert!(!registry_supports_npm_trusted_publishing(
            "https://registry.example.test"
        ));
    }

    #[tokio::test]
    async fn resolve_publish_auth_uses_exchanged_oidc_token() {
        let _env = scoped(&[("NPM_ID_TOKEN", NPM_ID_TOKEN)]);
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/-/npm/v1/oidc/token/exchange/package/%40scope%2Fpkg"))
            .and(header("authorization", format!("Bearer {NPM_ID_TOKEN}")))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "token_type": "oidc",
                "token": "short-lived-npm-token",
            })))
            .mount(&server)
            .await;

        let auth = resolve_publish_auth("@scope/pkg", &server.uri())
            .await
            .expect("OIDC exchange should resolve npm auth");

        assert_eq!(auth.token(), "short-lived-npm-token");
        assert_eq!(auth.source(), NpmAuthSource::Oidc);
    }

    #[tokio::test]
    async fn resolve_publish_auth_falls_back_to_npm_token_when_exchange_fails() {
        let _env = scoped(&[
            ("NPM_ID_TOKEN", NPM_ID_TOKEN),
            ("NPM_TOKEN", "fallback-npm-token"),
        ]);
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/-/npm/v1/oidc/token/exchange/package/%40scope%2Fpkg"))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "message": "package not configured for trusted publishing",
            })))
            .mount(&server)
            .await;

        let auth = resolve_publish_auth("@scope/pkg", &server.uri())
            .await
            .expect("npm token fallback should resolve auth");

        assert_eq!(auth.token(), "fallback-npm-token");
        assert_eq!(auth.source(), NpmAuthSource::Token);
    }

    #[tokio::test]
    async fn resolve_publish_auth_skips_oidc_for_custom_registry() {
        let _env = scoped(&[
            ("NPM_ID_TOKEN", NPM_ID_TOKEN),
            ("NPM_TOKEN", "custom-registry-token"),
        ]);

        let auth = resolve_publish_auth("@scope/pkg", "https://registry.example.test")
            .await
            .expect("custom npm-compatible registry should use token auth");

        assert_eq!(auth.token(), "custom-registry-token");
        assert_eq!(auth.source(), NpmAuthSource::Token);
    }
}
