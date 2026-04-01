//! OIDC token exchange for CI/CD environments.
//!
//! Supports:
//! - GitHub Actions: Requests JWT via `ACTIONS_ID_TOKEN_REQUEST_URL`
//! - GitLab CI: Reads JWT from `LPM_GITLAB_OIDC_TOKEN` env var
//!
//! The JWT is exchanged with the LPM registry for a short-lived LPM token
//! that can be used for publishing or installing.

use lpm_common::LpmError;

/// Result of an OIDC token exchange.
#[derive(Debug, Clone)]
pub struct OidcToken {
    pub token: String,
}

/// Detect which CI environment we're running in.
pub fn detect_ci_environment() -> Option<CiEnvironment> {
    // GitHub Actions
    if std::env::var("ACTIONS_ID_TOKEN_REQUEST_URL").is_ok()
        && std::env::var("ACTIONS_ID_TOKEN_REQUEST_TOKEN").is_ok()
    {
        return Some(CiEnvironment::GitHubActions);
    }

    // GitLab CI
    if std::env::var("GITLAB_CI").ok().as_deref() == Some("true")
        && std::env::var("LPM_GITLAB_OIDC_TOKEN").is_ok()
    {
        return Some(CiEnvironment::GitLabCI);
    }

    None
}

#[derive(Debug, Clone, PartialEq)]
pub enum CiEnvironment {
    GitHubActions,
    GitLabCI,
}

/// Exchange a CI OIDC token for an LPM token.
///
/// # Arguments
/// * `registry_url` - The LPM registry base URL
/// * `package_name` - Optional package name (for publish scope)
/// * `scope` - "publish" or "read"
pub async fn exchange_oidc_token(
    registry_url: &str,
    package_name: Option<&str>,
    scope: &str,
) -> Result<OidcToken, LpmError> {
    let ci = detect_ci_environment().ok_or_else(|| {
        LpmError::Registry("no OIDC provider detected (not in GitHub Actions or GitLab CI)".into())
    })?;

    let jwt = match ci {
        CiEnvironment::GitHubActions => fetch_github_jwt().await?,
        CiEnvironment::GitLabCI => fetch_gitlab_jwt()?,
    };

    // Exchange JWT for LPM token
    let url = format!("{}/api/registry/-/token/oidc?scope={}", registry_url, scope);

    let mut body = serde_json::json!({ "token": jwt });
    if let Some(pkg) = package_name {
        body["package"] = serde_json::json!(pkg);
    }

    let client = reqwest::Client::new();
    let response = client
        .post(&url)
        .json(&body)
        .send()
        .await
        .map_err(|e| LpmError::Registry(format!("OIDC exchange failed: {e}")))?;

    if !response.status().is_success() {
        let status = response.status();
        let text = response
            .text()
            .await
            .unwrap_or_else(|_| "unknown".to_string());
        return Err(LpmError::Registry(format!(
            "OIDC exchange failed ({status}): {text}"
        )));
    }

    let result: serde_json::Value = response
        .json()
        .await
        .map_err(|e| LpmError::Registry(format!("OIDC response parse error: {e}")))?;

    let token = result
        .get("token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| LpmError::Registry("OIDC response missing token".into()))?
        .to_string();

    Ok(OidcToken { token })
}

/// Fetch JWT from GitHub Actions OIDC provider.
async fn fetch_github_jwt() -> Result<String, LpmError> {
    let request_url = std::env::var("ACTIONS_ID_TOKEN_REQUEST_URL")
        .map_err(|_| LpmError::Registry("ACTIONS_ID_TOKEN_REQUEST_URL not set".into()))?;
    let request_token = std::env::var("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
        .map_err(|_| LpmError::Registry("ACTIONS_ID_TOKEN_REQUEST_TOKEN not set".into()))?;

    let url = format!("{request_url}&audience=https://lpm.dev");

    let client = reqwest::Client::new();
    let response = client
        .get(&url)
        .bearer_auth(&request_token)
        .send()
        .await
        .map_err(|e| LpmError::Registry(format!("GitHub OIDC JWT fetch failed: {e}")))?;

    if !response.status().is_success() {
        return Err(LpmError::Registry(format!(
            "GitHub OIDC JWT fetch failed: {}",
            response.status()
        )));
    }

    let body: serde_json::Value = response
        .json()
        .await
        .map_err(|e| LpmError::Registry(format!("GitHub OIDC response parse error: {e}")))?;

    body.get("value")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| LpmError::Registry("GitHub OIDC response missing 'value' field".into()))
}

/// Read JWT from GitLab CI environment variable.
fn fetch_gitlab_jwt() -> Result<String, LpmError> {
    std::env::var("LPM_GITLAB_OIDC_TOKEN")
        .map_err(|_| LpmError::Registry("LPM_GITLAB_OIDC_TOKEN not set".into()))
}
