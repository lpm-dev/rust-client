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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Mutex to serialize tests that mutate environment variables.
    // cargo test runs tests in parallel threads sharing the same process,
    // so concurrent env mutation causes races. cargo nextest doesn't need
    // this (each test is a separate process), but we support both runners.
    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    // Helper: save, set, and restore env vars. All env mutation is unsafe in Rust 1.66+.
    unsafe fn set_env(key: &str, val: &str) {
        // SAFETY: caller holds ENV_MUTEX, preventing concurrent env mutation.
        unsafe { std::env::set_var(key, val) };
    }
    unsafe fn remove_env(key: &str) {
        unsafe { std::env::remove_var(key) };
    }
    unsafe fn restore_env(key: &str, orig: Option<String>) {
        match orig {
            Some(v) => unsafe { std::env::set_var(key, v) },
            None => unsafe { std::env::remove_var(key) },
        }
    }

    #[test]
    fn detect_github_actions_environment() {
        let _lock = ENV_MUTEX.lock().unwrap();
        unsafe {
            let orig_url = std::env::var("ACTIONS_ID_TOKEN_REQUEST_URL").ok();
            let orig_token = std::env::var("ACTIONS_ID_TOKEN_REQUEST_TOKEN").ok();
            let orig_gitlab = std::env::var("GITLAB_CI").ok();

            remove_env("GITLAB_CI");
            set_env(
                "ACTIONS_ID_TOKEN_REQUEST_URL",
                "https://token.actions.githubusercontent.com",
            );
            set_env("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "test-token");

            let result = detect_ci_environment();
            assert_eq!(result, Some(CiEnvironment::GitHubActions));

            restore_env("ACTIONS_ID_TOKEN_REQUEST_URL", orig_url);
            restore_env("ACTIONS_ID_TOKEN_REQUEST_TOKEN", orig_token);
            restore_env("GITLAB_CI", orig_gitlab);
        }
    }

    #[test]
    fn detect_gitlab_ci_environment() {
        let _lock = ENV_MUTEX.lock().unwrap();
        unsafe {
            let orig_gitlab = std::env::var("GITLAB_CI").ok();
            let orig_token = std::env::var("LPM_GITLAB_OIDC_TOKEN").ok();
            let orig_gh_url = std::env::var("ACTIONS_ID_TOKEN_REQUEST_URL").ok();
            let orig_gh_tok = std::env::var("ACTIONS_ID_TOKEN_REQUEST_TOKEN").ok();

            remove_env("ACTIONS_ID_TOKEN_REQUEST_URL");
            remove_env("ACTIONS_ID_TOKEN_REQUEST_TOKEN");
            set_env("GITLAB_CI", "true");
            set_env("LPM_GITLAB_OIDC_TOKEN", "test-jwt");

            let result = detect_ci_environment();
            assert_eq!(result, Some(CiEnvironment::GitLabCI));

            restore_env("GITLAB_CI", orig_gitlab);
            restore_env("LPM_GITLAB_OIDC_TOKEN", orig_token);
            restore_env("ACTIONS_ID_TOKEN_REQUEST_URL", orig_gh_url);
            restore_env("ACTIONS_ID_TOKEN_REQUEST_TOKEN", orig_gh_tok);
        }
    }

    #[test]
    fn detect_no_ci_environment() {
        let _lock = ENV_MUTEX.lock().unwrap();
        unsafe {
            let orig_gh_url = std::env::var("ACTIONS_ID_TOKEN_REQUEST_URL").ok();
            let orig_gh_tok = std::env::var("ACTIONS_ID_TOKEN_REQUEST_TOKEN").ok();
            let orig_gitlab = std::env::var("GITLAB_CI").ok();
            let orig_gl_tok = std::env::var("LPM_GITLAB_OIDC_TOKEN").ok();

            remove_env("ACTIONS_ID_TOKEN_REQUEST_URL");
            remove_env("ACTIONS_ID_TOKEN_REQUEST_TOKEN");
            remove_env("GITLAB_CI");
            remove_env("LPM_GITLAB_OIDC_TOKEN");

            let result = detect_ci_environment();
            assert_eq!(result, None);

            restore_env("ACTIONS_ID_TOKEN_REQUEST_URL", orig_gh_url);
            restore_env("ACTIONS_ID_TOKEN_REQUEST_TOKEN", orig_gh_tok);
            restore_env("GITLAB_CI", orig_gitlab);
            restore_env("LPM_GITLAB_OIDC_TOKEN", orig_gl_tok);
        }
    }

    #[test]
    fn github_actions_requires_both_vars() {
        let _lock = ENV_MUTEX.lock().unwrap();
        unsafe {
            let orig_url = std::env::var("ACTIONS_ID_TOKEN_REQUEST_URL").ok();
            let orig_token = std::env::var("ACTIONS_ID_TOKEN_REQUEST_TOKEN").ok();
            let orig_gitlab = std::env::var("GITLAB_CI").ok();
            let orig_gl_tok = std::env::var("LPM_GITLAB_OIDC_TOKEN").ok();

            remove_env("GITLAB_CI");
            remove_env("LPM_GITLAB_OIDC_TOKEN");

            // Only URL set
            set_env("ACTIONS_ID_TOKEN_REQUEST_URL", "https://example.com");
            remove_env("ACTIONS_ID_TOKEN_REQUEST_TOKEN");
            assert_eq!(detect_ci_environment(), None);

            // Only token set
            remove_env("ACTIONS_ID_TOKEN_REQUEST_URL");
            set_env("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "tok");
            assert_eq!(detect_ci_environment(), None);

            restore_env("ACTIONS_ID_TOKEN_REQUEST_URL", orig_url);
            restore_env("ACTIONS_ID_TOKEN_REQUEST_TOKEN", orig_token);
            restore_env("GITLAB_CI", orig_gitlab);
            restore_env("LPM_GITLAB_OIDC_TOKEN", orig_gl_tok);
        }
    }

    #[test]
    fn gitlab_ci_requires_oidc_token() {
        let _lock = ENV_MUTEX.lock().unwrap();
        unsafe {
            let orig_gitlab = std::env::var("GITLAB_CI").ok();
            let orig_token = std::env::var("LPM_GITLAB_OIDC_TOKEN").ok();
            let orig_gh_url = std::env::var("ACTIONS_ID_TOKEN_REQUEST_URL").ok();
            let orig_gh_tok = std::env::var("ACTIONS_ID_TOKEN_REQUEST_TOKEN").ok();

            remove_env("ACTIONS_ID_TOKEN_REQUEST_URL");
            remove_env("ACTIONS_ID_TOKEN_REQUEST_TOKEN");
            set_env("GITLAB_CI", "true");
            remove_env("LPM_GITLAB_OIDC_TOKEN");

            assert_eq!(detect_ci_environment(), None);

            restore_env("GITLAB_CI", orig_gitlab);
            restore_env("LPM_GITLAB_OIDC_TOKEN", orig_token);
            restore_env("ACTIONS_ID_TOKEN_REQUEST_URL", orig_gh_url);
            restore_env("ACTIONS_ID_TOKEN_REQUEST_TOKEN", orig_gh_tok);
        }
    }

    #[test]
    fn fetch_gitlab_jwt_reads_env() {
        let _lock = ENV_MUTEX.lock().unwrap();
        unsafe {
            let orig = std::env::var("LPM_GITLAB_OIDC_TOKEN").ok();

            set_env("LPM_GITLAB_OIDC_TOKEN", "test-jwt-value");
            let result = fetch_gitlab_jwt();
            assert_eq!(result.unwrap(), "test-jwt-value");

            remove_env("LPM_GITLAB_OIDC_TOKEN");
            let result = fetch_gitlab_jwt();
            assert!(result.is_err());

            restore_env("LPM_GITLAB_OIDC_TOKEN", orig);
        }
    }
}
