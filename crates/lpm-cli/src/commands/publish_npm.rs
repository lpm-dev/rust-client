//! npm registry publish logic.
//!
//! Handles building the npm-compatible payload, sending the PUT request,
//! OTP detection and retry, and npm-specific error handling.

use crate::commands::publish_common::build_npm_payload;
use crate::output;
use lpm_common::LpmError;
use lpm_runner::lpm_json::NpmPublishConfig;

/// Default npm registry URL.
const NPM_REGISTRY_URL: &str = "https://registry.npmjs.org";

/// Result of a single registry publish attempt.
#[derive(Debug)]
pub struct NpmPublishResult {
    #[allow(dead_code)]
    pub registry: String,
    pub success: bool,
    pub error: Option<String>,
    pub duration: std::time::Duration,
}

/// Resolve the npm package name for publishing.
///
/// Priority: lpm.json `publish.npm.name` → package.json `name` → error if `@lpm.dev/`.
pub fn resolve_npm_name(
    pkg_json_name: &str,
    npm_config: Option<&NpmPublishConfig>,
) -> Result<String, LpmError> {
    // 1. Check lpm.json override
    if let Some(config) = npm_config
        && let Some(name) = &config.name
    {
        return Ok(name.clone());
    }

    // 2. Use package.json name if it's npm-compatible
    if pkg_json_name.starts_with("@lpm.dev/") {
        return Err(LpmError::Registry(
            "cannot publish @lpm.dev/ name to npm. Set publish.npm.name in lpm.json.\n  \
				 Example: {\"publish\": {\"npm\": {\"name\": \"@scope/pkg\"}}}"
                .to_string(),
        ));
    }

    // 3. Validate npm name rules
    validate_npm_name(pkg_json_name)?;

    Ok(pkg_json_name.to_string())
}

/// Validate that a package name is valid for npm.
fn validate_npm_name(name: &str) -> Result<(), LpmError> {
    if name.is_empty() {
        return Err(LpmError::Registry(
            "npm package name cannot be empty".into(),
        ));
    }
    if name.len() > 214 {
        return Err(LpmError::Registry(format!(
            "npm package name too long ({} chars, max 214)",
            name.len()
        )));
    }

    // npm names must be lowercase (except scoped names preserve case in scope)
    let check_name = if let Some((_scope, pkg)) = name.split_once('/') {
        pkg
    } else {
        name
    };

    if check_name != check_name.to_lowercase() {
        return Err(LpmError::Registry(format!(
            "npm package name must be lowercase: \"{name}\""
        )));
    }

    // No spaces or special chars (except - . _ ~)
    for ch in check_name.chars() {
        if !ch.is_ascii_alphanumeric() && !"-._~".contains(ch) {
            return Err(LpmError::Registry(format!(
                "npm package name contains invalid character '{ch}': \"{name}\""
            )));
        }
    }

    Ok(())
}

/// Resolve the npm access level.
///
/// All packages default to "public".
/// lpm.json `publish.npm.access` overrides the default.
pub fn resolve_npm_access(_npm_name: &str, npm_config: Option<&NpmPublishConfig>) -> String {
    if let Some(config) = npm_config
        && let Some(access) = &config.access
    {
        return access.clone();
    }

    // npm default: all packages default to public (npm requires explicit for first scoped publish)
    "public".to_string()
}

/// Resolve the npm registry URL.
pub fn resolve_npm_registry(npm_config: Option<&NpmPublishConfig>) -> String {
    npm_config
        .and_then(|c| c.registry.as_deref())
        .unwrap_or(NPM_REGISTRY_URL)
        .to_string()
}

/// Resolve the npm dist-tag.
pub fn resolve_npm_tag(npm_config: Option<&NpmPublishConfig>) -> String {
    npm_config
        .and_then(|c| c.tag.as_deref())
        .unwrap_or("latest")
        .to_string()
}

/// Publish a package to the npm registry.
///
/// Handles OTP detection and retry, npm-specific error codes.
#[allow(clippy::too_many_arguments)]
pub async fn publish_to_npm(
    token: &str,
    npm_name: &str,
    version: &str,
    version_data: &serde_json::Value,
    tarball_data: &[u8],
    access: &str,
    tag: &str,
    registry_url: &str,
    otp_preempt: bool,
    json_output: bool,
    yes: bool,
) -> Result<NpmPublishResult, LpmError> {
    let start = std::time::Instant::now();

    // S1: Credential isolation — assert no LPM token leaks to npm
    assert!(
        !token.starts_with("lpm_"),
        "SECURITY: LPM token must never be sent to npm registry"
    );

    // Reject HTTP for publish (S9)
    if !registry_url.starts_with("https://") {
        return Err(LpmError::Registry(format!(
            "refusing to publish over HTTP to {registry_url} — credentials require HTTPS"
        )));
    }

    let payload = build_npm_payload(
        npm_name,
        version,
        version_data,
        tarball_data,
        access,
        Some(tag),
    );

    // S3: Scale timeout based on tarball size
    let tarball_mb = tarball_data.len() as u64 / (1024 * 1024);
    let timeout_secs = std::cmp::min(60 + tarball_mb * 2, 600);
    let timeout = std::time::Duration::from_secs(timeout_secs);

    let client = reqwest::Client::builder()
        .timeout(timeout)
        .user_agent(format!("lpm-rs/{}", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| LpmError::Registry(format!("failed to create HTTP client: {e}")))?;

    let encoded_name = urlencoding::encode(npm_name);
    let url = format!("{registry_url}/{encoded_name}");

    // Pre-emptive OTP prompt if configured
    let mut otp_code: Option<String> = None;
    if otp_preempt && !json_output && !yes {
        let is_tty = std::io::IsTerminal::is_terminal(&std::io::stdin());
        if is_tty {
            otp_code = Some(prompt_npm_otp()?);
        }
    }

    // First attempt
    let mut req = client.put(&url).json(&payload).bearer_auth(token);
    if let Some(code) = &otp_code {
        req = req.header("npm-otp", code);
    }

    let response = req
        .send()
        .await
        .map_err(|e| LpmError::Registry(format!("npm publish request failed: {e}")))?;

    let status = response.status();
    let headers = response.headers().clone();

    // OTP required? (A4)
    // npm returns `www-authenticate: OTP` (uppercase) — match case-insensitively
    if status == reqwest::StatusCode::UNAUTHORIZED {
        let needs_otp = headers
            .get("www-authenticate")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.to_lowercase().contains("otp"));

        if needs_otp {
            if json_output || yes {
                return Err(LpmError::Registry(
                    "npm OTP required but running in non-interactive mode. \
					 Use an automation token (no OTP required)."
                        .into(),
                ));
            }

            if !json_output {
                output::warn("npm requires a one-time password");
            }

            let otp = prompt_npm_otp()?;

            // Retry with OTP header
            let retry_req = client
                .put(&url)
                .json(&payload)
                .bearer_auth(token)
                .header("npm-otp", &otp);

            let retry_response = retry_req
                .send()
                .await
                .map_err(|e| LpmError::Registry(format!("npm publish retry failed: {e}")))?;

            return handle_npm_response(retry_response, npm_name, version, &url, start).await;
        }
    }

    handle_npm_response(response, npm_name, version, &url, start).await
}

/// Handle npm publish response, mapping HTTP status codes to clear errors.
async fn handle_npm_response(
    response: reqwest::Response,
    npm_name: &str,
    version: &str,
    url: &str,
    start: std::time::Instant,
) -> Result<NpmPublishResult, LpmError> {
    let status = response.status();
    let duration = start.elapsed();

    let body: serde_json::Value = response
        .json()
        .await
        .unwrap_or_else(|_| serde_json::json!({}));

    let error_msg = body.get("error").and_then(|e| e.as_str()).unwrap_or("");

    if status.is_success() {
        return Ok(NpmPublishResult {
            registry: url.to_string(),
            success: true,
            error: None,
            duration,
        });
    }

    // Map npm-specific status codes to clear error messages
    let detailed_error = match status.as_u16() {
		401 => "authentication failed — check token permissions. Run `lpm login --npm`".to_string(),
		404 => "not found — this usually means the auth token is missing or invalid. Run `lpm login --npm`".to_string(),
		402 => "npm requires a paid plan for private packages. Publish with `access: \"public\"` or upgrade your npm plan.".to_string(),
		403 if error_msg.contains("version") || error_msg.contains("exists") => format!(
			"version {version} already exists on npm for {npm_name}"
		),
		403 => format!(
			"npm forbidden — token may lack publish permission. Create a granular token at npmjs.com/settings/tokens.\n  npm says: {error_msg}"
		),
		409 => format!(
			"version {version} already exists on npm for {npm_name}"
		),
		429 => "npm rate limit exceeded. Wait and try again.".to_string(),
		400 => format!(
			"bad request: {error_msg}"
		),
		_ => format!(
			"publish failed (HTTP {status}): {error_msg}"
		),
	};

    Ok(NpmPublishResult {
        registry: url.to_string(),
        success: false,
        error: Some(detailed_error),
        duration,
    })
}

/// Prompt the user for an npm OTP code.
fn prompt_npm_otp() -> Result<String, LpmError> {
    let code: String = cliclack::input("npm one-time password")
        .validate(|input: &String| {
            if input.len() == 6 && input.chars().all(|c| c.is_ascii_digit()) {
                Ok(())
            } else {
                Err("Must be a 6-digit code")
            }
        })
        .interact()
        .map_err(|e| LpmError::Registry(e.to_string()))?;
    Ok(code)
}

/// Detect if an HTTP response indicates OTP is required.
#[cfg(test)]
fn is_otp_required(status: reqwest::StatusCode, headers: &reqwest::header::HeaderMap) -> bool {
    status == reqwest::StatusCode::UNAUTHORIZED
        && headers
            .get("www-authenticate")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.contains("otp"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_npm_name_with_config_override() {
        let config = NpmPublishConfig {
            name: Some("@tolga/highlight".into()),
            ..Default::default()
        };
        let name = resolve_npm_name("@lpm.dev/neo.highlight", Some(&config)).unwrap();
        assert_eq!(name, "@tolga/highlight");
    }

    #[test]
    fn resolve_npm_name_plain_package_json() {
        let name = resolve_npm_name("my-package", None).unwrap();
        assert_eq!(name, "my-package");
    }

    #[test]
    fn resolve_npm_name_rejects_lpm_prefix() {
        let result = resolve_npm_name("@lpm.dev/owner.pkg", None);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("publish.npm.name"));
    }

    #[test]
    fn validate_npm_name_rejects_uppercase() {
        let result = validate_npm_name("MyPackage");
        assert!(result.is_err());
    }

    #[test]
    fn validate_npm_name_rejects_too_long() {
        let long_name = "a".repeat(215);
        let result = validate_npm_name(&long_name);
        assert!(result.is_err());
    }

    #[test]
    fn validate_npm_name_allows_valid() {
        assert!(validate_npm_name("my-package").is_ok());
        assert!(validate_npm_name("pkg123").is_ok());
        assert!(validate_npm_name("my.package").is_ok());
        assert!(validate_npm_name("my_package").is_ok());
    }

    #[test]
    fn resolve_npm_access_defaults() {
        assert_eq!(resolve_npm_access("@scope/pkg", None), "public");
        assert_eq!(resolve_npm_access("my-pkg", None), "public");
    }

    #[test]
    fn resolve_npm_access_with_config() {
        let config = NpmPublishConfig {
            access: Some("restricted".into()),
            ..Default::default()
        };
        assert_eq!(
            resolve_npm_access("@scope/pkg", Some(&config)),
            "restricted"
        );
    }

    #[test]
    fn otp_header_detection() {
        use reqwest::header::HeaderMap;

        let mut headers = HeaderMap::new();
        headers.insert("www-authenticate", "otp".parse().unwrap());
        assert!(is_otp_required(reqwest::StatusCode::UNAUTHORIZED, &headers));

        // No OTP header
        let empty_headers = HeaderMap::new();
        assert!(!is_otp_required(
            reqwest::StatusCode::UNAUTHORIZED,
            &empty_headers
        ));

        // Wrong status
        assert!(!is_otp_required(reqwest::StatusCode::FORBIDDEN, &headers));
    }
}
