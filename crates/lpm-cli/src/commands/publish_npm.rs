//! npm registry publish logic.
//!
//! Handles building the npm-compatible payload, sending the PUT request,
//! OTP detection and retry, and npm-specific error handling.

use crate::commands::publish_common::{
    NpmPayloadOptions, NpmProvenanceAttachment, build_npm_payload,
};
use crate::commands::web_auth;
use crate::output;
use lpm_common::LpmError;
use lpm_runner::lpm_json::NpmPublishConfig;
use std::time::Duration;

const NPM_PUBLISH_RESPONSE_MAX_BYTES: usize = 10 * 1024 * 1024;

/// Default npm registry URL.
pub(crate) const NPM_REGISTRY_URL: &str = "https://registry.npmjs.org";

/// Result of a single registry publish attempt.
#[derive(Debug)]
pub struct NpmPublishResult {
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
        validate_npm_name(name)?;
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
pub(crate) fn validate_npm_name(name: &str) -> Result<(), LpmError> {
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
    if name.starts_with("@lpm.dev/") {
        return Err(LpmError::Registry(
            "npm package names cannot use the reserved @lpm.dev/ scope".into(),
        ));
    }
    if matches!(name, "node_modules" | "favicon.ico") {
        return Err(LpmError::Registry(format!(
            "npm package name is reserved: \"{name}\""
        )));
    }

    let (scope, package_name) = if let Some(scoped) = name.strip_prefix('@') {
        let Some((scope, package_name)) = scoped.split_once('/') else {
            return Err(LpmError::Registry(format!(
                "npm scoped package name must contain one slash: \"{name}\""
            )));
        };
        if package_name.contains('/') {
            return Err(LpmError::Registry(format!(
                "npm scoped package name must contain one slash: \"{name}\""
            )));
        }
        (Some(scope), package_name)
    } else if name.contains('/') {
        return Err(LpmError::Registry(format!(
            "unscoped npm package name must not contain a slash: \"{name}\""
        )));
    } else {
        (None, name)
    };

    if let Some(scope) = scope {
        validate_npm_scope(scope, name)?;
    }
    validate_npm_package_component(package_name, name, scope.is_some())
}

fn validate_npm_scope(scope: &str, full_name: &str) -> Result<(), LpmError> {
    if scope.is_empty() {
        return Err(LpmError::Registry(format!(
            "npm package scope cannot be empty: \"{full_name}\""
        )));
    }
    validate_npm_name_case(scope, full_name)?;
    if !scope.bytes().all(|byte| {
        byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'-' | b'.' | b'_' | b'!' | b'~' | b'*' | b'\'' | b'(' | b')'
            )
    }) {
        return Err(LpmError::Registry(format!(
            "npm package scope contains characters that are not URL-safe: \"{full_name}\""
        )));
    }
    Ok(())
}

fn validate_npm_package_component(
    component: &str,
    full_name: &str,
    is_scoped: bool,
) -> Result<(), LpmError> {
    if component.is_empty() {
        return Err(LpmError::Registry(format!(
            "npm package name cannot be empty: \"{full_name}\""
        )));
    }
    let invalid_leading_character = component
        .as_bytes()
        .first()
        .is_some_and(|byte| *byte == b'.' || !is_scoped && matches!(byte, b'-' | b'_'));
    if invalid_leading_character {
        return Err(LpmError::Registry(format!(
            "npm package name has an invalid leading character: \"{full_name}\""
        )));
    }
    validate_npm_name_case(component, full_name)?;
    if !component
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_'))
    {
        return Err(LpmError::Registry(format!(
            "npm package name contains characters that are invalid for new packages: \"{full_name}\""
        )));
    }
    Ok(())
}

fn validate_npm_name_case(component: &str, full_name: &str) -> Result<(), LpmError> {
    if component.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Err(LpmError::Registry(format!(
            "npm package name must be lowercase: \"{full_name}\""
        )));
    }
    Ok(())
}

pub(crate) fn validate_npm_access(access: &str, source: &str) -> Result<(), LpmError> {
    if matches!(access, "public" | "restricted") {
        return Ok(());
    }
    Err(LpmError::Registry(format!(
        "{source} must be \"public\" or \"restricted\" (got \"{access}\")"
    )))
}

pub(crate) fn validate_npm_tag(tag: &str) -> Result<(), LpmError> {
    let characters_are_url_safe = !tag.is_empty()
        && tag.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'-' | b'.' | b'_' | b'!' | b'~' | b'*' | b'\'' | b'(' | b')'
                )
        });
    if !characters_are_url_safe {
        return Err(LpmError::Registry(format!(
            "publish.npm.tag must be a non-empty URL-safe dist-tag (got \"{tag}\")"
        )));
    }
    if lpm_semver::Version::parse(tag).is_ok() || lpm_semver::VersionReq::parse(tag).is_ok() {
        return Err(LpmError::Registry(format!(
            "publish.npm.tag must not be a semantic version or range (got \"{tag}\")"
        )));
    }
    Ok(())
}

pub(crate) fn validate_npm_registry(registry: &str) -> Result<(), LpmError> {
    validate_npm_registry_setting(registry, "publish.npm.registry")
}

pub(crate) fn validate_npm_registry_setting(registry: &str, source: &str) -> Result<(), LpmError> {
    let parsed = reqwest::Url::parse(registry).map_err(|_| {
        LpmError::Registry(format!(
            "{source} must be a valid HTTPS URL (got \"remote-url\")"
        ))
    })?;
    let safe_origin = parsed.origin().ascii_serialization();
    let safe_origin = if safe_origin == "null" {
        "remote-url"
    } else {
        &safe_origin
    };
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(LpmError::Registry(format!(
            "{source} must not contain credentials: \"{safe_origin}\""
        )));
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(LpmError::Registry(format!(
            "{source} must not contain a query or fragment: \"{safe_origin}\""
        )));
    }
    let host = parsed.host_str().unwrap_or_default();
    if parsed.scheme() == "https" || parsed.scheme() == "http" && lpm_common::is_loopback_host(host)
    {
        return Ok(());
    }
    Err(LpmError::Registry(format!(
        "{source} requires HTTPS except for loopback development registries (got \"{safe_origin}\")"
    )))
}

pub(crate) fn validate_npm_publish_config(
    npm_config: Option<&NpmPublishConfig>,
    validate_registry: bool,
) -> Result<(), LpmError> {
    let Some(config) = npm_config else {
        return Ok(());
    };
    if let Some(tag) = config.tag.as_deref() {
        validate_npm_tag(tag)?;
    }
    if validate_registry && let Some(registry) = config.registry.as_deref() {
        validate_npm_registry(registry)?;
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
///
/// Project config may route npm-compatible publishing to another
/// HTTPS registry, but authentication for non-default registries is
/// resolved separately as registry-scoped auth.
pub fn resolve_npm_registry(npm_config: Option<&NpmPublishConfig>) -> String {
    let resolved = npm_config
        .and_then(|c| c.registry.as_deref())
        .unwrap_or(NPM_REGISTRY_URL)
        .to_string();
    if resolved.trim_end_matches('/') != NPM_REGISTRY_URL.trim_end_matches('/') {
        tracing::warn!(
            target_url = %crate::install_ui::safe_url_origin(&resolved),
            default_url = NPM_REGISTRY_URL,
            "publish.npm.registry overridden; registry-scoped auth is required for non-default npm registries",
        );
    }
    resolved
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
    provenance_attachment: Option<&NpmProvenanceAttachment>,
    access: &str,
    tag: &str,
    registry_url: &str,
    otp_preempt: bool,
    json_output: bool,
    yes: bool,
) -> Result<NpmPublishResult, LpmError> {
    publish_to_npm_impl(
        token,
        npm_name,
        version,
        version_data,
        tarball_data,
        provenance_attachment,
        access,
        tag,
        registry_url,
        otp_preempt,
        json_output,
        yes,
        NpmPublishRuntime::production(),
    )
    .await
}

#[derive(Clone, Copy)]
struct NpmPublishRuntime {
    allow_http: bool,
    interactive: Option<bool>,
    open_browser: bool,
    web_auth_timeout: Duration,
    web_auth_poll_interval: Duration,
}

impl NpmPublishRuntime {
    fn production() -> Self {
        Self {
            allow_http: false,
            interactive: None,
            open_browser: true,
            web_auth_timeout: Duration::from_secs(5 * 60),
            web_auth_poll_interval: Duration::from_secs(1),
        }
    }

    #[cfg(test)]
    fn test() -> Self {
        Self {
            allow_http: true,
            interactive: Some(true),
            open_browser: false,
            web_auth_timeout: Duration::from_secs(1),
            web_auth_poll_interval: Duration::from_millis(1),
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn publish_to_npm_impl(
    token: &str,
    npm_name: &str,
    version: &str,
    version_data: &serde_json::Value,
    tarball_data: &[u8],
    provenance_attachment: Option<&NpmProvenanceAttachment>,
    access: &str,
    tag: &str,
    registry_url: &str,
    otp_preempt: bool,
    json_output: bool,
    yes: bool,
    runtime: NpmPublishRuntime,
) -> Result<NpmPublishResult, LpmError> {
    let start = std::time::Instant::now();

    // S1: Credential isolation — assert no LPM token leaks to npm
    assert!(
        !token.starts_with("lpm_"),
        "SECURITY: LPM token must never be sent to npm registry"
    );

    if !lpm_common::lpm_registry_url_is_accepted(registry_url) && !runtime.allow_http {
        return Err(LpmError::Registry(format!(
            "refusing to publish to {} — credentials require HTTPS or HTTP loopback",
            crate::install_ui::safe_url_origin(registry_url)
        )));
    }

    let payload = build_npm_payload(
        registry_url,
        npm_name,
        version,
        version_data,
        tarball_data,
        access,
        NpmPayloadOptions {
            tag: Some(tag),
            provenance_attachment,
        },
    );

    // S3: Scale timeout based on tarball size
    let tarball_mb = tarball_data.len() as u64 / (1024 * 1024);
    let timeout_secs = std::cmp::min(60 + tarball_mb * 2, 600);
    let timeout = std::time::Duration::from_secs(timeout_secs);

    let client = lpm_http::client_builder()
        .timeout(timeout)
        .user_agent(format!("lpm-rs/{}", crate::build_version::version()))
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
    let mut req =
        web_auth::add_npm_web_auth_headers(client.put(&url), web_auth::NPM_COMMAND_PUBLISH)
            .json(&payload)
            .bearer_auth(token);
    if let Some(code) = &otp_code {
        req = req.header("npm-otp", code);
    }

    let response = req.send().await.map_err(|e| {
        LpmError::Registry(format!(
            "npm publish request failed: {}",
            lpm_http::display_error(&e)
        ))
    })?;

    let status = response.status();
    let headers = response.headers().clone();

    // OTP required? (A4)
    if status == reqwest::StatusCode::UNAUTHORIZED {
        let body = response_json_or_empty(response).await?;
        if let Some(challenge) = web_auth::parse_web_auth_challenge_from_body(&body) {
            if !can_handle_interactive_challenge(json_output, yes, runtime) {
                return Err(LpmError::Registry(
                    "npm requires browser authentication to finish publishing, but this command is running in non-interactive mode. Re-run in a TTY or use an automation token.".into(),
                ));
            }

            let otp = web_auth::complete_web_auth_challenge(
                &client,
                &challenge,
                "publish",
                json_output,
                runtime.open_browser,
                runtime.web_auth_timeout,
                runtime.web_auth_poll_interval,
            )
            .await?;

            let retry_req =
                web_auth::add_npm_web_auth_headers(client.put(&url), web_auth::NPM_COMMAND_PUBLISH)
                    .json(&payload)
                    .bearer_auth(token)
                    .header("npm-otp", &otp);

            let retry_response = retry_req.send().await.map_err(|e| {
                LpmError::Registry(format!(
                    "npm publish retry failed: {}",
                    lpm_http::display_error(&e)
                ))
            })?;

            return handle_npm_response(retry_response, npm_name, version, start).await;
        }

        if is_otp_required(status, &headers) {
            if !can_handle_interactive_challenge(json_output, yes, runtime) {
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
            let retry_req =
                web_auth::add_npm_web_auth_headers(client.put(&url), web_auth::NPM_COMMAND_PUBLISH)
                    .json(&payload)
                    .bearer_auth(token)
                    .header("npm-otp", &otp);

            let retry_response = retry_req.send().await.map_err(|e| {
                LpmError::Registry(format!(
                    "npm publish retry failed: {}",
                    lpm_http::display_error(&e)
                ))
            })?;

            return handle_npm_response(retry_response, npm_name, version, start).await;
        }

        return Ok(handle_npm_response_body(
            status, body, npm_name, version, start,
        ));
    }

    handle_npm_response(response, npm_name, version, start).await
}

/// Handle npm publish response, mapping HTTP status codes to clear errors.
async fn handle_npm_response(
    response: reqwest::Response,
    npm_name: &str,
    version: &str,
    start: std::time::Instant,
) -> Result<NpmPublishResult, LpmError> {
    let status = response.status();
    let body = response_json_or_empty(response).await?;

    Ok(handle_npm_response_body(
        status, body, npm_name, version, start,
    ))
}

fn handle_npm_response_body(
    status: reqwest::StatusCode,
    body: serde_json::Value,
    npm_name: &str,
    version: &str,
    start: std::time::Instant,
) -> NpmPublishResult {
    let duration = start.elapsed();

    let error_msg = body.get("error").and_then(|e| e.as_str()).unwrap_or("");

    if status.is_success() {
        return NpmPublishResult {
            success: true,
            error: None,
            duration,
        };
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

    NpmPublishResult {
        success: false,
        error: Some(detailed_error),
        duration,
    }
}

async fn response_json_or_empty(
    response: reqwest::Response,
) -> Result<serde_json::Value, LpmError> {
    let body = lpm_http::read_body_capped(response, NPM_PUBLISH_RESPONSE_MAX_BYTES)
        .await
        .map_err(|error| LpmError::Registry(format!("npm publish response {error}")))?;
    Ok(
        serde_json::from_slice(lpm_common::strip_utf8_bom_bytes(&body))
            .unwrap_or_else(|_| serde_json::json!({})),
    )
}

fn can_handle_interactive_challenge(
    json_output: bool,
    yes: bool,
    runtime: NpmPublishRuntime,
) -> bool {
    if json_output || yes {
        return false;
    }
    runtime
        .interactive
        .unwrap_or_else(web_auth::terminal_is_interactive)
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
fn is_otp_required(status: reqwest::StatusCode, headers: &reqwest::header::HeaderMap) -> bool {
    status == reqwest::StatusCode::UNAUTHORIZED
        && headers
            .get("www-authenticate")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.to_ascii_lowercase().contains("otp"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

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
    fn validate_npm_name_rejects_malformed_scope_and_slash_shapes() {
        for name in ["@/pkg", "@Scope/pkg", "foo/bar"] {
            assert!(validate_npm_name(name).is_err(), "{name}");
        }
    }

    #[test]
    fn validate_npm_name_rejects_reserved_names_and_lpm_scope() {
        for name in ["node_modules", "favicon.ico", "@lpm.dev/owner.package"] {
            assert!(validate_npm_name(name).is_err(), "{name}");
        }
    }

    #[test]
    fn validate_npm_name_matches_new_package_leading_character_rules() {
        assert!(validate_npm_name("-pkg").is_err());
        assert!(validate_npm_name("@scope/_pkg").is_ok());
        assert!(validate_npm_name("@scope/-pkg").is_ok());
    }

    #[test]
    fn resolve_npm_name_validates_config_override() {
        let config = NpmPublishConfig {
            name: Some("@/pkg".into()),
            ..Default::default()
        };

        assert!(resolve_npm_name("valid-name", Some(&config)).is_err());
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
    fn validate_npm_access_rejects_unknown_value() {
        let error = validate_npm_access("private", "publish.npm.access").unwrap_err();

        assert!(error.to_string().contains("publish.npm.access"));
    }

    #[test]
    fn validate_npm_tag_matches_npm_package_arg_rules() {
        assert!(validate_npm_tag("1.2.3").is_err());
        assert!(validate_npm_tag("bad tag").is_err());
        assert!(validate_npm_tag("next").is_ok());
        for tag in ["-canary", "_next", "~beta", "release!", "release(test)"] {
            assert!(validate_npm_tag(tag).is_ok(), "{tag}");
        }
    }

    #[test]
    fn validate_npm_registry_allows_https_and_loopback_http_only() {
        assert!(validate_npm_registry("https://registry.example.test/npm").is_ok());
        assert!(validate_npm_registry("http://127.0.0.1:4873").is_ok());
        assert!(validate_npm_registry("http://registry.example.test/npm").is_err());
    }

    #[test]
    fn otp_header_detection() {
        use reqwest::header::HeaderMap;

        let mut headers = HeaderMap::new();
        headers.insert("www-authenticate", "OTP".parse().unwrap());
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

    #[tokio::test]
    async fn publish_to_npm_sends_web_auth_publish_headers() {
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/plain-pkg"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({})))
            .mount(&server)
            .await;

        let result = publish_to_npm_impl(
            "npm-token",
            "plain-pkg",
            "1.0.0",
            &serde_json::json!({ "name": "plain-pkg", "version": "1.0.0" }),
            b"fake-tarball",
            None,
            "public",
            "latest",
            &server.uri(),
            false,
            false,
            false,
            NpmPublishRuntime::test(),
        )
        .await
        .expect("publish should succeed");

        assert!(result.success);
        let requests = server.received_requests().await.unwrap();
        let publish_request = requests
            .iter()
            .find(|request| request.method.as_str() == "PUT")
            .expect("publish request should be recorded");
        assert_eq!(
            publish_request
                .headers
                .get(web_auth::NPM_AUTH_TYPE_HEADER)
                .and_then(|value| value.to_str().ok()),
            Some(web_auth::NPM_AUTH_TYPE_WEB)
        );
        assert_eq!(
            publish_request
                .headers
                .get(web_auth::NPM_COMMAND_HEADER)
                .and_then(|value| value.to_str().ok()),
            Some(web_auth::NPM_COMMAND_PUBLISH)
        );
    }

    #[tokio::test]
    async fn publish_to_npm_rejects_oversized_response_body() {
        const RESPONSE_CAP: usize = 10 * 1024 * 1024;
        let server = MockServer::start().await;
        let mut body = String::with_capacity(RESPONSE_CAP + 32);
        body.push_str(r#"{"padding":""#);
        body.extend(std::iter::repeat_n('x', RESPONSE_CAP));
        body.push_str(r#""}"#);
        Mock::given(method("PUT"))
            .and(path("/plain-pkg"))
            .respond_with(
                ResponseTemplate::new(201).set_body_raw(body.into_bytes(), "application/json"),
            )
            .mount(&server)
            .await;

        let error = publish_to_npm_impl(
            "npm-token",
            "plain-pkg",
            "1.0.0",
            &serde_json::json!({ "name": "plain-pkg", "version": "1.0.0" }),
            b"fake-tarball",
            None,
            "public",
            "latest",
            &server.uri(),
            false,
            false,
            false,
            NpmPublishRuntime::test(),
        )
        .await
        .expect_err("oversized npm response must be rejected");

        assert!(error.to_string().contains("exceeds cap"));
    }

    #[tokio::test]
    async fn publish_to_npm_attaches_explicit_sigstore_bundle() {
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/plain-pkg"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({})))
            .mount(&server)
            .await;
        let provenance = NpmProvenanceAttachment {
            media_type: "application/vnd.dev.sigstore.bundle+json;version=0.2".into(),
            data: r#"{"mediaType":"application/vnd.dev.sigstore.bundle+json;version=0.2"}"#.into(),
        };

        let result = publish_to_npm_impl(
            "npm-token",
            "plain-pkg",
            "1.0.0",
            &serde_json::json!({ "name": "plain-pkg", "version": "1.0.0" }),
            b"fake-tarball",
            Some(&provenance),
            "public",
            "latest",
            &server.uri(),
            false,
            false,
            false,
            NpmPublishRuntime::test(),
        )
        .await
        .expect("publish should succeed");

        assert!(result.success);
        let requests = server.received_requests().await.unwrap();
        let publish_request = requests
            .iter()
            .find(|request| request.method.as_str() == "PUT")
            .expect("publish request should be recorded");
        let payload: serde_json::Value = serde_json::from_slice(&publish_request.body).unwrap();
        let attachment = &payload["_attachments"]["plain-pkg-1.0.0.sigstore"];
        assert_eq!(attachment["content_type"], provenance.media_type);
        assert_eq!(attachment["data"], provenance.data);
        assert_eq!(attachment["length"], provenance.data.len());
    }

    #[tokio::test]
    async fn publish_to_npm_retries_with_web_auth_otp_token() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/done"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "token": "web-otp-token",
            })))
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path("/plain-pkg"))
            .and(header("npm-otp", "web-otp-token"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({})))
            .with_priority(1)
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path("/plain-pkg"))
            .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
                "authUrl": format!("{}/auth", server.uri()),
                "doneUrl": format!("{}/done", server.uri()),
            })))
            .with_priority(2)
            .mount(&server)
            .await;

        let result = publish_to_npm_impl(
            "npm-token",
            "plain-pkg",
            "1.0.0",
            &serde_json::json!({ "name": "plain-pkg", "version": "1.0.0" }),
            b"fake-tarball",
            None,
            "public",
            "latest",
            &server.uri(),
            false,
            false,
            false,
            NpmPublishRuntime::test(),
        )
        .await
        .expect("publish should complete after web-auth OTP retry");

        assert!(result.success);
        let requests = server.received_requests().await.unwrap();
        let publish_requests: Vec<_> = requests
            .iter()
            .filter(|request| request.method.as_str() == "PUT")
            .collect();
        assert_eq!(publish_requests.len(), 2);
        assert_eq!(
            publish_requests[1]
                .headers
                .get("npm-otp")
                .and_then(|value| value.to_str().ok()),
            Some("web-otp-token")
        );
        for request in publish_requests {
            assert_eq!(
                request
                    .headers
                    .get(web_auth::NPM_AUTH_TYPE_HEADER)
                    .and_then(|value| value.to_str().ok()),
                Some(web_auth::NPM_AUTH_TYPE_WEB)
            );
            assert_eq!(
                request
                    .headers
                    .get(web_auth::NPM_COMMAND_HEADER)
                    .and_then(|value| value.to_str().ok()),
                Some(web_auth::NPM_COMMAND_PUBLISH)
            );
        }
    }

    #[tokio::test]
    async fn publish_to_npm_preserves_classic_otp_noninteractive_error() {
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/plain-pkg"))
            .respond_with(
                ResponseTemplate::new(401)
                    .insert_header("www-authenticate", "OTP")
                    .set_body_json(serde_json::json!({})),
            )
            .mount(&server)
            .await;

        let err = publish_to_npm_impl(
            "npm-token",
            "plain-pkg",
            "1.0.0",
            &serde_json::json!({ "name": "plain-pkg", "version": "1.0.0" }),
            b"fake-tarball",
            None,
            "public",
            "latest",
            &server.uri(),
            false,
            true,
            false,
            NpmPublishRuntime::test(),
        )
        .await
        .unwrap_err();

        assert!(
            err.to_string().contains("npm OTP required"),
            "unexpected error: {err}"
        );
    }
}
