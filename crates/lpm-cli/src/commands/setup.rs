use crate::{oidc, output};
use lpm_common::LpmError;
use owo_colors::OwoColorize;
use std::path::Path;

/// Phase 35: resolve a usable LPM bearer for CI/CD `.npmrc` generation.
/// `setup` is best-effort — when no token is available it falls back
/// to the `${LPM_TOKEN}` placeholder so CI can interpolate at runtime.
async fn resolve_lpm_bearer_optional(registry_url: &str) -> Option<String> {
    let session = lpm_auth::SessionManager::new(registry_url, None);
    session
        .bearer_string_for(lpm_auth::AuthRequirement::TokenRequired)
        .await
        .ok()
}

/// Generate .npmrc for CI/CD environments.
///
/// Creates a .npmrc file that configures the LPM registry with auth token
/// so npm/pnpm/yarn can install @lpm.dev packages in CI.
///
/// Default: scoped config (`@lpm.dev:registry=`) — only LPM packages go through lpm.dev.
///
/// Flags:
/// - `--oidc`: Exchange an OIDC token from the CI environment instead of using stored auth.
/// - `--proxy`: Route ALL npm traffic through lpm.dev (Pro/Org feature for dependency visibility).
/// - `--registry` / `-r`: Override the registry URL.
pub async fn run(
    registry_url: &str,
    project_dir: &Path,
    json_output: bool,
    use_oidc: bool,
    proxy: bool,
) -> Result<(), LpmError> {
    // Resolve token: OIDC exchange > stored token > env var > placeholder.
    // Phase 35: SessionManager handles `LPM_TOKEN` fallback internally,
    // so the explicit `or_else(LPM_TOKEN)` step is no longer needed
    // here — `bearer_string_for` returns it as `EnvVar` source.
    let token: Option<String> = if use_oidc {
        match oidc::exchange_oidc_token(registry_url, None, "install").await {
            Ok(oidc_token) => Some(oidc_token.token),
            Err(e) => {
                if !json_output {
                    output::warn(&format!("OIDC token exchange failed: {e}"));
                    output::warn("Falling back to stored token / ${LPM_TOKEN} placeholder.");
                }
                resolve_lpm_bearer_optional(registry_url).await
            }
        }
    } else {
        resolve_lpm_bearer_optional(registry_url).await
    };

    let token_placeholder = token.as_deref().unwrap_or("${LPM_TOKEN}");
    let uses_env = token.is_none();

    // Build .npmrc content
    let registry_host = registry_url
        .trim_start_matches("https://")
        .trim_start_matches("http://");

    let registry_line = if proxy {
        format!("registry={}/api/registry/", registry_url)
    } else {
        format!("@lpm.dev:registry={}/api/registry/", registry_url)
    };

    let npmrc_content = format!(
        "//{}/:_authToken={}\n{}\n",
        registry_host, token_placeholder, registry_line
    );

    let npmrc_path = project_dir.join(".npmrc");

    if json_output {
        let json = serde_json::json!({
            "success": true,
            "path": npmrc_path.display().to_string(),
            "content": npmrc_content,
            "uses_env_var": uses_env,
            "oidc": use_oidc,
            "proxy": proxy,
        });
        println!("{}", serde_json::to_string_pretty(&json).unwrap());
    } else {
        std::fs::write(&npmrc_path, &npmrc_content)?;

        // S6: Restrict .npmrc permissions to owner-only (contains auth tokens)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&npmrc_path, std::fs::Permissions::from_mode(0o600));
        }

        output::success(&format!("Generated {}", ".npmrc".bold()));
        println!("  {}", npmrc_path.display().to_string().dimmed());

        if use_oidc && token.is_some() {
            output::info("Using OIDC-exchanged token.");
        }
        if proxy {
            output::info("Using proxy mode — all npm traffic routed through lpm.dev.");
        }

        if uses_env {
            println!();
            output::warn("No token found — .npmrc uses ${LPM_TOKEN} placeholder.");
            println!("  Set {} in your CI environment.", "LPM_TOKEN".bold());
        }
        println!();
    }

    Ok(())
}
