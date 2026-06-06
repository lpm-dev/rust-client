use crate::{install_ui, oidc};
use lpm_common::LpmError;
use std::path::Path;

fn hint_line(message: &str) {
    eprintln!("  {}", install_ui::dim(message));
}

/// resolve a usable LPM bearer for CI/CD `.npmrc` generation.
/// `setup ci` is best-effort — when no token is available it falls
/// back to the `${LPM_TOKEN}` placeholder so CI can interpolate at runtime.
async fn resolve_lpm_bearer_optional(registry_url: &str) -> Option<ResolvedSetupBearer> {
    let session = lpm_auth::SessionManager::new(registry_url, None);
    let token = session
        .bearer_string_for(lpm_auth::AuthRequirement::TokenRequired)
        .await
        .ok()?;
    let storage = match session.current_source() {
        Some(lpm_auth::TokenSource::StoredSession | lpm_auth::TokenSource::StoredLegacy) => {
            lpm_auth::auth_storage_status(registry_url)
        }
        _ => lpm_auth::AuthStorageStatus::none(),
    };
    Some(ResolvedSetupBearer { token, storage })
}

struct ResolvedSetupBearer {
    token: String,
    storage: lpm_auth::AuthStorageStatus,
}

impl ResolvedSetupBearer {
    fn oidc(token: String) -> Self {
        Self {
            token,
            storage: lpm_auth::AuthStorageStatus::none(),
        }
    }
}

fn setup_storage_status(token: Option<&ResolvedSetupBearer>) -> lpm_auth::AuthStorageStatus {
    token.map_or_else(lpm_auth::AuthStorageStatus::none, |resolved| {
        resolved.storage
    })
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
    // SessionManager handles `LPM_TOKEN` fallback internally,
    // so the explicit `or_else(LPM_TOKEN)` step is no longer needed
    // here — `bearer_string_for` returns it as `EnvVar` source.
    let token: Option<ResolvedSetupBearer> = if use_oidc {
        match oidc::exchange_oidc_token(registry_url, None, "install").await {
            Ok(oidc_token) => Some(ResolvedSetupBearer::oidc(oidc_token.token)),
            Err(e) => {
                if !json_output {
                    install_ui::warn(&format!("OIDC token exchange failed: {e}"));
                    install_ui::warn("Falling back to stored token / ${LPM_TOKEN} placeholder.");
                }
                resolve_lpm_bearer_optional(registry_url).await
            }
        }
    } else {
        resolve_lpm_bearer_optional(registry_url).await
    };

    let token_placeholder = token
        .as_ref()
        .map(|resolved| resolved.token.as_str())
        .unwrap_or("${LPM_TOKEN}");
    let uses_env = token.is_none();
    let storage_status = setup_storage_status(token.as_ref());

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
        // M37: stdout in JSON mode is frequently captured into CI
        // logs, support bundles, and artifacts — places no operator
        // expects to find a live bearer. Always emit the placeholder
        // shape in JSON output so a real token never gets serialised
        // there. The on-disk `.npmrc` still gets the real token
        // (chmod 0o600, owner-only) — that's where the consumer
        // actually needs to read it.
        let safe_content = format!(
            "//{}/:_authToken=${{LPM_TOKEN}}\n{}\n",
            registry_host, registry_line
        );
        let json = serde_json::json!({
            "success": true,
            "path": npmrc_path.display().to_string(),
            "content": safe_content,
            "uses_env_var": uses_env,
            "oidc": use_oidc,
            "proxy": proxy,
            "storage_backend": storage_status.backend_json_value(),
            "storage_degraded": storage_status.degraded,
            "note": if uses_env { "" } else { "JSON content uses ${LPM_TOKEN} placeholder; the on-disk .npmrc carries the actual token at 0o600." },
        });
        println!("{}", serde_json::to_string_pretty(&json).unwrap());
        // Still write the on-disk file even under --json so the
        // workflow that consumed the JSON envelope can read the
        // .npmrc the way it expects.
        std::fs::write(&npmrc_path, &npmrc_content)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&npmrc_path, std::fs::Permissions::from_mode(0o600));
        }
    } else {
        std::fs::write(&npmrc_path, &npmrc_content)?;

        // S6: Restrict .npmrc permissions to owner-only (contains auth tokens)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&npmrc_path, std::fs::Permissions::from_mode(0o600));
        }

        install_ui::done("Generated .npmrc");
        hint_line(&npmrc_path.display().to_string());

        if use_oidc && token.is_some() {
            install_ui::phase("Using OIDC-exchanged token.");
        }
        if proxy {
            install_ui::phase("Using proxy mode — all npm traffic routed through lpm.dev.");
        }

        if uses_env {
            install_ui::warn("No token found — .npmrc uses ${LPM_TOKEN} placeholder.");
            hint_line(&format!(
                "Set {} in your CI environment.",
                install_ui::cyan("LPM_TOKEN")
            ));
        }
    }

    Ok(())
}
