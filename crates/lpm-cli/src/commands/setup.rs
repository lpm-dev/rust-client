use crate::{auth_storage_notice, install_ui, oidc};
use lpm_common::LpmError;
use lpm_common::color::Painted;
use std::path::Path;

fn hint_line(message: &str) {
    eprintln!("  {}", install_ui::dim(message));
}

/// resolve a usable LPM bearer for CI/CD `.npmrc` generation.
/// `setup ci` is best-effort — when no token is available it falls
/// back to the `${LPM_TOKEN}` placeholder so CI can interpolate at runtime.
async fn resolve_lpm_bearer_optional(
    registry_url: &str,
    json_output: bool,
) -> Option<ResolvedSetupBearer> {
    let session = auth_storage_notice::attach(
        lpm_auth::SessionManager::new(registry_url, None),
        json_output,
    );
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
/// - `--registry` / `-r`: Override the registry URL.
pub async fn run(
    registry_url: &str,
    project_dir: &Path,
    json_output: bool,
    use_oidc: bool,
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
                    install_ui::warn_untrusted(&format!("OIDC token exchange failed: {e}"));
                    install_ui::warn("Falling back to stored token / ${LPM_TOKEN} placeholder.");
                }
                resolve_lpm_bearer_optional(registry_url, json_output).await
            }
        }
    } else {
        resolve_lpm_bearer_optional(registry_url, json_output).await
    };

    let token_placeholder = token
        .as_ref()
        .map_or("${LPM_TOKEN}", |resolved| resolved.token.as_str());
    let uses_env = token.is_none();
    let storage_status = setup_storage_status(token.as_ref());

    // Build .npmrc content
    let registry_host = registry_url
        .trim_start_matches("https://")
        .trim_start_matches("http://");

    let registry_line = format!("@lpm.dev:registry={}/api/registry/", registry_url);

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
            "proxy": false,
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

        if uses_env {
            install_ui::warn("No token found — .npmrc uses ${LPM_TOKEN} placeholder.");
            eprintln!(
                "  {} {} {}",
                install_ui::dim("Set"),
                install_ui::cyan("LPM_TOKEN"),
                install_ui::dim("in your CI environment.")
            );
        }
    }

    Ok(())
}

pub fn run_ci_platform(platform: &str, project_dir: &Path, env_mode: &str) -> Result<(), LpmError> {
    match platform {
        "github-actions" | "github" | "gha" => {
            setup_github_actions(project_dir, env_mode);
            Ok(())
        }
        "gitlab" | "gitlab-ci" => {
            setup_gitlab_ci(env_mode);
            Ok(())
        }
        _ => Err(LpmError::Script(format!(
            "unknown CI setup target: '{platform}'. Available: npmrc, github-actions, gitlab"
        ))),
    }
}

fn setup_github_actions(project_dir: &Path, env_mode: &str) {
    let vault_id = lpm_vault::vault_id::read_vault_id(project_dir)
        .unwrap_or_else(|| "<your-vault-id>".to_string());
    let env_mode = install_ui::field(env_mode);
    let vault_id = install_ui::field(&vault_id);

    println!();
    println!("  {} GitHub Actions OIDC Setup", "▸".bold());
    println!();
    println!(
        "  {} Add this to your workflow (.github/workflows/deploy.yml):",
        "1.".bold()
    );
    println!();
    println!(
        "  {}",
        "jobs:
    deploy:
      permissions:
        id-token: write
        contents: read
      steps:
        - uses: actions/checkout@v4
        - name: Install LPM
          run: npm install -g @lpm-registry/cli
        - name: Load secrets from env
          run: lpm env pull --oidc --env={ENV} --output=.env
          env:
            LPM_VAULT_ID: {VAULT_ID}
        - name: Deploy
          run: lpm run deploy"
            .replace("{ENV}", env_mode.as_ref())
            .replace("{VAULT_ID}", vault_id.as_ref())
            .dimmed()
    );
    println!();
    println!("  {} Authorize this repo:", "2.".bold());
    println!();
    println!(
        "  {}",
        format!(
            "lpm env oidc allow --provider=github --repo=<owner/repo> \
             --workflow=.github/workflows/deploy.yml --branch=main --env={env_mode}"
        )
        .bold()
    );
    println!();
}

fn setup_gitlab_ci(env_mode: &str) {
    let env_mode = install_ui::field(env_mode);

    println!();
    println!("  {} GitLab CI OIDC Setup", "▸".bold());
    println!();
    println!("  {} Add this to .gitlab-ci.yml:", "1.".bold());
    println!();
    println!(
        "  {}",
        "deploy:
  id_tokens:
    LPM_OIDC_TOKEN:
      aud: https://lpm.dev
  script:
    - npm install -g @lpm-registry/cli
    - lpm env pull --oidc --env={ENV} --output=.env
    - lpm run deploy"
            .replace("{ENV}", env_mode.as_ref())
            .dimmed()
    );
    println!();
    println!("  {} Authorize this project:", "2.".bold());
    println!();
    println!(
        "  {}",
        format!(
            "lpm env oidc allow --provider=gitlab --repo=<project-path> --branch=main --env={env_mode}"
        )
        .bold()
    );
    println!();
}
