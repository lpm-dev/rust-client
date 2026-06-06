use crate::commands::web_auth;
use crate::{auth, install_ui};
use lpm_common::LpmError;
use lpm_common::color::Painted;
use std::io::IsTerminal;
use std::time::Duration;

const NPM_REGISTRY_URL: &str = "https://registry.npmjs.org";
const NPM_DISPLAY: &str = "npmjs.org";
const GITHUB_DISPLAY: &str = "github.com";
const GITLAB_DISPLAY: &str = "gitlab.com";

pub async fn run_npm(token: Option<String>, json_output: bool) -> Result<(), LpmError> {
    if let Some(token) = token {
        return store_builtin_token(
            NPM_DISPLAY,
            token,
            "explicit-token",
            json_output,
            true,
            auth::set_npm_token_with_backend,
        );
    }
    if let Some(token) = env_npm_token() {
        return store_builtin_token(
            NPM_DISPLAY,
            token,
            "env:NPM_TOKEN",
            json_output,
            true,
            auth::set_npm_token_with_backend,
        );
    }

    if json_output || !web_auth::terminal_is_interactive() {
        return Err(LpmError::Registry(
            "npm web login requires an interactive terminal. Run `lpm login --npm` in a TTY, pass `--token <token>`, or set NPM_TOKEN.".into(),
        ));
    }

    let client = npm_web_auth_client()?;
    let challenge = web_auth::fetch_npm_web_login_challenge(&client, NPM_REGISTRY_URL).await?;
    let token = web_auth::complete_web_auth_challenge(
        &client,
        &challenge,
        "log in",
        json_output,
        true,
        Duration::from_secs(5 * 60),
        Duration::from_secs(1),
    )
    .await?;

    let storage_backend = auth::set_npm_token_with_backend(&token)
        .map_err(|e| LpmError::Registry(format!("failed to store npm token: {e}")))?;
    auth::clear_token_expiry(NPM_DISPLAY);

    if json_output {
        print_success_json(
            NPM_DISPLAY,
            "npm-web",
            true,
            Some(auth::AuthStorageStatus::from_backend(storage_backend)),
        );
    } else {
        install_ui::done(&format!(
            "Logged in to {} with npm web auth",
            NPM_DISPLAY.bold()
        ));
        render_storage_backend(auth::AuthStorageStatus::from_backend(storage_backend));
    }

    Ok(())
}

pub fn run_github(token: Option<String>, json_output: bool) -> Result<(), LpmError> {
    if let Some(token) = token {
        return store_builtin_token(
            GITHUB_DISPLAY,
            token,
            "explicit-token",
            json_output,
            true,
            auth::set_github_token_with_backend,
        );
    }

    if auth::get_github_cli_token().is_none() {
        return Err(LpmError::Registry(
            "GitHub Packages auth is not available. Run `gh auth login --hostname github.com`, pass `--token <token>`, or set GITHUB_TOKEN.".into(),
        ));
    }

    if json_output {
        print_success_json(GITHUB_DISPLAY, "gh", false, None);
    } else {
        install_ui::done(
            "GitHub Packages auth is available through GitHub CLI; no LPM token was stored",
        );
    }

    Ok(())
}

pub fn run_gitlab(token: Option<String>, json_output: bool) -> Result<(), LpmError> {
    if let Some(token) = token {
        return store_builtin_token(
            GITLAB_DISPLAY,
            token,
            "explicit-token",
            json_output,
            true,
            auth::set_gitlab_token_with_backend,
        );
    }

    if auth::get_gitlab_cli_token().is_none() {
        return Err(LpmError::Registry(
            "GitLab Packages auth is not available. Run `glab auth login`, pass `--token <token>`, or set GITLAB_TOKEN/CI_JOB_TOKEN.".into(),
        ));
    }

    if json_output {
        print_success_json(GITLAB_DISPLAY, "glab", false, None);
    } else {
        install_ui::done(
            "GitLab Packages auth is available through GitLab CLI; no LPM token was stored",
        );
    }

    Ok(())
}

pub fn run_custom(
    registry_url: &str,
    token: Option<String>,
    json_output: bool,
) -> Result<(), LpmError> {
    let token = match token {
        Some(token) => token,
        None if json_output => {
            return Err(LpmError::Registry(format!(
                "--token <token> required in JSON mode for custom registry {registry_url}"
            )));
        }
        None if !std::io::stdin().is_terminal() => {
            return Err(LpmError::Registry(format!(
                "--token <token> required in non-interactive mode for custom registry {registry_url}"
            )));
        }
        None => {
            install_ui::phase("Provide the registry auth token");
            cliclack::password(format!("Paste {registry_url} token"))
                .mask('*')
                .interact()
                .map_err(|e| LpmError::Registry(e.to_string()))?
        }
    };

    store_builtin_token(
        registry_url,
        token,
        "explicit-token",
        json_output,
        false,
        |token| auth::set_custom_registry_token_with_backend(registry_url, token),
    )
}

fn store_builtin_token(
    registry_display: &str,
    token: String,
    source: &str,
    json_output: bool,
    supports_otp_metadata: bool,
    store: impl FnOnce(&str) -> Result<auth::AuthStorageBackend, String>,
) -> Result<(), LpmError> {
    if token.is_empty() {
        return Err(LpmError::Registry("token cannot be empty".into()));
    }

    let metadata = token_metadata(registry_display, json_output, supports_otp_metadata);
    auth::clear_token_expiry(registry_display);
    let storage_backend =
        store(&token).map_err(|e| LpmError::Registry(format!("failed to store token: {e}")))?;
    let storage_status = auth::AuthStorageStatus::from_backend(storage_backend);

    if metadata.otp_required {
        auth::set_otp_required(registry_display, true);
    }

    if let Some(days) = metadata.expiry_days {
        let expires_date = chrono::Utc::now() + chrono::Duration::days(days as i64);
        let expires_iso = expires_date.format("%Y-%m-%d").to_string();
        auth::set_token_expiry(registry_display, &expires_iso);

        if !json_output {
            let expires_human = expires_date.format("%B %-d, %Y").to_string();
            let otp_note = if metadata.otp_required {
                ", 2FA enabled"
            } else {
                ""
            };
            install_ui::done(&format!(
                "Token stored for {} (reminder: {}{otp_note})",
                registry_display.bold(),
                expires_human.dimmed()
            ));
            render_storage_backend(storage_status);
            return Ok(());
        }
    }

    if json_output {
        println!(
            "{}",
            serde_json::json!({
                "success": true,
                "registry": registry_display,
                "source": source,
                "stored": true,
                "otp_required": metadata.otp_required,
                "storage_backend": storage_status.backend_json_value(),
                "storage_degraded": storage_status.degraded,
            })
        );
    } else {
        let otp_note = if metadata.otp_required {
            " (2FA enabled)"
        } else {
            ""
        };
        install_ui::done(&format!(
            "Token stored for {}{otp_note}",
            registry_display.bold()
        ));
        render_storage_backend(storage_status);
    }

    Ok(())
}

fn render_storage_backend(storage_status: auth::AuthStorageStatus) {
    if let Some(label) = storage_status.human_label() {
        install_ui::detail(&format!("secure storage backend: {label}"));
    }
    if storage_status.degraded {
        install_ui::warn(
            "Encrypted file fallback is active; unlock or repair the OS keychain and run login again to use keychain storage.",
        );
    }
}

#[derive(Default)]
struct TokenMetadata {
    expiry_days: Option<u32>,
    otp_required: bool,
}

fn token_metadata(
    registry_display: &str,
    json_output: bool,
    supports_otp_metadata: bool,
) -> TokenMetadata {
    if json_output || !std::io::stdin().is_terminal() {
        return TokenMetadata::default();
    }

    let days: String = cliclack::input("Token expiry reminder (days, or skip)")
        .placeholder("30")
        .default_input("30")
        .interact()
        .unwrap_or_default();
    let expiry_days = days.parse().ok();

    let otp_required = supports_otp_metadata
        && cliclack::confirm(format!(
            "Does this {registry_display} account use 2FA / OTP for publishing?"
        ))
        .initial_value(false)
        .interact()
        .unwrap_or(false);

    TokenMetadata {
        expiry_days,
        otp_required,
    }
}

fn env_npm_token() -> Option<String> {
    std::env::var("NPM_TOKEN")
        .ok()
        .filter(|token| !token.is_empty())
}

fn print_success_json(
    registry: &str,
    source: &str,
    stored: bool,
    storage_status: Option<auth::AuthStorageStatus>,
) {
    let storage_status = storage_status.unwrap_or_else(auth::AuthStorageStatus::none);
    println!(
        "{}",
        serde_json::json!({
            "success": true,
            "registry": registry,
            "source": source,
            "stored": stored,
            "storage_backend": storage_status.backend_json_value(),
            "storage_degraded": storage_status.degraded,
        })
    );
}

fn npm_web_auth_client() -> Result<reqwest::Client, LpmError> {
    reqwest::Client::builder()
        .user_agent(format!("lpm-rs/{}", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| LpmError::Registry(format!("failed to create HTTP client: {e}")))
}
