use crate::commands::web_auth;
use crate::prompt::PromptResultExt as _;
use crate::{auth, install_ui};
use lpm_common::LpmError;
use std::io::IsTerminal;
use std::time::Duration;

const NPM_REGISTRY_URL: &str = "https://registry.npmjs.org";
const NPM_DISPLAY: &str = "npmjs.org";
const GITHUB_DISPLAY: &str = "github.com";
const GITLAB_DISPLAY: &str = "gitlab.com";

/// `lpm login --socket`: checks the token with Socket, stores it, and turns
/// the Socket check of dependency skills on.
pub async fn run_socket(token: Option<String>, json_output: bool) -> Result<(), LpmError> {
    let token = match token {
        Some(token) => token,
        None if !json_output && std::io::stdin().is_terminal() => {
            cliclack::password("Socket API token (an organization token with packages:list)")
                .interact()
                .map_prompt_err(|e| LpmError::Script(format!("token prompt failed: {e}")))?
        }
        None => {
            return Err(LpmError::Registry(format!(
                "pass the Socket API token with `--token`; or set SOCKET_CLI_API_TOKEN instead of storing one, and turn the check on with `lpm config set {} socket`",
                crate::lpm_skills_config::SECURITY_PROVIDER_SETTING
            )));
        }
    };
    let token = token.trim();
    if token.is_empty() {
        return Err(LpmError::Registry("token cannot be empty".into()));
    }
    let organization = crate::dependency_skills::socket_organization(token)
        .await
        .map_err(|reason| LpmError::Registry(format!("Socket refused the token: {reason}")))?;
    let backend = auth::set_socket_token_with_backend(token)
        .map_err(|e| LpmError::Registry(format!("failed to store token: {e}")))?;
    crate::dependency_skills::socket_credentials_changed();
    crate::commands::config::set_skill_security_provider(
        crate::lpm_skills_config::SecurityProvider::Socket,
    )
    .await?;
    let storage = auth::AuthStorageStatus::from_backend(backend);
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "success": true,
                "provider": "socket",
                "organization": organization,
                "storage_backend": storage.backend_json_value(),
                "storage_degraded": storage.degraded,
            }))
            .map_err(|e| LpmError::Registry(format!("failed to serialize login result: {e}")))?
        );
    } else {
        install_ui::done_untrusted(&format!(
            "Socket token stored for {organization}; installs check the packages behind npm and other dependency skills with Socket before linking them"
        ));
        render_storage_backend(storage);
    }
    Ok(())
}

/// `client` is the registry client the web login's requests take their
/// `.npmrc` TLS settings from; a token given outright needs no request.
pub async fn run_npm(
    client: &lpm_registry::RegistryClient,
    token: Option<String>,
    json_output: bool,
) -> Result<(), LpmError> {
    if let Some(token) = token {
        return store_builtin_token(
            NPM_DISPLAY,
            &token,
            "explicit-token",
            json_output,
            true,
            auth::set_npm_token_with_backend,
        );
    }
    if let Some(token) = env_npm_token() {
        return store_builtin_token(
            NPM_DISPLAY,
            &token,
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

    let current_dir = std::env::current_dir().map_err(LpmError::Io)?;
    let tls = crate::commands::registry_reads::registry_client_for_directory(
        client,
        &current_dir,
        crate::commands::registry_reads::RegistryReads::NONE,
        json_output,
    )?;
    let http = npm_web_auth_client(tls.tls_client_builder_for(NPM_REGISTRY_URL).await?)?;
    let challenge = web_auth::fetch_npm_web_login_challenge(&http, NPM_REGISTRY_URL).await?;
    let token = web_auth::complete_web_auth_challenge(
        &tls,
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
        install_ui::done_line(crate::install_ui::terminal_line!(
            "Logged in to {} with npm web auth",
            install_ui::bold(NPM_DISPLAY)
        ));
        render_storage_backend(auth::AuthStorageStatus::from_backend(storage_backend));
    }

    Ok(())
}

pub fn run_github(
    token: Option<String>,
    save_env_token: bool,
    json_output: bool,
) -> Result<(), LpmError> {
    if let Some(token) = token {
        return store_builtin_token(
            GITHUB_DISPLAY,
            &token,
            "explicit-token",
            json_output,
            true,
            auth::set_github_token_with_backend,
        );
    }

    if save_env_token {
        let credential = auth::resolve_github_environment_credential().ok_or(
            LpmError::CredentialImportUnavailable {
                command: "lpm login --github --save-env-token",
                expected: "GITHUB_TOKEN",
            },
        )?;
        let source = credential.source();
        return credential.with_exposed_token(|token| {
            store_builtin_token(
                GITHUB_DISPLAY,
                token,
                source.as_json_value(),
                json_output,
                true,
                auth::set_github_token_with_backend,
            )
        });
    }

    let credential = auth::resolve_github_credential().ok_or_else(|| {
        LpmError::Registry(
            "GitHub Packages auth is not available. Set GITHUB_TOKEN, run `gh auth login --hostname github.com`, or pass `--token <token>`.".into(),
        )
    })?;
    report_available_auth(GITHUB_DISPLAY, credential.source(), json_output);

    Ok(())
}

pub fn run_gitlab(
    token: Option<String>,
    save_env_token: bool,
    json_output: bool,
) -> Result<(), LpmError> {
    if let Some(token) = token {
        return store_builtin_token(
            GITLAB_DISPLAY,
            &token,
            "explicit-token",
            json_output,
            true,
            auth::set_gitlab_token_with_backend,
        );
    }

    if save_env_token {
        let credential = auth::resolve_gitlab_environment_credential().ok_or(
            LpmError::CredentialImportUnavailable {
                command: "lpm login --gitlab --save-env-token",
                expected: "GITLAB_TOKEN",
            },
        )?;
        let source = credential.source();
        if source == auth::ThirdPartyCredentialSource::GitlabCiJob {
            return Err(LpmError::CredentialImportRejected {
                command: "lpm login --gitlab --save-env-token",
                auth_source: "CI_JOB_TOKEN",
            });
        }
        return credential.with_exposed_token(|token| {
            store_builtin_token(
                GITLAB_DISPLAY,
                token,
                source.as_json_value(),
                json_output,
                true,
                auth::set_gitlab_token_with_backend,
            )
        });
    }

    let credential = auth::resolve_gitlab_credential_for_host("https://gitlab.com").ok_or_else(
        || {
            LpmError::Registry(
                "GitLab Packages auth is not available. Set GITLAB_TOKEN or CI_JOB_TOKEN, run `glab auth login`, or pass `--token <token>`.".into(),
            )
        },
    )?;
    report_available_auth(GITLAB_DISPLAY, credential.source(), json_output);

    Ok(())
}

pub fn run_custom(
    registry_url: &str,
    token: Option<String>,
    json_output: bool,
) -> Result<(), LpmError> {
    lpm_auth::validate_custom_registry_url_for_storage(registry_url).map_err(LpmError::Registry)?;
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
            cliclack::password(crate::prompt::untrusted(format!(
                "Paste {registry_url} token"
            )))
            .mask('*')
            .interact()
            .map_prompt_err(|e| LpmError::Registry(e.to_string()))?
        }
    };

    store_builtin_token(
        registry_url,
        &token,
        "explicit-token",
        json_output,
        false,
        |token| auth::set_custom_registry_token_with_backend(registry_url, token),
    )
}

fn store_builtin_token(
    registry_display: &str,
    token: &str,
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
        store(token).map_err(|e| LpmError::Registry(format!("failed to store token: {e}")))?;
    let storage_status = auth::AuthStorageStatus::from_backend(storage_backend);

    if metadata.otp_required {
        auth::set_otp_required(registry_display, true);
    }

    let reminder = metadata.expiry_days.and_then(|days| {
        lpm_common::Timestamp::now()
            .checked_add(lpm_common::timestamp::Duration::days(i64::from(days)))
    });
    if let Some(expires_date) = reminder {
        let expires_on = expires_date.date();
        let expires_iso = expires_on.to_string();
        auth::set_token_expiry(registry_display, &expires_iso);

        if !json_output {
            let expires_human = format!(
                "{} {}, {}",
                expires_on.month(),
                expires_on.day(),
                expires_on.year()
            );
            let otp_note = if metadata.otp_required {
                ", 2FA enabled"
            } else {
                ""
            };
            install_ui::done_line(crate::install_ui::terminal_line!(
                "Token stored for {} (reminder: {}{})",
                install_ui::bold(registry_display),
                install_ui::dim(&expires_human),
                otp_note,
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
        install_ui::done_line(crate::install_ui::terminal_line!(
            "Token stored for {}{}",
            install_ui::bold(registry_display),
            otp_note,
        ));
        render_storage_backend(storage_status);
    }

    Ok(())
}

fn report_available_auth(
    registry_display: &str,
    source: auth::ThirdPartyCredentialSource,
    json_output: bool,
) {
    let storage_status = source.storage_status();
    if json_output {
        print_success_json(
            registry_display,
            source.as_json_value(),
            source.is_stored(),
            source.is_stored().then_some(storage_status),
        );
        return;
    }

    if source.is_stored() {
        install_ui::done_line(crate::install_ui::terminal_line!(
            "Stored auth is available for {}",
            install_ui::bold(registry_display),
        ));
        render_storage_backend(storage_status);
    } else {
        install_ui::done_line(crate::install_ui::terminal_line!(
            "Auth is available for {} through {}; no LPM token was stored",
            install_ui::bold(registry_display),
            install_ui::bold(source.as_json_value()),
        ));
    }
}

fn render_storage_backend(storage_status: auth::AuthStorageStatus) {
    if let Some(label) = storage_status.human_label() {
        install_ui::detail_untrusted(&format!("secure storage backend: {label}"));
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
        && cliclack::confirm(crate::prompt::untrusted(format!(
            "Does this {registry_display} account use 2FA / OTP for publishing?"
        )))
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

fn npm_web_auth_client(builder: reqwest::ClientBuilder) -> Result<reqwest::Client, LpmError> {
    builder
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(format!("lpm-rs/{}", crate::build_version::version()))
        .build()
        .map_err(|e| LpmError::Registry(format!("failed to create HTTP client: {e}")))
}

#[cfg(test)]
mod tests {
    #[test]
    fn custom_registry_storage_validator_rejects_userinfo_query_and_fragment() {
        for bad in [
            "https://user:secret@registry.example/npm",
            "https://registry.example/npm?token=abc",
            "https://registry.example/npm#frag",
            "ftp://registry.example/npm",
        ] {
            assert!(
                lpm_auth::validate_custom_registry_url_for_storage(bad).is_err(),
                "expected rejection for {bad}"
            );
        }
        assert!(
            lpm_auth::validate_custom_registry_url_for_storage("https://registry.example/npm")
                .is_ok()
        );
    }
}
