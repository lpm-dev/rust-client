use crate::{auth, install_ui, output};
use lpm_auth::AuthRequirement;
use lpm_common::LpmError;
use lpm_registry::RegistryClient;
use std::sync::Arc;

pub(crate) struct LogoutTargets<'a> {
    pub clear_lpm: bool,
    pub npm: bool,
    pub github: bool,
    pub gitlab: bool,
    pub custom_registry: Option<&'a str>,
    pub all_custom_registries: bool,
}

pub async fn run(
    client: &RegistryClient,
    session: &Arc<lpm_auth::SessionManager>,
    registry_url: &str,
    revoke: bool,
    json_output: bool,
    targets: LogoutTargets<'_>,
) -> Result<(), LpmError> {
    let environment_credential_active =
        targets.clear_lpm && std::env::var("LPM_TOKEN").is_ok_and(|token| !token.is_empty());
    let had_access = targets.clear_lpm && auth::has_stored_access_token(registry_url);
    let had_refresh = targets.clear_lpm && auth::has_refresh_token(registry_url);
    let had_lpm_session = had_access || had_refresh;

    if had_lpm_session && !json_output {
        install_ui::phase_line(crate::install_ui::terminal_line!(
            "Clearing stored {} session",
            install_ui::yellow("lpm.dev")
        ));
    }

    let mut pairings_revoked = false;
    let mut server_revoked = false;
    let mut errors = Vec::with_capacity(3);

    if targets.clear_lpm && revoke && had_lpm_session {
        let stored_session = Arc::new(session.stored_session_only());
        match stored_session
            .bearer_string_for(AuthRequirement::SessionRequired)
            .await
        {
            Ok(_) => {
                let revocation_client = client.clone_with_session_only(stored_session);
                match revocation_client.revoke_all_pairings().await {
                    Ok(()) => {
                        pairings_revoked = true;
                        if !json_output {
                            install_ui::done("Revoked browser pairings");
                        }
                    }
                    Err(error) => {
                        errors.push(bounded_error("pairing revocation", &error.to_string()));
                    }
                }

                match revocation_client.revoke_session().await {
                    Ok(()) => {
                        server_revoked = true;
                        if !json_output {
                            install_ui::done("Revoked server-side CLI session");
                        }
                    }
                    Err(error) => {
                        errors.push(bounded_error("session revocation", &error.to_string()));
                    }
                }
            }
            Err(_) => errors.push(
                "session revocation: the stored credential is not a refresh-backed CLI session"
                    .to_string(),
            ),
        }
    }

    let mut local_cleared = true;
    if targets.clear_lpm {
        record_local_clear(
            auth::clear_login_state(registry_url),
            "LPM.dev local credential clearing",
            &mut local_cleared,
            &mut errors,
        );
        if environment_credential_active {
            local_cleared = false;
            errors.push(
                "LPM.dev local credential clearing: LPM_TOKEN remains active in the parent process; unset LPM_TOKEN in that shell or CI environment"
                    .to_string(),
            );
        }
    }
    if targets.npm {
        let cleared = record_local_clear(
            auth::clear_npm_token(),
            "npm local credential clearing",
            &mut local_cleared,
            &mut errors,
        );
        if cleared && !json_output {
            output::success("Logged out from npmjs.org");
        }
        auth::clear_token_expiry("npmjs.org");
    }
    if targets.github {
        let cleared = record_local_clear(
            auth::clear_github_token(),
            "GitHub Packages local credential clearing",
            &mut local_cleared,
            &mut errors,
        );
        if cleared && !json_output {
            output::success(
                "Logged out from GitHub Packages fallback token (GitHub CLI auth is managed by gh)",
            );
        }
        auth::clear_token_expiry("github.com");
    }
    if targets.gitlab {
        let cleared = record_local_clear(
            auth::clear_gitlab_token(),
            "GitLab Packages local credential clearing",
            &mut local_cleared,
            &mut errors,
        );
        if cleared && !json_output {
            output::success(
                "Logged out from GitLab Packages fallback token (GitLab CLI auth is managed by glab)",
            );
        }
        auth::clear_token_expiry("gitlab.com");
    }
    if let Some(url) = targets.custom_registry {
        let cleared = record_local_clear(
            auth::clear_custom_registry_token(url),
            "custom registry local credential clearing",
            &mut local_cleared,
            &mut errors,
        );
        if cleared && !json_output {
            output::success_line(crate::install_ui::terminal_line!(
                "Logged out from {}",
                crate::install_ui::url(url),
            ));
        }
    }
    if targets.all_custom_registries {
        for (url, result) in auth::clear_all_custom_registries() {
            let operation = format!("custom registry {url} local credential clearing");
            let cleared = record_local_clear(result, &operation, &mut local_cleared, &mut errors);
            if cleared && !json_output {
                output::success_line(crate::install_ui::terminal_line!(
                    "Logged out from {}",
                    crate::install_ui::url(&url),
                ));
            }
        }
    }

    let success = errors.is_empty() && local_cleared;
    let result = LogoutResult {
        success,
        revoke_requested: revoke,
        pairings_revoked,
        server_revoked,
        local_cleared,
        registry: registry_url,
        errors,
        lpm_requested: targets.clear_lpm,
    };
    emit_result(result, json_output, !had_lpm_session);

    if success {
        Ok(())
    } else {
        Err(LpmError::ExitCode(1))
    }
}

fn record_local_clear(
    result: Result<(), String>,
    operation: &str,
    local_cleared: &mut bool,
    errors: &mut Vec<String>,
) -> bool {
    match result {
        Ok(()) => true,
        Err(error) => {
            *local_cleared = false;
            errors.push(bounded_error(operation, &error));
            false
        }
    }
}

struct LogoutResult<'a> {
    success: bool,
    revoke_requested: bool,
    pairings_revoked: bool,
    server_revoked: bool,
    local_cleared: bool,
    registry: &'a str,
    errors: Vec<String>,
    lpm_requested: bool,
}

fn emit_result(result: LogoutResult<'_>, json_output: bool, already_logged_out: bool) {
    if json_output {
        println!(
            "{}",
            serde_json::json!({
                "success": result.success,
                "revoke_requested": result.revoke_requested,
                "pairings_revoked": result.pairings_revoked,
                "server_revoked": result.server_revoked,
                "local_cleared": result.local_cleared,
                "registry": result.registry,
                "errors": result.errors,
            })
        );
        return;
    }

    if already_logged_out && result.lpm_requested {
        install_ui::phase_line(crate::install_ui::terminal_line!(
            "No stored {} session",
            install_ui::yellow("lpm.dev")
        ));
    } else if result.lpm_requested {
        if result.local_cleared {
            if result.success {
                install_ui::done_line(crate::install_ui::terminal_line!(
                    "Done · signed out of {}",
                    install_ui::yellow("lpm.dev")
                ));
            } else {
                install_ui::done("Local credentials were cleared");
            }
        } else {
            install_ui::warn("Local credentials could not be fully cleared");
        }
    }

    for error in &result.errors {
        install_ui::warn_untrusted(error);
    }
}

fn bounded_error(operation: &str, error: &str) -> String {
    let sanitized = lpm_common::sanitize_terminal_inline(error);
    let detail: String = sanitized.chars().take(300).collect();
    format!("{operation}: {detail}")
}
