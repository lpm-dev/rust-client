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
    let mut errors = Vec::with_capacity(5);
    let mut lpm_session_presence_known = true;
    let had_access = if targets.clear_lpm {
        match auth::has_stored_access_token_checked(registry_url) {
            Ok(present) => present,
            Err(error) => {
                lpm_session_presence_known = false;
                errors.push(bounded_error("stored session presence", &error));
                false
            }
        }
    } else {
        false
    };
    let had_refresh = if targets.clear_lpm {
        match auth::has_refresh_token_checked(registry_url) {
            Ok(present) => present,
            Err(error) => {
                lpm_session_presence_known = false;
                errors.push(bounded_error("stored session presence", &error));
                false
            }
        }
    } else {
        false
    };
    let had_lpm_session = had_access || had_refresh;

    if had_lpm_session && !json_output {
        install_ui::phase_line(crate::install_ui::terminal_line!(
            "Clearing stored {} session",
            install_ui::yellow("lpm.dev")
        ));
    }

    let mut pairings_revoked = false;
    let mut server_revoked = false;

    if targets.clear_lpm && revoke && had_lpm_session && lpm_session_presence_known {
        let stored_session = Arc::new(session.stored_session_only());
        match stored_session
            .bearer_string_for(AuthRequirement::SessionRequired)
            .await
        {
            Ok(_) => {
                let revocation_client = client.clone_with_session_only(stored_session);
                match revoke_pairings(&revocation_client).await {
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
            auth::clear_login_state_async(registry_url).await,
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
        let credential_cleared = record_local_clear(
            auth::clear_npm_token(),
            "npm local credential clearing",
            &mut local_cleared,
            &mut errors,
        );
        let metadata_cleared = record_local_clear(
            auth::clear_token_expiry_checked("npmjs.org"),
            "npm local expiry metadata clearing",
            &mut local_cleared,
            &mut errors,
        );
        if credential_cleared && metadata_cleared && !json_output {
            output::success("Logged out from npmjs.org");
        }
    }
    if targets.github {
        let credential_cleared = record_local_clear(
            auth::clear_github_token(),
            "GitHub Packages local credential clearing",
            &mut local_cleared,
            &mut errors,
        );
        let metadata_cleared = record_local_clear(
            auth::clear_token_expiry_checked("github.com"),
            "GitHub Packages local expiry metadata clearing",
            &mut local_cleared,
            &mut errors,
        );
        if credential_cleared && metadata_cleared && !json_output {
            output::success(
                "Logged out from GitHub Packages fallback token (GitHub CLI auth is managed by gh)",
            );
        }
    }
    if targets.gitlab {
        let credential_cleared = record_local_clear(
            auth::clear_gitlab_token(),
            "GitLab Packages local credential clearing",
            &mut local_cleared,
            &mut errors,
        );
        let metadata_cleared = record_local_clear(
            auth::clear_token_expiry_checked("gitlab.com"),
            "GitLab Packages local expiry metadata clearing",
            &mut local_cleared,
            &mut errors,
        );
        if credential_cleared && metadata_cleared && !json_output {
            output::success(
                "Logged out from GitLab Packages fallback token (GitLab CLI auth is managed by glab)",
            );
        }
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
        let result = auth::clear_all_custom_registries();
        for (url, result) in result.registries {
            let operation = format!("custom registry {url} local credential clearing");
            let cleared = record_local_clear(result, &operation, &mut local_cleared, &mut errors);
            if cleared && !json_output {
                output::success_line(crate::install_ui::terminal_line!(
                    "Logged out from {}",
                    crate::install_ui::url(&url),
                ));
            }
        }
        record_local_clear(
            result.tracking_cleanup,
            "custom registry tracking cleanup",
            &mut local_cleared,
            &mut errors,
        );
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
    emit_result(
        result,
        json_output,
        lpm_session_presence_known && !had_lpm_session,
    );

    if success {
        Ok(())
    } else {
        Err(LpmError::ExitCode(1))
    }
}

async fn revoke_pairings(client: &RegistryClient) -> Result<(), LpmError> {
    let expected_principal_id = crate::commands::env::auth::execute_sync_with_bearer(
        client,
        |registry_url, auth_token| async move {
            lpm_vault::sync::get_my_public_key_state(&registry_url, &auth_token).await
        },
    )
    .await?
    .principal_id;

    crate::commands::env::auth::execute_sync_with_bearer(client, |registry_url, auth_token| {
        let expected_principal_id = expected_principal_id.clone();
        async move {
            lpm_vault::sync::unpair_all(&registry_url, &auth_token, &expected_principal_id).await
        }
    })
    .await
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
