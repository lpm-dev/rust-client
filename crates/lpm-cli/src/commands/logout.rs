use crate::{auth, install_ui};
use lpm_common::LpmError;
use lpm_registry::RegistryClient;
use std::sync::Arc;

pub async fn run(
    client: &RegistryClient,
    session: &Arc<lpm_auth::SessionManager>,
    registry_url: &str,
    revoke: bool,
    json_output: bool,
) -> Result<(), LpmError> {
    let had_access = auth::get_token(registry_url).is_some();
    let had_refresh = auth::has_refresh_token(registry_url);

    if !had_access && !had_refresh {
        emit_result(
            LogoutResult {
                success: true,
                revoke_requested: revoke,
                pairings_revoked: false,
                server_revoked: false,
                local_cleared: true,
                registry: registry_url,
                errors: Vec::new(),
            },
            json_output,
            true,
        );
        return Ok(());
    }

    if !json_output {
        install_ui::phase_line(crate::install_ui::terminal_line!(
            "Clearing stored {} session",
            install_ui::yellow("lpm.dev")
        ));
    }

    let mut pairings_revoked = false;
    let mut server_revoked = false;
    let mut errors = Vec::with_capacity(3);

    if revoke {
        match session
            .bearer_string_for(lpm_auth::AuthRequirement::SessionRequired)
            .await
        {
            Ok(bearer) => {
                match lpm_vault::sync::unpair_all(registry_url, &bearer).await {
                    Ok(()) => {
                        pairings_revoked = true;
                        if !json_output {
                            install_ui::done("Revoked browser pairings");
                        }
                    }
                    Err(error) => {
                        errors.push(bounded_error("pairing revocation", &error));
                    }
                }

                match client.revoke_session().await {
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

    let local_cleared = match auth::clear_login_state(registry_url) {
        Ok(()) => true,
        Err(error) => {
            errors.push(bounded_error("local credential clearing", &error));
            false
        }
    };

    let success = errors.is_empty() && local_cleared;
    let result = LogoutResult {
        success,
        revoke_requested: revoke,
        pairings_revoked,
        server_revoked,
        local_cleared,
        registry: registry_url,
        errors,
    };
    emit_result(result, json_output, false);

    if success {
        Ok(())
    } else {
        Err(LpmError::ExitCode(1))
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

    if already_logged_out {
        install_ui::phase_line(crate::install_ui::terminal_line!(
            "No stored {} session",
            install_ui::yellow("lpm.dev")
        ));
        return;
    }

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
    for error in &result.errors {
        install_ui::warn_untrusted(error);
    }
}

fn bounded_error(operation: &str, error: &str) -> String {
    let sanitized = lpm_common::sanitize_terminal_inline(error);
    let detail: String = sanitized.chars().take(300).collect();
    format!("{operation}: {detail}")
}
