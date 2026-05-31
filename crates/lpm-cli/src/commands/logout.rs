use crate::{auth, install_ui};
use lpm_common::LpmError;
use lpm_registry::RegistryClient;

pub async fn run(
    client: &RegistryClient,
    registry_url: &str,
    revoke: bool,
    json_output: bool,
) -> Result<(), LpmError> {
    let token = auth::get_token(registry_url);
    let has_refresh = auth::has_refresh_token(registry_url);

    if token.is_none() && !has_refresh {
        if !json_output {
            install_ui::phase(&format!(
                "No stored {} session",
                install_ui::yellow("lpm.dev")
            ));
        }
        return Ok(());
    }

    if !json_output {
        install_ui::phase(&format!(
            "Clearing stored {} session",
            install_ui::yellow("lpm.dev")
        ));
    }

    // Optionally revoke on server
    if revoke {
        // Best-effort: don't fail logout if revocation fails
        match client.revoke_token().await {
            Ok(()) if !json_output => install_ui::done("Revoked server-side token"),
            Err(e) if !json_output => install_ui::warn(&format!(
                "Token revocation failed: {}",
                install_ui::dim(&e.to_string())
            )),
            _ => {}
        }
    }

    // Revoke all browser pairings (best-effort — don't block logout on failure).
    // Only attempt if user has a session (refresh token). Legacy tokens never had
    // pairings, and the server rejects non-session tokens on this endpoint.
    if has_refresh
        && let Some(ref t) = token
        && let Err(e) = lpm_vault::sync::unpair_all(registry_url, t).await
        && !json_output
    {
        install_ui::warn(&format!(
            "Failed to revoke browser pairings: {}",
            install_ui::dim(&e)
        ));
    }

    auth::clear_login_state(registry_url)
        .map_err(|e| LpmError::Registry(format!("failed to clear login state: {e}")))?;

    if json_output {
        let json = serde_json::json!({
            "success": true,
            "revoked": revoke,
            "registry": registry_url,
        });
        println!("{}", serde_json::to_string_pretty(&json).unwrap());
    } else {
        install_ui::done(&format!(
            "Done · signed out of {}",
            install_ui::yellow("lpm.dev")
        ));
    }

    Ok(())
}
