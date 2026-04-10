use crate::{auth, output};
use lpm_common::LpmError;
use lpm_registry::RegistryClient;
use owo_colors::OwoColorize;

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
            output::info("Not currently logged in.");
        }
        return Ok(());
    }

    // Optionally revoke on server
    if revoke {
        if !json_output {
            output::info("Revoking token on server...");
        }
        // Best-effort: don't fail logout if revocation fails
        if let Err(e) = client.revoke_token().await
            && !json_output
        {
            output::warn(&format!(
                "Token revocation failed: {}",
                e.to_string().dimmed()
            ));
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
        output::warn(&format!(
            "Failed to revoke browser pairings: {}",
            e.to_string().dimmed()
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
        println!();
        output::success("Successfully logged out.");
        if revoke {
            println!("  {}", "Token revoked on server".dimmed());
        }
        println!();
    }

    Ok(())
}
