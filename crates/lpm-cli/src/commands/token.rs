use crate::install_ui;
use lpm_common::LpmError;
use lpm_common::color::Painted;
use lpm_registry::{RegistryClient, parse_capped_api_json};

/// Rotate the current token (create new, revoke old).
pub async fn run_rotate(
    client: &RegistryClient,
    registry_url: &str,
    json_output: bool,
) -> Result<(), LpmError> {
    if !json_output {
        install_ui::phase(&format!("Rotating {} token", install_ui::yellow("lpm.dev")));
    }

    // The server handles rotation: POST creates new token and invalidates old
    let url = format!("{}/api/registry/-/token/rotate", registry_url);

    let response = client.post_json_raw(&url, &serde_json::json!({})).await?;

    let body: serde_json::Value =
        parse_capped_api_json(response, "token rotation response").await?;

    if let Some(new_token) = body.get("token").and_then(|t| t.as_str()) {
        // Store the new token
        let storage_backend = crate::auth::set_token_with_backend(registry_url, new_token)
            .map_err(|e| LpmError::Registry(format!("failed to store new token: {e}")))?;
        let storage_status = crate::auth::AuthStorageStatus::from_backend(storage_backend);

        // Store token expiry metadata (Feature 42)
        if let Some(expires) = body.get("expiresAt").and_then(|e| e.as_str()) {
            let date_part = expires.split('T').next().unwrap_or(expires);
            crate::auth::set_token_expiry(registry_url, date_part);
        }

        if json_output {
            let json = serde_json::json!({
                "success": true,
                "rotated": true,
                "expires_at": body.get("expiresAt"),
                "storage_backend": storage_status.backend_json_value(),
                "storage_degraded": storage_status.degraded,
            });
            println!("{}", serde_json::to_string_pretty(&json).unwrap());
        } else {
            install_ui::done("Old token invalidated");
            install_ui::done("New token stored");
            if let Some(label) = storage_status.human_label() {
                install_ui::detail(&format!("secure storage backend: {label}"));
            }
            if storage_status.degraded {
                install_ui::warn(
                    "Encrypted file fallback is active; unlock or repair the OS keychain and rotate again to use keychain storage.",
                );
            }
            install_ui::done("Done · session token rotated successfully");
            if let Some(expires) = body.get("expiresAt").and_then(|e| e.as_str()) {
                eprintln!("  {} {}", "Expires:".dimmed(), expires.dimmed());
            }
            eprintln!();
        }
    } else {
        let error = body
            .get("error")
            .and_then(|e| e.as_str())
            .unwrap_or("unknown error");
        return Err(LpmError::Registry(format!(
            "token rotation failed: {error}"
        )));
    }

    Ok(())
}
