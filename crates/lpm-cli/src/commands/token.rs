use crate::output;
use lpm_common::LpmError;
use lpm_registry::RegistryClient;
use owo_colors::OwoColorize;

/// Rotate the current token (create new, revoke old).
pub async fn run_rotate(
    client: &RegistryClient,
    registry_url: &str,
    json_output: bool,
) -> Result<(), LpmError> {
    if !json_output {
        output::info("Rotating token...");
    }

    // The server handles rotation: POST creates new token and invalidates old
    let url = format!("{}/api/registry/-/token/rotate", registry_url);

    let response = client.post_json_raw(&url, &serde_json::json!({})).await?;

    let body: serde_json::Value = response
        .json()
        .await
        .map_err(|e| LpmError::Registry(format!("failed to parse response: {e}")))?;

    if let Some(new_token) = body.get("token").and_then(|t| t.as_str()) {
        // Store the new token
        crate::auth::set_token(registry_url, new_token)
            .map_err(|e| LpmError::Registry(format!("failed to store new token: {e}")))?;

        if json_output {
            let json = serde_json::json!({
                "success": true,
                "rotated": true,
                "expires_at": body.get("expiresAt"),
            });
            println!("{}", serde_json::to_string_pretty(&json).unwrap());
        } else {
            output::success("Token rotated successfully");
            if let Some(expires) = body.get("expiresAt").and_then(|e| e.as_str()) {
                println!("  Expires: {}", expires.dimmed());
            }
            println!();
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
