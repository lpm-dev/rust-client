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

	if token.is_none() {
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
		if let Err(e) = client.revoke_token().await {
			if !json_output {
				output::warn(&format!("Token revocation failed: {}", e.to_string().dimmed()));
			}
		}
	}

	// Clear local token
	auth::clear_token(registry_url)
		.map_err(|e| LpmError::Registry(format!("failed to clear token: {e}")))?;

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
