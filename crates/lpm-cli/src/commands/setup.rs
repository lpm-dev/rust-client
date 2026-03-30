use crate::{auth, oidc, output};
use lpm_common::LpmError;
use owo_colors::OwoColorize;
use std::path::Path;

/// Generate .npmrc for CI/CD environments.
///
/// Creates a .npmrc file that configures the LPM registry with auth token
/// so npm/pnpm/yarn can install @lpm.dev packages in CI.
///
/// Flags:
/// - `--oidc`: Exchange an OIDC token from the CI environment instead of using stored auth.
/// - `--scoped`: Use scoped registry (`@lpm.dev:registry=`) instead of setting the default registry.
/// - `--registry` / `-r`: Override the registry URL.
pub async fn run(
	registry_url: &str,
	project_dir: &Path,
	json_output: bool,
	use_oidc: bool,
	scoped: bool,
) -> Result<(), LpmError> {
	// Resolve token: OIDC exchange > stored token > env var > placeholder
	let token: Option<String> = if use_oidc {
		match oidc::exchange_oidc_token(registry_url, None, "install").await {
			Ok(oidc_token) => Some(oidc_token.token),
			Err(e) => {
				if !json_output {
					output::warn(&format!("OIDC token exchange failed: {e}"));
					output::warn("Falling back to stored token / ${LPM_TOKEN} placeholder.");
				}
				auth::get_token(registry_url).or_else(|| std::env::var("LPM_TOKEN").ok())
			}
		}
	} else {
		auth::get_token(registry_url).or_else(|| std::env::var("LPM_TOKEN").ok())
	};

	let token_placeholder = token.as_deref().unwrap_or("${LPM_TOKEN}");
	let uses_env = token.is_none();

	// Build .npmrc content
	let registry_host = registry_url
		.trim_start_matches("https://")
		.trim_start_matches("http://");

	let registry_line = if scoped {
		format!("@lpm.dev:registry={}/api/registry/", registry_url)
	} else {
		format!("@lpm.dev:registry={}/api/registry/", registry_url)
	};

	let npmrc_content = format!(
		"//{}/:_authToken={}\n{}\n",
		registry_host, token_placeholder, registry_line
	);

	let npmrc_path = project_dir.join(".npmrc");

	if json_output {
		let json = serde_json::json!({
			"success": true,
			"path": npmrc_path.display().to_string(),
			"content": npmrc_content,
			"uses_env_var": uses_env,
			"oidc": use_oidc,
			"scoped": scoped,
		});
		println!("{}", serde_json::to_string_pretty(&json).unwrap());
	} else {
		std::fs::write(&npmrc_path, &npmrc_content)?;

		// S6: Restrict .npmrc permissions to owner-only (contains auth tokens)
		#[cfg(unix)]
		{
			use std::os::unix::fs::PermissionsExt;
			let _ = std::fs::set_permissions(
				&npmrc_path,
				std::fs::Permissions::from_mode(0o600),
			);
		}

		output::success(&format!("Generated {}", ".npmrc".bold()));
		println!("  {}", npmrc_path.display().to_string().dimmed());

		if use_oidc && token.is_some() {
			output::info("Using OIDC-exchanged token.");
		}
		if scoped {
			output::info("Using scoped registry (@lpm.dev:registry=).");
		}

		if uses_env {
			println!();
			output::warn("No token found — .npmrc uses ${LPM_TOKEN} placeholder.");
			println!(
				"  Set {} in your CI environment.",
				"LPM_TOKEN".bold()
			);
		}
		println!();
	}

	Ok(())
}
