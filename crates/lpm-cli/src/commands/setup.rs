use crate::{auth, output};
use lpm_common::LpmError;
use owo_colors::OwoColorize;
use std::path::Path;

/// Generate .npmrc for CI/CD environments.
///
/// Creates a .npmrc file that configures the LPM registry with auth token
/// so npm/pnpm/yarn can install @lpm.dev packages in CI.
pub async fn run(
	registry_url: &str,
	project_dir: &Path,
	json_output: bool,
) -> Result<(), LpmError> {
	let token = auth::get_token(registry_url).or_else(|| std::env::var("LPM_TOKEN").ok());

	let token_placeholder = token.as_deref().unwrap_or("${LPM_TOKEN}");
	let uses_env = token.is_none();

	// Build .npmrc content
	// Format: //registry.example.com/:_authToken=TOKEN
	let registry_host = registry_url
		.trim_start_matches("https://")
		.trim_start_matches("http://");

	let npmrc_content = format!(
		"//{}/:_authToken={}\n@lpm.dev:registry={}/api/registry/\n",
		registry_host, token_placeholder, registry_url
	);

	let npmrc_path = project_dir.join(".npmrc");

	if json_output {
		let json = serde_json::json!({
			"path": npmrc_path.display().to_string(),
			"content": npmrc_content,
			"uses_env_var": uses_env,
		});
		println!("{}", serde_json::to_string_pretty(&json).unwrap());
	} else {
		std::fs::write(&npmrc_path, &npmrc_content)?;

		output::success(&format!("Generated {}", ".npmrc".bold()));
		println!("  {}", npmrc_path.display().to_string().dimmed());

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
