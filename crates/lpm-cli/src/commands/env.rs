use crate::output;
use lpm_common::LpmError;
use owo_colors::OwoColorize;

/// Handle `lpm env` subcommands: install, list, use, pin.
pub async fn run(
	client: &lpm_registry::RegistryClient,
	action: &str,
	spec: Option<&str>,
	project_dir: &std::path::Path,
	json_output: bool,
) -> Result<(), LpmError> {
	let http_client = reqwest::Client::builder()
		.timeout(std::time::Duration::from_secs(60))
		.build()
		.map_err(|e| LpmError::Network(format!("failed to create HTTP client: {e}")))?;

	match action {
		"install" | "i" => {
			let spec = spec.ok_or_else(|| {
				LpmError::Script("missing version spec. Usage: lpm env install node@22".into())
			})?;

			let (runtime, version_spec) = parse_runtime_spec(spec)?;
			if runtime != "node" {
				return Err(LpmError::Script(format!(
					"runtime '{runtime}' not yet supported. Currently supported: node"
				)));
			}

			let platform = lpm_runtime::platform::Platform::current();
			output::info(&format!(
				"resolving node@{} for {}...",
				version_spec,
				platform
			));

			let releases = lpm_runtime::node::fetch_index(&http_client).await?;
			let release =
				lpm_runtime::node::resolve_version(&releases, &version_spec, &platform)
					.ok_or_else(|| {
						LpmError::Script(format!(
							"no node.js release found matching '{version_spec}'"
						))
					})?;

			let version = release.version_bare().to_string();

			if lpm_runtime::node::is_installed(&version) {
				if json_output {
					println!(
						"{}",
						serde_json::json!({"status": "already_installed", "version": version})
					);
				} else {
					output::success(&format!(
						"Node.js {} is already installed",
						version.bold()
					));
				}
				return Ok(());
			}

			output::info(&format!(
				"downloading Node.js {}...",
				release.version.bold()
			));

			let installed =
				lpm_runtime::download::install_node(&http_client, &release, &platform).await?;

			if json_output {
				println!(
					"{}",
					serde_json::json!({"status": "installed", "version": installed})
				);
			} else {
				output::success(&format!("Node.js {} installed", installed.bold()));
				let bin_dir = lpm_runtime::node::node_bin_dir(&installed)?;
				println!("  {} {}", "location:".dimmed(), bin_dir.display());
			}
		}

		"list" | "ls" => {
			let filter_runtime = spec.unwrap_or("node");
			if filter_runtime != "node" {
				return Err(LpmError::Script(format!(
					"runtime '{filter_runtime}' not yet supported"
				)));
			}

			let versions = lpm_runtime::node::list_installed()?;

			if json_output {
				println!(
					"{}",
					serde_json::to_string_pretty(
						&serde_json::json!({"runtime": "node", "versions": versions})
					)
					.unwrap()
				);
			} else if versions.is_empty() {
				output::info("No Node.js versions installed via LPM");
				println!(
					"  Run {} to install one",
					"lpm env install node@22".cyan()
				);
			} else {
				output::info(&format!(
					"Installed Node.js versions ({})",
					versions.len()
				));
				for v in &versions {
					println!("  {} {v}", "●".green());
				}
			}
		}

		"pin" => {
			let spec = spec.ok_or_else(|| {
				LpmError::Script("missing version. Usage: lpm env pin node@22.5.0".into())
			})?;

			let (runtime, version_spec) = parse_runtime_spec(spec)?;
			if runtime != "node" {
				return Err(LpmError::Script(format!(
					"runtime '{runtime}' not yet supported"
				)));
			}

			// Write to lpm.json
			let lpm_json_path = project_dir.join("lpm.json");
			let mut config: serde_json::Value = if lpm_json_path.exists() {
				let content = std::fs::read_to_string(&lpm_json_path)?;
				serde_json::from_str(&content)
					.map_err(|e| LpmError::Script(format!("failed to parse lpm.json: {e}")))?
			} else {
				serde_json::json!({})
			};

			// Ensure runtime section exists
			if config.get("runtime").is_none() {
				config["runtime"] = serde_json::json!({});
			}
			config["runtime"]["node"] = serde_json::Value::String(version_spec.clone());

			let content = serde_json::to_string_pretty(&config)
				.map_err(|e| LpmError::Script(format!("failed to serialize lpm.json: {e}")))?;
			std::fs::write(&lpm_json_path, content)?;

			if json_output {
				println!(
					"{}",
					serde_json::json!({"pinned": {"node": version_spec}})
				);
			} else {
				output::success(&format!(
					"Pinned node@{} in lpm.json",
					version_spec.bold()
				));
			}
		}

		_ => {
			return Err(LpmError::Script(format!(
				"unknown env action: '{action}'. Available: install, list, pin"
			)));
		}
	}

	Ok(())
}

/// Parse a runtime spec like "node@22" into ("node", "22").
/// If no runtime prefix, defaults to "node".
fn parse_runtime_spec(spec: &str) -> Result<(String, String), LpmError> {
	if let Some((runtime, version)) = spec.split_once('@') {
		Ok((runtime.to_string(), version.to_string()))
	} else {
		// No @ sign — assume it's a node version
		Ok(("node".to_string(), spec.to_string()))
	}
}
