use crate::output;
use lpm_common::LpmError;
use owo_colors::OwoColorize;

/// Handle `lpm plugin` subcommands: list, update.
pub async fn run(
	action: &str,
	plugin_name: Option<&str>,
	json_output: bool,
) -> Result<(), LpmError> {
	match action {
		"list" | "ls" => list(json_output).await,
		"update" | "upgrade" => update(plugin_name, json_output).await,
		"remove" | "rm" | "uninstall" => remove(plugin_name, json_output),
		_ => Err(LpmError::Script(format!(
			"unknown plugin action: '{action}'. Available: list, update, remove"
		))),
	}
}

/// List installed plugins and check for updates.
async fn list(json_output: bool) -> Result<(), LpmError> {
	let all_latest = lpm_plugin::versions::get_all_latest_versions().await;

	if json_output {
		let mut plugins = Vec::new();
		for def in lpm_plugin::registry::list_plugins() {
			let installed = lpm_plugin::store::list_installed_versions(def.name)?;
			let latest = all_latest
				.get(def.name)
				.cloned()
				.unwrap_or_else(|| def.latest_version.to_string());

			plugins.push(serde_json::json!({
				"name": def.name,
				"installed": installed,
				"latest": latest,
			}));
		}
		println!("{}", serde_json::to_string_pretty(&plugins).unwrap());
		return Ok(());
	}

	output::info("Plugins");

	let mut any_installed = false;
	for def in lpm_plugin::registry::list_plugins() {
		let installed = lpm_plugin::store::list_installed_versions(def.name)?;
		let latest = all_latest
			.get(def.name)
			.cloned()
			.unwrap_or_else(|| def.latest_version.to_string());

		if installed.is_empty() {
			println!(
				"  {} {} (not installed, latest: {})",
				"○".dimmed(),
				def.name,
				latest.dimmed(),
			);
		} else {
			any_installed = true;
			for ver in &installed {
				let is_latest = *ver == latest;
				let status = if is_latest {
					"✓ up to date".green().to_string()
				} else {
					format!("{} available", latest.bold())
				};
				println!(
					"  {} {} {} ({})",
					"●".green(),
					def.name,
					ver.bold(),
					status,
				);
			}
		}
	}

	if !any_installed {
		println!();
		println!(
			"  Run {} or {} to install plugins on first use",
			"lpm lint".cyan(),
			"lpm fmt".cyan(),
		);
	}

	Ok(())
}

/// Remove a plugin (specific version or all versions).
fn remove(plugin_name: Option<&str>, json_output: bool) -> Result<(), LpmError> {
	let name = plugin_name.ok_or_else(|| {
		LpmError::Script("missing plugin name. Usage: lpm plugin remove <name> [version]".into())
	})?;

	// Check if name contains @ for specific version: "oxlint@1.57.0"
	let (plugin, version) = if let Some((n, v)) = name.split_once('@') {
		(n, Some(v))
	} else {
		(name, None)
	};

	if let Some(ver) = version {
		let removed = lpm_plugin::store::remove_version(plugin, ver)?;
		if json_output {
			println!("{}", serde_json::json!({"removed": removed, "plugin": plugin, "version": ver}));
		} else if removed {
			output::success(&format!("removed {}@{}", plugin.bold(), ver));
		} else {
			output::info(&format!("{}@{} not installed", plugin, ver));
		}
	} else {
		let count = lpm_plugin::store::remove_all(plugin)?;
		if json_output {
			println!("{}", serde_json::json!({"removed": count, "plugin": plugin}));
		} else if count > 0 {
			output::success(&format!(
				"removed {} ({} version{})",
				plugin.bold(),
				count,
				if count == 1 { "" } else { "s" }
			));
		} else {
			output::info(&format!("{} not installed", plugin));
		}
	}

	Ok(())
}

/// Update a specific plugin or all plugins to latest version.
async fn update(
	plugin_name: Option<&str>,
	json_output: bool,
) -> Result<(), LpmError> {
	if let Some(name) = plugin_name {
		// Update specific plugin
		let version = lpm_plugin::update_plugin(name).await?;
		if json_output {
			println!("{}", serde_json::json!({"plugin": name, "version": version}));
		} else {
			output::success(&format!("{} updated to {}", name.bold(), version.bold()));
		}
	} else {
		// Update all plugins that are installed
		let mut updated = 0;
		for def in lpm_plugin::registry::list_plugins() {
			let installed = lpm_plugin::store::list_installed_versions(def.name)?;
			if installed.is_empty() {
				continue; // Skip plugins that aren't installed
			}

			let version = lpm_plugin::update_plugin(def.name).await?;
			if !json_output {
				output::success(&format!("{} → {}", def.name.bold(), version.bold()));
			}
			updated += 1;
		}

		if updated == 0 && !json_output {
			output::info("No plugins installed to update. Run `lpm lint` or `lpm fmt` to install.");
		}
	}

	Ok(())
}
