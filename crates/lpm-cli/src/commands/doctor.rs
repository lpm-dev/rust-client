use crate::{auth, output};
use lpm_common::LpmError;
use lpm_registry::RegistryClient;
use lpm_store::PackageStore;
use owo_colors::OwoColorize;
use std::path::Path;

/// Health check: verify auth, registry, store, and project state.
pub async fn run(
	client: &RegistryClient,
	registry_url: &str,
	project_dir: &Path,
	json_output: bool,
) -> Result<(), LpmError> {
	let mut checks = Vec::new();
	let mut all_ok = true;

	// 1. Registry reachable?
	let registry_ok = client.health_check().await.unwrap_or(false);
	checks.push(("Registry reachable", registry_ok, registry_url.to_string()));
	if !registry_ok {
		all_ok = false;
	}

	// 2. Auth token valid?
	let token_exists = auth::get_token(registry_url).is_some();
	let auth_ok = if token_exists {
		client.whoami().await.is_ok()
	} else {
		false
	};
	checks.push((
		"Authentication",
		auth_ok,
		if auth_ok {
			"valid token".into()
		} else if token_exists {
			"token exists but invalid".into()
		} else {
			"no token found — run lpm-rs login".into()
		},
	));
	if !auth_ok {
		all_ok = false;
	}

	// 3. Global store accessible?
	let store_ok = PackageStore::default_location().is_ok();
	let store_path = PackageStore::default_location()
		.map(|s| s.root().display().to_string())
		.unwrap_or_else(|_| "unknown".into());
	checks.push(("Global store", store_ok, store_path));
	if !store_ok {
		all_ok = false;
	}

	// 4. package.json exists?
	let pkg_json = project_dir.join("package.json");
	let pkg_ok = pkg_json.exists();
	checks.push((
		"package.json",
		pkg_ok,
		if pkg_ok {
			pkg_json.display().to_string()
		} else {
			"not found in current directory".into()
		},
	));

	// 5. node_modules intact?
	let nm = project_dir.join("node_modules");
	let nm_ok = nm.exists() && nm.join(".lpm").exists();
	checks.push((
		"node_modules",
		nm_ok,
		if nm_ok {
			"exists with .lpm store".into()
		} else if nm.exists() {
			"exists but no .lpm store (may need lpm-rs install)".into()
		} else {
			"not found (run lpm-rs install)".into()
		},
	));

	// 6. Lockfile?
	let lockfile = project_dir.join("lpm.lock");
	let lock_ok = lockfile.exists();
	checks.push((
		"Lockfile",
		lock_ok,
		if lock_ok {
			"lpm.lock exists".into()
		} else {
			"not found (run lpm-rs install)".into()
		},
	));

	if json_output {
		let results: Vec<_> = checks
			.iter()
			.map(|(name, ok, detail)| {
				serde_json::json!({"check": name, "ok": ok, "detail": detail})
			})
			.collect();
		println!(
			"{}",
			serde_json::to_string_pretty(&serde_json::json!({
				"all_ok": all_ok,
				"checks": results,
			}))
			.unwrap()
		);
	} else {
		println!();
		for (name, ok, detail) in &checks {
			let icon = if *ok {
				"✔".green().to_string()
			} else {
				"✖".red().to_string()
			};
			println!("  {icon} {} {}", name.bold(), detail.dimmed());
		}
		println!();
		if all_ok {
			output::success("All checks passed");
		} else {
			output::warn("Some checks failed — see above");
		}
		println!();
	}

	Ok(())
}
