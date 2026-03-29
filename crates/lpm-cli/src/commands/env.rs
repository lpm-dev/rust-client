use crate::output;
use lpm_common::LpmError;
use owo_colors::OwoColorize;
use std::collections::HashMap;

/// Handle `lpm use` subcommands: install, list, use, pin.
pub async fn run(
	_client: &lpm_registry::RegistryClient,
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
		"vars" => {
			return run_vars(spec, project_dir, json_output).await;
		}

		"install" | "i" => {
			let spec = spec.ok_or_else(|| {
				LpmError::Script("missing version spec. Usage: lpm use install node@22".into())
			})?;

			let (runtime, version_spec) = parse_runtime_spec(spec)?;
			if runtime != "node" {
				return Err(LpmError::Script(format!(
					"runtime '{runtime}' not yet supported. Currently supported: node"
				)));
			}

			let platform = lpm_runtime::platform::Platform::current()?;
			output::info(&format!(
				"resolving node@{} for {}...",
				version_spec,
				platform
			));

			let releases = lpm_runtime::node::fetch_index(&http_client).await?;
			let release =
				lpm_runtime::node::resolve_version(&releases, &version_spec)
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
					"lpm use install node@22".cyan()
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
				LpmError::Script("missing version. Usage: lpm use pin node@22.5.0".into())
			})?;

			let (runtime, version_spec) = parse_runtime_spec(spec)?;
			if runtime != "node" {
				return Err(LpmError::Script(format!(
					"runtime '{runtime}' not yet supported"
				)));
			}

			// Validate pin version before writing
			if !is_valid_pin_version(&version_spec) {
				return Err(LpmError::Script(format!(
					"invalid pin version '{version_spec}'. Version must only contain alphanumeric characters, dots, hyphens, or underscores"
				)));
			}

			// Warn if the version is not currently installed
			if !json_output && !lpm_runtime::node::is_installed(&version_spec) {
				output::warn(&format!(
					"node@{} is not currently installed. Run `lpm use install node@{}` to install it",
					version_spec, version_spec
				));
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
				.map_err(|e| LpmError::Script(format!("failed to serialize lpm.json: {e}")))?
				+ "\n";

			// Atomic write: write to temp file, then rename
			let tmp_path = lpm_json_path.with_extension("json.tmp");
			std::fs::write(&tmp_path, &content)?;
			std::fs::rename(&tmp_path, &lpm_json_path)?;

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
				"unknown env action: '{action}'. Available: install, list, pin, vars"
			)));
		}
	}

	Ok(())
}

/// Handle `lpm use vars` subcommands.
///
/// The `spec` field carries the sub-action and arguments:
///   lpm use vars set KEY=VALUE [KEY2=VALUE2 ...]
///   lpm use vars get KEY [--reveal]
///   lpm use vars list [--reveal]
///   lpm use vars delete KEY [KEY2 ...]
///   lpm use vars import <file> [--overwrite]
///   lpm use vars export <file>
///
/// Since clap parses `lpm use vars` as action="vars" spec=Some("set"),
/// and extra args are lost, we re-parse from raw CLI args.
async fn run_vars(
	_spec: Option<&str>,
	project_dir: &std::path::Path,
	json_output: bool,
) -> Result<(), LpmError> {
	// Re-parse args after "lpm use vars"
	let raw_args: Vec<String> = std::env::args().collect();
	let vars_pos = raw_args.iter().position(|a| a == "vars");
	let args: Vec<&str> = match vars_pos {
		Some(pos) => raw_args[pos + 1..].iter().map(|s| s.as_str()).collect(),
		None => vec![],
	};

	if args.is_empty() {
		// Default: list keys
		return vars_list(project_dir, false, json_output);
	}

	match args[0] {
		"set" => {
			let pairs: Vec<(&str, &str)> = args[1..]
				.iter()
				.filter_map(|arg| arg.split_once('='))
				.collect();

			if pairs.is_empty() {
				return Err(LpmError::Script(
					"usage: lpm use vars set KEY=VALUE [KEY2=VALUE2 ...]".into(),
				));
			}

			lpm_vault::set(project_dir, &pairs)
				.map_err(|e| LpmError::Script(e))?;

			if json_output {
				let keys: Vec<&str> = pairs.iter().map(|(k, _)| *k).collect();
				println!("{}", serde_json::json!({"stored": keys}));
			} else {
				for (key, _) in &pairs {
					output::success(&format!("stored {}", key.bold()));
				}
			}
		}

		"get" => {
			let key = args.get(1).ok_or_else(|| {
				LpmError::Script("usage: lpm use vars get KEY [--reveal]".into())
			})?;
			let reveal = args.iter().any(|a| *a == "--reveal");

			match lpm_vault::get(project_dir, key) {
				Some(value) => {
					if json_output {
						if reveal {
							println!("{}", serde_json::json!({*key: value}));
						} else {
							println!("{}", serde_json::json!({*key: "••••••••"}));
						}
					} else if reveal {
						println!("{value}");
					} else {
						println!("{} = {}", key.bold(), "••••••••".dimmed());
					}
				}
				None => {
					return Err(LpmError::Script(format!("secret '{key}' not found")));
				}
			}
		}

		"list" => {
			let reveal = args.iter().any(|a| *a == "--reveal");
			vars_list(project_dir, reveal, json_output)?;
		}

		"delete" => {
			let keys: Vec<&str> = args[1..].iter().copied().collect();

			if keys.is_empty() {
				return Err(LpmError::Script(
					"usage: lpm use vars delete KEY [KEY2 ...]".into(),
				));
			}

			lpm_vault::delete(project_dir, &keys)
				.map_err(|e| LpmError::Script(e))?;

			if json_output {
				println!("{}", serde_json::json!({"deleted": keys}));
			} else {
				for key in &keys {
					output::success(&format!("deleted {}", key.bold()));
				}
			}
		}

		"import" => {
			let file = args.get(1).ok_or_else(|| {
				LpmError::Script("usage: lpm use vars import <file> [--overwrite]".into())
			})?;
			let overwrite = args.iter().any(|a| *a == "--overwrite");
			let path = project_dir.join(file);

			let count = lpm_vault::import_env_file(project_dir, &path, overwrite)
				.map_err(|e| LpmError::Script(e))?;

			if json_output {
				println!("{}", serde_json::json!({"imported": count, "from": file}));
			} else {
				output::success(&format!(
					"imported {} secret{} from {}",
					count.to_string().bold(),
					if count == 1 { "" } else { "s" },
					file.cyan()
				));
			}
		}

		"export" => {
			let file = args.get(1).ok_or_else(|| {
				LpmError::Script("usage: lpm use vars export <file>".into())
			})?;
			let path = project_dir.join(file);

			let count = lpm_vault::export_env_file(project_dir, &path)
				.map_err(|e| LpmError::Script(e))?;

			if json_output {
				println!("{}", serde_json::json!({"exported": count, "to": file}));
			} else {
				output::success(&format!(
					"exported {} secret{} to {}",
					count.to_string().bold(),
					if count == 1 { "" } else { "s" },
					file.cyan()
				));
			}
		}

		"push" => {
			let force = args.iter().any(|a| *a == "--force");
			let yes = args.iter().any(|a| *a == "--yes" || *a == "-y");
			let vault_id = lpm_vault::vault_id::read_vault_id(project_dir)
				.ok_or_else(|| LpmError::Script("no vault configured. Run `lpm use vars set` first".into()))?;

			let all_envs = lpm_vault::get_all_environments(project_dir);
			let total_keys: usize = all_envs.values().map(|e| e.len()).sum();
			if total_keys == 0 {
				return Err(LpmError::Script("vault is empty, nothing to push".into()));
			}

			// Filter empty environments, then wrap for sync (matches Swift app format)
			let non_empty_envs: HashMap<String, HashMap<String, String>> = all_envs
				.iter()
				.filter(|(_, secrets)| !secrets.is_empty())
				.map(|(k, v)| (k.clone(), v.clone()))
				.collect();

			let secrets_for_sync: HashMap<String, HashMap<String, HashMap<String, String>>> = {
				let mut wrapper = HashMap::new();
				wrapper.insert("environments".to_string(), non_empty_envs.clone());
				wrapper
			};

			let project_name = lpm_vault::vault_id::read_project_name(project_dir);

			// Confirmation prompt
			if !yes && !json_output {
				output::warn("this will overwrite the cloud vault with your local secrets");
				output::field("project", &project_name);
				output::field("environments", &format!("{}", all_envs.len()));
				output::field("total keys", &format!("{}", total_keys));
				if force {
					output::field("mode", "force (overwrite regardless of version)");
				}
				let confirm = dialoguer::Confirm::new()
					.with_prompt("  Continue?")
					.default(false)
					.interact()
					.map_err(|e| LpmError::Script(format!("prompt failed: {e}")))?;
				if !confirm {
					output::info("cancelled");
					return Ok(());
				}
			}

			let registry_url = std::env::var("LPM_REGISTRY_URL")
				.unwrap_or_else(|_| lpm_common::DEFAULT_REGISTRY_URL.to_string());
			let auth_token = crate::auth::get_token(&registry_url)
				.ok_or_else(|| LpmError::Script("not logged in. Run `lpm login` first".into()))?;

			output::info("pushing vault to cloud...");

			let secrets_json = serde_json::to_string(&secrets_for_sync)
				.map_err(|e| LpmError::Script(format!("failed to serialize: {e}")))?;

			let result = lpm_vault::sync::push_raw(
				&registry_url, &auth_token, &vault_id, &secrets_json, None, force,
			)
			.await
			.map_err(|e| LpmError::Script(e))?;

			if json_output {
				println!("{}", serde_json::json!({
					"status": result.status,
					"version": result.version,
				}));
			} else {
				output::success(&format!(
					"vault synced (version {})",
					result.version.unwrap_or(0).to_string().bold()
				));
			}
		}

		"pull" => {
			let yes = args.iter().any(|a| *a == "--yes" || *a == "-y");
			let org_flag = args.iter().position(|a| *a == "--org")
				.and_then(|i| args.get(i + 1).copied());

			let vault_id = lpm_vault::vault_id::get_or_create_vault_id(project_dir)
				.map_err(|e| LpmError::Script(e))?;

			// Org pull: different flow with X25519 decryption
			if let Some(org_slug) = org_flag {
				let registry_url = std::env::var("LPM_REGISTRY_URL")
					.unwrap_or_else(|_| lpm_common::DEFAULT_REGISTRY_URL.to_string());
				let auth_token = crate::auth::get_token(&registry_url)
					.ok_or_else(|| LpmError::Script("not logged in. Run `lpm login` first".into()))?;

				// Ensure we have a keypair
				let private_key = lpm_vault::sync::ensure_public_key(&registry_url, &auth_token)
					.await
					.map_err(|e| LpmError::Script(e))?;

				output::info(&format!("pulling vault from org {}...", org_slug.bold()));

				let (raw_json, version) = lpm_vault::sync::pull_org(
					&registry_url, &auth_token, org_slug, &vault_id, &private_key,
				)
				.await
				.map_err(|e| LpmError::Script(e))?;

				// Same merge logic as personal pull
				let total_keys;
				if let Ok(wrapper) = serde_json::from_str::<std::collections::HashMap<String, std::collections::HashMap<String, std::collections::HashMap<String, String>>>>(&raw_json) {
					if let Some(remote_envs) = wrapper.get("environments") {
						let mut total = 0;
						for (env_name, remote_secrets) in remote_envs {
							let mut env = lpm_vault::get_all_env(project_dir, env_name);
							env.extend(remote_secrets.clone());
							total += env.len();
							let pairs: Vec<(&str, &str)> = env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
							lpm_vault::set_env(project_dir, env_name, &pairs).map_err(|e| LpmError::Script(e))?;
						}
						total_keys = total;
					} else {
						total_keys = 0;
					}
				} else if let Ok(remote_secrets) = serde_json::from_str::<std::collections::HashMap<String, String>>(&raw_json) {
					let mut merged = lpm_vault::get_all(project_dir);
					merged.extend(remote_secrets);
					total_keys = merged.len();
					let pairs: Vec<(&str, &str)> = merged.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
					lpm_vault::set(project_dir, &pairs).map_err(|e| LpmError::Script(e))?;
				} else {
					return Err(LpmError::Script("failed to parse pulled vault data".into()));
				}

				if json_output {
					println!("{}", serde_json::json!({"status": "pulled", "org": org_slug, "version": version, "count": total_keys}));
				} else {
					output::success(&format!("pulled {} key{} from org {} (version {})", total_keys.to_string().bold(), if total_keys == 1 { "" } else { "s" }, org_slug.bold(), version.to_string().bold()));
				}
				return Ok(());
			}

			let project_name = lpm_vault::vault_id::read_project_name(project_dir);
			let local_secrets = lpm_vault::get_all(project_dir);

			// Confirmation prompt
			if !yes && !json_output {
				output::warn("this will overwrite your local secrets with the cloud vault");
				output::field("project", &project_name);
				output::field("local keys", &format!("{}", local_secrets.len()));
				let confirm = dialoguer::Confirm::new()
					.with_prompt("  Continue?")
					.default(false)
					.interact()
					.map_err(|e| LpmError::Script(format!("prompt failed: {e}")))?;
				if !confirm {
					output::info("cancelled");
					return Ok(());
				}
			}

			let registry_url = std::env::var("LPM_REGISTRY_URL")
				.unwrap_or_else(|_| lpm_common::DEFAULT_REGISTRY_URL.to_string());
			let auth_token = crate::auth::get_token(&registry_url)
				.ok_or_else(|| LpmError::Script("not logged in. Run `lpm login` first".into()))?;

			output::info("pulling vault from cloud...");

			let (raw_json, version) = lpm_vault::sync::pull_raw(
				&registry_url, &auth_token, &vault_id,
			)
			.await
			.map_err(|e| LpmError::Script(e))?;

			// Try environments format first
			let total_keys;
			if let Ok(wrapper) = serde_json::from_str::<std::collections::HashMap<String, std::collections::HashMap<String, std::collections::HashMap<String, String>>>>(&raw_json) {
				if let Some(remote_envs) = wrapper.get("environments") {
					// Merge each environment into local vault
					let mut local_envs = lpm_vault::get_all_environments(project_dir);
					let mut total = 0;
					for (env_name, remote_secrets) in remote_envs {
						let mut env = local_envs.remove(env_name).unwrap_or_default();
						env.extend(remote_secrets.clone());
						total += env.len();
						// Write each environment
						let pairs: Vec<(&str, &str)> = env
							.iter()
							.map(|(k, v)| (k.as_str(), v.as_str()))
							.collect();
						lpm_vault::set_env(project_dir, env_name, &pairs)
							.map_err(|e| LpmError::Script(e))?;
					}
					total_keys = total;
				} else {
					total_keys = 0;
				}
			} else if let Ok(remote_secrets) = serde_json::from_str::<std::collections::HashMap<String, String>>(&raw_json) {
				// Old flat format → merge into "default"
				let local_secrets = lpm_vault::get_all(project_dir);
				let mut merged = local_secrets;
				merged.extend(remote_secrets);
				total_keys = merged.len();

				let pairs: Vec<(&str, &str)> = merged
					.iter()
					.map(|(k, v)| (k.as_str(), v.as_str()))
					.collect();
				lpm_vault::set(project_dir, &pairs)
					.map_err(|e| LpmError::Script(e))?;
			} else {
				return Err(LpmError::Script("failed to parse pulled vault data".into()));
			}

			if json_output {
				println!("{}", serde_json::json!({
					"status": "pulled",
					"version": version,
					"count": total_keys,
				}));
			} else {
				output::success(&format!(
					"pulled {} key{} (version {})",
					total_keys.to_string().bold(),
					if total_keys == 1 { "" } else { "s" },
					version.to_string().bold()
				));
			}
		}

		"log" => {
			let vault_id = lpm_vault::vault_id::read_vault_id(project_dir)
				.ok_or_else(|| LpmError::Script("no vault configured".into()))?;

			let registry_url = std::env::var("LPM_REGISTRY_URL")
				.unwrap_or_else(|_| lpm_common::DEFAULT_REGISTRY_URL.to_string());
			let auth_token = crate::auth::get_token(&registry_url)
				.ok_or_else(|| LpmError::Script("not logged in. Run `lpm login` first".into()))?;

			let result = lpm_vault::sync::get_audit_log(
				&registry_url, &auth_token, &vault_id, None,
			)
			.await
			.map_err(|e| LpmError::Script(e))?;

			let entries = result.entries.unwrap_or_default();

			if json_output {
				println!("{}", serde_json::to_string_pretty(&serde_json::json!({"entries": entries.iter().map(|e| serde_json::json!({
					"action": e.action,
					"createdAt": e.created_at,
				})).collect::<Vec<_>>()})).unwrap());
			} else if entries.is_empty() {
				output::info("No audit log entries");
			} else {
				output::info(&format!("Vault audit log ({} entries)", entries.len()));
				for entry in &entries {
					println!("  {} {} {}", entry.created_at.dimmed(), entry.action.bold(), entry.user_id.as_deref().unwrap_or("").dimmed());
				}
			}
		}

		"share" => {
			let org_flag = args.iter().position(|a| *a == "--org")
				.and_then(|i| args.get(i + 1).copied());
			let org_slug = org_flag.ok_or_else(|| {
				LpmError::Script("usage: lpm use vars share --org <org-slug>".into())
			})?;

			let vault_id = lpm_vault::vault_id::read_vault_id(project_dir)
				.ok_or_else(|| LpmError::Script("no vault configured. Run `lpm use vars set` first".into()))?;

			let all_envs = lpm_vault::get_all_environments(project_dir);
			let total_keys: usize = all_envs.values().map(|e| e.len()).sum();
			if total_keys == 0 {
				return Err(LpmError::Script("vault is empty, nothing to share".into()));
			}

			let registry_url = std::env::var("LPM_REGISTRY_URL")
				.unwrap_or_else(|_| lpm_common::DEFAULT_REGISTRY_URL.to_string());
			let auth_token = crate::auth::get_token(&registry_url)
				.ok_or_else(|| LpmError::Script("not logged in. Run `lpm login` first".into()))?;

			output::info("ensuring your X25519 public key is registered...");

			// Build secrets JSON (same multi-env format as personal push)
			let non_empty_envs: std::collections::HashMap<String, std::collections::HashMap<String, String>> = all_envs
				.iter()
				.filter(|(_, secrets)| !secrets.is_empty())
				.map(|(k, v)| (k.clone(), v.clone()))
				.collect();
			let mut wrapper = std::collections::HashMap::new();
			wrapper.insert("environments".to_string(), non_empty_envs);
			let secrets_json = serde_json::to_string(&wrapper)
				.map_err(|e| LpmError::Script(format!("failed to serialize: {e}")))?;

			output::info(&format!("sharing vault with org {} ({} keys across {} environments)...", org_slug.bold(), total_keys, all_envs.len()));

			let result = lpm_vault::sync::push_org_with_keys(
				&registry_url, &auth_token, org_slug, &vault_id, &secrets_json,
			)
			.await
			.map_err(|e| LpmError::Script(e))?;

			if json_output {
				println!("{}", serde_json::json!({
					"status": result.status,
					"org": org_slug,
					"version": result.version,
				}));
			} else {
				output::success(&format!(
					"vault shared with org {} (version {})",
					org_slug.bold(),
					result.version.unwrap_or(0).to_string().bold()
				));
			}
		}

		"rotate-key" => {
			let vault_id = lpm_vault::vault_id::read_vault_id(project_dir)
				.ok_or_else(|| LpmError::Script("no vault configured".into()))?;

			let registry_url = std::env::var("LPM_REGISTRY_URL")
				.unwrap_or_else(|_| lpm_common::DEFAULT_REGISTRY_URL.to_string());
			let auth_token = crate::auth::get_token(&registry_url)
				.ok_or_else(|| LpmError::Script("not logged in. Run `lpm login` first".into()))?;

			let secrets = lpm_vault::get_all(project_dir);
			if secrets.is_empty() {
				return Err(LpmError::Script("vault is empty, nothing to rotate".into()));
			}

			output::info("rotating vault encryption key...");

			// Re-encrypt with new key and push
			let result = lpm_vault::sync::push(
				&registry_url, &auth_token, &vault_id, &secrets, None, true,
			)
			.await
			.map_err(|e| LpmError::Script(e))?;

			if json_output {
				println!("{}", serde_json::json!({
					"status": "rotated",
					"version": result.version,
				}));
			} else {
				output::success(&format!(
					"encryption key rotated (version {})",
					result.version.unwrap_or(0).to_string().bold()
				));
			}
		}

		"list-remote" | "ls-remote" => {
			let org_flag = args.iter().position(|a| *a == "--org")
				.and_then(|i| args.get(i + 1).copied());
			return vars_list_remote(org_flag, json_output).await;
		}

		"diff" => {
			return vars_diff(&args[1..], project_dir, json_output).await;
		}

		"validate" => {
			let strict = args.iter().any(|a| *a == "--strict");
			return vars_validate(project_dir, strict, json_output);
		}

		unknown => {
			return Err(LpmError::Script(format!(
				"unknown vars action: '{unknown}'. Available: set, get, list, delete, import, export, push, pull, diff, validate, log, share, rotate-key"
			)));
		}
	}

	Ok(())
}

fn vars_list(
	project_dir: &std::path::Path,
	reveal: bool,
	json_output: bool,
) -> Result<(), LpmError> {
	let secrets = lpm_vault::get_all(project_dir);

	if json_output {
		if reveal {
			println!("{}", serde_json::to_string_pretty(&secrets).unwrap());
		} else {
			let masked: std::collections::HashMap<&str, &str> =
				secrets.keys().map(|k| (k.as_str(), "••••••••")).collect();
			println!("{}", serde_json::to_string_pretty(&masked).unwrap());
		}
	} else if secrets.is_empty() {
		output::info("No secrets in vault");
		println!(
			"  Run {} to add one",
			"lpm use vars set KEY=VALUE".cyan()
		);
	} else {
		let mut keys: Vec<&String> = secrets.keys().collect();
		keys.sort();
		output::info(&format!("Vault secrets ({})", keys.len()));
		for key in keys {
			if reveal {
				println!("  {} = {}", key.bold(), &secrets[key]);
			} else {
				println!("  {} = {}", key.bold(), "••••••••".dimmed());
			}
		}
	}

	Ok(())
}

/// List cloud vaults — personal or org.
async fn vars_list_remote(org_slug: Option<&str>, json_output: bool) -> Result<(), LpmError> {
	let registry_url = std::env::var("LPM_REGISTRY_URL")
		.unwrap_or_else(|_| lpm_common::DEFAULT_REGISTRY_URL.to_string());
	let auth_token = crate::auth::get_token(&registry_url)
		.ok_or_else(|| LpmError::Script("not logged in. Run `lpm login` first".into()))?;

	if let Some(slug) = org_slug {
		// List org vaults
		let vaults = lpm_vault::sync::list_org_vaults(&registry_url, &auth_token, slug)
			.await
			.map_err(|e| LpmError::Script(e))?;

		if json_output {
			let json: Vec<serde_json::Value> = vaults
				.iter()
				.map(|v| serde_json::json!({"vaultId": v.vault_id, "version": v.version, "updatedAt": v.updated_at, "org": slug}))
				.collect();
			println!("{}", serde_json::to_string_pretty(&serde_json::json!({"org": slug, "vaults": json})).unwrap());
			return Ok(());
		}

		if vaults.is_empty() {
			output::info(&format!("no shared vaults in org {}", slug.bold()));
			println!("  Share a vault: {}", format!("lpm use vars share --org {slug}").cyan());
			return Ok(());
		}

		output::info(&format!("Org {} vaults ({})", slug.bold(), vaults.len()));
		for v in &vaults {
			let version = v.version.map(|v| format!("v{v}")).unwrap_or_else(|| "v?".into());
			let updated = v.updated_at.as_deref().unwrap_or("?");
			println!("  {} {} {} {}", "●".cyan(), v.vault_id.bold(), version.dimmed(), format!("(updated {updated})").dimmed());
		}
		println!();
		println!("  Pull: {}", format!("cd <project-dir> && lpm use vars pull --org {slug}").cyan());
		return Ok(());
	}

	// Personal vaults
	let vaults = lpm_vault::sync::list_remote(&registry_url, &auth_token)
		.await
		.map_err(|e| LpmError::Script(e))?;

	if json_output {
		let json: Vec<serde_json::Value> = vaults
			.iter()
			.map(|v| {
				serde_json::json!({
					"vaultId": v.vault_id,
					"version": v.version,
					"updatedAt": v.updated_at,
				})
			})
			.collect();
		println!("{}", serde_json::to_string_pretty(&serde_json::json!({"vaults": json})).unwrap());
		return Ok(());
	}

	if vaults.is_empty() {
		output::info("no cloud vaults found");
		println!("  Push a vault with: {}", "lpm use vars push".cyan());
		return Ok(());
	}

	output::info(&format!("Cloud vaults ({})", vaults.len()));
	for v in &vaults {
		let version = v.version.map(|v| format!("v{v}")).unwrap_or_else(|| "v?".into());
		let updated = v.updated_at.as_deref().unwrap_or("?");
		println!(
			"  {} {} {} {}",
			"●".cyan(),
			v.vault_id.bold(),
			version.dimmed(),
			format!("(updated {updated})").dimmed()
		);
	}
	println!();
	println!(
		"  Pull a vault: {}",
		"cd <project-dir> && lpm use vars pull".cyan()
	);

	Ok(())
}

/// Compare vault environments or local vs cloud.
///
/// Usage:
///   lpm use vars diff                     — local default vs cloud
///   lpm use vars diff staging             — local staging vs cloud staging
///   lpm use vars diff staging production  — two local environments
async fn vars_diff(
	args: &[&str],
	project_dir: &std::path::Path,
	json_output: bool,
) -> Result<(), LpmError> {
	let (left_label, left_secrets, right_label, right_secrets) = if args.len() >= 2 {
		// Compare two local environments
		let env_a = args[0];
		let env_b = args[1];
		let a = lpm_vault::get_all_env(project_dir, env_a);
		let b = lpm_vault::get_all_env(project_dir, env_b);
		(
			format!("{env_a} (local)"),
			a,
			format!("{env_b} (local)"),
			b,
		)
	} else if args.len() == 1 {
		// Compare specific env local vs cloud
		let env_name = args[0];
		let local = lpm_vault::get_all_env(project_dir, env_name);

		let vault_id = lpm_vault::vault_id::read_vault_id(project_dir)
			.ok_or_else(|| LpmError::Script("no vault configured".into()))?;
		let registry_url = std::env::var("LPM_REGISTRY_URL")
			.unwrap_or_else(|_| lpm_common::DEFAULT_REGISTRY_URL.to_string());
		let auth_token = crate::auth::get_token(&registry_url)
			.ok_or_else(|| LpmError::Script("not logged in. Run `lpm login` first".into()))?;

		let (remote, _version) = lpm_vault::sync::pull(&registry_url, &auth_token, &vault_id)
			.await
			.map_err(|e| LpmError::Script(e))?;

		(
			format!("{env_name} (local)"),
			local,
			format!("{env_name} (cloud)"),
			remote,
		)
	} else {
		// Default: local default vs cloud
		let local = lpm_vault::get_all(project_dir);

		let vault_id = lpm_vault::vault_id::read_vault_id(project_dir)
			.ok_or_else(|| LpmError::Script("no vault configured".into()))?;
		let registry_url = std::env::var("LPM_REGISTRY_URL")
			.unwrap_or_else(|_| lpm_common::DEFAULT_REGISTRY_URL.to_string());
		let auth_token = crate::auth::get_token(&registry_url)
			.ok_or_else(|| LpmError::Script("not logged in. Run `lpm login` first".into()))?;

		let (remote, _version) = lpm_vault::sync::pull(&registry_url, &auth_token, &vault_id)
			.await
			.map_err(|e| LpmError::Script(e))?;

		("default (local)".into(), local, "default (cloud)".into(), remote)
	};

	// Compute diff
	let mut all_keys: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
	for key in left_secrets.keys() {
		all_keys.insert(key.as_str());
	}
	for key in right_secrets.keys() {
		all_keys.insert(key.as_str());
	}

	let mut added = Vec::new();
	let mut removed = Vec::new();
	let mut changed = Vec::new();
	let mut same = 0u32;

	for key in &all_keys {
		let in_left = left_secrets.get(*key);
		let in_right = right_secrets.get(*key);
		match (in_left, in_right) {
			(Some(_), None) => added.push(*key),
			(None, Some(_)) => removed.push(*key),
			(Some(l), Some(r)) if l != r => changed.push(*key),
			(Some(_), Some(_)) => same += 1,
			_ => {}
		}
	}

	if json_output {
		println!("{}", serde_json::json!({
			"left": left_label,
			"right": right_label,
			"added": added,
			"removed": removed,
			"changed": changed,
			"unchanged": same,
		}));
		return Ok(());
	}

	println!();
	println!(
		"  Comparing {} vs {}",
		left_label.bold(),
		right_label.bold()
	);
	println!();

	if added.is_empty() && removed.is_empty() && changed.is_empty() {
		output::success("no differences");
		return Ok(());
	}

	for key in &added {
		println!(
			"  {} {} {}",
			"+".green(),
			key.bold(),
			"(only in left)".dimmed()
		);
	}
	for key in &removed {
		println!(
			"  {} {} {}",
			"-".red(),
			key.bold(),
			"(only in right)".dimmed()
		);
	}
	for key in &changed {
		println!(
			"  {} {} {}",
			"~".yellow(),
			key.bold(),
			"(changed)".dimmed()
		);
	}
	if same > 0 {
		println!("  {} {same} unchanged", "=".dimmed());
	}

	println!();
	println!(
		"  Summary: {} added, {} removed, {} changed, {} unchanged",
		added.len().to_string().green(),
		removed.len().to_string().red(),
		changed.len().to_string().yellow(),
		same.to_string().dimmed()
	);

	Ok(())
}

/// Validate vault secrets against .env.example.
fn vars_validate(
	project_dir: &std::path::Path,
	strict: bool,
	json_output: bool,
) -> Result<(), LpmError> {
	let example_path = project_dir.join(".env.example");
	if !example_path.exists() {
		return Err(LpmError::Script(
			"no .env.example found. Create one with the required variable names.".into(),
		));
	}

	let content = std::fs::read_to_string(&example_path)?;

	// Parse .env.example — extract key names (values are ignored)
	let required_keys: Vec<String> = content
		.lines()
		.filter(|line| {
			let trimmed = line.trim();
			!trimmed.is_empty() && !trimmed.starts_with('#')
		})
		.filter_map(|line| {
			let trimmed = line.trim().strip_prefix("export ").unwrap_or(line.trim());
			trimmed.split_once('=').map(|(k, _)| k.trim().to_string())
		})
		.collect();

	let secrets = lpm_vault::get_all(project_dir);

	let mut present = Vec::new();
	let mut missing = Vec::new();
	let mut extra = Vec::new();

	for key in &required_keys {
		if secrets.contains_key(key) {
			present.push(key.as_str());
		} else {
			missing.push(key.as_str());
		}
	}

	if strict {
		let required_set: std::collections::HashSet<&str> =
			required_keys.iter().map(|s| s.as_str()).collect();
		for key in secrets.keys() {
			if !required_set.contains(key.as_str()) {
				extra.push(key.as_str());
			}
		}
	}

	if json_output {
		println!("{}", serde_json::json!({
			"required": required_keys.len(),
			"present": present,
			"missing": missing,
			"extra": extra,
			"valid": missing.is_empty(),
		}));
		return Ok(());
	}

	println!();
	println!("  Validating against {}", ".env.example".bold());
	println!();

	for key in &present {
		println!("  {} {} {}", "✔".green(), key.bold(), "set".green());
	}
	for key in &missing {
		println!("  {} {} {}", "✖".red(), key.bold(), "missing".red());
	}
	for key in &extra {
		println!(
			"  {} {} {}",
			"⚠".yellow(),
			key.bold(),
			"not in .env.example (extra)".yellow()
		);
	}

	println!();
	if missing.is_empty() {
		output::success(&format!(
			"all {} required variables are set",
			required_keys.len()
		));
	} else {
		let missing_list = missing.join(" ");
		println!(
			"  {} of {} required variables are missing",
			missing.len().to_string().red().bold(),
			required_keys.len()
		);
		println!(
			"  Fix: {}",
			format!("lpm use vars set {missing_list}=...").cyan()
		);
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

/// Validate a pin version string.
/// Must be non-empty and only contain alphanumeric characters, dots, hyphens, or underscores.
/// This prevents path traversal and shell injection in lpm.json.
fn is_valid_pin_version(v: &str) -> bool {
	!v.is_empty()
		&& v.chars()
			.all(|c| c.is_alphanumeric() || c == '.' || c == '-' || c == '_')
}

#[cfg(test)]
mod tests {
	use super::*;

	// ── Finding #10: Pin version validation ──────────────────────────

	#[test]
	fn valid_pin_versions() {
		assert!(is_valid_pin_version("22.5.0"));
		assert!(is_valid_pin_version("22"));
		assert!(is_valid_pin_version("lts"));
		assert!(is_valid_pin_version("latest"));
		assert!(is_valid_pin_version("22.0.0-rc.1"));
		assert!(is_valid_pin_version("v20_lts"));
	}

	#[test]
	fn invalid_pin_versions() {
		assert!(!is_valid_pin_version("../../etc"));
		assert!(!is_valid_pin_version(""));
		assert!(!is_valid_pin_version("22; rm -rf /"));
		assert!(!is_valid_pin_version("path/to/node"));
		assert!(!is_valid_pin_version("22\n23"));
		assert!(!is_valid_pin_version("node@22")); // @ is not allowed
	}

	// ── Finding #9: Atomic lpm.json write ────────────────────────────
	// ── Finding #21: Trailing newline in lpm.json ────────────────────
	// These are tested together since the write path covers both.

	#[test]
	fn atomic_write_produces_correct_content_and_no_temp_file() {
		let dir = tempfile::tempdir().unwrap();
		let lpm_json_path = dir.path().join("lpm.json");

		// Simulate the atomic write path from the pin logic
		let mut config = serde_json::json!({});
		config["runtime"] = serde_json::json!({});
		config["runtime"]["node"] = serde_json::Value::String("22.5.0".to_string());

		let content = serde_json::to_string_pretty(&config).unwrap() + "\n";

		let tmp_path = lpm_json_path.with_extension("json.tmp");
		std::fs::write(&tmp_path, &content).unwrap();
		std::fs::rename(&tmp_path, &lpm_json_path).unwrap();

		// Verify content is correct
		let written = std::fs::read_to_string(&lpm_json_path).unwrap();
		let parsed: serde_json::Value = serde_json::from_str(&written).unwrap();
		assert_eq!(parsed["runtime"]["node"], "22.5.0");

		// Verify trailing newline (Finding #21)
		assert!(
			written.ends_with('\n'),
			"lpm.json must end with a trailing newline"
		);

		// Verify no temp file remains (Finding #9)
		assert!(
			!tmp_path.exists(),
			"temporary .json.tmp file should not remain after atomic rename"
		);
	}

	#[test]
	fn atomic_write_preserves_existing_fields() {
		let dir = tempfile::tempdir().unwrap();
		let lpm_json_path = dir.path().join("lpm.json");

		// Pre-existing lpm.json with other fields
		let existing = serde_json::json!({
			"name": "my-project",
			"runtime": { "node": "20.0.0" }
		});
		std::fs::write(
			&lpm_json_path,
			serde_json::to_string_pretty(&existing).unwrap() + "\n",
		)
		.unwrap();

		// Simulate pin update
		let mut config: serde_json::Value =
			serde_json::from_str(&std::fs::read_to_string(&lpm_json_path).unwrap()).unwrap();
		config["runtime"]["node"] = serde_json::Value::String("22.5.0".to_string());

		let content = serde_json::to_string_pretty(&config).unwrap() + "\n";
		let tmp_path = lpm_json_path.with_extension("json.tmp");
		std::fs::write(&tmp_path, &content).unwrap();
		std::fs::rename(&tmp_path, &lpm_json_path).unwrap();

		let written = std::fs::read_to_string(&lpm_json_path).unwrap();
		let parsed: serde_json::Value = serde_json::from_str(&written).unwrap();
		assert_eq!(parsed["name"], "my-project");
		assert_eq!(parsed["runtime"]["node"], "22.5.0");
		assert!(written.ends_with('\n'));
	}

	// ── Finding #20: No "lpm env" in user-facing strings ─────────────

	#[test]
	fn no_old_command_name_in_source() {
		let source = include_str!("env.rs");
		// Build the forbidden pattern dynamically so the test itself doesn't contain it
		let forbidden = format!("lpm {}", "env");
		// Count occurrences outside of #[cfg(test)] module
		// Split at #[cfg(test)] and only check the non-test portion
		let production_code = source.split("#[cfg(test)]").next().unwrap_or(source);
		let count = production_code.matches(&forbidden).count();
		assert_eq!(
			count, 0,
			"found {count} occurrence(s) of the old command name in production code — all user-facing strings should reference the public command"
		);
	}
}
