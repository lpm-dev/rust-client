use crate::output;
use lpm_common::LpmError;
use owo_colors::OwoColorize;
use std::collections::HashMap;

fn build_sync_environments(
    all_envs: &HashMap<String, HashMap<String, String>>,
    env_map: &HashMap<String, String>,
    environments: Option<&lpm_env::EnvironmentsConfig>,
) -> HashMap<String, HashMap<String, String>> {
    let mut ordered_envs: Vec<_> = all_envs
        .iter()
        .filter(|(_, secrets)| !secrets.is_empty())
        .map(|(storage_key, secrets)| {
            let resolved = lpm_env::resolver::resolve(storage_key, env_map, environments);
            let is_canonical_storage = resolved.canonical == *storage_key;
            (
                resolved.canonical,
                is_canonical_storage,
                storage_key.as_str(),
                secrets,
            )
        })
        .collect();

    ordered_envs.sort_by(|left, right| {
        left.0
            .cmp(&right.0)
            .then(left.1.cmp(&right.1))
            .then(left.2.cmp(right.2))
    });

    let mut canonical_envs = HashMap::new();
    for (canonical, _is_canonical_storage, _storage_key, secrets) in ordered_envs {
        canonical_envs
            .entry(canonical)
            .or_insert_with(HashMap::new)
            .extend(secrets.clone());
    }

    canonical_envs
}

fn parse_remote_pull_payload_for_overwrite(
    raw_json: &str,
) -> Result<HashMap<String, HashMap<String, String>>, String> {
    if let Ok(wrapper) = serde_json::from_str::<
        HashMap<String, HashMap<String, HashMap<String, String>>>,
    >(raw_json)
    {
        return Ok(wrapper.get("environments").cloned().unwrap_or_default());
    }

    if let Ok(remote_secrets) = serde_json::from_str::<HashMap<String, String>>(raw_json) {
        return Ok(HashMap::from([("default".to_string(), remote_secrets)]));
    }

    Err("failed to parse pulled vault data".to_string())
}

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
                LpmError::Script("missing version spec. Usage: lpm use node@22".into())
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
                version_spec, platform
            ));

            let releases = lpm_runtime::node::fetch_index(&http_client).await?;
            let release =
                lpm_runtime::node::resolve_version(&releases, &version_spec).ok_or_else(|| {
                    LpmError::Script(format!(
                        "no node.js release found matching '{version_spec}'"
                    ))
                })?;

            let version = release.version_bare().to_string();

            if lpm_runtime::node::is_installed(&version) {
                if json_output {
                    println!(
                        "{}",
                        serde_json::json!({"success": true, "status": "already_installed", "version": version})
                    );
                } else {
                    output::success(&format!("Node.js {} is already installed", version.bold()));
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
                    serde_json::json!({"success": true, "status": "installed", "version": installed})
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
						&serde_json::json!({"success": true, "runtime": "node", "versions": versions})
					)
					.unwrap()
				);
            } else if versions.is_empty() {
                output::info("No Node.js versions installed via LPM");
                println!("  Run {} to install one", "lpm use node@22".cyan());
            } else {
                output::info(&format!("Installed Node.js versions ({})", versions.len()));
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
                    "node@{} is not currently installed. Run `lpm use node@{}` to install it",
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
                    serde_json::json!({"success": true, "pinned": {"node": version_spec}})
                );
            } else {
                output::success(&format!("Pinned node@{} in lpm.json", version_spec.bold()));
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
        return vars_list(project_dir, None, false, json_output);
    }

    match args[0] {
        "set" => {
            let (env_input, remaining) = parse_env_flag(&args[1..])?;
            let pairs: Vec<(&str, &str)> = remaining
                .iter()
                .filter_map(|arg| arg.split_once('='))
                .collect();

            if pairs.is_empty() {
                return Err(LpmError::Script(
                    "usage: lpm use vars set [--env=<name>] KEY=VALUE [KEY2=VALUE2 ...]".into(),
                ));
            }

            let (resolved_env, _config) = resolve_env_from_flag(env_input, project_dir)?;
            let env_label = resolved_env.as_deref().unwrap_or("default");

            match &resolved_env {
                Some(env) => {
                    lpm_vault::set_env(project_dir, env, &pairs).map_err(LpmError::Script)?;
                }
                None => {
                    lpm_vault::set(project_dir, &pairs).map_err(LpmError::Script)?;
                }
            }

            if json_output {
                let keys: Vec<&str> = pairs.iter().map(|(k, _)| *k).collect();
                println!(
                    "{}",
                    serde_json::json!({"success": true, "stored": keys, "env": env_label})
                );
            } else {
                for (key, _) in &pairs {
                    output::success(&format!("stored {} ({})", key.bold(), env_label));
                }
            }
        }

        "get" => {
            let (env_input, remaining) = parse_env_flag(&args[1..])?;
            let key = remaining
                .iter()
                .find(|a| **a != "--reveal")
                .ok_or_else(|| {
                    LpmError::Script("usage: lpm use vars get [--env=<name>] KEY [--reveal]".into())
                })?;
            let reveal = remaining.contains(&"--reveal");

            let (resolved_env, _config) = resolve_env_from_flag(env_input, project_dir)?;

            let value = match &resolved_env {
                Some(env) => lpm_vault::get_env(project_dir, env, key),
                None => lpm_vault::get(project_dir, key),
            };

            match value {
                Some(value) => {
                    if json_output {
                        if reveal {
                            println!("{}", serde_json::json!({"success": true, *key: value}));
                        } else {
                            println!("{}", serde_json::json!({"success": true, *key: "••••••••"}));
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
            let (env_input, remaining) = parse_env_flag(&args[1..])?;
            let reveal = remaining.contains(&"--reveal");
            let (resolved_env, _config) = resolve_env_from_flag(env_input, project_dir)?;
            vars_list(project_dir, resolved_env.as_deref(), reveal, json_output)?;
        }

        "delete" => {
            let (env_input, remaining) = parse_env_flag(&args[1..])?;
            let keys: Vec<&str> = remaining.to_vec();

            if keys.is_empty() {
                return Err(LpmError::Script(
                    "usage: lpm use vars delete [--env=<name>] KEY [KEY2 ...]".into(),
                ));
            }

            let (resolved_env, _config) = resolve_env_from_flag(env_input, project_dir)?;
            let env_label = resolved_env.as_deref().unwrap_or("default");

            match &resolved_env {
                Some(env) => {
                    lpm_vault::delete_env(project_dir, env, &keys).map_err(LpmError::Script)?;
                }
                None => {
                    lpm_vault::delete(project_dir, &keys).map_err(LpmError::Script)?;
                }
            }

            if json_output {
                println!(
                    "{}",
                    serde_json::json!({"success": true, "deleted": keys, "env": env_label})
                );
            } else {
                for key in &keys {
                    output::success(&format!("deleted {} ({})", key.bold(), env_label));
                }
            }
        }

        "import" => {
            let (env_input, remaining) = parse_env_flag(&args[1..])?;
            let file = remaining
                .iter()
                .find(|a| **a != "--overwrite")
                .ok_or_else(|| {
                    LpmError::Script(
                        "usage: lpm use vars import [--env=<name>] <file> [--overwrite]".into(),
                    )
                })?;
            let overwrite = remaining.contains(&"--overwrite");
            let path = project_dir.join(file);

            let (resolved_env, _config) = resolve_env_from_flag(env_input, project_dir)?;
            let env_label = resolved_env.as_deref().unwrap_or("default");

            let count = match &resolved_env {
                Some(env) => lpm_vault::import_env_file_to_env(project_dir, env, &path, overwrite)
                    .map_err(LpmError::Script)?,
                None => lpm_vault::import_env_file(project_dir, &path, overwrite)
                    .map_err(LpmError::Script)?,
            };

            if json_output {
                println!(
                    "{}",
                    serde_json::json!({"success": true, "imported": count, "from": *file, "env": env_label})
                );
            } else {
                output::success(&format!(
                    "imported {} secret{} from {} ({})",
                    count.to_string().bold(),
                    if count == 1 { "" } else { "s" },
                    file.cyan(),
                    env_label
                ));
            }
        }

        "export" => {
            let (env_input, remaining) = parse_env_flag(&args[1..])?;
            let file = remaining.first().ok_or_else(|| {
                LpmError::Script("usage: lpm use vars export [--env=<name>] <file>".into())
            })?;
            let path = project_dir.join(file);

            let (resolved_env, _config) = resolve_env_from_flag(env_input, project_dir)?;
            let env_label = resolved_env.as_deref().unwrap_or("default");

            let count = match &resolved_env {
                Some(env) => lpm_vault::export_env_file_from_env(project_dir, env, &path)
                    .map_err(LpmError::Script)?,
                None => lpm_vault::export_env_file(project_dir, &path).map_err(LpmError::Script)?,
            };

            if json_output {
                println!(
                    "{}",
                    serde_json::json!({"success": true, "exported": count, "to": *file, "env": env_label})
                );
            } else {
                output::success(&format!(
                    "exported {} secret{} to {} ({})",
                    count.to_string().bold(),
                    if count == 1 { "" } else { "s" },
                    file.cyan(),
                    env_label
                ));
            }
        }

        "push" => {
            // Route to platform push if --to flag is present
            if args.iter().any(|a| a.starts_with("--to")) {
                return vars_platform_push(&args[1..], project_dir, json_output).await;
            }

            let force = args.contains(&"--force");
            let yes = args.iter().any(|a| *a == "--yes" || *a == "-y");
            let vault_id = lpm_vault::vault_id::read_vault_id(project_dir).ok_or_else(|| {
                LpmError::Script("no vault configured. Run `lpm use vars set` first".into())
            })?;

            let all_envs = lpm_vault::get_all_environments(project_dir);
            let total_keys: usize = all_envs.values().map(|e| e.len()).sum();
            if total_keys == 0 {
                return Err(LpmError::Script("vault is empty, nothing to push".into()));
            }

            let config = lpm_runner::lpm_json::read_lpm_json(project_dir)
                .ok()
                .flatten();
            let empty_env_map = HashMap::new();
            let env_map = config.as_ref().map_or(&empty_env_map, |c| &c.env);
            let environments = config.as_ref().and_then(|c| c.environments.as_ref());
            let non_empty_envs = build_sync_environments(&all_envs, env_map, environments);

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
                let confirm = cliclack::confirm("Continue?")
                    .initial_value(false)
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

            let schema_value = config.as_ref().map(|c| {
                let mut obj = serde_json::Map::new();
                obj.insert("version".into(), serde_json::json!(2));

                // envSchema: flat var map (serialize .vars directly, not the EnvSchema wrapper)
                if let Some(env_schema) = &c.env_schema
                    && let Ok(v) = serde_json::to_value(&env_schema.vars)
                {
                    obj.insert("envSchema".into(), v);
                }

                // envConfig: alias → canonical mapping from lpm.json "env" field
                if !c.env.is_empty() {
                    let env_config: serde_json::Map<_, _> = c
                        .env
                        .iter()
                        .filter_map(|(alias, file_path)| {
                            let mode = lpm_env::resolver::extract_mode_from_env_path(file_path)?;
                            Some((
                                alias.clone(),
                                serde_json::json!({
                                    "canonical": mode,
                                    "file": file_path,
                                }),
                            ))
                        })
                        .collect();
                    obj.insert("envConfig".into(), serde_json::Value::Object(env_config));
                }

                // environments: inheritance config (extends, file, sensitive)
                if let Some(envs) = &c.environments
                    && let Ok(v) = serde_json::to_value(envs)
                {
                    obj.insert("environments".into(), v);
                }

                serde_json::Value::Object(obj)
            });

            let push_metadata = lpm_vault::sync::PushMetadata {
                name: Some(&project_name),
                schema: schema_value.as_ref(),
            };
            let expected_version = expected_personal_sync_version(project_dir, force);

            let result = lpm_vault::sync::push_raw(
                &registry_url,
                &auth_token,
                &vault_id,
                &secrets_json,
                expected_version,
                force,
                Some(&push_metadata),
            )
            .await
            .map_err(LpmError::Script)?;

            if let Some(version) = result.version {
                lpm_vault::vault_id::write_personal_sync_version(project_dir, version)
                    .map_err(LpmError::Script)?;
            }

            if json_output {
                println!(
                    "{}",
                    serde_json::json!({
                        "success": true,
                        "status": result.status,
                        "version": result.version,
                    })
                );
            } else {
                output::success(&format!(
                    "vault synced (version {})",
                    result.version.unwrap_or(0).to_string().bold()
                ));
            }
        }

        "pull" => {
            // Route to platform pull if --from flag is present
            if args.iter().any(|a| a.starts_with("--from")) {
                return vars_platform_pull(&args[1..], project_dir, json_output).await;
            }

            // Route to OIDC pull if --oidc flag is present
            if args.contains(&"--oidc") {
                return vars_oidc_pull(&args[1..], project_dir, json_output).await;
            }

            let yes = args.iter().any(|a| *a == "--yes" || *a == "-y");
            let org_flag = args
                .iter()
                .position(|a| *a == "--org")
                .and_then(|i| args.get(i + 1).copied());

            let vault_id = lpm_vault::vault_id::get_or_create_vault_id(project_dir)
                .map_err(LpmError::Script)?;

            // Org pull: different flow with X25519 decryption
            if let Some(org_slug) = org_flag {
                let registry_url = std::env::var("LPM_REGISTRY_URL")
                    .unwrap_or_else(|_| lpm_common::DEFAULT_REGISTRY_URL.to_string());
                let auth_token = crate::auth::get_token(&registry_url).ok_or_else(|| {
                    LpmError::Script("not logged in. Run `lpm login` first".into())
                })?;

                // Ensure we have a keypair
                let private_key = lpm_vault::sync::ensure_public_key(&registry_url, &auth_token)
                    .await
                    .map_err(LpmError::Script)?;

                output::info(&format!("pulling vault from org {}...", org_slug.bold()));

                let (raw_json, version) = lpm_vault::sync::pull_org(
                    &registry_url,
                    &auth_token,
                    org_slug,
                    &vault_id,
                    &private_key,
                )
                .await
                .map_err(LpmError::Script)?;

                // Same merge logic as personal pull
                let total_keys;
                if let Ok(wrapper) = serde_json::from_str::<
                    std::collections::HashMap<
                        String,
                        std::collections::HashMap<
                            String,
                            std::collections::HashMap<String, String>,
                        >,
                    >,
                >(&raw_json)
                {
                    if let Some(remote_envs) = wrapper.get("environments") {
                        let mut total = 0;
                        for (env_name, remote_secrets) in remote_envs {
                            let mut env = lpm_vault::get_all_env(project_dir, env_name);
                            env.extend(remote_secrets.clone());
                            total += env.len();
                            let pairs: Vec<(&str, &str)> =
                                env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
                            lpm_vault::set_env(project_dir, env_name, &pairs)
                                .map_err(LpmError::Script)?;
                        }
                        total_keys = total;
                    } else {
                        total_keys = 0;
                    }
                } else if let Ok(remote_secrets) =
                    serde_json::from_str::<std::collections::HashMap<String, String>>(&raw_json)
                {
                    let mut merged = lpm_vault::get_all(project_dir);
                    merged.extend(remote_secrets);
                    total_keys = merged.len();
                    let pairs: Vec<(&str, &str)> = merged
                        .iter()
                        .map(|(k, v)| (k.as_str(), v.as_str()))
                        .collect();
                    lpm_vault::set(project_dir, &pairs).map_err(LpmError::Script)?;
                } else {
                    return Err(LpmError::Script("failed to parse pulled vault data".into()));
                }

                lpm_vault::vault_id::write_org_sync_version(project_dir, org_slug, version)
                    .map_err(LpmError::Script)?;

                if json_output {
                    println!(
                        "{}",
                        serde_json::json!({"success": true, "status": "pulled", "org": org_slug, "version": version, "count": total_keys})
                    );
                } else {
                    output::success(&format!(
                        "pulled {} key{} from org {} (version {})",
                        total_keys.to_string().bold(),
                        if total_keys == 1 { "" } else { "s" },
                        org_slug.bold(),
                        version.to_string().bold()
                    ));
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
                let confirm = cliclack::confirm("Continue?")
                    .initial_value(false)
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

            let (raw_json, version) =
                lpm_vault::sync::pull_raw(&registry_url, &auth_token, &vault_id)
                    .await
                    .map_err(LpmError::Script)?;

            let remote_envs =
                parse_remote_pull_payload_for_overwrite(&raw_json).map_err(LpmError::Script)?;
            let total_keys: usize = remote_envs.values().map(|env| env.len()).sum();
            lpm_vault::replace_all_environments(project_dir, &remote_envs)
                .map_err(LpmError::Script)?;

            lpm_vault::vault_id::write_personal_sync_version(project_dir, version)
                .map_err(LpmError::Script)?;

            if json_output {
                println!(
                    "{}",
                    serde_json::json!({
                        "success": true,
                        "status": "pulled",
                        "version": version,
                        "count": total_keys,
                    })
                );
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

            let result =
                lpm_vault::sync::get_audit_log(&registry_url, &auth_token, &vault_id, None)
                    .await
                    .map_err(LpmError::Script)?;

            let entries = result.entries.unwrap_or_default();

            if json_output {
                println!("{}", serde_json::to_string_pretty(&serde_json::json!({"success": true, "entries": entries.iter().map(|e| serde_json::json!({
					"action": e.action,
					"created_at": e.created_at,
				})).collect::<Vec<_>>()})).unwrap());
            } else if entries.is_empty() {
                output::info("No audit log entries");
            } else {
                output::info(&format!("Vault audit log ({} entries)", entries.len()));
                for entry in &entries {
                    println!(
                        "  {} {} {}",
                        entry.created_at.dimmed(),
                        entry.action.bold(),
                        entry.user_id.as_deref().unwrap_or("").dimmed()
                    );
                }
            }
        }

        "share" => {
            let org_flag = args
                .iter()
                .position(|a| *a == "--org")
                .and_then(|i| args.get(i + 1).copied());
            let org_slug = org_flag.ok_or_else(|| {
                LpmError::Script("usage: lpm use vars share --org <org-slug>".into())
            })?;

            let vault_id = lpm_vault::vault_id::read_vault_id(project_dir).ok_or_else(|| {
                LpmError::Script("no vault configured. Run `lpm use vars set` first".into())
            })?;

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

            let config = lpm_runner::lpm_json::read_lpm_json(project_dir)
                .ok()
                .flatten();
            let empty_env_map = HashMap::new();
            let env_map = config.as_ref().map_or(&empty_env_map, |c| &c.env);
            let environments = config.as_ref().and_then(|c| c.environments.as_ref());
            let non_empty_envs = build_sync_environments(&all_envs, env_map, environments);
            let mut wrapper = std::collections::HashMap::new();
            wrapper.insert("environments".to_string(), non_empty_envs);
            let secrets_json = serde_json::to_string(&wrapper)
                .map_err(|e| LpmError::Script(format!("failed to serialize: {e}")))?;

            output::info(&format!(
                "sharing vault with org {} ({} keys across {} environments)...",
                org_slug.bold(),
                total_keys,
                all_envs.len()
            ));

            let result = lpm_vault::sync::push_org_with_keys(
                &registry_url,
                &auth_token,
                org_slug,
                &vault_id,
                &secrets_json,
                expected_org_sync_version(project_dir, org_slug),
            )
            .await
            .map_err(LpmError::Script)?;

            if let Some(version) = result.version {
                lpm_vault::vault_id::write_org_sync_version(project_dir, org_slug, version)
                    .map_err(LpmError::Script)?;
            }

            if json_output {
                println!(
                    "{}",
                    serde_json::json!({
                        "success": true,
                        "status": result.status,
                        "org": org_slug,
                        "version": result.version,
                    })
                );
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
            let result =
                lpm_vault::sync::push(&registry_url, &auth_token, &vault_id, &secrets, None, true)
                    .await
                    .map_err(LpmError::Script)?;

            if let Some(version) = result.version {
                lpm_vault::vault_id::write_personal_sync_version(project_dir, version)
                    .map_err(LpmError::Script)?;
            }

            if json_output {
                println!(
                    "{}",
                    serde_json::json!({
                        "success": true,
                        "status": "rotated",
                        "version": result.version,
                    })
                );
            } else {
                output::success(&format!(
                    "encryption key rotated (version {})",
                    result.version.unwrap_or(0).to_string().bold()
                ));
            }
        }

        "list-remote" | "ls-remote" => {
            let org_flag = args
                .iter()
                .position(|a| *a == "--org")
                .and_then(|i| args.get(i + 1).copied());
            return vars_list_remote(org_flag, json_output).await;
        }

        "diff" => {
            return vars_diff(&args[1..], project_dir, json_output).await;
        }

        "validate" => {
            let strict = args.contains(&"--strict");
            return vars_validate(project_dir, strict, json_output);
        }

        "example" => {
            let (env_input, _remaining) = parse_env_flag(&args[1..])?;
            return vars_example(project_dir, env_input, json_output);
        }

        "print" => {
            return vars_print(&args[1..], project_dir);
        }

        "check" => {
            return vars_check(project_dir, json_output);
        }

        "connect" => {
            return vars_connect(&args[1..], project_dir, json_output).await;
        }

        "oidc" => {
            return vars_oidc(&args[1..], project_dir, json_output).await;
        }

        "status" => {
            return vars_platform_status(project_dir, json_output).await;
        }

        "pair" => {
            let code = args.get(1).ok_or_else(|| {
                LpmError::Script(
                    "usage: lpm use vars pair <CODE>\n  The 6-character pairing code shown in the dashboard.".into(),
                )
            })?;

            // Validate code format: 6 uppercase alphanumeric chars (no I/O/0/1)
            if code.len() != 6 || !code.chars().all(|c| c.is_ascii_alphanumeric()) {
                return Err(LpmError::Script(
                    "invalid pairing code. Expected 6 alphanumeric characters (e.g., ABC123)."
                        .into(),
                ));
            }
            let code = code.to_ascii_uppercase();

            let registry_url = std::env::var("LPM_REGISTRY_URL")
                .unwrap_or_else(|_| lpm_common::DEFAULT_REGISTRY_URL.to_string());
            let auth_token = crate::auth::get_token(&registry_url)
                .ok_or_else(|| LpmError::Script("not logged in. Run `lpm login` first".into()))?;

            // Vault pairing requires a CLI session (access+refresh token pair).
            // Legacy tokens (pre-session auth) are rejected by the server.
            if !crate::auth::has_refresh_token(&registry_url) {
                return Err(LpmError::Script(
                    "your current login uses a legacy token that doesn't support vault pairing.\n  Run `lpm logout` then `lpm login` to upgrade to a session-based login.".into(),
                ));
            }

            output::info("fetching pairing session...");

            // 1. Fetch pending session → get browser's P-256 public key
            let session = lpm_vault::sync::get_pairing_session(&registry_url, &auth_token, &code)
                .await
                .map_err(LpmError::Script)?;

            if session.status != "pending" {
                return Err(LpmError::Script(format!(
                    "pairing session is '{}' (expected 'pending'). The code may have expired or already been used.",
                    session.status
                )));
            }

            let browser_pub_b64 = session.browser_public_key.ok_or_else(|| {
                LpmError::Script("server did not return browser public key".into())
            })?;

            // 2. Get wrapping key from keychain
            let wrapping_key =
                lpm_vault::crypto::get_or_create_wrapping_key().map_err(LpmError::Script)?;

            // 3. P-256 ECDH → wrap wrapping key for browser
            let (encrypted_wrapping_key, ephemeral_public_key) =
                lpm_vault::crypto::p256_pair_wrap_key(&wrapping_key, &browser_pub_b64)
                    .map_err(LpmError::Script)?;

            // 4. Send approval
            lpm_vault::sync::approve_pairing(
                &registry_url,
                &auth_token,
                &code,
                &encrypted_wrapping_key,
                &ephemeral_public_key,
            )
            .await
            .map_err(LpmError::Script)?;

            if json_output {
                println!(
                    "{}",
                    serde_json::json!({ "success": true, "status": "paired" })
                );
            } else {
                println!();
                output::success("browser paired successfully");
                println!(
                    "  {}",
                    "The dashboard can now decrypt your vault secrets.".dimmed()
                );
                println!();
            }
        }

        "unpair" => {
            let registry_url = std::env::var("LPM_REGISTRY_URL")
                .unwrap_or_else(|_| lpm_common::DEFAULT_REGISTRY_URL.to_string());
            let auth_token = crate::auth::get_token(&registry_url)
                .ok_or_else(|| LpmError::Script("not logged in. Run `lpm login` first".into()))?;

            if !crate::auth::has_refresh_token(&registry_url) {
                return Err(LpmError::Script(
                    "your current login uses a legacy token that doesn't support vault operations.\n  Run `lpm logout` then `lpm login` to upgrade to a session-based login.".into(),
                ));
            }

            output::info("revoking all browser pairings...");

            lpm_vault::sync::unpair_all(&registry_url, &auth_token)
                .await
                .map_err(LpmError::Script)?;

            if json_output {
                println!(
                    "{}",
                    serde_json::json!({ "success": true, "status": "revoked" })
                );
            } else {
                println!();
                output::success("all browser pairings revoked");
                println!(
                    "  {}",
                    "Paired browsers will need to re-pair to access secrets.".dimmed()
                );
                println!();
            }
        }

        "init" => {
            let force = args.contains(&"--force");
            return vars_init(project_dir, force, json_output);
        }

        "ls" => {
            return vars_ls(project_dir, json_output);
        }

        "copy" | "cp" => {
            let remaining = &args[1..];
            if remaining.len() < 2 {
                return Err(LpmError::Script(
                    "usage: lpm use vars copy <source-env> <target-env> [--overwrite]".into(),
                ));
            }
            let overwrite = remaining.contains(&"--overwrite");
            let envs: Vec<&&str> = remaining.iter().filter(|a| **a != "--overwrite").collect();
            if envs.len() < 2 {
                return Err(LpmError::Script(
                    "usage: lpm use vars copy <source-env> <target-env> [--overwrite]".into(),
                ));
            }
            return vars_copy(project_dir, envs[0], envs[1], overwrite, json_output);
        }

        unknown => {
            return Err(LpmError::Script(format!(
                "unknown vars action: '{unknown}'. Available: set, get, list, delete, import, export, push, pull, diff, validate, example, print, check, connect, status, log, share, rotate-key, pair, unpair, init, ls, copy"
            )));
        }
    }

    Ok(())
}

fn vars_example(
    project_dir: &std::path::Path,
    env_input: Option<&str>,
    json_output: bool,
) -> Result<(), LpmError> {
    let config = lpm_runner::lpm_json::read_lpm_json(project_dir)
        .map_err(|e| LpmError::Script(e.to_string()))?;

    let schema = config
        .as_ref()
        .and_then(|c| c.env_schema.as_ref())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            LpmError::Script(
                "no envSchema defined in lpm.json. Add an envSchema section first.".into(),
            )
        })?;

    // Resolve env name for the output filename — write path, use resolve_checked
    let (resolved_env, env_label, example_filename) = match env_input {
        Some(input) => {
            let empty = HashMap::new();
            let env_map = config.as_ref().map_or(&empty, |c| &c.env);
            let environments = config.as_ref().and_then(|c| c.environments.as_ref());
            let resolved = lpm_env::resolver::resolve_checked(input, env_map, environments)
                .map_err(|e| LpmError::Script(format!("invalid environment name: {e}")))?;
            let filename = format!(".env.{}.example", resolved.canonical);
            let label = resolved.canonical.clone();
            (Some(resolved), label, filename)
        }
        None => (None, "default".to_string(), ".env.example".to_string()),
    };

    // Generate the example content
    let mut content = lpm_env::generate_env_example(schema);

    // If --env is specified, add a header comment noting the environment
    if let Some(ref env) = resolved_env {
        let header = format!(
            "# Environment: {}{}\n#\n",
            env.canonical,
            env.alias
                .as_ref()
                .map(|a| format!(" (lpm run {a})"))
                .unwrap_or_default()
        );
        content = header + &content;
    }

    if json_output {
        println!(
            "{}",
            serde_json::json!({
                "variables": schema.len(),
                "environment": env_label,
                "filename": example_filename,
                "content": content,
            })
        );
        return Ok(());
    }

    let example_path = project_dir.join(&example_filename);
    std::fs::write(&example_path, &content)
        .map_err(|e| LpmError::Script(format!("failed to write {example_filename}: {e}")))?;

    output::success(&format!(
        "generated {} ({} variables)",
        example_filename.bold(),
        schema.len()
    ));

    Ok(())
}

/// `lpm use vars init` — interactive environment setup.
///
/// Detects lpm.json config, scans for .env files, imports each into
/// the correct vault environment, and creates empty envs for configured
/// environments without files.
fn vars_init(
    project_dir: &std::path::Path,
    force: bool,
    json_output: bool,
) -> Result<(), LpmError> {
    let config = lpm_runner::lpm_json::read_lpm_json(project_dir)
        .ok()
        .flatten();

    let empty_env_map = HashMap::new();
    let env_map = config.as_ref().map_or(&empty_env_map, |c| &c.env);
    let environments = config.as_ref().and_then(|c| c.environments.as_ref());
    let vault_envs = lpm_vault::get_all_environments(project_dir);

    // Build the list of environments to process
    let all_envs = lpm_env::resolver::list_all(env_map, environments, &vault_envs);

    // Collect actions to perform
    struct InitAction {
        canonical: String,
        alias: Option<String>,
        file_path: Option<String>,
        file_exists: bool,
        file_var_count: usize,
        vault_exists: bool,
        vault_var_count: usize,
    }

    let mut actions: Vec<InitAction> = Vec::new();

    for env in &all_envs {
        let vault_vars = vault_envs.get(&env.canonical);
        let vault_exists = vault_vars.is_some_and(|v| !v.is_empty());
        let vault_var_count = vault_vars.map_or(0, |v| v.len());

        // Determine the .env file to check
        let file_path = env.file_path.clone().or_else(|| {
            if env.canonical == "default" {
                Some(".env".to_string())
            } else {
                Some(format!(".env.{}", env.canonical))
            }
        });

        let (file_exists, file_var_count) = if let Some(ref fp) = file_path {
            let abs = project_dir.join(fp);
            if abs.exists() {
                let content = std::fs::read_to_string(&abs).unwrap_or_default();
                let count = lpm_vault::parse_env_content(&content).len();
                (true, count)
            } else {
                (false, 0)
            }
        } else {
            (false, 0)
        };

        actions.push(InitAction {
            canonical: env.canonical.clone(),
            alias: env.alias.clone(),
            file_path,
            file_exists,
            file_var_count,
            vault_exists,
            vault_var_count,
        });
    }

    if json_output {
        let json_actions: Vec<serde_json::Value> = actions
            .iter()
            .map(|a| {
                serde_json::json!({
                    "environment": a.canonical,
                    "alias": a.alias,
                    "filePath": a.file_path,
                    "fileExists": a.file_exists,
                    "fileVarCount": a.file_var_count,
                    "vaultExists": a.vault_exists,
                    "vaultVarCount": a.vault_var_count,
                })
            })
            .collect();

        // Perform imports
        let mut results = Vec::new();
        for action in &actions {
            if action.file_exists && (!action.vault_exists || force) {
                let fp = action.file_path.as_deref().unwrap();
                let path = project_dir.join(fp);
                let count = if action.canonical == "default" {
                    lpm_vault::import_env_file(project_dir, &path, force)
                } else {
                    lpm_vault::import_env_file_to_env(project_dir, &action.canonical, &path, force)
                }
                .map_err(LpmError::Script)?;
                results.push(serde_json::json!({
                    "environment": action.canonical,
                    "action": "imported",
                    "count": count,
                }));
            } else if !action.vault_exists && !action.file_exists {
                // Create empty env by writing an empty set
                if action.canonical != "default" {
                    lpm_vault::set_env(project_dir, &action.canonical, &[])
                        .map_err(LpmError::Script)?;
                }
                results.push(serde_json::json!({
                    "environment": action.canonical,
                    "action": "created_empty",
                }));
            }
        }

        println!(
            "{}",
            serde_json::json!({
                "success": true,
                "environments": json_actions,
                "actions": results,
            })
        );
        return Ok(());
    }

    // Display detected config
    if !env_map.is_empty() {
        println!();
        output::info("detected lpm.json env config:");
        for env in &all_envs {
            if let Some(alias) = &env.alias {
                println!(
                    "    {}  {}  {}",
                    alias.bold(),
                    "->".dimmed(),
                    env.file_path
                        .as_deref()
                        .unwrap_or(&format!(".env.{}", env.canonical))
                        .dimmed(),
                );
            }
        }
        println!();
    }

    // Show file scan results
    output::info("scanning .env files:");
    for action in &actions {
        let fallback = format!(".env.{}", action.canonical);
        let fp = action.file_path.as_deref().unwrap_or(&fallback);
        if action.file_exists {
            println!(
                "    {} {} ({} variable{})",
                "found".green(),
                fp.bold(),
                action.file_var_count,
                if action.file_var_count == 1 { "" } else { "s" }
            );
        } else {
            println!("    {}  {}", "missing".dimmed(), fp.dimmed());
        }
    }
    println!();

    // Perform actions
    let mut imported_count = 0;
    let mut created_count = 0;
    let mut skipped_count = 0;

    for action in &actions {
        if action.file_exists && (!action.vault_exists || force) {
            let fp = action.file_path.as_deref().unwrap();
            let path = project_dir.join(fp);
            let count = if action.canonical == "default" {
                lpm_vault::import_env_file(project_dir, &path, force)
            } else {
                lpm_vault::import_env_file_to_env(project_dir, &action.canonical, &path, force)
            }
            .map_err(LpmError::Script)?;
            output::success(&format!(
                "imported {} variable{} from {} into \"{}\"",
                count,
                if count == 1 { "" } else { "s" },
                fp.cyan(),
                action.canonical
            ));
            imported_count += 1;
        } else if action.file_exists && action.vault_exists {
            println!(
                "  {} \"{}\" already has {} secret{} (use {} to overwrite)",
                "skip".yellow(),
                action.canonical,
                action.vault_var_count,
                if action.vault_var_count == 1 { "" } else { "s" },
                "--force".bold()
            );
            skipped_count += 1;
        } else if !action.vault_exists && !action.file_exists && action.canonical != "default" {
            // Create empty env
            lpm_vault::set_env(project_dir, &action.canonical, &[]).map_err(LpmError::Script)?;
            output::success(&format!("created empty \"{}\"", action.canonical));
            created_count += 1;
        }
    }

    println!();
    let total = imported_count + created_count;
    if total > 0 || skipped_count > 0 {
        output::success(&format!(
            "vault initialized with {} environment{}{}",
            all_envs.len(),
            if all_envs.len() == 1 { "" } else { "s" },
            if skipped_count > 0 {
                format!(" ({skipped_count} skipped)")
            } else {
                String::new()
            }
        ));
        println!("  Run {} to sync to cloud", "lpm use vars push".cyan());
    } else {
        output::info("vault already initialized — nothing to do");
    }
    println!();

    Ok(())
}

/// `lpm use vars ls` — environment overview table.
///
/// Shows all environments with variable counts, schema status, and aliases.
fn vars_ls(project_dir: &std::path::Path, json_output: bool) -> Result<(), LpmError> {
    let config = lpm_runner::lpm_json::read_lpm_json(project_dir)
        .ok()
        .flatten();

    let empty_env_map = HashMap::new();
    let env_map = config.as_ref().map_or(&empty_env_map, |c| &c.env);
    let environments = config.as_ref().and_then(|c| c.environments.as_ref());
    let schema = config.as_ref().and_then(|c| c.env_schema.as_ref());
    let vault_envs = lpm_vault::get_all_environments(project_dir);
    let all_envs = lpm_env::resolver::list_all(env_map, environments, &vault_envs);

    if all_envs.is_empty() {
        if json_output {
            println!(
                "{}",
                serde_json::json!({"success": true, "environments": []})
            );
        } else {
            output::info("no environments found");
            println!("  Run {} to set up", "lpm use vars init".cyan());
        }
        return Ok(());
    }

    // Build rows
    struct EnvRow {
        canonical: String,
        var_count: usize,
        schema_status: Option<(usize, usize)>, // (valid, total)
        alias: Option<String>,
        source: lpm_env::EnvSource,
    }

    let mut rows: Vec<EnvRow> = Vec::new();

    for env in &all_envs {
        // Replicate the actual loader fallback behavior from dotenv.rs:79-88:
        // If the env-specific vault is completely empty, fall back to default.
        // If it has any secrets, use ONLY it (no per-key fallback to default).
        let env_specific = vault_envs.get(&env.canonical);
        let effective_vars = if env.canonical == "default" {
            env_specific.cloned().unwrap_or_default()
        } else {
            match env_specific {
                Some(v) if !v.is_empty() => v.clone(),
                _ => vault_envs.get("default").cloned().unwrap_or_default(),
            }
        };
        let var_count = env_specific.map_or(0, |v| v.len());

        let schema_status = schema.map(|s| {
            let total = s.vars.iter().filter(|(_, r)| r.required).count();
            let valid = s
                .vars
                .iter()
                .filter(|(_, r)| r.required)
                .filter(|(k, _)| effective_vars.contains_key(k.as_str()))
                .count();
            (valid, total)
        });

        rows.push(EnvRow {
            canonical: env.canonical.clone(),
            var_count,
            schema_status,
            alias: env.alias.clone(),
            source: env.source.clone(),
        });
    }

    if json_output {
        let json_rows: Vec<serde_json::Value> = rows
            .iter()
            .map(|r| {
                let mut obj = serde_json::json!({
                    "environment": r.canonical,
                    "variables": r.var_count,
                    "alias": r.alias,
                    "source": format!("{:?}", r.source),
                });
                if let Some((valid, total)) = r.schema_status {
                    obj["schemaValid"] = serde_json::json!(valid);
                    obj["schemaTotal"] = serde_json::json!(total);
                }
                obj
            })
            .collect();
        println!(
            "{}",
            serde_json::json!({"success": true, "environments": json_rows})
        );
        return Ok(());
    }

    // Calculate column widths
    let name_width = rows
        .iter()
        .map(|r| r.canonical.len())
        .max()
        .unwrap_or(11)
        .max(11);
    let alias_width = rows
        .iter()
        .filter_map(|r| r.alias.as_ref().map(|a| a.len()))
        .max()
        .unwrap_or(5)
        .max(5);

    println!();
    // Header
    println!(
        "  {:<name_width$}  {:>9}  {:>10}  {:<alias_width$}",
        "Environment", "Variables", "Required", "Alias",
    );
    println!(
        "  {:<name_width$}  {:>9}  {:>10}  {:<alias_width$}",
        "-".repeat(name_width),
        "-".repeat(9),
        "-".repeat(10),
        "-".repeat(alias_width),
    );

    for row in &rows {
        let schema_str = match row.schema_status {
            Some((valid, total)) if total > 0 => {
                if valid == total {
                    format!("{valid}/{total} {}", "ok".green())
                } else {
                    format!("{valid}/{total} {}", "!!".red())
                }
            }
            _ => "-".dimmed().to_string(),
        };

        let alias_str = row.alias.as_deref().unwrap_or("-").dimmed().to_string();

        let source_indicator = match row.source {
            lpm_env::EnvSource::Legacy => format!(" {}", "legacy".yellow()),
            _ => String::new(),
        };

        println!(
            "  {:<name_width$}  {:>9}  {:>10}  {:<alias_width$}{}",
            row.canonical.bold(),
            row.var_count,
            schema_str,
            alias_str,
            source_indicator,
        );
    }
    println!();

    Ok(())
}

/// `lpm use vars copy <src> <dst>` — copy all secrets from one environment to another.
fn vars_copy(
    project_dir: &std::path::Path,
    src: &str,
    dst: &str,
    overwrite: bool,
    json_output: bool,
) -> Result<(), LpmError> {
    let config = lpm_runner::lpm_json::read_lpm_json(project_dir)
        .ok()
        .flatten();
    let empty = HashMap::new();
    let env_map = config.as_ref().map_or(&empty, |c| &c.env);
    let environments = config.as_ref().and_then(|c| c.environments.as_ref());

    // Resolve both env names (src = read path, dst = write path)
    let resolved_src = lpm_env::resolver::resolve(src, env_map, environments);
    let resolved_dst = lpm_env::resolver::resolve_checked(dst, env_map, environments)
        .map_err(|e| LpmError::Script(format!("invalid target environment: {e}")))?;

    if resolved_src.canonical == resolved_dst.canonical {
        return Err(LpmError::Script(
            "source and target environments are the same".into(),
        ));
    }

    let src_secrets = lpm_vault::get_all_env(project_dir, &resolved_src.storage_key);
    if src_secrets.is_empty() {
        return Err(LpmError::Script(format!(
            "no secrets in source environment \"{}\"",
            resolved_src.canonical
        )));
    }

    let dst_secrets = lpm_vault::get_all_env(project_dir, &resolved_dst.storage_key);

    // Compute what will be copied
    let mut to_copy = Vec::new();
    let mut to_skip = Vec::new();
    for (key, value) in &src_secrets {
        if dst_secrets.contains_key(key) && !overwrite {
            to_skip.push(key.as_str());
        } else {
            to_copy.push((key.as_str(), value.as_str()));
        }
    }

    if to_copy.is_empty() {
        if json_output {
            println!(
                "{}",
                serde_json::json!({
                    "success": true,
                    "copied": 0,
                    "skipped": to_skip.len(),
                    "source": resolved_src.canonical,
                    "target": resolved_dst.canonical,
                })
            );
        } else {
            output::info(&format!(
                "nothing to copy — all {} key{} already exist in \"{}\" (use {} to overwrite)",
                to_skip.len(),
                if to_skip.len() == 1 { "" } else { "s" },
                resolved_dst.canonical,
                "--overwrite".bold()
            ));
        }
        return Ok(());
    }

    // Perform the copy
    lpm_vault::set_env(project_dir, &resolved_dst.canonical, &to_copy).map_err(LpmError::Script)?;

    if json_output {
        println!(
            "{}",
            serde_json::json!({
                "success": true,
                "copied": to_copy.len(),
                "skipped": to_skip.len(),
                "source": resolved_src.canonical,
                "target": resolved_dst.canonical,
            })
        );
    } else {
        output::success(&format!(
            "copied {} secret{} from \"{}\" to \"{}\"{}",
            to_copy.len(),
            if to_copy.len() == 1 { "" } else { "s" },
            resolved_src.canonical,
            resolved_dst.canonical,
            if to_skip.is_empty() {
                String::new()
            } else {
                format!(
                    " ({} existing skipped, use {} to overwrite)",
                    to_skip.len(),
                    "--overwrite".bold()
                )
            }
        ));
    }

    Ok(())
}

fn vars_print(args: &[&str], project_dir: &std::path::Path) -> Result<(), LpmError> {
    // Parse --format=<fmt> and --env=<mode> and --schema-only
    let mut format_str = "dotenv";
    let mut env_mode: Option<&str> = None;
    let mut schema_only = false;

    let mut i = 0;
    while i < args.len() {
        if let Some(fmt) = args[i].strip_prefix("--format=") {
            format_str = fmt;
        } else if args[i] == "--format" {
            if let Some(next) = args.get(i + 1) {
                format_str = next;
                i += 1;
            }
        } else if let Some(mode) = args[i].strip_prefix("--env=") {
            env_mode = Some(mode);
        } else if args[i] == "--env" {
            if let Some(next) = args.get(i + 1) {
                env_mode = Some(next);
                i += 1;
            }
        } else if args[i] == "--schema-only" {
            schema_only = true;
        }
        i += 1;
    }

    let format = lpm_env::PrintFormat::parse(format_str).ok_or_else(|| {
        LpmError::Script(format!(
            "unknown format: '{format_str}'. Available: {}",
            lpm_env::PrintFormat::all_names()
        ))
    })?;

    // Read config first so we can resolve env aliases
    let config = lpm_runner::lpm_json::read_lpm_json(project_dir)
        .ok()
        .flatten();

    // Resolve the env mode through the canonical resolver (e.g., "dev" → "development")
    let empty_env_map = std::collections::HashMap::new();
    let resolved_mode = env_mode.map(|m| {
        let env_map = config.as_ref().map_or(&empty_env_map, |c| &c.env);
        let environments = config.as_ref().and_then(|c| c.environments.as_ref());
        lpm_env::resolver::resolve(m, env_map, environments).canonical
    });

    // Use the unified loader (handles inheritance, vault, schema validation + defaults)
    let mut env_vars = lpm_runner::dotenv::load_project_env(project_dir, resolved_mode.as_deref())?;
    let schema = config.as_ref().and_then(|c| c.env_schema.as_ref());

    // Collect secret keys for masking
    let secret_keys: std::collections::HashSet<String> = schema
        .map(|s| {
            s.vars
                .iter()
                .filter(|(_, rule)| rule.secret)
                .map(|(k, _)| k.clone())
                .collect()
        })
        .unwrap_or_default();

    // Filter to schema-only if requested
    if schema_only && let Some(schema) = schema {
        let schema_keys: std::collections::HashSet<&str> =
            schema.vars.keys().map(|k| k.as_str()).collect();
        env_vars.retain(|k, _| schema_keys.contains(k.as_str()));
    }

    let output = lpm_env::format_env(&env_vars, format, &secret_keys);
    println!("{output}");

    Ok(())
}

fn vars_check(project_dir: &std::path::Path, json_output: bool) -> Result<(), LpmError> {
    let config = lpm_runner::lpm_json::read_lpm_json(project_dir)
        .map_err(|e| LpmError::Script(e.to_string()))?;

    let schema = config
        .and_then(|c| c.env_schema)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            LpmError::Script(
                "no envSchema defined in lpm.json. Add an envSchema section first.".into(),
            )
        })?;

    // Get all environment names from lpm.json env mapping
    let lpm_config = lpm_runner::lpm_json::read_lpm_json(project_dir)
        .ok()
        .flatten();

    // Discover all environments via the canonical resolver.
    // This produces a consistent, deduplicated list from config + vault,
    // with legacy vault keys surfaced separately (never collapsed).
    let vault_envs = lpm_vault::get_all_environments(project_dir);
    let empty_env_map = std::collections::HashMap::new();
    let all_envs = lpm_env::resolver::list_all(
        lpm_config.as_ref().map_or(&empty_env_map, |c| &c.env),
        lpm_config.as_ref().and_then(|c| c.environments.as_ref()),
        &vault_envs,
    );
    let env_names: Vec<String> = all_envs.iter().map(|e| e.canonical.clone()).collect();

    let mut results: Vec<(String, usize, Vec<lpm_env::ValidationError>)> = Vec::new();
    let mut all_valid = true;

    // Temporarily skip validation in load_project_env — we run it manually per-env for reporting
    lpm_runner::script::set_skip_env_validation(true);

    for env_name in &env_names {
        let mode = if env_name == "default" {
            None
        } else {
            Some(env_name.as_str())
        };

        // Use unified loader (handles inheritance + vault) — hard errors on cycle/missing
        let mut env_vars = lpm_runner::dotenv::load_project_env(project_dir, mode)?;

        // Run schema validation manually to collect per-env errors
        let errors = lpm_env::validate(&schema, &mut env_vars);
        if !errors.is_empty() {
            all_valid = false;
        }
        results.push((env_name.clone(), schema.len(), errors));
    }

    // Restore validation flag
    lpm_runner::script::set_skip_env_validation(false);

    if json_output {
        let json_results: Vec<serde_json::Value> = results
            .iter()
            .map(|(name, total, errors)| {
                serde_json::json!({
                    "environment": name,
                    "total": total,
                    "valid": total - errors.len(),
                    "errors": errors.iter().map(|e| {
                        serde_json::json!({
                            "key": e.key,
                            "error": e.to_string(),
                        })
                    }).collect::<Vec<_>>(),
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::json!({
                "success": all_valid,
                "environments": json_results,
            })
        );
        return Ok(());
    }

    println!();
    for (name, total, errors) in &results {
        let valid = total - errors.len();
        if errors.is_empty() {
            println!(
                "  {}  {}  {}/{} valid",
                name.bold(),
                "✓".green(),
                valid,
                total
            );
        } else {
            let missing: Vec<&str> = errors.iter().map(|e| e.key.as_str()).collect();
            println!(
                "  {}  {}  {}/{} — missing: {}",
                name.bold(),
                "✗".red(),
                valid,
                total,
                missing.join(", ").red()
            );
        }
    }
    println!();

    if all_valid {
        output::success("all environments valid");
    } else {
        return Err(LpmError::EnvValidation(
            "one or more environments have missing or invalid variables".into(),
        ));
    }

    Ok(())
}

// ─── Platform Sync (Tier 4B) ──────────────────────────────────────

/// Get the LPM auth token and registry URL for API calls.
fn get_platform_auth() -> Result<(String, String), LpmError> {
    let registry_url = std::env::var("LPM_REGISTRY_URL")
        .unwrap_or_else(|_| lpm_common::DEFAULT_REGISTRY_URL.to_string());
    let auth_token = crate::auth::get_token(&registry_url)
        .ok_or_else(|| LpmError::Script("not logged in. Run `lpm login` first".into()))?;
    Ok((registry_url, auth_token))
}

/// `lpm use vars connect <platform> --project=<id> [--token=<token>] [--team=<id>] [--label=<name>]`
async fn vars_connect(
    args: &[&str],
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
    if args.is_empty() {
        return Err(LpmError::Script(
            "usage: lpm use vars connect <platform> --project=<id> [--token=<token>]".into(),
        ));
    }

    let platform = args[0];
    let vault_id =
        lpm_vault::vault_id::get_or_create_vault_id(project_dir).map_err(LpmError::Script)?;
    let (registry_url, auth_token) = get_platform_auth()?;

    // Parse flags
    let mut project_id: Option<&str> = None;
    let mut team_id: Option<&str> = None;
    let mut platform_token: Option<&str> = None;
    let mut label: Option<&str> = None;
    let mut linked_env: Option<&str> = None;

    let mut i = 1;
    while i < args.len() {
        if let Some(v) = args[i].strip_prefix("--project=") {
            project_id = Some(v);
        } else if args[i] == "--project" {
            if let Some(next) = args.get(i + 1) {
                project_id = Some(next);
                i += 1;
            }
        } else if let Some(v) = args[i].strip_prefix("--token=") {
            platform_token = Some(v);
        } else if args[i] == "--token" {
            if let Some(next) = args.get(i + 1) {
                platform_token = Some(next);
                i += 1;
            }
        } else if let Some(v) = args[i].strip_prefix("--team=") {
            team_id = Some(v);
        } else if args[i] == "--team" {
            if let Some(next) = args.get(i + 1) {
                team_id = Some(next);
                i += 1;
            }
        } else if let Some(v) = args[i].strip_prefix("--label=") {
            label = Some(v);
        } else if args[i] == "--label"
            && let Some(next) = args.get(i + 1)
        {
            label = Some(next);
            i += 1;
        } else if let Some(v) = args[i].strip_prefix("--linked-env=") {
            linked_env = Some(v);
        } else if args[i] == "--linked-env"
            && let Some(next) = args.get(i + 1)
        {
            linked_env = Some(next);
            i += 1;
        } else if args[i].starts_with("--") {
            output::warn(&format!("unknown flag '{}' — ignored", args[i]));
        }
        i += 1;
    }

    let project_id = project_id.ok_or_else(|| {
        LpmError::Script(format!(
            "missing --project flag. Usage: lpm use vars connect {platform} --project=<id>"
        ))
    })?;

    // Prompt for token if not provided via flag
    let token_owned;
    let platform_token = if let Some(t) = platform_token {
        t
    } else {
        token_owned = cliclack::password(format!("Paste {platform} API token"))
            .interact()
            .map_err(|e| LpmError::Script(format!("prompt failed: {e}")))?;
        token_owned.as_str()
    };

    // Build connection config
    let mut connection_config = serde_json::json!({
        "projectId": project_id,
    });
    if let Some(team) = team_id {
        connection_config["teamId"] = serde_json::Value::String(team.to_string());
    }
    // Resolve linked env through canonical resolver if provided
    if let Some(env_input) = linked_env {
        let config = lpm_runner::lpm_json::read_lpm_json(project_dir)
            .ok()
            .flatten();
        let empty = std::collections::HashMap::new();
        let env_map = config.as_ref().map_or(&empty, |c| &c.env);
        let environments = config.as_ref().and_then(|c| c.environments.as_ref());
        let resolved = lpm_env::resolver::resolve_checked(env_input, env_map, environments)
            .map_err(|e| LpmError::Script(format!("invalid --linked-env value: {e}")))?;
        connection_config["linkedEnv"] = serde_json::Value::String(resolved.canonical.clone());
    }

    output::info(&format!("connecting to {platform}..."));

    // Send to server
    let client = reqwest::Client::new();
    let response = client
        .post(format!("{registry_url}/api/vault/platforms/connect"))
        .bearer_auth(&auth_token)
        .json(&serde_json::json!({
            "vaultId": vault_id,
            "platform": platform,
            "token": platform_token,
            "connectionConfig": connection_config,
            "label": label,
        }))
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| LpmError::Network(format!("failed to connect: {e}")))?;

    if !response.status().is_success() {
        let body: serde_json::Value = response
            .json()
            .await
            .unwrap_or(serde_json::json!({"error": "unknown error"}));
        return Err(LpmError::Script(
            body["error"]
                .as_str()
                .unwrap_or("connection failed")
                .to_string(),
        ));
    }

    let result: serde_json::Value = response
        .json()
        .await
        .map_err(|e| LpmError::Script(format!("parse error: {e}")))?;

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&result).unwrap_or_default()
        );
    } else {
        let status = result["status"].as_str().unwrap_or("connected");
        output::success(&format!(
            "{platform} {} (project: {project_id})",
            status.bold()
        ));
    }

    Ok(())
}

/// `lpm use vars push --to <platform> [--env=<mode>] [--clean] [--yes]`
async fn vars_platform_push(
    args: &[&str],
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
    let vault_id = lpm_vault::vault_id::read_vault_id(project_dir).ok_or_else(|| {
        LpmError::Script("no vault configured. Run `lpm use vars set` first".into())
    })?;
    let (registry_url, auth_token) = get_platform_auth()?;

    // Parse flags
    let mut platform: Option<&str> = None;
    let mut env_mode: Option<&str> = None;
    let mut clean = false;
    let mut yes = false;

    for arg in args {
        if let Some(v) = arg.strip_prefix("--to=") {
            platform = Some(v);
        } else if *arg == "--to" {
            // Next arg handled by positional scan below
        } else if let Some(v) = arg.strip_prefix("--env=") {
            env_mode = Some(v);
        } else if *arg == "--clean" {
            clean = true;
        } else if *arg == "--yes" || *arg == "-y" {
            yes = true;
        }
    }

    // Handle --to <value> (space-separated)
    if platform.is_none() {
        for (i, arg) in args.iter().enumerate() {
            if *arg == "--to"
                && let Some(next) = args.get(i + 1)
            {
                platform = Some(next);
            }
        }
    }

    let platform = platform.ok_or_else(|| {
        LpmError::Script("missing --to flag. Usage: lpm use vars push --to <platform>".into())
    })?;

    // Resolve env mode through canonical resolver — write path, use resolve_checked
    // (push sends secrets to a remote platform, invalid names should fail fast)
    let resolved_env_mode = if let Some(input) = env_mode {
        let config = lpm_runner::lpm_json::read_lpm_json(project_dir)
            .ok()
            .flatten();
        let empty = std::collections::HashMap::new();
        let env_map = config.as_ref().map_or(&empty, |c| &c.env);
        let environments = config.as_ref().and_then(|c| c.environments.as_ref());
        let resolved = lpm_env::resolver::resolve_checked(input, env_map, environments)
            .map_err(|e| LpmError::Script(format!("invalid environment name: {e}")))?;
        Some(resolved.canonical)
    } else {
        None
    };

    // Load resolved env vars (same as what lpm run sees)
    let env_vars = lpm_runner::dotenv::load_project_env(project_dir, resolved_env_mode.as_deref())?;

    // Convert to string-string map for JSON serialization
    let vars: std::collections::HashMap<String, String> = env_vars;

    output::info(&format!("comparing with {platform}..."));

    // Step 1: Dry-run to get diff
    let client = reqwest::Client::new();
    let dry_run_response = client
        .post(format!(
            "{registry_url}/api/vault/platforms/push?dryRun=true"
        ))
        .bearer_auth(&auth_token)
        .json(&serde_json::json!({
            "vaultId": vault_id,
            "platform": platform,
            "env": resolved_env_mode.as_deref().unwrap_or("default"),
            "vars": vars,
            "clean": clean,
        }))
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| LpmError::Network(format!("failed to reach server: {e}")))?;

    if !dry_run_response.status().is_success() {
        let body: serde_json::Value = dry_run_response
            .json()
            .await
            .unwrap_or(serde_json::json!({"error": "unknown error"}));
        return Err(LpmError::Script(
            body["error"].as_str().unwrap_or("push failed").to_string(),
        ));
    }

    let diff: serde_json::Value = dry_run_response
        .json()
        .await
        .map_err(|e| LpmError::Script(format!("parse error: {e}")))?;

    let added = diff["added"].as_array().map(|a| a.len()).unwrap_or(0);
    let changed = diff["changed"].as_array().map(|a| a.len()).unwrap_or(0);
    let removed = diff["removed"].as_array().map(|a| a.len()).unwrap_or(0);
    let unchanged = diff["unchanged"].as_u64().unwrap_or(0);
    let orphans = diff["orphans"].as_array().map(|a| a.len()).unwrap_or(0);

    if added == 0 && changed == 0 && removed == 0 {
        if json_output {
            println!(
                "{}",
                serde_json::json!({"status": "no_changes", "platform": platform})
            );
        } else {
            output::success(&format!("{platform} is already in sync"));
            if orphans > 0 {
                output::warn(&format!(
                    "{orphans} orphan var(s) on {platform} not in vault. Use --clean to remove."
                ));
            }
        }
        return Ok(());
    }

    // Show diff
    if !json_output {
        println!();
        println!(
            "  {} — {}",
            platform.bold(),
            resolved_env_mode.as_deref().unwrap_or("default")
        );
        println!();

        if let Some(keys) = diff["added"].as_array() {
            for key in keys {
                println!(
                    "  {} {} {}",
                    "+".green(),
                    key.as_str().unwrap_or("").bold(),
                    "(new)".dimmed()
                );
            }
        }
        if let Some(keys) = diff["changed"].as_array() {
            for key in keys {
                println!(
                    "  {} {} {}",
                    "~".yellow(),
                    key.as_str().unwrap_or("").bold(),
                    "(changed)".dimmed()
                );
            }
        }
        if let Some(keys) = diff["removed"].as_array() {
            for key in keys {
                println!(
                    "  {} {} {}",
                    "-".red(),
                    key.as_str().unwrap_or("").bold(),
                    "(will be removed)".dimmed()
                );
            }
        }
        if unchanged > 0 {
            println!("  {} {unchanged} unchanged", "=".dimmed());
        }
        if orphans > 0 && !clean {
            println!(
                "  {} {orphans} orphan(s) on {platform} {}",
                "⚠".yellow(),
                "(use --clean to remove)".dimmed()
            );
        }
        println!();
    }

    // Confirm
    if !yes && !json_output {
        let confirm = cliclack::confirm(format!(
            "Push {added} added, {changed} changed, {removed} removed to {platform}?"
        ))
        .initial_value(false)
        .interact()
        .map_err(|e| LpmError::Script(format!("prompt failed: {e}")))?;

        if !confirm {
            output::info("cancelled");
            return Ok(());
        }
    }

    // Step 2: Apply
    output::info(&format!("pushing to {platform}..."));

    let push_response = client
        .post(format!("{registry_url}/api/vault/platforms/push"))
        .bearer_auth(&auth_token)
        .json(&serde_json::json!({
            "vaultId": vault_id,
            "platform": platform,
            "env": resolved_env_mode.as_deref().unwrap_or("default"),
            "vars": vars,
            "clean": clean,
        }))
        .timeout(std::time::Duration::from_secs(60))
        .send()
        .await
        .map_err(|e| LpmError::Network(format!("push failed: {e}")))?;

    if !push_response.status().is_success() {
        let body: serde_json::Value = push_response
            .json()
            .await
            .unwrap_or(serde_json::json!({"error": "unknown error"}));
        return Err(LpmError::Script(
            body["error"].as_str().unwrap_or("push failed").to_string(),
        ));
    }

    let result: serde_json::Value = push_response
        .json()
        .await
        .map_err(|e| LpmError::Script(format!("parse error: {e}")))?;

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&result).unwrap_or_default()
        );
    } else {
        let added_count = result["added"].as_u64().unwrap_or(0);
        let updated_count = result["updated"].as_u64().unwrap_or(0);
        let removed_count = result["removed"].as_u64().unwrap_or(0);

        output::success(&format!(
            "{platform} synced — {added_count} added, {updated_count} updated, {removed_count} removed"
        ));
    }

    Ok(())
}

/// `lpm use vars status`
async fn vars_platform_status(
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
    let vault_id = lpm_vault::vault_id::read_vault_id(project_dir).ok_or_else(|| {
        LpmError::Script("no vault configured. Run `lpm use vars set` first".into())
    })?;
    let (registry_url, auth_token) = get_platform_auth()?;

    // Load default env vars (backward compat)
    let default_vars = lpm_runner::dotenv::load_project_env(project_dir, None)?;

    // Build per-environment vars map for env-bound connections.
    // The server picks the right env per connection based on connectionConfig.linkedEnv.
    let config = lpm_runner::lpm_json::read_lpm_json(project_dir)
        .ok()
        .flatten();
    let empty_env_map = HashMap::new();
    let env_map = config.as_ref().map_or(&empty_env_map, |c| &c.env);
    let environments = config.as_ref().and_then(|c| c.environments.as_ref());
    let vault_envs = lpm_vault::get_all_environments(project_dir);
    let all_envs = lpm_env::resolver::list_all(env_map, environments, &vault_envs);

    // Collect all known environment names from config + vault
    let mut env_names: std::collections::HashSet<String> =
        all_envs.iter().map(|e| e.canonical.clone()).collect();

    // Also discover environments from .env.* files on disk.
    // A connection might be linked to e.g. "preview" which exists only as
    // .env.preview — not in lpm.json or vault. Without scanning disk,
    // envVars would miss it and the server would fall back to default vars.
    if let Ok(entries) = std::fs::read_dir(project_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if let Some(mode) = name.strip_prefix(".env.") {
                // Skip .local variants and .example files
                if !mode.contains(".local") && !mode.ends_with(".example") && !mode.is_empty() {
                    env_names.insert(mode.to_string());
                }
            }
        }
    }

    let mut env_vars_map: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();
    for env_name in &env_names {
        let mode = if env_name == "default" {
            None
        } else {
            Some(env_name.as_str())
        };
        if let Ok(vars) = lpm_runner::dotenv::load_project_env(project_dir, mode) {
            env_vars_map.insert(
                env_name.clone(),
                serde_json::to_value(&vars).unwrap_or_default(),
            );
        }
    }

    output::info("checking platform status...");

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{registry_url}/api/vault/platforms/status"))
        .bearer_auth(&auth_token)
        .json(&serde_json::json!({
            "vaultId": vault_id,
            "vars": default_vars,
            "envVars": env_vars_map,
        }))
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| LpmError::Network(format!("failed to reach server: {e}")))?;

    if !response.status().is_success() {
        let body: serde_json::Value = response
            .json()
            .await
            .unwrap_or(serde_json::json!({"error": "unknown error"}));
        return Err(LpmError::Script(
            body["error"]
                .as_str()
                .unwrap_or("status check failed")
                .to_string(),
        ));
    }

    let result: serde_json::Value = response
        .json()
        .await
        .map_err(|e| LpmError::Script(format!("parse error: {e}")))?;

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&result).unwrap_or_default()
        );
        return Ok(());
    }

    let platforms = result["platforms"].as_array();
    if platforms.is_none() || platforms.unwrap().is_empty() {
        output::warn("no platform connections. Run 'lpm use vars connect <platform>' to add one.");
        return Ok(());
    }

    println!();
    for platform in platforms.unwrap() {
        let name = platform["platform"].as_str().unwrap_or("?");
        let label = platform["label"].as_str().unwrap_or("");
        let env = platform["env"].as_str().unwrap_or("default");
        let status = platform["status"].as_str().unwrap_or("?");
        let last_push = platform["lastPushAt"].as_str();

        let env_suffix = if env != "default" {
            format!(" [{}]", env)
        } else {
            String::new()
        };
        let display_name = if label.is_empty() {
            format!("{name}{env_suffix}")
        } else {
            format!("{name} ({label}){env_suffix}")
        };

        let push_info = last_push
            .map(|t| format!("  last push: {t}"))
            .unwrap_or_else(|| "  never pushed".to_string());

        match status {
            "synced" => {
                println!(
                    "  {} {}  {}",
                    "✓".green(),
                    display_name.bold(),
                    "synced".green()
                );
            }
            "drifted" => {
                let added = platform["added"].as_u64().unwrap_or(0);
                let changed = platform["changed"].as_u64().unwrap_or(0);
                let removed = platform["removed"].as_u64().unwrap_or(0);
                let drift_keys_arr = platform["driftKeys"]
                    .as_array()
                    .map(|a| a.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>())
                    .unwrap_or_default();

                let total_drift = added + changed + removed;

                println!(
                    "  {} {}  {} — +{added} ~{changed} -{removed}",
                    "⚠".yellow(),
                    display_name.bold(),
                    "drifted".yellow()
                );
                if !drift_keys_arr.is_empty() {
                    let display = drift_keys_arr.join(", ");
                    let extra = total_drift.saturating_sub(drift_keys_arr.len() as u64);
                    if extra > 0 {
                        println!(
                            "    {} {}",
                            display.dimmed(),
                            format!("and {extra} more").dimmed()
                        );
                    } else {
                        println!("    {}", display.dimmed());
                    }
                }
            }
            "write_only" => {
                println!(
                    "  {} {}  {}{}",
                    "?".dimmed(),
                    display_name.bold(),
                    "write-only".dimmed(),
                    push_info.dimmed()
                );
            }
            "error" => {
                let err = platform["error"].as_str().unwrap_or("unknown error");
                println!("  {} {}  {}", "✗".red(), display_name.bold(), err.red());
            }
            _ => {
                println!("  {} {}  {status}", "?".dimmed(), display_name.bold());
            }
        }
    }
    println!();

    Ok(())
}

// ─── OIDC (Tier 5) ────────────────────────────────────────────────

/// `lpm use vars oidc allow --provider=github --repo=owner/repo --branch=main --env=production`
async fn vars_oidc(
    args: &[&str],
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
    if args.is_empty() {
        return Err(LpmError::Script(
            "usage: lpm use vars oidc allow --provider=github --repo=<owner/repo> --branch=<branch> --env=<env>".into(),
        ));
    }

    match args[0] {
        "allow" => vars_oidc_allow(&args[1..], project_dir, json_output).await,
        "list" => vars_oidc_list(project_dir, json_output).await,
        unknown => Err(LpmError::Script(format!(
            "unknown oidc action: '{unknown}'. Available: allow, list"
        ))),
    }
}

/// `lpm use vars oidc allow --provider=github --repo=owner/repo --branch=main --env=production`
async fn vars_oidc_allow(
    args: &[&str],
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
    let vault_id =
        lpm_vault::vault_id::get_or_create_vault_id(project_dir).map_err(LpmError::Script)?;
    let (registry_url, auth_token) = get_platform_auth()?;

    let mut provider = "github";
    let mut repo: Option<&str> = None;
    let mut branches: Vec<String> = vec!["main".to_string()];
    let mut envs: Vec<String> = Vec::new();
    let mut allow_forks = false;

    for arg in args {
        if let Some(v) = arg.strip_prefix("--provider=") {
            provider = v;
        } else if let Some(v) = arg.strip_prefix("--repo=") {
            repo = Some(v);
        } else if let Some(v) = arg.strip_prefix("--branch=") {
            branches = v.split(',').map(|s| s.trim().to_string()).collect();
        } else if let Some(v) = arg.strip_prefix("--env=") {
            envs = v.split(',').map(|s| s.trim().to_string()).collect();
        } else if *arg == "--allow-forks" {
            allow_forks = true;
        }
    }

    let repo = repo.ok_or_else(|| {
        LpmError::Script(
            "missing --repo flag. Usage: lpm use vars oidc allow --repo=owner/repo".into(),
        )
    })?;

    // Canonicalize env names through resolver — OIDC policies store canonical names
    if !envs.is_empty() {
        let config = lpm_runner::lpm_json::read_lpm_json(project_dir)
            .ok()
            .flatten();
        let empty = std::collections::HashMap::new();
        let env_map = config.as_ref().map_or(&empty, |c| &c.env);
        let environments = config.as_ref().and_then(|c| c.environments.as_ref());

        let mut canonical_envs = Vec::with_capacity(envs.len());
        for input in &envs {
            match lpm_env::resolver::resolve_checked(input, env_map, environments) {
                Ok(resolved) => {
                    if resolved.canonical != *input && !json_output {
                        output::info(&format!(
                            "resolved \"{}\" → canonical \"{}\"",
                            input, resolved.canonical
                        ));
                    }
                    canonical_envs.push(resolved.canonical);
                }
                Err(e) => {
                    // Warn on unknown names, don't block — matches spec
                    if !json_output {
                        output::warn(&format!(
                            "\"{}\" is not a known environment name: {}. Storing as-is.",
                            input, e
                        ));
                    }
                    canonical_envs.push(input.clone());
                }
            }
        }
        envs = canonical_envs;
    }

    let subject = format!("repo:{repo}");

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{registry_url}/api/vault/oidc/policies"))
        .bearer_auth(&auth_token)
        .json(&serde_json::json!({
            "vaultId": vault_id,
            "provider": provider,
            "subject": subject,
            "allowedBranches": branches,
            "allowedEnvironments": envs,
            "allowForks": allow_forks,
        }))
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| LpmError::Network(format!("failed to reach server: {e}")))?;

    if !response.status().is_success() {
        let body: serde_json::Value = response
            .json()
            .await
            .unwrap_or(serde_json::json!({"error": "unknown error"}));
        return Err(LpmError::Script(
            body["error"].as_str().unwrap_or("failed").to_string(),
        ));
    }

    let result: serde_json::Value = response
        .json()
        .await
        .map_err(|e| LpmError::Script(format!("parse error: {e}")))?;

    if !json_output {
        output::success(&format!(
            "OIDC policy set: {provider} {} on branches [{}] for envs [{}]",
            repo.bold(),
            branches.join(", "),
            if envs.is_empty() {
                "all".to_string()
            } else {
                envs.join(", ")
            }
        ));
    }

    // Escrow the wrapping key so the server can decrypt for CI pulls.
    // Best-effort: don't fail if escrow upload fails (the policy was already created).
    match lpm_vault::crypto::get_or_create_wrapping_key() {
        Ok(wrapping_key) => {
            let wrapping_key_hex = hex::encode(wrapping_key);
            match lpm_vault::sync::upload_escrow_key(
                &registry_url,
                &auth_token,
                &vault_id,
                &wrapping_key_hex,
            )
            .await
            {
                Ok(()) => {
                    if !json_output {
                        output::info(
                            "CI escrow enabled — secrets will be decrypted server-side for OIDC pulls",
                        );
                    }
                }
                Err(e) => {
                    if !json_output {
                        output::warn(&format!(
                            "Failed to escrow wrapping key (CI pull may not work): {}",
                            e.dimmed()
                        ));
                    }
                }
            }
        }
        Err(e) => {
            if !json_output {
                output::warn(&format!(
                    "Could not read wrapping key for CI escrow: {}",
                    e.dimmed()
                ));
            }
        }
    }

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&result).unwrap_or_default()
        );
    }

    Ok(())
}

/// `lpm use vars oidc list`
async fn vars_oidc_list(project_dir: &std::path::Path, json_output: bool) -> Result<(), LpmError> {
    let vault_id = lpm_vault::vault_id::read_vault_id(project_dir)
        .ok_or_else(|| LpmError::Script("no vault configured".into()))?;
    let (registry_url, auth_token) = get_platform_auth()?;

    let client = reqwest::Client::new();
    let response = client
        .get(format!(
            "{registry_url}/api/vault/oidc/policies?vaultId={vault_id}"
        ))
        .bearer_auth(&auth_token)
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| LpmError::Network(format!("failed to reach server: {e}")))?;

    if !response.status().is_success() {
        let body: serde_json::Value = response
            .json()
            .await
            .unwrap_or(serde_json::json!({"error": "unknown error"}));
        return Err(LpmError::Script(
            body["error"].as_str().unwrap_or("failed").to_string(),
        ));
    }

    let result: serde_json::Value = response
        .json()
        .await
        .map_err(|e| LpmError::Script(format!("parse error: {e}")))?;

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&result).unwrap_or_default()
        );
        return Ok(());
    }

    let policies = result["policies"].as_array();
    if policies.is_none() || policies.unwrap().is_empty() {
        output::warn("no OIDC policies configured. Run 'lpm use vars oidc allow' to add one.");
        return Ok(());
    }

    println!();
    for policy in policies.unwrap() {
        let provider = policy["provider"].as_str().unwrap_or("?");
        let subject = policy["subject"].as_str().unwrap_or("?");
        let branches = policy["allowedBranches"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default();
        let envs = policy["allowedEnvironments"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default();
        let forks = policy["allowForks"].as_bool().unwrap_or(false);

        println!(
            "  {} {}  branches: [{}]  envs: [{}]{}",
            provider.bold(),
            subject,
            if branches.is_empty() {
                "all"
            } else {
                &branches
            },
            if envs.is_empty() { "all" } else { &envs },
            if forks { "  forks: allowed" } else { "" }
        );
    }
    println!();

    Ok(())
}

/// `lpm use vars pull --oidc [--env=<mode>] [--output=<file>]`
///
/// Exchange CI OIDC token for a short-lived LPM token, then pull vault secrets.
async fn vars_oidc_pull(
    args: &[&str],
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
    let vault_id = lpm_vault::vault_id::read_vault_id(project_dir).ok_or_else(|| {
        LpmError::Script(
            "no vault configured. Set LPM_VAULT_ID or run 'lpm use vars set' first".into(),
        )
    })?;

    // Also check env var override for vault ID (useful in CI where lpm.json may not exist)
    let vault_id = std::env::var("LPM_VAULT_ID").unwrap_or(vault_id);

    let registry_url = std::env::var("LPM_REGISTRY_URL")
        .unwrap_or_else(|_| lpm_common::DEFAULT_REGISTRY_URL.to_string());

    let mut env_mode: Option<&str> = None;
    let mut output_file: Option<&str> = None;

    for arg in args {
        if let Some(v) = arg.strip_prefix("--env=") {
            env_mode = Some(v);
        } else if let Some(v) = arg.strip_prefix("--output=") {
            output_file = Some(v);
        }
    }

    // Get OIDC token from CI environment
    let oidc_token = get_ci_oidc_token().await?;

    // Exchange OIDC token for short-lived LPM token
    let client = reqwest::Client::new();
    let exchange_response = client
        .post(format!("{registry_url}/api/vault/oidc"))
        .json(&serde_json::json!({
            "oidcToken": oidc_token,
            "vaultId": vault_id,
            "env": env_mode,
        }))
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| LpmError::Network(format!("OIDC exchange failed: {e}")))?;

    if !exchange_response.status().is_success() {
        let body: serde_json::Value = exchange_response
            .json()
            .await
            .unwrap_or(serde_json::json!({"error": "unknown error"}));
        let error = body["error"].as_str().unwrap_or("OIDC exchange failed");
        let hint = body["hint"].as_str().unwrap_or("");
        let msg = if hint.is_empty() {
            error.to_string()
        } else {
            format!("{error}\n  Hint: {hint}")
        };
        return Err(LpmError::Script(msg));
    }

    let exchange_result: serde_json::Value = exchange_response
        .json()
        .await
        .map_err(|e| LpmError::Script(format!("parse error: {e}")))?;

    let lpm_token = exchange_result["token"]
        .as_str()
        .ok_or_else(|| LpmError::Script("missing token in OIDC response".into()))?;

    // Pull via CI escrow — server decrypts and returns plaintext secrets
    let (vars, env_name) = lpm_vault::sync::ci_pull(&registry_url, lpm_token, &vault_id, env_mode)
        .await
        .map_err(LpmError::Script)?;

    if let Some(file) = output_file {
        // Write .env file with KEY=VALUE pairs
        let mut content =
            format!("# LPM vault secrets (env: {env_name})\n# Pulled via OIDC CI escrow\n");
        let mut keys: Vec<&String> = vars.keys().collect();
        keys.sort();
        for key in &keys {
            let value = &vars[*key];
            // Quote values that contain spaces, newlines, or special chars
            if value.contains(' ')
                || value.contains('\n')
                || value.contains('#')
                || value.contains('"')
            {
                let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
                content.push_str(&format!("{key}=\"{escaped}\"\n"));
            } else {
                content.push_str(&format!("{key}={value}\n"));
            }
        }

        std::fs::write(file, &content)
            .map_err(|e| LpmError::Script(format!("failed to write {file}: {e}")))?;

        if !json_output {
            output::success(&format!(
                "wrote {} secret{} to {} (env: {})",
                keys.len().to_string().bold(),
                if keys.len() == 1 { "" } else { "s" },
                file,
                env_name,
            ));
        }
    } else if json_output {
        println!(
            "{}",
            serde_json::json!({ "env": env_name, "vars": vars, "count": vars.len() })
        );
    } else {
        output::success(&format!(
            "pulled {} secret{} via OIDC (env: {})",
            vars.len().to_string().bold(),
            if vars.len() == 1 { "" } else { "s" },
            env_name,
        ));
    }

    Ok(())
}

/// Get the OIDC token from the CI environment.
///
/// Checks platform-specific env vars:
/// - GitHub Actions: `ACTIONS_ID_TOKEN_REQUEST_TOKEN` + `ACTIONS_ID_TOKEN_REQUEST_URL`
/// - GitLab CI: `CI_JOB_JWT_V2` or `LPM_OIDC_TOKEN`
/// - Generic: `LPM_OIDC_TOKEN`
async fn get_ci_oidc_token() -> Result<String, LpmError> {
    // GitHub Actions: need to request the token from the runtime
    if std::env::var("GITHUB_ACTIONS").is_ok() {
        let request_token = std::env::var("ACTIONS_ID_TOKEN_REQUEST_TOKEN").map_err(|_| {
            LpmError::Script(
                "ACTIONS_ID_TOKEN_REQUEST_TOKEN not set. Add 'permissions: id-token: write' to your workflow.".into(),
            )
        })?;
        let request_url = std::env::var("ACTIONS_ID_TOKEN_REQUEST_URL")
            .map_err(|_| LpmError::Script("ACTIONS_ID_TOKEN_REQUEST_URL not set".into()))?;

        // Request OIDC token from GitHub's runtime with our audience
        let url = format!("{request_url}&audience=https://lpm.dev");
        let client = reqwest::Client::new();
        let response = client
            .get(&url)
            .header("Authorization", format!("Bearer {request_token}"))
            .send()
            .await
            .map_err(|e| LpmError::Network(format!("failed to get GitHub OIDC token: {e}")))?;

        if !response.status().is_success() {
            return Err(LpmError::Script(format!(
                "GitHub OIDC token request failed ({})",
                response.status()
            )));
        }

        let body: serde_json::Value = response
            .json()
            .await
            .map_err(|e| LpmError::Script(format!("failed to parse OIDC response: {e}")))?;

        return body["value"]
            .as_str()
            .map(|s: &str| s.to_string())
            .ok_or_else(|| LpmError::Script("no token in GitHub OIDC response".into()));
    }

    // GitLab CI
    if let Ok(token) = std::env::var("CI_JOB_JWT_V2") {
        return Ok(token);
    }

    // Generic fallback
    if let Ok(token) = std::env::var("LPM_OIDC_TOKEN") {
        return Ok(token);
    }

    Err(LpmError::Script(
        "no OIDC token found. Set LPM_OIDC_TOKEN or ensure your CI is configured for OIDC.".into(),
    ))
}

/// `lpm use vars pull --from <platform> [--env=<mode>] [--yes]`
async fn vars_platform_pull(
    args: &[&str],
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
    let vault_id =
        lpm_vault::vault_id::get_or_create_vault_id(project_dir).map_err(LpmError::Script)?;
    let (registry_url, auth_token) = get_platform_auth()?;

    // Parse flags
    let mut platform: Option<&str> = None;
    let mut env_name: Option<&str> = None;
    let mut yes = false;

    for (i, arg) in args.iter().enumerate() {
        if let Some(v) = arg.strip_prefix("--from=") {
            platform = Some(v);
        } else if *arg == "--from"
            && let Some(next) = args.get(i + 1)
        {
            platform = Some(next);
        } else if let Some(v) = arg.strip_prefix("--env=") {
            env_name = Some(v);
        } else if *arg == "--yes" || *arg == "-y" {
            yes = true;
        }
    }

    let platform = platform.ok_or_else(|| {
        LpmError::Script("missing --from flag. Usage: lpm use vars pull --from <platform>".into())
    })?;

    output::info(&format!("pulling from {platform}..."));

    // Request vars from server
    let client = reqwest::Client::new();
    let response = client
        .post(format!("{registry_url}/api/vault/platforms/pull"))
        .bearer_auth(&auth_token)
        .json(&serde_json::json!({
            "vaultId": vault_id,
            "platform": platform,
        }))
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| LpmError::Network(format!("failed to reach server: {e}")))?;

    if !response.status().is_success() {
        let body: serde_json::Value = response
            .json()
            .await
            .unwrap_or(serde_json::json!({"error": "unknown error"}));
        return Err(LpmError::Script(
            body["error"].as_str().unwrap_or("pull failed").to_string(),
        ));
    }

    let result: serde_json::Value = response
        .json()
        .await
        .map_err(|e| LpmError::Script(format!("parse error: {e}")))?;

    let vars = result["vars"]
        .as_object()
        .ok_or_else(|| LpmError::Script("invalid response: missing vars".into()))?;

    let count = vars.len();

    if count == 0 {
        output::warn(&format!("no env vars found on {platform}"));
        return Ok(());
    }

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&result).unwrap_or_default()
        );
    } else {
        println!();
        println!("  Found {count} variable(s) on {platform}:");
        println!();
        for key in vars.keys() {
            println!("    {}", key.bold());
        }
        println!();
    }

    // Confirm before importing
    if !yes && !json_output {
        let confirm = cliclack::confirm(format!(
            "Import {count} variable(s) from {platform} into vault?"
        ))
        .initial_value(true)
        .interact()
        .map_err(|e| LpmError::Script(format!("prompt failed: {e}")))?;

        if !confirm {
            output::info("cancelled");
            return Ok(());
        }
    }

    // Store in vault
    let pairs: Vec<(&str, &str)> = vars
        .iter()
        .filter_map(|(k, v)| v.as_str().map(|val| (k.as_str(), val)))
        .collect();

    if let Some(env) = env_name {
        lpm_vault::set_env(project_dir, env, &pairs).map_err(LpmError::Script)?;
    } else {
        lpm_vault::set(project_dir, &pairs).map_err(LpmError::Script)?;
    }

    if !json_output {
        output::success(&format!(
            "imported {count} variable(s) from {platform} into vault{}",
            env_name.map(|e| format!(" ({e})")).unwrap_or_default()
        ));
    }

    Ok(())
}

/// Parse `--env=<name>` or `--env <name>` from args, returning the env value
/// and the remaining args with the flag stripped.
///
/// Returns `Err` if `--env` is present but has no value (bare trailing `--env`).
fn parse_env_flag<'a>(args: &'a [&'a str]) -> Result<(Option<&'a str>, Vec<&'a str>), LpmError> {
    let mut env_mode = None;
    let mut remaining = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if let Some(val) = args[i].strip_prefix("--env=") {
            env_mode = Some(val);
        } else if args[i] == "--env" {
            match args.get(i + 1) {
                Some(next) if !next.starts_with('-') => {
                    env_mode = Some(*next);
                    i += 1;
                }
                _ => {
                    return Err(LpmError::Script(
                        "--env requires a value (e.g., --env=production or --env production)"
                            .into(),
                    ));
                }
            }
        } else {
            remaining.push(args[i]);
        }
        i += 1;
    }
    Ok((env_mode, remaining))
}

/// Load lpm.json config and resolve an --env flag value to a canonical env name.
/// Returns (canonical_env_name_or_none, lpm_config_or_none).
/// Resolve an `--env` flag value to a canonical env name.
///
/// Returns `Err` if the flag was provided but the value is invalid.
/// Returns `Ok(None)` if no `--env` flag was provided (use default).
fn resolve_env_from_flag(
    env_input: Option<&str>,
    project_dir: &std::path::Path,
) -> Result<(Option<String>, Option<lpm_runner::lpm_json::LpmJsonConfig>), LpmError> {
    let config = lpm_runner::lpm_json::read_lpm_json(project_dir)
        .ok()
        .flatten();
    let empty = std::collections::HashMap::new();
    match env_input {
        Some(input) => {
            let env_map = config.as_ref().map_or(&empty, |c| &c.env);
            let environments = config.as_ref().and_then(|c| c.environments.as_ref());
            let resolved = lpm_env::resolver::resolve_checked(input, env_map, environments)
                .map_err(|e| LpmError::Script(format!("invalid environment name: {e}")))?;
            Ok((Some(resolved.canonical), config))
        }
        None => Ok((None, config)),
    }
}

fn vars_list(
    project_dir: &std::path::Path,
    env_name: Option<&str>,
    reveal: bool,
    json_output: bool,
) -> Result<(), LpmError> {
    let secrets = match env_name {
        Some(env) => lpm_vault::get_all_env(project_dir, env),
        None => lpm_vault::get_all(project_dir),
    };
    let env_label = env_name.unwrap_or("default");

    if json_output {
        if reveal {
            println!("{}", serde_json::to_string_pretty(&secrets).unwrap());
        } else {
            let masked: std::collections::HashMap<&str, &str> =
                secrets.keys().map(|k| (k.as_str(), "••••••••")).collect();
            println!("{}", serde_json::to_string_pretty(&masked).unwrap());
        }
    } else if secrets.is_empty() {
        output::info(&format!("No secrets in vault ({env_label})"));
        println!("  Run {} to add one", "lpm use vars set KEY=VALUE".cyan());
    } else {
        let mut keys: Vec<&String> = secrets.keys().collect();
        keys.sort();
        output::info(&format!("Vault secrets — {} ({})", env_label, keys.len()));
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
            .map_err(LpmError::Script)?;

        if json_output {
            let json: Vec<serde_json::Value> = vaults
				.iter()
				.map(|v| serde_json::json!({"vault_id": v.vault_id, "version": v.version, "updated_at": v.updated_at, "org": slug}))
				.collect();
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &serde_json::json!({"success": true, "org": slug, "vaults": json})
                )
                .unwrap()
            );
            return Ok(());
        }

        if vaults.is_empty() {
            output::info(&format!("no shared vaults in org {}", slug.bold()));
            println!(
                "  Share a vault: {}",
                format!("lpm use vars share --org {slug}").cyan()
            );
            return Ok(());
        }

        output::info(&format!("Org {} vaults ({})", slug.bold(), vaults.len()));
        for v in &vaults {
            let version = v
                .version
                .map(|v| format!("v{v}"))
                .unwrap_or_else(|| "v?".into());
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
            "  Pull: {}",
            format!("cd <project-dir> && lpm use vars pull --org {slug}").cyan()
        );
        return Ok(());
    }

    // Personal vaults
    let vaults = lpm_vault::sync::list_remote(&registry_url, &auth_token)
        .await
        .map_err(LpmError::Script)?;

    if json_output {
        let json: Vec<serde_json::Value> = vaults
            .iter()
            .map(|v| {
                serde_json::json!({
                    "vault_id": v.vault_id,
                    "version": v.version,
                    "updated_at": v.updated_at,
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({"success": true, "vaults": json}))
                .unwrap()
        );
        return Ok(());
    }

    if vaults.is_empty() {
        output::info("no cloud vaults found");
        println!("  Push a vault with: {}", "lpm use vars push".cyan());
        return Ok(());
    }

    output::info(&format!("Cloud vaults ({})", vaults.len()));
    for v in &vaults {
        let version = v
            .version
            .map(|v| format!("v{v}"))
            .unwrap_or_else(|| "v?".into());
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
    let config = lpm_runner::lpm_json::read_lpm_json(project_dir)
        .ok()
        .flatten();
    let empty_env_map = std::collections::HashMap::new();
    let env_map = config.as_ref().map_or(&empty_env_map, |c| &c.env);
    let environments = config.as_ref().and_then(|c| c.environments.as_ref());

    let (left_label, left_secrets, right_label, right_secrets) = if args.len() >= 2 {
        // Compare two local environments — resolve aliases to canonical names
        let resolved_a = lpm_env::resolver::resolve(args[0], env_map, environments);
        let resolved_b = lpm_env::resolver::resolve(args[1], env_map, environments);
        let a = lpm_vault::get_all_env(project_dir, &resolved_a.storage_key);
        let b = lpm_vault::get_all_env(project_dir, &resolved_b.storage_key);
        (
            format!("{} (local)", resolved_a.canonical),
            a,
            format!("{} (local)", resolved_b.canonical),
            b,
        )
    } else if args.len() == 1 {
        // Compare specific env local vs cloud — fetch the same env from cloud, not "default"
        let resolved = lpm_env::resolver::resolve(args[0], env_map, environments);
        let local = lpm_vault::get_all_env(project_dir, &resolved.storage_key);

        let vault_id = lpm_vault::vault_id::read_vault_id(project_dir)
            .ok_or_else(|| LpmError::Script("no vault configured".into()))?;
        let registry_url = std::env::var("LPM_REGISTRY_URL")
            .unwrap_or_else(|_| lpm_common::DEFAULT_REGISTRY_URL.to_string());
        let auth_token = crate::auth::get_token(&registry_url)
            .ok_or_else(|| LpmError::Script("not logged in. Run `lpm login` first".into()))?;

        let (remote, _version) =
            lpm_vault::sync::pull_env(&registry_url, &auth_token, &vault_id, &resolved.canonical)
                .await
                .map_err(LpmError::Script)?;

        (
            format!("{} (local)", resolved.canonical),
            local,
            format!("{} (cloud)", resolved.canonical),
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
            .map_err(LpmError::Script)?;

        (
            "default (local)".into(),
            local,
            "default (cloud)".into(),
            remote,
        )
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
        println!(
            "{}",
            serde_json::json!({
                "success": true,
                "left": left_label,
                "right": right_label,
                "added": added,
                "removed": removed,
                "changed": changed,
                "unchanged": same,
            })
        );
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
        println!("  {} {} {}", "~".yellow(), key.bold(), "(changed)".dimmed());
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

fn expected_personal_sync_version(project_dir: &std::path::Path, force: bool) -> Option<i32> {
    if force {
        return None;
    }

    lpm_vault::vault_id::read_personal_sync_version(project_dir)
}

fn expected_org_sync_version(project_dir: &std::path::Path, org_slug: &str) -> Option<i32> {
    lpm_vault::vault_id::read_org_sync_version(project_dir, org_slug)
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
        println!(
            "{}",
            serde_json::json!({
                "success": true,
                "required": required_keys.len(),
                "present": present,
                "missing": missing,
                "extra": extra,
                "valid": missing.is_empty(),
            })
        );
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

    #[test]
    fn build_sync_environments_canonicalizes_legacy_alias_keys() {
        let mut env_map = HashMap::new();
        env_map.insert("dev".into(), ".env.development".into());

        let mut all_envs = HashMap::new();
        all_envs.insert(
            "dev".into(),
            HashMap::from([(String::from("API_KEY"), String::from("legacy-secret"))]),
        );

        let sync_envs = build_sync_environments(&all_envs, &env_map, None);

        assert_eq!(sync_envs.len(), 1, "sync payload should contain exactly one environment");
        assert!(
            sync_envs.contains_key("development"),
            "legacy alias keys should be canonicalized before sync"
        );
        assert!(
            !sync_envs.contains_key("dev"),
            "legacy alias storage keys should not leak into cloud sync payloads"
        );
    }

    #[test]
    fn build_sync_environments_prefers_canonical_values_when_legacy_alias_collides() {
        let mut env_map = HashMap::new();
        env_map.insert("dev".into(), ".env.development".into());

        let mut all_envs = HashMap::new();
        all_envs.insert(
            "dev".into(),
            HashMap::from([
                (String::from("SHARED"), String::from("legacy")),
                (String::from("ONLY_LEGACY"), String::from("present")),
            ]),
        );
        all_envs.insert(
            "development".into(),
            HashMap::from([
                (String::from("SHARED"), String::from("canonical")),
                (String::from("ONLY_CANONICAL"), String::from("present")),
            ]),
        );

        let sync_envs = build_sync_environments(&all_envs, &env_map, None);
        let development = sync_envs
            .get("development")
            .expect("canonical environment should be present in sync payload");

        assert_eq!(sync_envs.len(), 1, "legacy alias and canonical env should collapse into one sync payload entry");
        assert_eq!(development.get("SHARED").map(String::as_str), Some("canonical"));
        assert_eq!(development.get("ONLY_LEGACY").map(String::as_str), Some("present"));
        assert_eq!(development.get("ONLY_CANONICAL").map(String::as_str), Some("present"));
    }

    #[test]
    fn parse_remote_pull_payload_for_overwrite_uses_remote_environments_exactly() {
        let raw_json = serde_json::json!({
            "environments": {
                "default": {
                    "KEEP": "remote",
                    "REMOTE_ONLY": "fresh"
                },
                "production": {
                    "PROD_ONLY": "remote"
                }
            }
        })
        .to_string();

        let parsed = parse_remote_pull_payload_for_overwrite(&raw_json).unwrap();

        assert_eq!(parsed.len(), 2);
        assert_eq!(
            parsed
                .get("default")
                .and_then(|env| env.get("KEEP"))
                .map(String::as_str),
            Some("remote")
        );
        assert_eq!(
            parsed
                .get("default")
                .and_then(|env| env.get("REMOTE_ONLY"))
                .map(String::as_str),
            Some("fresh")
        );
        assert!(parsed.get("default").and_then(|env| env.get("DROP_ME")).is_none());
        assert!(!parsed.contains_key("preview"));
        assert_eq!(
            parsed
                .get("production")
                .and_then(|env| env.get("PROD_ONLY"))
                .map(String::as_str),
            Some("remote")
        );
    }

    #[test]
    fn parse_remote_pull_payload_for_overwrite_wraps_flat_payload_as_default() {
        let raw_json = serde_json::json!({
            "KEEP": "remote",
            "REMOTE_ONLY": "fresh"
        })
        .to_string();

        let parsed = parse_remote_pull_payload_for_overwrite(&raw_json).unwrap();

        assert_eq!(parsed.len(), 1);
        assert_eq!(
            parsed
                .get("default")
                .and_then(|env| env.get("KEEP"))
                .map(String::as_str),
            Some("remote")
        );
        assert_eq!(
            parsed
                .get("default")
                .and_then(|env| env.get("REMOTE_ONLY"))
                .map(String::as_str),
            Some("fresh")
        );
    }

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

    #[test]
    fn expected_personal_sync_version_uses_stored_version_when_not_forced() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("lpm.json"), r#"{"vault":"vault-123"}"#).unwrap();
        lpm_vault::vault_id::write_personal_sync_version(dir.path(), 6).unwrap();

        assert_eq!(expected_personal_sync_version(dir.path(), false), Some(6));
    }

    #[test]
    fn expected_personal_sync_version_skips_cas_in_force_mode() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("lpm.json"), r#"{"vault":"vault-123"}"#).unwrap();
        lpm_vault::vault_id::write_personal_sync_version(dir.path(), 6).unwrap();

        assert_eq!(expected_personal_sync_version(dir.path(), true), None);
    }

    #[test]
    fn expected_org_sync_version_reads_org_scoped_metadata() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("lpm.json"), r#"{"vault":"vault-123"}"#).unwrap();
        lpm_vault::vault_id::write_org_sync_version(dir.path(), "acme", 9).unwrap();

        assert_eq!(expected_org_sync_version(dir.path(), "acme"), Some(9));
        assert_eq!(expected_org_sync_version(dir.path(), "umbrella"), None);
    }
}
