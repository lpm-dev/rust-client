use super::prelude::*;

/// `lpm env connect <platform> --project=<id> [--token=<token>] [--team=<id>] [--label=<name>]`
pub(super) async fn vars_connect(
    args: &[&str],
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
    if args.is_empty() {
        return Err(LpmError::Script(
            "usage: lpm env connect <platform> --project=<id> [--token=<token>]".into(),
        ));
    }

    let platform = args[0];
    let vault_id =
        lpm_vault::vault_id::get_or_create_vault_id(project_dir).map_err(LpmError::Script)?;
    let (registry_url, auth_token) = super::auth::get_platform_auth(json_output).await?;

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
        } else if args[i].starts_with("--") && !json_output {
            output::warn(&format!("unknown flag '{}' — ignored", args[i]));
        }
        i += 1;
    }

    let project_id = project_id.ok_or_else(|| {
        LpmError::Script(format!(
            "missing --project flag. Usage: lpm env connect {platform} --project=<id>"
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
        connection_config["linkedEnv"] = serde_json::Value::String(resolved.canonical);
    }

    if !json_output {
        output::info(&format!("connecting to {platform}..."));
    }

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
        let body: serde_json::Value =
            super::response::parse_capped_platform_json_or_unknown(response).await;
        return Err(LpmError::Script(
            body["error"]
                .as_str()
                .unwrap_or("connection failed")
                .to_string(),
        ));
    }

    let result: serde_json::Value = super::response::parse_capped_platform_json(response).await?;

    if json_output {
        super::response::print_json_value(&super::response::success_envelope(result));
    } else {
        let status = result["status"].as_str().unwrap_or("connected");
        output::success(&format!(
            "{platform} {} (project: {project_id})",
            status.bold()
        ));
    }

    Ok(())
}

/// `lpm env push --to <platform> [--env=<mode>] [--clean] [--yes]`
pub(super) async fn vars_platform_push(
    args: &[&str],
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
    let vault_id = lpm_vault::vault_id::read_vault_id(project_dir)
        .ok_or_else(|| LpmError::Script("no vault configured. Run `lpm env set` first".into()))?;
    let (registry_url, auth_token) = super::auth::get_platform_auth(json_output).await?;

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
        LpmError::Script("missing --to flag. Usage: lpm env push --to <platform>".into())
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

    if !json_output {
        output::info(&format!("comparing with {platform}..."));
    }

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
        let body: serde_json::Value =
            super::response::parse_capped_platform_json_or_unknown(dry_run_response).await;
        return Err(LpmError::Script(
            body["error"].as_str().unwrap_or("push failed").to_string(),
        ));
    }

    let diff: serde_json::Value =
        super::response::parse_capped_platform_json(dry_run_response).await?;

    let added = diff["added"].as_array().map_or(0, |a| a.len());
    let changed = diff["changed"].as_array().map_or(0, |a| a.len());
    let removed = diff["removed"].as_array().map_or(0, |a| a.len());
    let unchanged = diff["unchanged"].as_u64().unwrap_or(0);
    let orphans = diff["orphans"].as_array().map_or(0, |a| a.len());

    if added == 0 && changed == 0 && removed == 0 {
        if json_output {
            super::response::print_json_value(&serde_json::json!({
                "success": true,
                "status": "no_changes",
                "platform": platform,
            }));
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
                "!".yellow(),
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
    if !json_output {
        output::info(&format!("pushing to {platform}..."));
    }

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
        let body: serde_json::Value =
            super::response::parse_capped_platform_json_or_unknown(push_response).await;
        return Err(LpmError::Script(
            body["error"].as_str().unwrap_or("push failed").to_string(),
        ));
    }

    let result: serde_json::Value =
        super::response::parse_capped_platform_json(push_response).await?;

    if json_output {
        super::response::print_json_value(&super::response::success_envelope(result));
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

/// `lpm env status`
pub(super) async fn vars_platform_status(
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
    let vault_id = lpm_vault::vault_id::read_vault_id(project_dir)
        .ok_or_else(|| LpmError::Script("no vault configured. Run `lpm env set` first".into()))?;
    let (registry_url, auth_token) = super::auth::get_platform_auth(json_output).await?;

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
    let vault_envs = lpm_vault::try_get_all_environments(project_dir).map_err(LpmError::Script)?;
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

    if !json_output {
        output::info("checking platform status...");
    }

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
        let body: serde_json::Value =
            super::response::parse_capped_platform_json_or_unknown(response).await;
        return Err(LpmError::Script(
            body["error"]
                .as_str()
                .unwrap_or("status check failed")
                .to_string(),
        ));
    }

    let result: serde_json::Value = super::response::parse_capped_platform_json(response).await?;

    if json_output {
        super::response::print_json_value(&super::response::success_envelope(result));
        return Ok(());
    }

    let platforms = result["platforms"].as_array();
    if platforms.is_none() || platforms.unwrap().is_empty() {
        output::warn("no platform connections. Run 'lpm env connect <platform>' to add one.");
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

        let push_info = last_push.map_or_else(
            || "  never pushed".to_string(),
            |t| format!("  last push: {t}"),
        );

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
                    "!".yellow(),
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

/// `lpm env pull --from <platform> [--env=<mode>] [--yes]`
pub(super) async fn vars_platform_pull(
    args: &[&str],
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
    let vault_id =
        lpm_vault::vault_id::get_or_create_vault_id(project_dir).map_err(LpmError::Script)?;
    let (registry_url, auth_token) = super::auth::get_platform_auth(json_output).await?;

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
        LpmError::Script("missing --from flag. Usage: lpm env pull --from <platform>".into())
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
        let body: serde_json::Value =
            super::response::parse_capped_platform_json_or_unknown(response).await;
        return Err(LpmError::Script(
            body["error"].as_str().unwrap_or("pull failed").to_string(),
        ));
    }

    let result: serde_json::Value = super::response::parse_capped_platform_json(response).await?;

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
