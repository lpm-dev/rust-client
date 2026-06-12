use super::prelude::*;

/// `lpm env init` — interactive environment setup.
///
/// Detects lpm.json config, scans for .env files, imports each into
/// the correct vault environment, and creates empty envs for configured
/// environments without files.
pub(super) fn vars_init(
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
    let vault_envs = lpm_vault::try_get_all_environments(project_dir).map_err(LpmError::Script)?;

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
        println!("  Run {} to sync to cloud", "lpm env push".cyan());
    } else {
        output::info("vault already initialized — nothing to do");
    }
    println!();

    Ok(())
}

/// `lpm env ls` — environment overview table.
///
/// Shows all environments with variable counts, schema status, and aliases.
pub(super) fn vars_ls(project_dir: &std::path::Path, json_output: bool) -> Result<(), LpmError> {
    let config = lpm_runner::lpm_json::read_lpm_json(project_dir)
        .ok()
        .flatten();

    let empty_env_map = HashMap::new();
    let env_map = config.as_ref().map_or(&empty_env_map, |c| &c.env);
    let environments = config.as_ref().and_then(|c| c.environments.as_ref());
    let schema = config.as_ref().and_then(|c| c.env_schema.as_ref());
    let vault_envs = lpm_vault::try_get_all_environments(project_dir).map_err(LpmError::Script)?;
    let all_envs = lpm_env::resolver::list_all(env_map, environments, &vault_envs);

    if all_envs.is_empty() {
        if json_output {
            println!(
                "{}",
                serde_json::json!({"success": true, "environments": []})
            );
        } else {
            output::info("no environments found");
            println!("  Run {} to set up", "lpm env init".cyan());
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
    let sync_summary = lpm_vault::vault_id::read_sync_summary(project_dir);

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
    let updated_width = rows
        .iter()
        .filter(|r| sync_summary.synced && r.var_count > 0)
        .filter_map(|_| sync_summary.synced_at.as_ref().map(|t| t.len()))
        .max()
        .unwrap_or(7)
        .max(7);

    println!();
    println!(
        "  {:<name_width$}  {:>9}  {:>6}  {:<updated_width$}",
        "Environment", "Variables", "Synced", "Updated",
    );

    for row in &rows {
        let schema_suffix = match row.schema_status {
            Some((valid, total)) if total > 0 => {
                if valid == total {
                    format!(" {}", install_ui::status_ok(&format!("{valid}/{total} ok")))
                } else {
                    format!(" {}", install_ui::red(&format!("{valid}/{total} !!")))
                }
            }
            _ => String::new(),
        };

        let row_synced = sync_summary.synced && row.var_count > 0;
        let synced_raw = if row_synced { "yes" } else { "no" };
        let synced_padded = format!("{synced_raw:>6}");
        let synced_str = if row_synced {
            install_ui::status_ok(&synced_padded)
        } else {
            install_ui::dim(&synced_padded)
        };

        let updated_raw = if row_synced {
            sync_summary.synced_at.as_deref().unwrap_or("-")
        } else {
            "-"
        };
        let updated_str = install_ui::dim(&format!("{updated_raw:<updated_width$}"));

        let source_indicator = match row.source {
            lpm_env::EnvSource::Legacy => format!(" {}", install_ui::yellow("legacy")),
            _ => String::new(),
        };

        let var_count = install_ui::dim(&format!("{:>9}", row.var_count));

        println!(
            "  {:<name_width$}  {}  {}  {}{}{}",
            row.canonical, var_count, synced_str, updated_str, schema_suffix, source_indicator,
        );
    }
    println!();
    println!(
        "  {} {}",
        install_ui::dim("Active environment:"),
        install_ui::status_ok("default")
    );
    println!(
        "  {}",
        install_ui::dim("Use lpm env list --env <name> to inspect secrets.")
    );
    println!();
    Ok(())
}

/// `lpm env copy <src> <dst>` — copy all secrets from one environment to another.
pub(super) fn vars_copy(
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

    let src_secrets = lpm_vault::try_get_all_env(project_dir, &resolved_src.storage_key)
        .map_err(LpmError::Script)?;
    if src_secrets.is_empty() {
        return Err(LpmError::Script(format!(
            "no secrets in source environment \"{}\"",
            resolved_src.canonical
        )));
    }

    let dst_secrets = lpm_vault::try_get_all_env(project_dir, &resolved_dst.storage_key)
        .map_err(LpmError::Script)?;

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
