use super::prelude::*;

struct InitAction {
    canonical: String,
    alias: Option<String>,
    file_path: String,
    vault_exists: bool,
    vault_var_count: usize,
}

enum InitActionOutcome {
    Imported(usize),
    CreatedEmpty,
}

struct InitActionResult {
    file_exists: bool,
    file_variable_count: usize,
    outcome: Option<InitActionOutcome>,
}

fn perform_init_actions(
    project_dir: &std::path::Path,
    actions: &[InitAction],
    force: bool,
    snapshot: lpm_vault::EnvironmentInitializationSnapshot,
) -> Result<Vec<InitActionResult>, LpmError> {
    let initializations = actions
        .iter()
        .map(|action| lpm_vault::EnvironmentFileInitialization {
            environment: action.canonical.clone(),
            source_path: project_dir.join(&action.file_path),
            import_if_present: !action.vault_exists || force,
            create_if_missing: !action.vault_exists && action.canonical != "default",
        })
        .collect::<Vec<_>>();
    lpm_vault::initialize_environments_from_files_with_snapshot(
        project_dir,
        &initializations,
        force,
        snapshot,
    )
    .map_err(LpmError::Script)
    .map(|results| {
        results
            .into_iter()
            .map(|result| InitActionResult {
                file_exists: result.file_present,
                file_variable_count: result.file_variable_count,
                outcome: result
                    .imported_count
                    .map(InitActionOutcome::Imported)
                    .or_else(|| {
                        result
                            .created_empty
                            .then_some(InitActionOutcome::CreatedEmpty)
                    }),
            })
            .collect()
    })
}

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
    let manifest = super::sync_payload::CloudManifestSnapshot::read(project_dir)?;
    let vault_id = manifest
        .vault
        .vault_id()
        .map_err(LpmError::Script)?
        .map(str::to_owned);
    let config = manifest.config;

    let empty_env_map = HashMap::new();
    let env_map = config.as_ref().map_or(&empty_env_map, |c| &c.env);
    let environments = config.as_ref().and_then(|c| c.environments.as_ref());
    let snapshot = lpm_vault::capture_environment_initialization_snapshot(vault_id.as_deref())
        .map_err(LpmError::Script)?;

    // Build the list of environments to process
    let all_envs = lpm_env::resolver::list_all_from_vault_names(
        env_map,
        environments,
        snapshot.environment_names(),
    );

    let mut actions: Vec<InitAction> = Vec::new();

    for env in &all_envs {
        let vault_var_count = snapshot
            .environment_variable_count(&env.canonical)
            .unwrap_or(0);
        let vault_exists = vault_var_count > 0;

        // Determine the .env file to check
        let file_path = env.file_path.clone().unwrap_or_else(|| {
            if env.canonical == "default" {
                ".env".to_string()
            } else {
                format!(".env.{}", env.canonical)
            }
        });

        actions.push(InitAction {
            canonical: env.canonical.clone(),
            alias: env.alias.clone(),
            file_path,
            vault_exists,
            vault_var_count,
        });
    }
    let action_results = perform_init_actions(project_dir, &actions, force, snapshot)?;

    let json_actions = json_output.then(|| {
        actions
            .iter()
            .zip(&action_results)
            .map(|(action, result)| {
                serde_json::json!({
                    "environment": action.canonical,
                    "alias": action.alias,
                    "filePath": action.file_path,
                    "fileExists": result.file_exists,
                    "fileVarCount": result.file_variable_count,
                    "vaultExists": action.vault_exists,
                    "vaultVarCount": action.vault_var_count,
                })
            })
            .collect::<Vec<serde_json::Value>>()
    });

    if !json_output && !env_map.is_empty() {
        println!();
        output::info("detected lpm.json env config:");
        for env in &all_envs {
            if let Some(alias) = &env.alias {
                println!(
                    "{}",
                    install_ui::terminal_line!(
                        "    {}  {}  {}",
                        install_ui::bold(alias),
                        install_ui::dim("->"),
                        install_ui::dim(
                            env.file_path
                                .as_deref()
                                .unwrap_or(&format!(".env.{}", env.canonical)),
                        ),
                    )
                );
            }
        }
        println!();
    }

    if !json_output {
        output::info("scanning .env files:");
        for (action, result) in actions.iter().zip(&action_results) {
            if result.file_exists {
                println!(
                    "{}",
                    install_ui::terminal_line!(
                        "    {} {} ({} variable{})",
                        install_ui::green("found"),
                        install_ui::bold(&action.file_path),
                        result.file_variable_count,
                        if result.file_variable_count == 1 {
                            ""
                        } else {
                            "s"
                        },
                    )
                );
            } else {
                println!(
                    "{}",
                    install_ui::terminal_line!(
                        "    {}  {}",
                        install_ui::dim("missing"),
                        install_ui::dim(&action.file_path),
                    )
                );
            }
        }
        println!();
    }

    if json_output {
        let results = actions
            .iter()
            .zip(&action_results)
            .filter_map(|(action, result)| match result.outcome.as_ref() {
                Some(InitActionOutcome::Imported(count)) => Some(serde_json::json!({
                    "environment": action.canonical,
                    "action": "imported",
                    "count": count,
                })),
                Some(InitActionOutcome::CreatedEmpty) => Some(serde_json::json!({
                    "environment": action.canonical,
                    "action": "created_empty",
                })),
                None => None,
            })
            .collect::<Vec<_>>();
        println!(
            "{}",
            serde_json::json!({
                "success": true,
                "environments": json_actions.unwrap_or_default(),
                "actions": results,
            })
        );
        return Ok(());
    }

    let mut imported_count = 0;
    let mut created_count = 0;
    let mut skipped_count = 0;

    for (action, result) in actions.iter().zip(&action_results) {
        if let Some(InitActionOutcome::Imported(count)) = result.outcome.as_ref() {
            output::success_line(install_ui::terminal_line!(
                "imported {} variable{} from {} into \"{}\"",
                count,
                if *count == 1 { "" } else { "s" },
                install_ui::cyan(&action.file_path),
                &action.canonical,
            ));
            imported_count += 1;
        } else if result.file_exists && action.vault_exists {
            println!(
                "{}",
                install_ui::terminal_line!(
                    "  {} \"{}\" already has {} secret{} (use {} to overwrite)",
                    install_ui::yellow("skip"),
                    &action.canonical,
                    action.vault_var_count,
                    if action.vault_var_count == 1 { "" } else { "s" },
                    install_ui::bold("--force"),
                )
            );
            skipped_count += 1;
        } else if matches!(
            result.outcome.as_ref(),
            Some(InitActionOutcome::CreatedEmpty)
        ) {
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
fn effective_schema_vars<'a>(
    canonical: &str,
    vault_envs: &'a HashMap<String, HashMap<String, String>>,
) -> Option<&'a HashMap<String, String>> {
    let env_specific = vault_envs.get(canonical);
    if canonical == "default" {
        env_specific
    } else {
        match env_specific {
            Some(vars) if !vars.is_empty() => Some(vars),
            _ => vault_envs.get("default"),
        }
    }
}

pub(super) fn vars_ls(project_dir: &std::path::Path, json_output: bool) -> Result<(), LpmError> {
    let manifest = super::sync_payload::CloudManifestSnapshot::read(project_dir)?;
    let vault_id = manifest
        .vault
        .vault_id()
        .map_err(LpmError::Script)?
        .map(str::to_owned);
    let sync_summary = manifest.vault.sync_summary();
    let config = manifest.config;

    let empty_env_map = HashMap::new();
    let env_map = config.as_ref().map_or(&empty_env_map, |c| &c.env);
    let environments = config.as_ref().and_then(|c| c.environments.as_ref());
    let schema = config.as_ref().and_then(|c| c.env_schema.as_ref());
    let vault_envs = match vault_id.as_deref() {
        Some(vault_id) => {
            lpm_vault::try_get_all_environments_for_vault_id(vault_id).map_err(LpmError::Script)?
        }
        None => HashMap::new(),
    };
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
    for env in &all_envs {
        // Replicate the actual loader fallback behavior from dotenv.rs:79-88:
        // If the env-specific vault is completely empty, fall back to default.
        // If it has any secrets, use ONLY it (no per-key fallback to default).
        let env_specific = vault_envs.get(&env.canonical);
        let effective_vars = effective_schema_vars(&env.canonical, &vault_envs);
        let var_count = env_specific.map_or(0, |v| v.len());

        let schema_status = schema.map(|s| {
            let total = s.vars.iter().filter(|(_, r)| r.required).count();
            let valid = s
                .vars
                .iter()
                .filter(|(_, r)| r.required)
                .filter(|(k, _)| effective_vars.is_some_and(|vars| vars.contains_key(k.as_str())))
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
                    install_ui::terminal_line!(
                        " {}",
                        install_ui::status_ok(&format!("{valid}/{total} ok")),
                    )
                } else {
                    install_ui::terminal_line!(
                        " {}",
                        install_ui::red(&format!("{valid}/{total} !!")),
                    )
                }
            }
            _ => install_ui::TerminalLine::new(""),
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
            lpm_env::EnvSource::Legacy => {
                install_ui::terminal_line!(" {}", install_ui::yellow("legacy"))
            }
            _ => install_ui::TerminalLine::new(""),
        };

        let var_count = install_ui::dim(&format!("{:>9}", row.var_count));

        println!(
            "{}",
            install_ui::terminal_line!(
                "  {:<name_width$}  {}  {}  {}{}{}",
                &row.canonical,
                var_count,
                synced_str,
                updated_str,
                schema_suffix,
                source_indicator,
            )
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
    let config = lpm_runner::lpm_json::read_lpm_json(project_dir).map_err(LpmError::Script)?;
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

    let copy = lpm_vault::copy_environment(
        project_dir,
        &resolved_src.storage_key,
        &resolved_dst.storage_key,
        overwrite,
    )
    .map_err(LpmError::Script)?;
    let Some(copy) = copy else {
        return Err(LpmError::Script(format!(
            "no secrets in source environment \"{}\"",
            resolved_src.canonical
        )));
    };

    if copy.copied == 0 {
        if json_output {
            println!(
                "{}",
                serde_json::json!({
                    "success": true,
                    "copied": 0,
                    "skipped": copy.skipped,
                    "source": resolved_src.canonical,
                    "target": resolved_dst.canonical,
                })
            );
        } else {
            output::info_line(install_ui::terminal_line!(
                "nothing to copy — all {} key{} already exist in \"{}\" (use {} to overwrite)",
                copy.skipped,
                if copy.skipped == 1 { "" } else { "s" },
                &resolved_dst.canonical,
                install_ui::bold("--overwrite"),
            ));
        }
        return Ok(());
    }

    if json_output {
        println!(
            "{}",
            serde_json::json!({
                "success": true,
                "copied": copy.copied,
                "skipped": copy.skipped,
                "source": resolved_src.canonical,
                "target": resolved_dst.canonical,
            })
        );
    } else {
        let message = if copy.skipped == 0 {
            install_ui::terminal_line!(
                "copied {} secret{} from \"{}\" to \"{}\"",
                copy.copied,
                if copy.copied == 1 { "" } else { "s" },
                &resolved_src.canonical,
                &resolved_dst.canonical,
            )
        } else {
            install_ui::terminal_line!(
                "copied {} secret{} from \"{}\" to \"{}\" ({} existing skipped, use {} to overwrite)",
                copy.copied,
                if copy.copied == 1 { "" } else { "s" },
                &resolved_src.canonical,
                &resolved_dst.canonical,
                copy.skipped,
                install_ui::bold("--overwrite"),
            )
        };
        output::success_line(message);
    }

    Ok(())
}

#[cfg(test)]
mod performance_tests {
    use super::*;

    #[test]
    fn effective_schema_vars_borrow_environment_specific_and_default_maps() {
        let default = HashMap::from([("DEFAULT".to_string(), "secret".to_string())]);
        let production = HashMap::from([("PROD".to_string(), "secret".to_string())]);
        let empty = HashMap::new();
        let vault_envs = HashMap::from([
            ("default".to_string(), default),
            ("production".to_string(), production),
            ("preview".to_string(), empty),
        ]);

        let default_reference = &vault_envs["default"];
        let production_reference = &vault_envs["production"];
        assert!(std::ptr::eq(
            effective_schema_vars("default", &vault_envs).expect("default should exist"),
            default_reference,
        ));
        assert!(std::ptr::eq(
            effective_schema_vars("production", &vault_envs).expect("production should exist"),
            production_reference,
        ));
        assert!(std::ptr::eq(
            effective_schema_vars("preview", &vault_envs).expect("empty preview should fall back"),
            default_reference,
        ));
        assert!(std::ptr::eq(
            effective_schema_vars("missing", &vault_envs)
                .expect("missing environment should fall back"),
            default_reference,
        ));
    }

    #[test]
    fn effective_schema_vars_is_absent_without_a_default_fallback() {
        let vault_envs = HashMap::from([("preview".to_string(), HashMap::new())]);
        assert!(effective_schema_vars("preview", &vault_envs).is_none());
    }
}
