use super::prelude::*;

pub(super) fn schema_definition(
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
    match lpm_runner::lpm_json::resolve_schema_definition(project_dir) {
        Ok(resolved) => {
            if json_output {
                println!(
                    "{}",
                    serde_json::json!({
                        "command":"env.schema", "success":true,
                        "context":{"kind":"definition"}, "variables":resolved.schema.len(),
                        "origins":resolved.origins, "groupOrigins":resolved.group_origins,
                        "dependencies":resolved.dependencies.iter().map(|dependency| &dependency.path).collect::<Vec<_>>(),
                        "fingerprint":hex::encode(resolved.fingerprint), "diagnostics":[],
                    })
                );
            } else {
                install_ui::done_line(crate::install_ui::terminal_line!(
                    "envSchema is valid ({} variables, {} imported files)",
                    resolved.schema.len(),
                    resolved.dependencies.len()
                ));
            }
            Ok(())
        }
        Err(error) => {
            if json_output {
                println!(
                    "{}",
                    serde_json::json!({"command":"env.schema", "success":false, "context":{"kind":"definition"}, "diagnostics":[error.diagnostic]})
                );
                Err(LpmError::ExitCode(1))
            } else {
                Err(LpmError::EnvValidation(error.to_string()))
            }
        }
    }
}

pub(super) fn vars_example(
    project_dir: &std::path::Path,
    env_input: Option<&str>,
    json_output: bool,
) -> Result<(), LpmError> {
    let config = lpm_runner::lpm_json::read_lpm_json(project_dir).map_err(LpmError::Script)?;

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
    lpm_common::write_file_atomic_with_options(
        &example_path,
        content.as_bytes(),
        lpm_common::AtomicWriteOptions::new().sync_file(),
    )
    .map_err(|e| LpmError::Script(format!("failed to write {example_filename}: {e}")))?;

    output::success_line(install_ui::terminal_line!(
        "generated {} ({} variables)",
        install_ui::bold(&example_filename),
        schema.len(),
    ));

    Ok(())
}

#[expect(
    clippy::too_many_arguments,
    reason = "CLI print keeps exposure, scope, and output options explicit"
)]
pub(super) fn vars_print(
    env_mode: Option<&str>,
    format: Option<lpm_env::PrintFormat>,
    schema_only: bool,
    client_only: bool,
    ci: bool,
    scope: &super::arguments::Scope,
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
    if json_output && (ci || format.is_some_and(|format| format != lpm_env::PrintFormat::Json)) {
        return Err(LpmError::Script(
            "--json conflicts with --ci or a non-JSON --format".into(),
        ));
    }
    if ci {
        return super::ci::emit_project_env_for_ci(
            project_dir,
            env_mode,
            super::ci::CiEnvDestination::Stdout,
            false,
        );
    }
    let format = format.unwrap_or(if json_output {
        lpm_env::PrintFormat::Json
    } else {
        lpm_env::PrintFormat::Dotenv
    });
    let config = lpm_runner::lpm_json::read_lpm_json(project_dir).map_err(LpmError::Script)?;
    if (schema_only || client_only)
        && config
            .as_ref()
            .and_then(|config| config.env_schema.as_ref())
            .is_none_or(|schema| schema.is_empty())
    {
        return Err(LpmError::Script(
            "--schema-only and --client-only require a non-empty envSchema in lpm.json".into(),
        ));
    }

    let output = format_print_env(
        project_dir,
        env_mode,
        config.as_ref(),
        schema_only,
        client_only,
        format,
        scope,
    )?;
    println!("{output}");
    Ok(())
}

fn format_print_env(
    project_dir: &std::path::Path,
    resolved_mode: Option<&str>,
    config: Option<&lpm_runner::lpm_json::LpmJsonConfig>,
    schema_only: bool,
    client_only: bool,
    format: lpm_env::PrintFormat,
    scope: &super::arguments::Scope,
) -> Result<String, LpmError> {
    // Use the unified loader (handles inheritance, vault, overrides, schema validation + defaults)
    let composed = lpm_runner::dotenv::load_project_env_with_config_and_context(
        project_dir,
        resolved_mode,
        config,
        scope.stage.unwrap_or_default(),
        scope.service.as_deref(),
        lpm_runner::dotenv::OverridePolicy::Apply,
    )?;
    // Every format is machine-readable, so overridden keys are reported on
    // stderr, never marked in the output.
    lpm_runner::dotenv::announce_personal_overrides(&composed, resolved_mode.unwrap_or("default"));
    let mut env_vars = composed.into_vars();
    let schema = config.and_then(|c| c.env_schema.as_ref());

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
    if (schema_only || client_only)
        && let Some(schema) = schema
    {
        env_vars.retain(|key, _| {
            schema
                .vars
                .get(key)
                .is_some_and(|rule| !client_only || rule.client)
        });
    }

    Ok(lpm_env::format_env(&env_vars, format, &secret_keys))
}

fn check_environments(
    env_input: Option<&str>,
    config: Option<&lpm_runner::lpm_json::LpmJsonConfig>,
    load_inventory: impl FnOnce() -> Result<HashMap<String, HashMap<String, String>>, LpmError>,
) -> Result<Vec<lpm_env::ResolvedEnv>, LpmError> {
    let empty_env_map = std::collections::HashMap::new();
    let all_envs = if let Some(env_input) = env_input {
        vec![lpm_runner::dotenv::resolve_project_environment(
            Some(env_input),
            config,
        )?]
    } else {
        let vault_envs = load_inventory()?;
        lpm_env::resolver::list_all(
            config.map_or(&empty_env_map, |c| &c.env),
            config.and_then(|c| c.environments.as_ref()),
            &vault_envs,
        )
    };
    Ok(all_envs)
}

pub(super) fn vars_check(
    project_dir: &std::path::Path,
    env_input: Option<&str>,
    scope: &super::arguments::Scope,
    json_output: bool,
) -> Result<(), LpmError> {
    let lpm_config = lpm_runner::lpm_json::read_lpm_json(project_dir).map_err(LpmError::Script)?;

    let schema = lpm_config
        .as_ref()
        .and_then(|config| config.env_schema.as_ref())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            LpmError::Script(
                "no envSchema defined in lpm.json. Add an envSchema section first.".into(),
            )
        })?;

    // Discover all environments via the canonical resolver.
    // This produces a consistent, deduplicated list from config + vault,
    // with legacy vault keys surfaced separately (never collapsed).
    let all_envs = check_environments(env_input, lpm_config.as_ref(), || {
        lpm_vault::try_get_all_environments(project_dir)
            .map_err(lpm_runner::dotenv::vault_error(LpmError::Script))
    })?;
    struct Checked {
        name: String,
        total: usize,
        errors: Vec<lpm_env::ValidationError>,
        from_overrides: std::collections::HashSet<String>,
        ignored: Vec<String>,
        characters: Vec<lpm_runner::dotenv::StoredValueCharacters>,
    }
    let mut results: Vec<Checked> = Vec::with_capacity(all_envs.len());
    let mut all_valid = true;
    let validator = lpm_env::EnvValidator::new(schema);
    for environment in &all_envs {
        if lpm_env::resolver::validate_env_name(&environment.canonical).is_err() {
            all_valid = false;
            results.push(Checked {
                name: environment.canonical.clone(),
                total: schema.len(),
                errors: vec![lpm_env::ValidationError {
                    key: "env.name".into(),
                    kind: lpm_env::ValidationErrorKind::InvalidEnvironmentName {
                        canonical: environment.canonical.clone(),
                        alias: environment.alias.clone(),
                    },
                    description: None,
                    is_secret: false,
                }],
                from_overrides: std::collections::HashSet::new(),
                ignored: Vec::new(),
                characters: Vec::new(),
            });
            continue;
        }
        let (checked, ignored) = lpm_runner::dotenv::collect_ignored_env_names(|| {
            let layers = lpm_runner::dotenv::load_project_env_layers_for_resolved(
                project_dir,
                environment,
                lpm_config.as_ref(),
                lpm_runner::dotenv::OverridePolicy::Apply,
            )?;
            let characters = layers.stored_value_characters();
            let mut composed = layers.compose(lpm_config.as_ref(), scope.service.as_deref())?;
            let errors = composed.evaluate(
                Some(&validator),
                lpm_env::EvalContext {
                    environment: &environment.canonical,
                    stage: scope.stage.unwrap_or_default(),
                    service: scope.service.as_deref(),
                },
            )?;
            let from_overrides = errors
                .iter()
                .filter(|error| composed.caused_by_override(error))
                .map(|error| error.key.clone())
                .collect();
            Ok::<_, LpmError>((errors, from_overrides, characters))
        });
        let (errors, from_overrides, characters) = checked?;
        all_valid &= errors.is_empty();
        results.push(Checked {
            name: environment.canonical.clone(),
            total: schema.len(),
            errors,
            from_overrides,
            ignored,
            characters,
        });
    }

    if json_output {
        let json_results: Vec<serde_json::Value> = results
            .iter()
            .map(|Checked { name, total, errors, from_overrides, ignored, characters }| {
                let value_warnings: Vec<serde_json::Value> = characters
                    .iter()
                    .map(|stored| {
                        let mut warning = super::characters::json(&stored.key, &stored.characters);
                        warning["personal_override"] = serde_json::json!(stored.personal_override);
                        warning
                    })
                    .collect();
                serde_json::json!({
                    "environment": name,
                    "total": total,
                    "valid": valid_variable_count(schema, errors),
                    "ignored": ignored,
                    "value_warnings": value_warnings,
                    "errors": errors.iter().map(|e| {
                        let mut diagnostic = serde_json::json!({"key": e.key, "error": e.to_string()});
                        if let lpm_env::ValidationErrorKind::GroupViolation { group, mode } = &e.kind {
                            diagnostic["group"] = serde_json::json!(group);
                            diagnostic["mode"] = serde_json::json!(mode);
                        }
                        if from_overrides.contains(&e.key) {
                            diagnostic["personalOverride"] = serde_json::json!(true);
                        }
                        diagnostic
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
        return if all_valid {
            Ok(())
        } else {
            Err(LpmError::ExitCode(1))
        };
    }

    println!();
    for Checked {
        name,
        total,
        errors,
        from_overrides,
        ignored,
        characters,
    } in &results
    {
        let valid = valid_variable_count(schema, errors);
        if errors.is_empty() {
            println!(
                "{}",
                install_ui::terminal_line!(
                    "  {}  {}  {}/{} valid",
                    install_ui::bold(name),
                    install_ui::green("✓"),
                    valid,
                    total,
                )
            );
        } else {
            println!(
                "{}",
                install_ui::terminal_line!(
                    "  {}  {}  {}/{} valid",
                    install_ui::bold(name),
                    install_ui::red("✗"),
                    valid,
                    total,
                )
            );
            for error in errors {
                if from_overrides.contains(&error.key) {
                    println!(
                        "    {} {}",
                        install_ui::red(&error.to_string()),
                        install_ui::dim(&format!(
                            "(from a personal override on {})",
                            lpm_runner::dotenv::THIS_MACHINE
                        ))
                    );
                } else {
                    println!("    {}", install_ui::red(&error.to_string()));
                }
            }
        }
        if !ignored.is_empty() {
            println!(
                "    {}",
                install_ui::yellow(&lpm_runner::dotenv::ignored_env_note(ignored))
            );
        }
        for stored in characters {
            let heading = if stored.personal_override {
                format!(
                    "{} (a personal override on {}) has characters that are hard to see",
                    stored.key,
                    lpm_runner::dotenv::THIS_MACHINE
                )
            } else {
                format!("{} has characters that are hard to see", stored.key)
            };
            println!("    {}", install_ui::yellow(&heading));
            for line in super::characters::lines(&stored.characters) {
                println!("{}", install_ui::terminal_line!("      {}", line));
            }
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

/// Validate vault secrets against .env.example.
pub(super) fn vars_validate(
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

    let content =
        lpm_common::read_text_file_capped(&example_path, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES)?;

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

    let secrets = lpm_vault::try_get_all(project_dir)
        .map_err(lpm_runner::dotenv::vault_error(LpmError::Script))?;

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
        extra.sort_unstable();
    }

    let valid = missing.is_empty() && (!strict || extra.is_empty());

    if json_output {
        println!(
            "{}",
            serde_json::json!({
                "success": valid,
                "required": required_keys.len(),
                "present": present,
                "missing": missing,
                "extra": extra,
                "valid": valid,
            })
        );
        return if valid {
            Ok(())
        } else {
            Err(LpmError::ExitCode(1))
        };
    }

    println!();
    println!("  Validating against {}", ".env.example".bold());
    println!();

    for key in &present {
        println!(
            "{}",
            install_ui::terminal_line!(
                "  {} {} {}",
                install_ui::green("✓"),
                install_ui::bold(key),
                install_ui::green("set"),
            )
        );
    }
    for key in &missing {
        println!(
            "{}",
            install_ui::terminal_line!(
                "  {} {} {}",
                install_ui::red("✗"),
                install_ui::bold(key),
                install_ui::red("missing"),
            )
        );
    }
    for key in &extra {
        println!(
            "{}",
            install_ui::terminal_line!(
                "  {} {} {}",
                install_ui::yellow("!"),
                install_ui::bold(key),
                install_ui::yellow("not in .env.example (extra)"),
            )
        );
    }

    println!();
    if valid {
        output::success(&format!(
            "all {} required variables are set",
            required_keys.len()
        ));
    } else if !missing.is_empty() {
        let missing_list_capacity = missing.iter().map(|key| key.len() + 4).sum::<usize>()
            + missing.len().saturating_sub(1);
        let mut missing_assignments = String::with_capacity(missing_list_capacity);
        for (index, key) in missing.iter().enumerate() {
            if index > 0 {
                missing_assignments.push(' ');
            }
            missing_assignments.push_str(key);
            missing_assignments.push_str("=...");
        }
        println!(
            "{}",
            install_ui::terminal_line!(
                "  {} of {} required variables are missing",
                install_ui::red(&missing.len().to_string()),
                required_keys.len(),
            )
        );
        println!(
            "{}",
            install_ui::terminal_line!(
                "  Fix: {}",
                install_ui::cyan(&format!("lpm env set {missing_assignments}")),
            )
        );
    }

    if strict && !extra.is_empty() {
        let extra_list = extra.join(" ");
        println!(
            "{}",
            install_ui::terminal_line!(
                "  {} extra variables are not declared in .env.example",
                install_ui::red(&extra.len().to_string()),
            )
        );
        println!(
            "{}",
            install_ui::terminal_line!(
                "  Fix: remove them with {} or add them to .env.example",
                install_ui::cyan(&format!("lpm env delete {extra_list}")),
            )
        );
    }

    if valid {
        Ok(())
    } else {
        Err(LpmError::ExitCode(1))
    }
}

pub(super) fn valid_variable_count(
    schema: &lpm_env::EnvSchema,
    errors: &[lpm_env::ValidationError],
) -> usize {
    if errors.iter().any(|error| error.key == "env.name") {
        return 0;
    }
    let failed: std::collections::HashSet<&str> = errors
        .iter()
        .filter_map(|error| {
            schema
                .vars
                .contains_key(&error.key)
                .then_some(error.key.as_str())
        })
        .collect();
    schema.len() - failed.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_checks_do_not_decode_the_environment_inventory() {
        let called = std::cell::Cell::new(false);
        let selected = check_environments(Some("production"), None, || {
            called.set(true);
            Ok(HashMap::new())
        })
        .unwrap();
        assert_eq!(selected[0].canonical, "production");
        assert!(!called.get());
    }

    #[test]
    fn client_print_uses_one_manifest_snapshot_for_defaults_and_filtering() {
        let project = tempfile::tempdir().unwrap();
        let path = project.path().join("lpm.json");
        std::fs::write(&path, r#"{"envSchema":{"clientPrefixes":["APP_"],"vars":{"APP_TOKEN":{"client":true,"default":"public-fixture"}}}}"#).unwrap();
        let config = lpm_runner::lpm_json::read_lpm_json(project.path())
            .unwrap()
            .unwrap();
        std::fs::write(
            path,
            r#"{"envSchema":{"vars":{"APP_TOKEN":{"secret":true}}}}"#,
        )
        .unwrap();
        let printed = format_print_env(
            project.path(),
            None,
            Some(&config),
            false,
            true,
            lpm_env::PrintFormat::Json,
            &super::super::arguments::Scope {
                stage: None,
                service: None,
            },
        )
        .unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&printed).unwrap(),
            serde_json::json!({"APP_TOKEN":"public-fixture"})
        );
    }
}
