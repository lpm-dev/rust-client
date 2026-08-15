use super::prelude::*;

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
    std::fs::write(&example_path, &content)
        .map_err(|e| LpmError::Script(format!("failed to write {example_filename}: {e}")))?;

    output::success_line(install_ui::terminal_line!(
        "generated {} ({} variables)",
        install_ui::bold(&example_filename),
        schema.len(),
    ));

    Ok(())
}

pub(super) fn vars_print(args: &[&str], project_dir: &std::path::Path) -> Result<(), LpmError> {
    // Parse --format=<fmt> and --env=<mode> and --schema-only
    let mut format_str = "dotenv";
    let mut env_mode: Option<&str> = None;
    let mut schema_only = false;
    let mut ci = false;

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
        } else if args[i] == "--ci" {
            ci = true;
        }
        i += 1;
    }

    if ci {
        return super::ci::emit_project_env_for_ci(
            project_dir,
            env_mode,
            super::ci::CiEnvDestination::Stdout,
        );
    }

    let format = lpm_env::PrintFormat::parse(format_str).ok_or_else(|| {
        LpmError::Script(format!(
            "unknown format: '{format_str}'. Available: {}",
            lpm_env::PrintFormat::all_names()
        ))
    })?;

    // Read config first so we can resolve env aliases
    let config = lpm_runner::lpm_json::read_lpm_json(project_dir).map_err(LpmError::Script)?;

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

pub(super) fn vars_check(project_dir: &std::path::Path, json_output: bool) -> Result<(), LpmError> {
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
    let vault_envs = lpm_vault::try_get_all_environments(project_dir).map_err(LpmError::Script)?;
    let empty_env_map = std::collections::HashMap::new();
    let all_envs = lpm_env::resolver::list_all(
        lpm_config.as_ref().map_or(&empty_env_map, |c| &c.env),
        lpm_config.as_ref().and_then(|c| c.environments.as_ref()),
        &vault_envs,
    );
    let env_names: Vec<String> = all_envs.iter().map(|e| e.canonical.clone()).collect();

    let mut results: Vec<(String, usize, Vec<lpm_env::ValidationError>)> = Vec::new();
    let mut all_valid = true;
    let validator = lpm_env::EnvValidator::new(schema);

    for env_name in &env_names {
        let mode = if env_name == "default" {
            None
        } else {
            Some(env_name.as_str())
        };

        // Use unified loader (handles inheritance + vault) — hard errors on cycle/missing
        let mut env_vars =
            lpm_runner::dotenv::load_project_env_with_schema_validation(project_dir, mode, false)?;

        // Run schema validation manually to collect per-env errors
        let errors = validator.validate(&mut env_vars);
        if !errors.is_empty() {
            all_valid = false;
        }
        results.push((env_name.clone(), schema.len(), errors));
    }

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
        return if all_valid {
            Ok(())
        } else {
            Err(LpmError::ExitCode(1))
        };
    }

    println!();
    for (name, total, errors) in &results {
        let valid = total - errors.len();
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
                println!("    {}", install_ui::red(&error.to_string()));
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

    let secrets = lpm_vault::try_get_all(project_dir).map_err(LpmError::Script)?;

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
