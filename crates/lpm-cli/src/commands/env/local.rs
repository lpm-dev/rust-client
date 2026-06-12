use super::prelude::*;

pub(super) fn env_set(
    args: &[&str],
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
    let (env_input, remaining) = parse_env_flag(args)?;
    let pairs: Vec<(&str, &str)> = remaining
        .iter()
        .filter_map(|arg| arg.split_once('='))
        .collect();

    if pairs.is_empty() {
        return Err(LpmError::Script(
            "usage: lpm env set [--env=<name>] KEY=VALUE [KEY2=VALUE2 ...]".into(),
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
    Ok(())
}

pub(super) fn env_get(
    args: &[&str],
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
    let (env_input, remaining) = parse_env_flag(args)?;
    let key = remaining
        .iter()
        .find(|a| **a != "--reveal")
        .ok_or_else(|| {
            LpmError::Script("usage: lpm env get [--env=<name>] KEY [--reveal]".into())
        })?;
    let reveal = remaining.contains(&"--reveal");

    let (resolved_env, _config) = resolve_env_from_flag(env_input, project_dir)?;

    let value = match &resolved_env {
        Some(env) => lpm_vault::try_get_env(project_dir, env, key),
        None => lpm_vault::try_get(project_dir, key),
    };
    let value = value.map_err(LpmError::Script)?;

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
    Ok(())
}

pub(super) fn env_list(
    args: &[&str],
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
    let (env_input, remaining) = parse_env_flag(args)?;
    let reveal = remaining.contains(&"--reveal");
    let (resolved_env, _config) = resolve_env_from_flag(env_input, project_dir)?;
    vars_list(project_dir, resolved_env.as_deref(), reveal, json_output)?;
    Ok(())
}

pub(super) fn env_delete(
    args: &[&str],
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
    let (env_input, remaining) = parse_env_flag(args)?;
    let keys: Vec<&str> = remaining.to_vec();

    if keys.is_empty() {
        return Err(LpmError::Script(
            "usage: lpm env delete [--env=<name>] KEY [KEY2 ...]".into(),
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
    Ok(())
}

pub(super) fn env_import(
    args: &[&str],
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
    let (env_input, remaining) = parse_env_flag(args)?;
    let file = remaining
        .iter()
        .find(|a| **a != "--overwrite")
        .ok_or_else(|| {
            LpmError::Script("usage: lpm env import [--env=<name>] <file> [--overwrite]".into())
        })?;
    let overwrite = remaining.contains(&"--overwrite");
    let path = project_dir.join(file);

    let (resolved_env, _config) = resolve_env_from_flag(env_input, project_dir)?;
    let env_label = resolved_env.as_deref().unwrap_or("default");

    let count = match &resolved_env {
        Some(env) => lpm_vault::import_env_file_to_env(project_dir, env, &path, overwrite)
            .map_err(LpmError::Script)?,
        None => {
            lpm_vault::import_env_file(project_dir, &path, overwrite).map_err(LpmError::Script)?
        }
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
    Ok(())
}

pub(super) fn env_export(
    args: &[&str],
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
    let (env_input, remaining) = parse_env_flag(args)?;
    let file = remaining
        .first()
        .ok_or_else(|| LpmError::Script("usage: lpm env export [--env=<name>] <file>".into()))?;
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
    Ok(())
}

/// Parse `--env=<name>` or `--env <name>` from args, returning the env value
/// and the remaining args with the flag stripped.
///
/// Returns `Err` if `--env` is present but has no value (bare trailing `--env`).
pub(super) fn parse_env_flag<'a>(
    args: &'a [&'a str],
) -> Result<(Option<&'a str>, Vec<&'a str>), LpmError> {
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
pub(super) fn resolve_env_from_flag(
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

pub(super) fn vars_list(
    project_dir: &std::path::Path,
    env_name: Option<&str>,
    reveal: bool,
    json_output: bool,
) -> Result<(), LpmError> {
    let secrets = match env_name {
        Some(env) => lpm_vault::try_get_all_env(project_dir, env),
        None => lpm_vault::try_get_all(project_dir),
    };
    let secrets = secrets.map_err(LpmError::Script)?;
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
        println!("  Run {} to add one", "lpm env set KEY=VALUE".cyan());
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
