use super::prelude::*;

pub(super) fn env_set(
    env_input: Option<&str>,
    assignments: &[String],
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
    let pairs: Vec<(&str, &str)> = assignments
        .iter()
        .map(|arg| {
            let pair = arg
                .split_once('=')
                .ok_or_else(|| LpmError::Script("expected KEY=VALUE".into()))?;
            if !lpm_env::is_valid_env_var_name(pair.0) {
                return Err(LpmError::Script(
                    "env keys must match [A-Za-z_][A-Za-z0-9_]*".into(),
                ));
            }
            Ok(pair)
        })
        .collect::<Result<_, _>>()?;

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
            output::success_line(install_ui::terminal_line!(
                "stored {} ({})",
                install_ui::bold(key),
                env_label,
            ));
        }
    }
    Ok(())
}

pub(super) fn env_get(
    env_input: Option<&str>,
    key: &str,
    reveal: bool,
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
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
                    println!("{}", serde_json::json!({"success": true, key: value}));
                } else {
                    println!("{}", serde_json::json!({"success": true, key: "••••••••"}));
                }
            } else if reveal {
                println!("{value}");
            } else {
                println!(
                    "{}",
                    install_ui::terminal_line!(
                        "{} = {}",
                        install_ui::bold(key),
                        install_ui::dim("••••••••"),
                    )
                );
            }
        }
        None => {
            return Err(LpmError::Script(format!("secret '{key}' not found")));
        }
    }
    Ok(())
}

pub(super) fn env_list(
    env_input: Option<&str>,
    reveal: bool,
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
    let (resolved_env, _config) = resolve_env_from_flag(env_input, project_dir)?;
    vars_list(project_dir, resolved_env.as_deref(), reveal, json_output)?;
    Ok(())
}

pub(super) fn env_delete(
    env_input: Option<&str>,
    keys: &[String],
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
    let keys: Vec<&str> = keys.iter().map(String::as_str).collect();
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
            output::success_line(install_ui::terminal_line!(
                "deleted {} ({})",
                install_ui::bold(key),
                env_label,
            ));
        }
    }
    Ok(())
}

pub(super) fn env_import(
    env_input: Option<&str>,
    file: &str,
    overwrite: bool,
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
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
            serde_json::json!({"success": true, "imported": count, "from": file, "env": env_label})
        );
    } else {
        output::success_line(install_ui::terminal_line!(
            "imported {} secret{} from {} ({})",
            install_ui::bold(&count.to_string()),
            if count == 1 { "" } else { "s" },
            install_ui::cyan(file),
            env_label,
        ));
    }
    Ok(())
}

pub(super) fn env_export(
    env_input: Option<&str>,
    file: &str,
    ci: bool,
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
    if ci {
        return super::ci::emit_project_env_for_ci(
            project_dir,
            env_input,
            super::ci::CiEnvDestination::DotenvFile(file),
            json_output,
        );
    }
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
            serde_json::json!({"success": true, "exported": count, "to": file, "env": env_label})
        );
    } else {
        output::success_line(install_ui::terminal_line!(
            "exported {} secret{} to {} ({})",
            install_ui::bold(&count.to_string()),
            if count == 1 { "" } else { "s" },
            install_ui::cyan(file),
            env_label,
        ));
    }
    Ok(())
}

/// Resolve an `--env` flag value to a canonical env name.
///
/// Returns `Err` if the flag was provided but the value is invalid.
/// Returns `Ok(None)` if no `--env` flag was provided (use default).
pub(super) fn resolve_env_from_flag(
    env_input: Option<&str>,
    project_dir: &std::path::Path,
) -> Result<(Option<String>, Option<lpm_runner::lpm_json::LpmJsonConfig>), LpmError> {
    let config = lpm_runner::lpm_json::read_lpm_json(project_dir).map_err(LpmError::Script)?;
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
                println!(
                    "{}",
                    install_ui::terminal_line!("  {} = {}", install_ui::bold(key), &secrets[key],)
                );
            } else {
                println!(
                    "{}",
                    install_ui::terminal_line!(
                        "  {} = {}",
                        install_ui::bold(key),
                        install_ui::dim("••••••••"),
                    )
                );
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::resolve_env_from_flag;

    #[test]
    fn resolve_named_environment_rejects_malformed_lpm_json() {
        let project = tempfile::tempdir().expect("create temporary project");
        std::fs::write(
            project.path().join("lpm.json"),
            r#"{"env":{"prod":"production"}"#,
        )
        .expect("write malformed lpm.json");

        let result = resolve_env_from_flag(Some("prod"), project.path());

        assert!(
            result.is_err(),
            "named environment resolution must preserve lpm.json parse failures"
        );
    }
}
