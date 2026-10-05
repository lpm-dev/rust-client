use std::collections::HashSet;
use std::path::Path;

use lpm_common::LpmError;

use crate::install_ui;

pub(super) enum CiEnvDestination<'a> {
    Stdout,
    DotenvFile(&'a str),
}

pub(super) fn emit_project_env_for_ci(
    project_dir: &Path,
    env_mode: Option<&str>,
    destination: CiEnvDestination<'_>,
    json_output: bool,
) -> Result<(), LpmError> {
    let format = match destination {
        CiEnvDestination::Stdout => detect_ci_format(),
        CiEnvDestination::DotenvFile(_) => lpm_env::PrintFormat::Dotenv,
    };
    let (resolved_env, config) = super::local::resolve_env_from_flag(env_mode, project_dir)?;
    let env_vars = lpm_runner::dotenv::load_project_env_with_config_and_context(
        project_dir,
        env_mode,
        config.as_ref(),
        lpm_env::EnvStage::Ci,
        None,
    )?;
    let secret_keys: HashSet<String> = config
        .as_ref()
        .and_then(|config| config.env_schema.as_ref())
        .map(|schema| {
            schema
                .vars
                .iter()
                .filter_map(|(key, rule)| rule.secret.then_some(key.clone()))
                .collect()
        })
        .unwrap_or_default();
    let output = lpm_env::format_env(&env_vars, format, &secret_keys);

    match destination {
        CiEnvDestination::Stdout => {
            println!("{output}");
            install_ui::done_untrusted(&format!(
                "Emitted {} environment variables for {}",
                env_vars.len(),
                ci_format_label(format)
            ));
        }
        CiEnvDestination::DotenvFile(file) => {
            lpm_common::write_file_atomic_with_options(
                &project_dir.join(file),
                output.as_bytes(),
                lpm_common::AtomicWriteOptions::new()
                    .unix_mode(0o600)
                    .sync_file(),
            )
            .map_err(|e| LpmError::Script(format!("failed to write {file}: {e}")))?;
            if json_output {
                println!(
                    "{}",
                    serde_json::json!({"success":true, "exported":env_vars.len(), "to":file, "env":resolved_env.as_deref().unwrap_or("default")})
                );
                return Ok(());
            }
            install_ui::done_line(crate::install_ui::terminal_line!(
                "Wrote {} vars to {}",
                install_ui::status_ok(&env_vars.len().to_string()),
                install_ui::cyan(file)
            ));
        }
    }

    Ok(())
}

fn ci_format_label(format: lpm_env::PrintFormat) -> &'static str {
    match format {
        lpm_env::PrintFormat::GithubActions => "GitHub Actions",
        lpm_env::PrintFormat::Dotenv => "dotenv",
        _ => "generic CI",
    }
}

fn detect_ci_format() -> lpm_env::PrintFormat {
    if std::env::var("GITHUB_ACTIONS").is_ok() {
        lpm_env::PrintFormat::GithubActions
    } else if std::env::var("VERCEL").is_ok() {
        lpm_env::PrintFormat::Dotenv
    } else {
        lpm_env::PrintFormat::Shell
    }
}
