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
) -> Result<(), LpmError> {
    let format = match destination {
        CiEnvDestination::Stdout => detect_ci_format(),
        CiEnvDestination::DotenvFile(_) => lpm_env::PrintFormat::Dotenv,
    };
    let env_vars = lpm_runner::dotenv::load_project_env(project_dir, env_mode)?;
    let secret_keys = secret_keys(project_dir);
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
            std::fs::write(file, &output)
                .map_err(|e| LpmError::Script(format!("failed to write {file}: {e}")))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Err(e) =
                    std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o600))
                {
                    tracing::warn!(
                        path = %file,
                        error = %e,
                        "failed to set 0o600 on ci env output file; secrets may be readable by other local uids",
                    );
                }
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

fn secret_keys(project_dir: &Path) -> HashSet<String> {
    lpm_runner::lpm_json::read_lpm_json(project_dir)
        .ok()
        .flatten()
        .and_then(|config| config.env_schema)
        .map(|schema| {
            schema
                .vars
                .into_iter()
                .filter_map(|(key, rule)| rule.secret.then_some(key))
                .collect()
        })
        .unwrap_or_default()
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
