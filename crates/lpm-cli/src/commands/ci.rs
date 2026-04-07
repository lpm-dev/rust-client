//! CI/CD helpers for LPM.
//!
//! - `lpm ci env` — output env vars in CI-native format (auto-detects platform)
//! - `lpm ci setup github-actions` — generate OIDC workflow YAML

use lpm_common::LpmError;
use owo_colors::OwoColorize;
use std::path::Path;

/// Entry point for `lpm ci <action>`.
pub async fn run(
    action: &str,
    args: &[&str],
    project_dir: &Path,
    json_output: bool,
) -> Result<(), LpmError> {
    match action {
        "env" => ci_env(args, project_dir, json_output),
        "setup" => ci_setup(args, project_dir),
        _ => Err(LpmError::Script(format!(
            "unknown ci action: '{action}'. Available: env, setup"
        ))),
    }
}

/// `lpm ci env [--env=<mode>] [--output=<file>]`
///
/// Auto-detects CI platform and outputs env vars in the correct format.
fn ci_env(args: &[&str], project_dir: &Path, _json_output: bool) -> Result<(), LpmError> {
    let mut env_mode: Option<&str> = None;
    let mut output_file: Option<&str> = None;

    for arg in args {
        if let Some(v) = arg.strip_prefix("--env=") {
            env_mode = Some(v);
        } else if let Some(v) = arg.strip_prefix("--output=") {
            output_file = Some(v);
        }
    }

    // Auto-detect CI platform
    let format = detect_ci_format();

    // Load resolved env vars
    let env_vars = lpm_runner::dotenv::load_project_env(project_dir, env_mode)?;

    // Read schema for secret detection
    let config = lpm_runner::lpm_json::read_lpm_json(project_dir)
        .ok()
        .flatten();
    let secret_keys: std::collections::HashSet<String> = config
        .as_ref()
        .and_then(|c| c.env_schema.as_ref())
        .map(|s| {
            s.vars
                .iter()
                .filter(|(_, rule)| rule.secret)
                .map(|(k, _)| k.clone())
                .collect()
        })
        .unwrap_or_default();

    let output = lpm_env::format_env(&env_vars, format, &secret_keys);

    if let Some(file) = output_file {
        // Write to file (dotenv format for --output)
        let dotenv_output =
            lpm_env::format_env(&env_vars, lpm_env::PrintFormat::Dotenv, &secret_keys);
        std::fs::write(file, &dotenv_output)
            .map_err(|e| LpmError::Script(format!("failed to write {file}: {e}")))?;
        eprintln!("  {} wrote {} vars to {file}", "✓".green(), env_vars.len());
    } else {
        // Print to stdout in CI-native format
        println!("{output}");
    }

    Ok(())
}

/// Auto-detect CI platform from environment variables.
fn detect_ci_format() -> lpm_env::PrintFormat {
    if std::env::var("GITHUB_ACTIONS").is_ok() {
        lpm_env::PrintFormat::GithubActions
    } else if std::env::var("VERCEL").is_ok() {
        lpm_env::PrintFormat::Dotenv
    } else {
        // GitLab CI, CircleCI, and all others: use shell export format
        lpm_env::PrintFormat::Shell
    }
}

/// `lpm ci setup <platform> [--env=<mode>]`
///
/// Generate CI workflow boilerplate for OIDC-based vault access.
fn ci_setup(args: &[&str], project_dir: &Path) -> Result<(), LpmError> {
    let platform = args.first().ok_or_else(|| {
        LpmError::Script("usage: lpm ci setup <platform>. Available: github-actions".into())
    })?;

    let mut env_mode = "production";
    for arg in args {
        if let Some(v) = arg.strip_prefix("--env=") {
            env_mode = v;
        }
    }

    match *platform {
        "github-actions" | "github" | "gha" => setup_github_actions(project_dir, env_mode),
        "gitlab" | "gitlab-ci" => setup_gitlab_ci(env_mode),
        _ => Err(LpmError::Script(format!(
            "unknown CI platform: '{platform}'. Available: github-actions, gitlab"
        ))),
    }
}

fn setup_github_actions(project_dir: &Path, env_mode: &str) -> Result<(), LpmError> {
    let vault_id = lpm_vault::vault_id::read_vault_id(project_dir)
        .unwrap_or_else(|| "<your-vault-id>".to_string());

    println!();
    println!("  {} GitHub Actions OIDC Setup", "▸".bold());
    println!();
    println!(
        "  {} Add this to your workflow (.github/workflows/deploy.yml):",
        "1.".bold()
    );
    println!();
    println!(
        "  {}",
        "jobs:
    deploy:
      permissions:
        id-token: write
        contents: read
      steps:
        - uses: actions/checkout@v4
        - name: Install LPM
          run: npm install -g @lpm-registry/cli
        - name: Load secrets from vault
          run: lpm use vars pull --oidc --env={ENV} --output=.env
          env:
            LPM_VAULT_ID: {VAULT_ID}
        - name: Deploy
          run: lpm exec -- ./deploy.sh"
            .replace("{ENV}", env_mode)
            .replace("{VAULT_ID}", &vault_id)
            .dimmed()
    );
    println!();
    println!("  {} Authorize this repo:", "2.".bold());
    println!();
    println!(
        "  {}",
        format!(
            "lpm use vars oidc allow --provider=github --repo=<owner/repo> --branch=main --env={env_mode}"
        )
        .bold()
    );
    println!();

    Ok(())
}

fn setup_gitlab_ci(env_mode: &str) -> Result<(), LpmError> {
    println!();
    println!("  {} GitLab CI OIDC Setup", "▸".bold());
    println!();
    println!("  {} Add this to .gitlab-ci.yml:", "1.".bold());
    println!();
    println!(
        "  {}",
        "deploy:
  id_tokens:
    LPM_OIDC_TOKEN:
      aud: https://lpm.dev
  script:
    - npm install -g @lpm-registry/cli
    - lpm use vars pull --oidc --env={ENV} --output=.env
    - lpm exec -- ./deploy.sh"
            .replace("{ENV}", env_mode)
            .dimmed()
    );
    println!();
    println!("  {} Authorize this project:", "2.".bold());
    println!();
    println!(
        "  {}",
        format!(
            "lpm use vars oidc allow --provider=gitlab --repo=<project-path> --branch=main --env={env_mode}"
        )
        .bold()
    );
    println!();

    Ok(())
}
