use super::github::{github_api_url, validate_repository, validate_repository_id};
use super::prelude::*;

const GITHUB_API_VERSION: &str = "2022-11-28";
const GITHUB_OIDC_USER_AGENT: &str = "lpm-env-oidc";
const OIDC_POLICY_ID_ENV: &str = "LPM_OIDC_POLICY_ID";

struct GitHubRepositoryIdentity {
    id: String,
    full_name: String,
}

#[derive(serde::Deserialize)]
struct GitHubRepositoryResponse {
    id: u64,
    full_name: String,
}

fn normalize_oidc_policy_id(value: &str) -> Option<String> {
    let normalized = value.trim().to_ascii_lowercase();
    let bytes = normalized.as_bytes();
    if bytes.len() != 36
        || bytes[8] != b'-'
        || bytes[13] != b'-'
        || bytes[18] != b'-'
        || bytes[23] != b'-'
        || bytes[14] != b'4'
        || !matches!(bytes[19], b'8' | b'9' | b'a' | b'b')
    {
        return None;
    }
    if bytes
        .iter()
        .enumerate()
        .any(|(index, byte)| !matches!(index, 8 | 13 | 18 | 23) && !byte.is_ascii_hexdigit())
    {
        return None;
    }
    Some(normalized)
}

fn resolve_oidc_policy_id(explicit: Option<&str>) -> Result<String, LpmError> {
    let value = if let Some(value) = explicit {
        value.to_string()
    } else {
        match std::env::var(OIDC_POLICY_ID_ENV) {
            Ok(value) => value,
            Err(std::env::VarError::NotPresent) => {
                return Err(LpmError::Script(format!(
                    "OIDC policy selection is required. Set {OIDC_POLICY_ID_ENV} to the policy ID \
                     returned by `lpm env oidc allow`, or pass --policy-id=<uuid>."
                )));
            }
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err(LpmError::Script(format!(
                    "{OIDC_POLICY_ID_ENV} must contain a UTF-8 server-issued UUID."
                )));
            }
        }
    };
    normalize_oidc_policy_id(&value).ok_or_else(|| {
        LpmError::Script(format!(
            "OIDC policy ID must be a server-issued UUID. Check {OIDC_POLICY_ID_ENV}, \
             --policy-id, or run `lpm env oidc list`."
        ))
    })
}

fn policy_id_from_response(result: &serde_json::Value) -> Result<String, LpmError> {
    result["policyId"]
        .as_str()
        .and_then(normalize_oidc_policy_id)
        .ok_or_else(|| {
            LpmError::Script(
                "the server did not return a valid OIDC policy ID. The policy may have been \
                 created, but CI cannot select it safely. Run `lpm env oidc list` to recover \
                 the policy ID before enabling CI pulls."
                    .into(),
            )
        })
}

/// `lpm env oidc allow --provider=github --repo=owner/repo --workflow=.github/workflows/deploy.yml --branch=main --env=production [--events=push,workflow_dispatch] [--allow-forks]`
pub(super) async fn vars_oidc(
    client: &lpm_registry::RegistryClient,
    args: &[&str],
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
    if args.is_empty() {
        return Err(LpmError::Script(
            "usage: lpm env oidc allow --provider=github --repo=<owner/repo> \
             --workflow=.github/workflows/<file>.yml --branch=<branch> --env=<env> \
             [--events=push,workflow_dispatch] [--allow-forks]"
                .into(),
        ));
    }

    match args[0] {
        "--help" | "-h" => {
            print_oidc_help();
            Ok(())
        }
        "allow" if args[1..].iter().any(|arg| matches!(*arg, "--help" | "-h")) => {
            print_oidc_allow_help();
            Ok(())
        }
        "allow" => vars_oidc_allow(client, &args[1..], project_dir, json_output).await,
        "list" => vars_oidc_list(client, project_dir, json_output).await,
        unknown => Err(LpmError::Script(format!(
            "unknown oidc action: '{unknown}'. Available: allow, list"
        ))),
    }
}

fn print_oidc_help() {
    println!(
        "Usage:\n  lpm env oidc allow [OPTIONS]\n  lpm env oidc list\n\n\
         Run `lpm env oidc allow --help` before updating an existing policy."
    );
}

fn print_oidc_allow_help() {
    println!(
        r#"Usage:
  lpm env oidc allow --provider=github --repo=<owner/repo> [--repository-id=<numeric-id>] --workflow=.github/workflows/<file>.yml --branch=<list> --env=<list> [--events=<list>] [--allow-forks]

  lpm env oidc allow --provider=gitlab --project-id=<numeric-project-id> --branch=<list> --env=<list>

The CLI looks up the immutable ID for a public GitHub repository. For a private repository, set GITHUB_TOKEN or GH_TOKEN, or pass --repository-id.

This command replaces the policy's complete allowlists. Run `lpm env oidc list` first, then supply every branch, environment, workflow, and event that should remain allowed."#
    );
}

/// `lpm env oidc allow --provider=github --repo=owner/repo --workflow=.github/workflows/deploy.yml --branch=main --env=production`
pub(super) async fn vars_oidc_allow(
    registry_client: &lpm_registry::RegistryClient,
    args: &[&str],
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
    let mut provider = "github";
    let mut repo: Option<&str> = None;
    let mut repository_id: Option<&str> = None;
    let mut project_id: Option<&str> = None;
    let mut branches: Vec<String> = vec!["main".to_string()];
    let mut envs: Vec<String> = Vec::new();
    let mut workflows: Vec<String> = Vec::new();
    let mut events: Vec<String> = Vec::new();
    let mut events_supplied = false;
    let mut allow_forks = false;

    for arg in args {
        if let Some(v) = arg.strip_prefix("--provider=") {
            provider = v;
        } else if let Some(v) = arg.strip_prefix("--repo=") {
            repo = Some(v);
        } else if let Some(v) = arg.strip_prefix("--repository-id=") {
            repository_id = Some(v);
        } else if let Some(v) = arg.strip_prefix("--project-id=") {
            project_id = Some(v);
        } else if let Some(v) = arg.strip_prefix("--branch=") {
            branches = v.split(',').map(|s| s.trim().to_string()).collect();
        } else if let Some(v) = arg.strip_prefix("--env=") {
            envs = v.split(',').map(|s| s.trim().to_string()).collect();
        } else if let Some(v) = arg.strip_prefix("--workflow=") {
            workflows = v.split(',').map(|s| s.trim().to_string()).collect();
        } else if let Some(v) = arg.strip_prefix("--events=") {
            events = v.split(',').map(|s| s.trim().to_string()).collect();
            events_supplied = true;
        } else if *arg == "--allow-forks" {
            allow_forks = true;
        } else {
            return Err(LpmError::Script(format!(
                "unknown OIDC policy argument: {arg}"
            )));
        }
    }

    if envs.is_empty() {
        return Err(LpmError::Script(
            "missing --env flag; name at least one environment this policy may access".into(),
        ));
    }

    let (subject, identity_label, repository_id) = match provider {
        "github" => {
            if project_id.is_some() {
                return Err(LpmError::Script(
                    "--project-id applies only to GitLab OIDC policies".into(),
                ));
            }
            let repo = repo.ok_or_else(|| {
                LpmError::Script(
                    "missing --repo flag. Usage: lpm env oidc allow --provider=github \
                     --repo=owner/repo --workflow=.github/workflows/deploy.yml \
                     --branch=main --env=production"
                        .into(),
                )
            })?;
            validate_repository(repo, "--repo")?;
            if workflows.is_empty() {
                return Err(LpmError::Script(
                    "missing --workflow flag. GitHub policies require \
                     --workflow=.github/workflows/<file>.yml"
                        .into(),
                ));
            }
            for workflow in &workflows {
                let valid = workflow.starts_with(".github/workflows/")
                    && !workflow[".github/workflows/".len()..].contains('/')
                    && (workflow.ends_with(".yml") || workflow.ends_with(".yaml"));
                if !valid {
                    return Err(LpmError::Script(format!(
                        "workflow path '{workflow}' must be of the form \
                         `.github/workflows/<file>.yml`"
                    )));
                }
            }
            if !events_supplied {
                events.push("push".to_string());
            }
            let identity = resolve_github_repository_identity(repo, repository_id).await?;
            (
                format!("repo:{}", identity.full_name),
                format!("repository {}", identity.full_name),
                Some(identity.id),
            )
        }
        "gitlab" => {
            if repo.is_some()
                || repository_id.is_some()
                || !workflows.is_empty()
                || events_supplied
                || allow_forks
            {
                return Err(LpmError::Script(
                    "GitLab OIDC policies do not accept GitHub-only --repo, --repository-id, \
                     --workflow, --events, or --allow-forks flags"
                        .into(),
                ));
            }
            let project_id = project_id.ok_or_else(|| {
                LpmError::Script(
                    "missing --project-id flag. GitLab policies require the numeric project ID"
                        .into(),
                )
            })?;
            if project_id.starts_with('0')
                || project_id.is_empty()
                || !project_id.bytes().all(|byte| byte.is_ascii_digit())
            {
                return Err(LpmError::Script(
                    "--project-id must be a positive numeric GitLab project ID".into(),
                ));
            }
            (
                format!("project:{project_id}"),
                format!("project ID {project_id}"),
                None,
            )
        }
        unknown => {
            return Err(LpmError::Script(format!(
                "unsupported OIDC provider '{unknown}'; available providers: github, gitlab"
            )));
        }
    };

    if !envs.is_empty() {
        let config = lpm_runner::lpm_json::read_lpm_json(project_dir).map_err(LpmError::Script)?;
        let empty = std::collections::HashMap::new();
        let env_map = config.as_ref().map_or(&empty, |c| &c.env);
        let environments = config.as_ref().and_then(|c| c.environments.as_ref());

        let mut canonical_envs = Vec::with_capacity(envs.len());
        for input in &envs {
            match lpm_env::resolver::resolve_checked(input, env_map, environments) {
                Ok(resolved) => {
                    if resolved.canonical != *input && !json_output {
                        output::info(&format!(
                            "resolved \"{}\" → canonical \"{}\"",
                            input, resolved.canonical
                        ));
                    }
                    canonical_envs.push(resolved.canonical);
                }
                Err(e) => {
                    // Warn on unknown names, don't block — matches spec
                    if !json_output {
                        output::warn(&format!(
                            "\"{}\" is not a known environment name: {}. Storing as-is.",
                            input, e
                        ));
                    }
                    canonical_envs.push(input.clone());
                }
            }
        }
        envs = canonical_envs;
    }

    let vault_id =
        lpm_vault::vault_id::get_or_create_vault_id(project_dir).map_err(LpmError::Script)?;
    let mut policy_body = serde_json::json!({
        "vaultId": vault_id,
        "provider": provider,
        "subject": subject,
        "allowedBranches": branches,
        "allowedEnvironments": envs,
        "allowedWorkflows": workflows,
        "allowedEvents": events,
        "allowForks": allow_forks,
    });
    if let Some(repository_id) = &repository_id {
        policy_body["repositoryId"] = serde_json::Value::String(repository_id.clone());
    }
    let result = super::auth::execute_lpm_with_bearer(
        registry_client,
        lpm_auth::AuthRequirement::TokenRequired,
        |registry_url, auth_token| {
            let policy_body = policy_body.clone();
            async move { create_oidc_policy(&registry_url, &auth_token, &policy_body).await }
        },
    )
    .await?;
    let policy_id = policy_id_from_response(&result)?;

    let wrapping_key = lpm_vault::crypto::get_or_create_wrapping_key()
        .map_err(|error| oidc_escrow_setup_error("retrieving the local wrapping key", &error))?;
    let wrapping_key_hex = hex::encode(wrapping_key);
    super::auth::execute_sync_with_bearer(
        registry_client,
        lpm_auth::AuthRequirement::TokenRequired,
        |registry_url, auth_token| {
            let vault_id = vault_id.clone();
            let wrapping_key_hex = wrapping_key_hex.clone();
            async move {
                lpm_vault::sync::upload_escrow_key(
                    &registry_url,
                    &auth_token,
                    &vault_id,
                    &wrapping_key_hex,
                )
                .await
            }
        },
    )
    .await
    .map_err(|error| oidc_escrow_setup_error("uploading the wrapping key", &error.to_string()))?;

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&result).unwrap_or_default()
        );
    } else {
        let environment_label = envs.join(", ");
        if provider == "gitlab" {
            output::success_line(install_ui::terminal_line!(
                "OIDC policy set: gitlab {} on branches [{}] for envs [{}]",
                install_ui::bold(&identity_label),
                branches.join(", "),
                environment_label,
            ));
        } else {
            output::success_line(install_ui::terminal_line!(
                "OIDC policy set: github {} on branches [{}] for envs [{}] via workflows [{}] events [{}]",
                install_ui::bold(&identity_label),
                branches.join(", "),
                environment_label,
                workflows.join(", "),
                events.join(", "),
            ));
        }
        output::info("CI escrow enabled — secrets will be decrypted server-side for OIDC pulls");
        output::info(&format!("policy ID: {policy_id}"));
        if provider == "gitlab" {
            output::info(&format!(
                "Store {OIDC_POLICY_ID_ENV}={policy_id} as a GitLab CI/CD variable. Mark it protected only when every allowed ref is protected."
            ));
        } else {
            output::info(&format!(
                "Store {OIDC_POLICY_ID_ENV}={policy_id} as a GitHub Actions repository variable before running `lpm env pull --oidc`."
            ));
        }
    }

    Ok(())
}

async fn resolve_github_repository_identity(
    repository: &str,
    explicit_id: Option<&str>,
) -> Result<GitHubRepositoryIdentity, LpmError> {
    if let Some(repository_id) = explicit_id {
        validate_repository_id(repository_id)?;
        return Ok(GitHubRepositoryIdentity {
            id: repository_id.to_string(),
            full_name: repository.to_string(),
        });
    }

    let client = lpm_http::client_builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|error| {
            LpmError::Network(format!(
                "failed to build GitHub repository lookup client: {error}"
            ))
        })?;
    let mut request = client
        .get(format!(
            "{}/repos/{repository}",
            github_api_url()?.trim_end_matches('/')
        ))
        .header(reqwest::header::USER_AGENT, GITHUB_OIDC_USER_AGENT)
        .header(reqwest::header::ACCEPT, "application/vnd.github+json")
        .header("X-GitHub-Api-Version", GITHUB_API_VERSION);
    if let Some(token) = github_api_token() {
        request = request.bearer_auth(token);
    }
    let response = request.send().await.map_err(|error| {
        LpmError::Network(format!(
            "GitHub repository ID lookup failed: {}",
            lpm_http::display_error(&error)
        ))
    })?;
    let status = response.status();
    if !status.is_success() {
        let remediation = if matches!(status.as_u16(), 403 | 429) {
            "Set GITHUB_TOKEN or GH_TOKEN, or pass --repository-id=<numeric-id>."
        } else {
            "For a private repository, set GITHUB_TOKEN or GH_TOKEN, or pass --repository-id=<numeric-id>."
        };
        return Err(LpmError::Script(format!(
            "GitHub repository ID lookup for {repository} failed with HTTP {status}. {remediation}"
        )));
    }

    let response_identity: GitHubRepositoryResponse =
        super::response::parse_capped_platform_json(response).await?;
    let repository_id = response_identity.id.to_string();
    validate_repository_id(&repository_id)?;
    validate_repository(&response_identity.full_name, "GitHub repository name")?;
    if !response_identity.full_name.eq_ignore_ascii_case(repository) {
        return Err(LpmError::Script(format!(
            "GitHub returned repository {} while {repository} was requested",
            response_identity.full_name
        )));
    }
    Ok(GitHubRepositoryIdentity {
        id: repository_id,
        full_name: response_identity.full_name,
    })
}

fn github_api_token() -> Option<String> {
    ["GITHUB_TOKEN", "GH_TOKEN"].into_iter().find_map(|name| {
        std::env::var(name)
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    })
}

fn oidc_escrow_setup_error(step: &str, error: &str) -> LpmError {
    LpmError::Script(format!(
        "OIDC policy may already have been created, but CI pulls are not ready because escrow \
         setup failed while {step}: {error}. Fix the escrow problem, then rerun the same \
         `lpm env oidc allow` command; rerunning safely updates the existing policy."
    ))
}

async fn parse_authenticated_oidc_response(
    response: reqwest::Response,
) -> Result<serde_json::Value, LpmError> {
    let status = response.status();
    if !status.is_success() {
        let body: serde_json::Value =
            super::response::parse_capped_platform_json_or_unknown(response).await;
        if status == reqwest::StatusCode::UNAUTHORIZED {
            return Err(LpmError::AuthRequired);
        }
        return Err(LpmError::Script(
            body["error"].as_str().unwrap_or("failed").to_string(),
        ));
    }
    super::response::parse_capped_platform_json(response).await
}

async fn create_oidc_policy(
    registry_url: &str,
    auth_token: &str,
    policy_body: &serde_json::Value,
) -> Result<serde_json::Value, LpmError> {
    let client = lpm_http::client_builder()
        .build()
        .map_err(|error| LpmError::Network(format!("failed to build HTTP client: {error}")))?;
    let response = client
        .post(format!("{registry_url}/api/vault/oidc/policies"))
        .bearer_auth(auth_token)
        .json(policy_body)
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|error| {
            LpmError::Network(format!(
                "failed to reach server: {}",
                lpm_http::display_error(&error)
            ))
        })?;
    parse_authenticated_oidc_response(response).await
}

async fn list_oidc_policies(
    registry_url: &str,
    auth_token: &str,
    vault_id: &str,
) -> Result<serde_json::Value, LpmError> {
    let client = lpm_http::client_builder()
        .build()
        .map_err(|error| LpmError::Network(format!("failed to build HTTP client: {error}")))?;
    let response = client
        .get(format!(
            "{registry_url}/api/vault/oidc/policies?vaultId={vault_id}"
        ))
        .bearer_auth(auth_token)
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|error| {
            LpmError::Network(format!(
                "failed to reach server: {}",
                lpm_http::display_error(&error)
            ))
        })?;
    parse_authenticated_oidc_response(response).await
}

/// `lpm env oidc list`
pub(super) async fn vars_oidc_list(
    registry_client: &lpm_registry::RegistryClient,
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
    let vault_id = lpm_vault::vault_id::read_vault_id(project_dir)
        .ok_or_else(|| LpmError::Script("no vault configured".into()))?;
    let result = super::auth::execute_lpm_with_bearer(
        registry_client,
        lpm_auth::AuthRequirement::TokenRequired,
        |registry_url, auth_token| {
            let vault_id = vault_id.clone();
            async move { list_oidc_policies(&registry_url, &auth_token, &vault_id).await }
        },
    )
    .await?;
    let policies = result["policies"]
        .as_array()
        .ok_or_else(|| LpmError::Script("invalid OIDC policy list response".into()))?;
    let policy_ids = policies
        .iter()
        .map(policy_id_from_response_for_list)
        .collect::<Result<Vec<_>, _>>()?;

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&result).unwrap_or_default()
        );
        return Ok(());
    }

    if policies.is_empty() {
        output::warn("no OIDC policies configured. Run 'lpm env oidc allow' to add one.");
        return Ok(());
    }

    println!();
    // Render a JSON array field as a comma-joined string. Empty array
    // or missing field collapses to an empty string; the display logic
    // below replaces empty with `"-"` rather than `"all"` so a policy
    // that's missing required fields doesn't read as "wide-open."
    fn render_strings(field: &serde_json::Value) -> String {
        field
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default()
    }
    for (policy, policy_id) in policies.iter().zip(&policy_ids) {
        let provider = policy["provider"].as_str().unwrap_or("?");
        let subject = policy["subject"].as_str().unwrap_or("?");
        let identity = match (provider, policy["repositoryId"].as_str()) {
            ("github", Some(id)) => format!("{subject} (repository ID {id})"),
            ("github", None) => format!("{subject} (repository ID missing, update required)"),
            _ => subject.to_string(),
        };
        let branches = render_strings(&policy["allowedBranches"]);
        let envs = render_strings(&policy["allowedEnvironments"]);
        let workflows = render_strings(&policy["allowedWorkflows"]);
        let events = render_strings(&policy["allowedEvents"]);
        let forks = policy["allowForks"].as_bool().unwrap_or(false);

        let bb = if branches.is_empty() { "-" } else { &branches };
        let ee = if envs.is_empty() { "-" } else { &envs };
        let ww = if workflows.is_empty() {
            "-"
        } else {
            &workflows
        };
        let ev = if events.is_empty() { "-" } else { &events };
        println!(
            "{}",
            install_ui::terminal_line!(
                "  {} {}\n      policy ID: {}\n      branches:  [{}]\n      envs:      [{}]\n      workflows: [{}]\n      events:    [{}]{}",
                install_ui::bold(provider),
                identity,
                policy_id,
                bb,
                ee,
                ww,
                ev,
                if forks {
                    "\n      forks:     allowed"
                } else {
                    ""
                },
            )
        );
    }
    println!();

    Ok(())
}

fn policy_id_from_response_for_list(policy: &serde_json::Value) -> Result<String, LpmError> {
    policy["id"]
        .as_str()
        .and_then(normalize_oidc_policy_id)
        .ok_or_else(|| {
            LpmError::Script(
                "the server returned an OIDC policy without a valid policy ID; rerun the command after the Registry is updated"
                    .into(),
            )
        })
}

/// `lpm env pull --oidc [--policy-id=<uuid>] [--env=<mode>] [--output=<file>]`
///
/// Exchange CI OIDC token for a short-lived LPM token, then pull vault secrets.
pub(super) async fn vars_oidc_pull(
    registry_client: &lpm_registry::RegistryClient,
    args: &[&str],
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
    let vault_id = resolve_oidc_pull_vault_id(project_dir)?;

    let registry_url = registry_client.base_url().to_owned();

    let mut env_mode: Option<&str> = None;
    let mut output_file: Option<&str> = None;
    let mut explicit_policy_id: Option<&str> = None;

    for arg in args {
        if *arg == "--oidc" {
            continue;
        } else if let Some(v) = arg.strip_prefix("--env=") {
            env_mode = Some(v);
        } else if let Some(v) = arg.strip_prefix("--output=") {
            output_file = Some(v);
        } else if let Some(v) = arg.strip_prefix("--policy-id=") {
            if explicit_policy_id.replace(v).is_some() {
                return Err(LpmError::Script(
                    "--policy-id may be supplied only once".into(),
                ));
            }
        } else {
            return Err(LpmError::Script(format!(
                "unknown OIDC pull argument: {arg}"
            )));
        }
    }
    let policy_id = resolve_oidc_policy_id(explicit_policy_id)?;

    // Get OIDC token from CI environment
    let oidc_token = get_ci_oidc_token().await?;

    // Exchange OIDC token for short-lived LPM token
    let client = lpm_http::client_builder()
        .build()
        .map_err(|error| LpmError::Network(format!("failed to build HTTP client: {error}")))?;
    let exchange_response = client
        .post(format!("{registry_url}/api/vault/oidc"))
        .json(&serde_json::json!({
            "oidcToken": oidc_token,
            "vaultId": vault_id,
            "env": env_mode,
            "policyId": policy_id,
        }))
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|error| {
            LpmError::Network(format!(
                "OIDC exchange failed: {}",
                lpm_http::display_error(&error)
            ))
        })?;

    if !exchange_response.status().is_success() {
        let body: serde_json::Value =
            super::response::parse_capped_platform_json_or_unknown(exchange_response).await;
        let error = body["error"].as_str().unwrap_or("OIDC exchange failed");
        let hint = body["hint"].as_str().unwrap_or("");
        let code = body["code"].as_str().unwrap_or("");
        return Err(LpmError::Script(build_oidc_pull_error_message(
            error, hint, code,
        )));
    }

    let exchange_result: serde_json::Value =
        super::response::parse_capped_platform_json(exchange_response).await?;

    let lpm_token = exchange_result["token"]
        .as_str()
        .ok_or_else(|| LpmError::Script("missing token in OIDC response".into()))?;

    // Pull via CI escrow — server decrypts and returns plaintext secrets
    let (vars, env_name) = lpm_vault::sync::ci_pull(&registry_url, lpm_token, &vault_id, env_mode)
        .await
        .map_err(LpmError::Script)?;

    if let Some(file) = output_file {
        // Write .env file with KEY=VALUE pairs
        let mut content =
            format!("# LPM vault secrets (env: {env_name})\n# Pulled via OIDC CI escrow\n");
        let mut keys: Vec<&String> = vars.keys().collect();
        keys.sort();
        for key in &keys {
            let value = &vars[*key];
            // Quote values that contain spaces, newlines, or special chars
            if value.contains(' ')
                || value.contains('\n')
                || value.contains('#')
                || value.contains('"')
            {
                let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
                content.push_str(&format!("{key}=\"{escaped}\"\n"));
            } else {
                content.push_str(&format!("{key}={value}\n"));
            }
        }

        std::fs::write(file, &content)
            .map_err(|e| LpmError::Script(format!("failed to write {file}: {e}")))?;

        // Restrict to owner-only on Unix. The default umask leaves
        // dotenv files at 0o644 on most distros, which means any
        // concurrent CI build step running as a different uid
        // (sidecar containers, sibling daemons, shared runners) can
        // read the plaintext secrets escrowed here. Best-effort: on
        // filesystems without POSIX modes the chmod is a no-op, but
        // the call is still cheap and the failure path is just a
        // tracing::warn — never blocks the user's pipeline.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            if let Err(e) = std::fs::set_permissions(file, perms) {
                tracing::warn!(
                    path = %file,
                    error = %e,
                    "failed to set 0o600 on env-pull dotenv file; secret may be readable by other local uids",
                );
            }
        }

        if !json_output {
            output::success_line(install_ui::terminal_line!(
                "wrote {} secret{} to {} (env: {})",
                install_ui::bold(&keys.len().to_string()),
                if keys.len() == 1 { "" } else { "s" },
                file,
                env_name,
            ));
        }
    } else if json_output {
        println!(
            "{}",
            serde_json::json!({ "env": env_name, "vars": vars, "count": vars.len() })
        );
    } else {
        output::success_line(install_ui::terminal_line!(
            "pulled {} secret{} via OIDC (env: {})",
            install_ui::bold(&vars.len().to_string()),
            if vars.len() == 1 { "" } else { "s" },
            env_name,
        ));
    }

    Ok(())
}

fn resolve_oidc_pull_vault_id(project_dir: &std::path::Path) -> Result<String, LpmError> {
    if let Ok(value) = std::env::var("LPM_VAULT_ID") {
        let vault_id = value.trim();
        if !vault_id.is_empty() {
            if !lpm_vault::vault_id::is_safe_vault_id(vault_id) {
                return Err(LpmError::Script(
                    "LPM_VAULT_ID is unsafe; use a vault ID without path separators, control \
                     characters, or path-traversal components."
                        .into(),
                ));
            }
            return Ok(vault_id.to_owned());
        }
    }

    lpm_vault::vault_id::read_vault_id(project_dir).ok_or_else(|| {
        LpmError::Script(
            "no vault configured. Set a non-empty LPM_VAULT_ID or add `vault` to lpm.json".into(),
        )
    })
}

/// Get the OIDC token from the CI environment for the env-vault flow.
///
/// Audience is `https://lpm.dev` (the vault verifier rejects anything else),
/// so this routes through the shared registry-exchange resolver. Honors
/// `LPM_OIDC_TOKEN` (canonical), GitHub Actions runtime, and the legacy
/// `LPM_GITLAB_OIDC_TOKEN` alias.
async fn get_ci_oidc_token() -> Result<String, LpmError> {
    crate::oidc::resolve_registry_exchange_jwt()
        .await
        .map_err(|e| LpmError::Script(format!("{e}")))
}

/// Map a server-side error response from `POST /api/vault/oidc` to a
/// user-facing message with a code-specific remediation hint appended.
///
/// The mint endpoint returns a stable machine-readable `code` on
/// every 403/429; this CLI maps each code to an actionable next
/// step so CI logs surface "what to do" rather than just "what failed."
///
/// Precedence:
///   1. If the server sent a `hint` field, use it verbatim.
///   2. Else if the code matches a known taxonomy entry, use the
///      CLI-side mapping.
///   3. Else emit just the server's `error` string.
fn build_oidc_pull_error_message(error: &str, hint: &str, code: &str) -> String {
    let code_hint = match code {
        "policy_not_found" => Some(
            "No OIDC policy matches this selector and CI identity. Verify \
             LPM_OIDC_POLICY_ID with `lpm env oidc list`, or create a policy with \
             `lpm env oidc allow`.",
        ),
        "policy_selector_required" | "policy_selector_invalid" | "policy_ambiguous" => Some(
            "Set LPM_OIDC_POLICY_ID to the policy ID shown by `lpm env oidc allow` or \
             `lpm env oidc list`, or pass --policy-id=<uuid>.",
        ),
        "policy_misconfigured" => Some(
            "The OIDC policy exists but is missing required fields (likely a pre-migration \
             row). Open the dashboard at <registry>/dashboard/vaults to update it.",
        ),
        "branch_not_allowed" => Some(
            "The branch claim from your CI's OIDC token isn't in the policy's allowedBranches. \
             Inspect the complete policy with `lpm env oidc list`, then review \
             `lpm env oidc allow --help` before deliberately replacing its allowlists.",
        ),
        "env_not_allowed" => Some(
            "The requested env isn't in the policy's allowedEnvironments. Inspect the complete \
             policy with `lpm env oidc list`, then review `lpm env oidc allow --help` before \
             deliberately replacing its allowlists.",
        ),
        "ref_type_not_allowed" => Some(
            "The GitLab OIDC token identifies a tag or another non-branch ref. Branch allowlists \
             authorize branch pipelines only; run this job from an allowed branch.",
        ),
        "workflow_not_allowed" => Some(
            "The workflow file that minted this token isn't in the policy's allowedWorkflows. \
             Inspect the complete policy with `lpm env oidc list`, then review \
             `lpm env oidc allow --help` before deliberately replacing its allowlists.",
        ),
        "event_not_allowed" => Some(
            "The CI event_name that triggered this run isn't in the policy's allowedEvents. \
             Inspect the complete policy with `lpm env oidc list`, then review \
             `lpm env oidc allow --help` before deliberately replacing its allowlists.",
        ),
        "fork_not_allowed" => Some(
            "The OIDC token was minted by a fork PR but the policy has allowForks=false. \
             Inspect the complete policy with `lpm env oidc list`, then review \
             `lpm env oidc allow --help` before deliberately replacing its allowlists. \
             Fork-triggerable pull_request_target events run with base-repository secrets, \
             so authorize them only after reviewing that complete policy.",
        ),
        "missing_branch_claim" => Some(
            "The OIDC token from your CI provider has no branch claim. Confirm your provider \
             sets the ref/branch claim correctly (GitHub Actions does by default; some \
             self-hosted runners may not).",
        ),
        "rate_limited" => Some(
            "Rate limit exceeded on /api/vault/oidc. Retry after the Retry-After interval. \
             If this is a sustained issue, check whether multiple CI jobs share a runner IP.",
        ),
        _ => None,
    };
    match (hint.is_empty(), code_hint) {
        (false, _) => format!("{error}\n  Hint: {hint}"),
        (true, Some(h)) => format!("{error}\n  Hint: {h}"),
        (true, None) => error.to_string(),
    }
}

#[cfg(test)]
mod oidc_error_hint_tests {
    use super::build_oidc_pull_error_message;

    #[test]
    fn server_hint_takes_precedence_over_code_mapping() {
        let msg = build_oidc_pull_error_message(
            "Env not authorized",
            "Run: lpm env oidc allow --env=production",
            "env_not_allowed",
        );
        // Server-supplied `hint` wins; CLI-side mapping is not appended on top.
        assert!(msg.contains("Run: lpm env oidc allow --env=production"));
        // The branch_not_allowed string from the CLI mapping must not leak in.
        assert!(!msg.contains("allowedBranches"));
    }

    #[test]
    fn policy_misconfigured_code_maps_to_dashboard_hint() {
        let msg = build_oidc_pull_error_message(
            "OIDC policy is misconfigured (no allowed branches set).",
            "",
            "policy_misconfigured",
        );
        assert!(msg.contains("OIDC policy is misconfigured"));
        assert!(msg.contains("dashboard"));
        assert!(msg.contains("Hint:"));
    }

    #[test]
    fn provider_neutral_codes_do_not_invent_github_flags_without_server_hint() {
        for code in [
            "policy_not_found",
            "branch_not_allowed",
            "env_not_allowed",
            "ref_type_not_allowed",
        ] {
            let message = build_oidc_pull_error_message("not allowed", "", code);
            assert!(!message.contains("--repo"), "{code}: {message}");
            assert!(!message.contains("--workflow"), "{code}: {message}");
        }
    }

    #[test]
    fn gitlab_non_branch_ref_code_explains_branch_only_policy() {
        let message =
            build_oidc_pull_error_message("Ref type not authorized", "", "ref_type_not_allowed");
        assert!(message.contains("tag"));
        assert!(message.contains("branch pipelines only"));
    }

    #[test]
    fn workflow_not_allowed_requires_complete_policy_review() {
        let msg =
            build_oidc_pull_error_message("Workflow not authorized", "", "workflow_not_allowed");
        assert!(msg.contains("lpm env oidc list"));
        assert!(msg.contains("lpm env oidc allow --help"));
        assert!(msg.contains("allowedWorkflows"));
    }

    #[test]
    fn complete_policy_denials_require_review_instead_of_authorizing_the_denied_claim() {
        for code in [
            "workflow_not_allowed",
            "event_not_allowed",
            "fork_not_allowed",
        ] {
            let message = build_oidc_pull_error_message("not allowed", "", code);
            assert!(message.contains("lpm env oidc list"), "{code}: {message}");
            assert!(
                message.contains("lpm env oidc allow --help"),
                "{code}: {message}"
            );
            assert!(!message.contains("Add it:"), "{code}: {message}");
            assert!(!message.contains("--allow-forks"), "{code}: {message}");
        }
    }

    #[test]
    fn fork_not_allowed_warns_about_pull_request_target() {
        let msg = build_oidc_pull_error_message("Forks not allowed", "", "fork_not_allowed");
        assert!(!msg.contains("--allow-forks"));
        assert!(msg.contains("pull_request_target"));
        assert!(msg.contains("lpm env oidc list"));
    }

    #[test]
    fn rate_limited_mentions_retry_after() {
        let msg = build_oidc_pull_error_message("rate limited", "", "rate_limited");
        assert!(msg.contains("Retry-After"));
    }

    #[test]
    fn unknown_code_falls_through_to_raw_error() {
        let msg = build_oidc_pull_error_message("Something failed", "", "totally_unknown");
        // No "Hint:" prefix because neither server-hint nor known-code matched.
        assert_eq!(msg, "Something failed");
    }

    #[test]
    fn no_code_no_hint_yields_raw_error() {
        let msg = build_oidc_pull_error_message("Boom", "", "");
        assert_eq!(msg, "Boom");
    }
}
