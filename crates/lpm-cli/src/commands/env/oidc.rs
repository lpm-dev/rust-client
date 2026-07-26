use super::prelude::*;

/// `lpm env oidc allow --provider=github --repo=owner/repo --workflow=.github/workflows/deploy.yml --branch=main --env=production [--events=push,workflow_dispatch] [--allow-forks]`
pub(super) async fn vars_oidc(
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
        "allow" => vars_oidc_allow(&args[1..], project_dir, json_output).await,
        "list" => vars_oidc_list(project_dir, json_output).await,
        unknown => Err(LpmError::Script(format!(
            "unknown oidc action: '{unknown}'. Available: allow, list"
        ))),
    }
}

/// `lpm env oidc allow --provider=github --repo=owner/repo --workflow=.github/workflows/deploy.yml --branch=main --env=production`
pub(super) async fn vars_oidc_allow(
    args: &[&str],
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
    let vault_id =
        lpm_vault::vault_id::get_or_create_vault_id(project_dir).map_err(LpmError::Script)?;
    let (registry_url, auth_token) = super::auth::get_platform_auth(json_output).await?;

    let mut provider = "github";
    let mut repo: Option<&str> = None;
    let mut branches: Vec<String> = vec!["main".to_string()];
    let mut envs: Vec<String> = Vec::new();
    // No default: the server schema is `.min(1)`, and the safe default
    // ".github/workflows/deploy.yml" guesses the user's workflow name
    // (which is almost always wrong). Forcing the user to supply it
    // surfaces the security model.
    let mut workflows: Vec<String> = Vec::new();
    // `allowedEvents`. Defaults to push-only — the safest
    // event for fork-PR exposure. Adding `pull_request_target` to
    // this list also requires `--allow-forks` (cross-field check
    // enforced server-side, gated on JWT fixtures).
    let mut events: Vec<String> = vec!["push".to_string()];
    let mut allow_forks = false;

    for arg in args {
        if let Some(v) = arg.strip_prefix("--provider=") {
            provider = v;
        } else if let Some(v) = arg.strip_prefix("--repo=") {
            repo = Some(v);
        } else if let Some(v) = arg.strip_prefix("--branch=") {
            branches = v.split(',').map(|s| s.trim().to_string()).collect();
        } else if let Some(v) = arg.strip_prefix("--env=") {
            envs = v.split(',').map(|s| s.trim().to_string()).collect();
        } else if let Some(v) = arg.strip_prefix("--workflow=") {
            workflows = v.split(',').map(|s| s.trim().to_string()).collect();
        } else if let Some(v) = arg.strip_prefix("--events=") {
            events = v.split(',').map(|s| s.trim().to_string()).collect();
        } else if *arg == "--allow-forks" {
            allow_forks = true;
        }
    }

    let repo = repo.ok_or_else(|| {
        LpmError::Script(
            "missing --repo flag. Usage: lpm env oidc allow --repo=owner/repo \
             --workflow=.github/workflows/deploy.yml --branch=main --env=production"
                .into(),
        )
    })?;

    if workflows.is_empty() {
        return Err(LpmError::Script(
            "missing --workflow flag. Usage: lpm env oidc allow --repo=owner/repo \
             --workflow=.github/workflows/deploy.yml [--workflow=path2,path3]"
                .into(),
        ));
    }

    // Validate workflow paths client-side so the user gets a fast
    // failure instead of waiting for the server round-trip. The shape
    // matches the server's Zod regex
    // (`lib/validations/vault.js::GITHUB_WORKFLOW_PATH_RE`).
    for wf in &workflows {
        let valid = wf.starts_with(".github/workflows/")
            && !wf[".github/workflows/".len()..].contains('/')
            && (wf.ends_with(".yml") || wf.ends_with(".yaml"));
        if !valid {
            return Err(LpmError::Script(format!(
                "workflow path '{wf}' must be of the form `.github/workflows/<file>.yml` \
                 (subdirectories under .github/workflows/ are not supported by GitHub Actions)"
            )));
        }
    }

    // Canonicalize env names through resolver — OIDC policies store canonical names
    if !envs.is_empty() {
        let config = lpm_runner::lpm_json::read_lpm_json(project_dir)
            .ok()
            .flatten();
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

    let subject = format!("repo:{repo}");

    let client = lpm_http::client_builder()
        .build()
        .map_err(|error| LpmError::Network(format!("failed to build HTTP client: {error}")))?;
    let response = client
        .post(format!("{registry_url}/api/vault/oidc/policies"))
        .bearer_auth(&auth_token)
        .json(&serde_json::json!({
            "vaultId": vault_id,
            "provider": provider,
            "subject": subject,
            "allowedBranches": branches,
            "allowedEnvironments": envs,
            "allowedWorkflows": workflows,
            "allowedEvents": events,
            "allowForks": allow_forks,
        }))
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|error| {
            LpmError::Network(format!(
                "failed to reach server: {}",
                lpm_http::display_error(&error)
            ))
        })?;

    if !response.status().is_success() {
        let body: serde_json::Value =
            super::response::parse_capped_platform_json_or_unknown(response).await;
        return Err(LpmError::Script(
            body["error"].as_str().unwrap_or("failed").to_string(),
        ));
    }

    let result: serde_json::Value = super::response::parse_capped_platform_json(response).await?;

    let wrapping_key = lpm_vault::crypto::get_or_create_wrapping_key()
        .map_err(|error| oidc_escrow_setup_error("retrieving the local wrapping key", &error))?;
    let wrapping_key_hex = hex::encode(wrapping_key);
    lpm_vault::sync::upload_escrow_key(&registry_url, &auth_token, &vault_id, &wrapping_key_hex)
        .await
        .map_err(|error| oidc_escrow_setup_error("uploading the wrapping key", &error))?;

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&result).unwrap_or_default()
        );
    } else {
        output::success_line(install_ui::terminal_line!(
            "OIDC policy set: {} {} on branches [{}] for envs [{}] via workflows [{}] events [{}]",
            provider,
            install_ui::bold(repo),
            branches.join(", "),
            if envs.is_empty() {
                "all".to_string()
            } else {
                envs.join(", ")
            },
            workflows.join(", "),
            events.join(", "),
        ));
        output::info("CI escrow enabled — secrets will be decrypted server-side for OIDC pulls");
    }

    Ok(())
}

fn oidc_escrow_setup_error(step: &str, error: &str) -> LpmError {
    LpmError::Script(format!(
        "OIDC policy may already have been created, but CI pulls are not ready because escrow \
         setup failed while {step}: {error}. Fix the escrow problem, then rerun the same \
         `lpm env oidc allow` command; rerunning safely updates the existing policy."
    ))
}

/// `lpm env oidc list`
pub(super) async fn vars_oidc_list(
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
    let vault_id = lpm_vault::vault_id::read_vault_id(project_dir)
        .ok_or_else(|| LpmError::Script("no vault configured".into()))?;
    let (registry_url, auth_token) = super::auth::get_platform_auth(json_output).await?;

    let client = lpm_http::client_builder()
        .build()
        .map_err(|error| LpmError::Network(format!("failed to build HTTP client: {error}")))?;
    let response = client
        .get(format!(
            "{registry_url}/api/vault/oidc/policies?vaultId={vault_id}"
        ))
        .bearer_auth(&auth_token)
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|error| {
            LpmError::Network(format!(
                "failed to reach server: {}",
                lpm_http::display_error(&error)
            ))
        })?;

    if !response.status().is_success() {
        let body: serde_json::Value =
            super::response::parse_capped_platform_json_or_unknown(response).await;
        return Err(LpmError::Script(
            body["error"].as_str().unwrap_or("failed").to_string(),
        ));
    }

    let result: serde_json::Value = super::response::parse_capped_platform_json(response).await?;

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&result).unwrap_or_default()
        );
        return Ok(());
    }

    let policies = result["policies"].as_array();
    if policies.is_none() || policies.unwrap().is_empty() {
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
    for policy in policies.unwrap() {
        let provider = policy["provider"].as_str().unwrap_or("?");
        let subject = policy["subject"].as_str().unwrap_or("?");
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
                "  {} {}\n      branches:  [{}]\n      envs:      [{}]\n      workflows: [{}]\n      events:    [{}]{}",
                install_ui::bold(provider),
                subject,
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

/// `lpm env pull --oidc [--env=<mode>] [--output=<file>]`
///
/// Exchange CI OIDC token for a short-lived LPM token, then pull vault secrets.
pub(super) async fn vars_oidc_pull(
    args: &[&str],
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
    let vault_id = resolve_oidc_pull_vault_id(project_dir)?;

    let registry_url = lpm_common::resolve_lpm_registry_url();

    let mut env_mode: Option<&str> = None;
    let mut output_file: Option<&str> = None;

    for arg in args {
        if let Some(v) = arg.strip_prefix("--env=") {
            env_mode = Some(v);
        } else if let Some(v) = arg.strip_prefix("--output=") {
            output_file = Some(v);
        }
    }

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
            "No OIDC policy exists for this repo+vault. Create one with: \
             lpm env oidc allow --repo=<owner/repo> --workflow=.github/workflows/<file>.yml \
             --branch=<name> --env=<name>",
        ),
        "policy_misconfigured" => Some(
            "The OIDC policy exists but is missing required fields (likely a pre-migration \
             row). Open the dashboard at <registry>/dashboard/vaults to update it.",
        ),
        "branch_not_allowed" => Some(
            "The branch claim from your CI's OIDC token isn't in the policy's allowedBranches. \
             Update the policy: lpm env oidc allow --repo=<owner/repo> --branch=<list> --workflow=...",
        ),
        "env_not_allowed" => Some(
            "The requested env isn't in the policy's allowedEnvironments. Update the policy: \
             lpm env oidc allow --repo=<owner/repo> --env=<list> --workflow=...",
        ),
        "workflow_not_allowed" => Some(
            "The workflow file that minted this token isn't in the policy's allowedWorkflows. \
             Add it: lpm env oidc allow --repo=<owner/repo> --workflow=<path>",
        ),
        "event_not_allowed" => Some(
            "The CI event_name that triggered this run isn't in the policy's allowedEvents. \
             Add it: lpm env oidc allow --repo=<owner/repo> --events=push,workflow_dispatch",
        ),
        "fork_not_allowed" => Some(
            "The OIDC token was minted by a fork PR but the policy has allowForks=false. \
             Add --allow-forks to lpm env oidc allow if this is intentional (note: only \
             enable for public repos with trusted maintainers — pull_request_target events \
             from forks run with BASE secrets).",
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
    fn workflow_not_allowed_names_the_remediation_flag() {
        let msg =
            build_oidc_pull_error_message("Workflow not authorized", "", "workflow_not_allowed");
        assert!(msg.contains("--workflow"));
        assert!(msg.contains("allowedWorkflows"));
    }

    #[test]
    fn fork_not_allowed_warns_about_pull_request_target() {
        let msg = build_oidc_pull_error_message("Forks not allowed", "", "fork_not_allowed");
        assert!(msg.contains("--allow-forks"));
        assert!(msg.contains("pull_request_target"));
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
