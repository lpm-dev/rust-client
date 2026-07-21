use super::prelude::*;
use futures::TryStreamExt;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

const VERCEL_API_URL: &str = "https://api.vercel.com";
const PLATFORM_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const PLATFORM_MUTATION_CONCURRENCY: usize = 8;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct VercelConnectionConfig {
    project_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    team_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    target: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    linked_env: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PlatformConnection {
    platform: String,
    token: String,
    connection_config: serde_json::Value,
    label: Option<String>,
    last_push_at: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PlatformCredentialsResponse {
    connections: Vec<PlatformConnection>,
}

#[derive(Debug, Clone)]
struct VercelVariable {
    id: String,
    value: String,
    targets: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct VercelVariableResponse {
    id: String,
    key: String,
    #[serde(default)]
    value: String,
    #[serde(default)]
    target: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct VercelPagination {
    next: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct VercelListResponse {
    #[serde(default)]
    envs: Vec<VercelVariableResponse>,
    pagination: Option<VercelPagination>,
}

#[derive(Debug)]
struct PlatformDiff {
    added: Vec<String>,
    changed: Vec<String>,
    removed: Vec<String>,
    unchanged: Vec<String>,
}

#[derive(Debug)]
struct PlatformPushResult {
    added: usize,
    updated: usize,
    removed: usize,
}

#[derive(Debug)]
enum VercelMutation {
    Add { key: String, value: String },
    Update { id: String, value: String },
    Remove { id: String },
}

#[derive(Debug)]
enum MutationKind {
    Added,
    Updated,
    Removed,
}

struct VercelClient {
    http: reqwest::Client,
    api_url: String,
    token: String,
    config: VercelConnectionConfig,
}

impl VercelClient {
    fn new(token: String, config: VercelConnectionConfig) -> Result<Self, LpmError> {
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::limited(5))
            .timeout(PLATFORM_TIMEOUT)
            .build()
            .map_err(|error| {
                LpmError::Network(format!("failed to build Vercel client: {error}"))
            })?;
        Ok(Self {
            http,
            api_url: vercel_api_url()?,
            token,
            config,
        })
    }

    fn from_connection(connection: &PlatformConnection) -> Result<Self, LpmError> {
        if connection.platform != "vercel" {
            return Err(LpmError::Script(format!(
                "unsupported platform '{}'; this CLI currently supports Vercel",
                connection.platform
            )));
        }
        let config =
            serde_json::from_value::<VercelConnectionConfig>(connection.connection_config.clone())
                .map_err(|error| LpmError::Script(format!("invalid Vercel connection: {error}")))?;
        Self::new(connection.token.clone(), config)
    }

    fn collection_url(&self, version: &str) -> String {
        let project = urlencoding::encode(&self.config.project_id);
        let mut url = format!("{}/{version}/projects/{project}/env", self.api_url);
        if let Some(team_id) = &self.config.team_id {
            url.push_str("?teamId=");
            url.push_str(&urlencoding::encode(team_id));
        }
        url
    }

    fn item_url(&self, id: &str) -> String {
        let project = urlencoding::encode(&self.config.project_id);
        let id = urlencoding::encode(id);
        let mut url = format!("{}/v9/projects/{project}/env/{id}", self.api_url);
        if let Some(team_id) = &self.config.team_id {
            url.push_str("?teamId=");
            url.push_str(&urlencoding::encode(team_id));
        }
        url
    }

    fn selected_targets(&self) -> Vec<String> {
        self.config
            .target
            .clone()
            .unwrap_or_else(|| vec!["production".into(), "preview".into(), "development".into()])
    }

    async fn list(&self) -> Result<HashMap<String, VercelVariable>, LpmError> {
        let project = urlencoding::encode(&self.config.project_id);
        let mut variables = HashMap::new();
        let mut cursor: Option<String> = None;

        for page in 0..20 {
            let mut params = vec![("decrypt", "true".to_string())];
            if let Some(team_id) = &self.config.team_id {
                params.push(("teamId", team_id.clone()));
            }
            if let Some(until) = &cursor {
                params.push(("until", until.clone()));
            }
            let url = format!("{}/v10/projects/{project}/env", self.api_url);
            let response = self
                .http
                .get(url)
                .bearer_auth(&self.token)
                .query(&params)
                .send()
                .await
                .map_err(|error| LpmError::Network(format!("Vercel list failed: {error}")))?;
            let (status, body) = read_platform_response(response).await?;
            if !status.is_success() {
                return Err(vercel_api_error("list", status, &body));
            }
            let data: VercelListResponse = serde_json::from_slice(&body)
                .map_err(|error| LpmError::Script(format!("invalid Vercel response: {error}")))?;
            let selected_targets = self.selected_targets().into_iter().collect::<HashSet<_>>();
            for variable in data.envs {
                if is_vercel_managed_variable(&variable.key) {
                    continue;
                }
                if variable.target.is_empty() {
                    return Err(LpmError::Script(format!(
                        "Vercel value {} has no deployment target; refusing an ambiguous sync",
                        variable.key
                    )));
                }
                if !variable
                    .target
                    .iter()
                    .any(|target| selected_targets.contains(target))
                {
                    continue;
                }
                if !variable
                    .target
                    .iter()
                    .all(|target| selected_targets.contains(target))
                {
                    return Err(LpmError::Script(format!(
                        "Vercel value {} also applies outside the configured targets; split the variable by target before syncing",
                        variable.key
                    )));
                }
                let key = variable.key;
                if variables.contains_key(&key) {
                    return Err(LpmError::Script(format!(
                        "Vercel returned multiple values named {key} for the configured targets; consolidate them before syncing"
                    )));
                }
                variables.insert(
                    key,
                    VercelVariable {
                        id: variable.id,
                        value: variable.value,
                        targets: variable.target,
                    },
                );
            }

            cursor = data
                .pagination
                .and_then(|pagination| pagination.next)
                .and_then(json_scalar_string);
            if cursor.is_none() {
                return Ok(variables);
            }
            if page == 19 {
                return Err(LpmError::Script(
                    "Vercel returned more than 20 pages of env values; refusing an unbounded sync"
                        .into(),
                ));
            }
        }

        Ok(variables)
    }

    async fn apply(
        &self,
        diff: &PlatformDiff,
        local: &HashMap<String, String>,
        remote: &HashMap<String, VercelVariable>,
    ) -> Result<PlatformPushResult, LpmError> {
        let mut mutations =
            Vec::with_capacity(diff.added.len() + diff.changed.len() + diff.removed.len());
        for key in &diff.added {
            let value = local
                .get(key)
                .ok_or_else(|| LpmError::Script(format!("missing local value for {key}")))?;
            mutations.push(VercelMutation::Add {
                key: key.clone(),
                value: value.clone(),
            });
        }
        for key in &diff.changed {
            let value = local
                .get(key)
                .ok_or_else(|| LpmError::Script(format!("missing local value for {key}")))?;
            let variable = remote
                .get(key)
                .ok_or_else(|| LpmError::Script(format!("missing Vercel value for {key}")))?;
            self.assert_mutation_targets(key, variable)?;
            mutations.push(VercelMutation::Update {
                id: variable.id.clone(),
                value: value.clone(),
            });
        }
        for key in &diff.removed {
            let variable = remote
                .get(key)
                .ok_or_else(|| LpmError::Script(format!("missing Vercel value for {key}")))?;
            self.assert_mutation_targets(key, variable)?;
            mutations.push(VercelMutation::Remove {
                id: variable.id.clone(),
            });
        }

        let outcomes: Vec<MutationKind> = futures::stream::iter(mutations)
            .map(|mutation| self.apply_one(mutation))
            .buffer_unordered(PLATFORM_MUTATION_CONCURRENCY)
            .try_collect()
            .await?;

        let mut result = PlatformPushResult {
            added: 0,
            updated: 0,
            removed: 0,
        };
        for outcome in outcomes {
            match outcome {
                MutationKind::Added => result.added += 1,
                MutationKind::Updated => result.updated += 1,
                MutationKind::Removed => result.removed += 1,
            }
        }
        Ok(result)
    }

    fn assert_mutation_targets(
        &self,
        key: &str,
        variable: &VercelVariable,
    ) -> Result<(), LpmError> {
        let selected_targets = self.selected_targets().into_iter().collect::<HashSet<_>>();
        if variable.targets.is_empty()
            || !variable
                .targets
                .iter()
                .all(|target| selected_targets.contains(target))
        {
            return Err(LpmError::Script(format!(
                "Vercel value {key} does not match the configured deployment targets"
            )));
        }
        Ok(())
    }

    async fn apply_one(&self, mutation: VercelMutation) -> Result<MutationKind, LpmError> {
        let (operation, kind, request) = match mutation {
            VercelMutation::Add { key, value } => {
                let targets = self.selected_targets();
                (
                    "create",
                    MutationKind::Added,
                    self.http
                        .post(self.collection_url("v10"))
                        .bearer_auth(&self.token)
                        .json(&serde_json::json!({
                            "key": key,
                            "value": value,
                            "type": "encrypted",
                            "target": targets,
                        })),
                )
            }
            VercelMutation::Update { id, value } => (
                "update",
                MutationKind::Updated,
                self.http
                    .patch(self.item_url(&id))
                    .bearer_auth(&self.token)
                    .json(&serde_json::json!({ "value": value })),
            ),
            VercelMutation::Remove { id } => (
                "delete",
                MutationKind::Removed,
                self.http
                    .delete(self.item_url(&id))
                    .bearer_auth(&self.token),
            ),
        };

        let response = request
            .send()
            .await
            .map_err(|error| LpmError::Network(format!("Vercel {operation} failed: {error}")))?;
        let (status, body) = read_platform_response(response).await?;
        if !status.is_success() {
            return Err(vercel_api_error(operation, status, &body));
        }
        Ok(kind)
    }
}

fn vercel_api_url() -> Result<String, LpmError> {
    if !cfg!(any(debug_assertions, feature = "acceptance-test-hooks")) {
        return Ok(VERCEL_API_URL.into());
    }
    let Some(candidate) = std::env::var_os("LPM_ACCEPTANCE_VERCEL_API_BASE_URL") else {
        return Ok(VERCEL_API_URL.into());
    };
    if std::env::var("ACCEPTANCE_RUN_ID")
        .ok()
        .is_none_or(|value| value.trim().is_empty())
    {
        return Ok(VERCEL_API_URL.into());
    }
    let candidate = candidate.to_string_lossy();
    let parsed = reqwest::Url::parse(&candidate)
        .map_err(|error| LpmError::Script(format!("invalid acceptance Vercel URL: {error}")))?;
    let host = parsed.host_str().unwrap_or_default();
    if !matches!(host, "127.0.0.1" | "localhost" | "::1") {
        return Err(LpmError::Script(
            "the acceptance Vercel URL must use a loopback host".into(),
        ));
    }
    Ok(candidate.trim_end_matches('/').to_string())
}

fn is_vercel_managed_variable(key: &str) -> bool {
    matches!(
        key,
        "VERCEL"
            | "VERCEL_URL"
            | "VERCEL_ENV"
            | "VERCEL_REGION"
            | "VERCEL_GIT_COMMIT_SHA"
            | "VERCEL_GIT_COMMIT_MESSAGE"
            | "VERCEL_GIT_COMMIT_AUTHOR_LOGIN"
            | "VERCEL_GIT_COMMIT_AUTHOR_NAME"
            | "VERCEL_GIT_COMMIT_REF"
            | "VERCEL_GIT_PROVIDER"
            | "VERCEL_GIT_REPO_SLUG"
            | "VERCEL_GIT_REPO_OWNER"
            | "VERCEL_GIT_REPO_ID"
            | "VERCEL_GIT_PULL_REQUEST_ID"
            | "VERCEL_BRANCH_URL"
            | "VERCEL_PROJECT_PRODUCTION_URL"
    )
}

fn json_scalar_string(value: serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(value) => Some(value),
        serde_json::Value::Number(value) => Some(value.to_string()),
        _ => None,
    }
}

fn compute_diff(
    remote: &HashMap<String, VercelVariable>,
    local: &HashMap<String, String>,
    clean: bool,
) -> PlatformDiff {
    let mut added = Vec::new();
    let mut changed = Vec::new();
    let mut unchanged = Vec::new();
    for (key, value) in local {
        if is_vercel_managed_variable(key) {
            continue;
        }
        match remote.get(key) {
            None => added.push(key.clone()),
            Some(existing) if existing.value != *value => changed.push(key.clone()),
            Some(_) => unchanged.push(key.clone()),
        }
    }

    let mut removed = if clean {
        remote
            .keys()
            .filter(|key| !local.contains_key(*key) && !is_vercel_managed_variable(key))
            .cloned()
            .collect()
    } else {
        Vec::new()
    };
    added.sort_unstable();
    changed.sort_unstable();
    removed.sort_unstable();
    unchanged.sort_unstable();
    PlatformDiff {
        added,
        changed,
        removed,
        unchanged,
    }
}

async fn read_platform_response(
    response: reqwest::Response,
) -> Result<(reqwest::StatusCode, Vec<u8>), LpmError> {
    let status = response.status();
    let body = super::response::read_capped_platform_body(response).await?;
    Ok((status, body))
}

async fn read_signed_lpm_response(
    response: reqwest::Response,
    auth_token: &str,
) -> Result<(reqwest::StatusCode, Vec<u8>), LpmError> {
    let status = response.status();
    let signature = response
        .headers()
        .get(lpm_vault::signature::SIGNATURE_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let body = super::response::read_capped_platform_body(response).await?;
    if status.is_success() {
        lpm_vault::signature::verify_response_body(&body, auth_token, signature.as_deref())
            .map_err(|error| LpmError::Script(error.to_string()))?;
    }
    Ok((status, body))
}

fn response_error(status: reqwest::StatusCode, body: &[u8], fallback: &str) -> LpmError {
    let message = serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|value| value["error"].as_str().map(str::to_owned))
        .unwrap_or_else(|| format!("{fallback} (HTTP {status})"));
    LpmError::Script(message)
}

fn vercel_api_error(operation: &str, status: reqwest::StatusCode, body: &[u8]) -> LpmError {
    let detail = String::from_utf8_lossy(body);
    let detail = detail.trim();
    let suffix = if detail.is_empty() {
        String::new()
    } else {
        format!(": {}", detail.chars().take(300).collect::<String>())
    };
    LpmError::Script(format!(
        "Vercel {operation} failed with HTTP {status}{suffix}"
    ))
}

async fn fetch_connections(
    registry_url: &str,
    auth_token: &str,
    vault_id: &str,
    platform: Option<&str>,
) -> Result<Vec<PlatformConnection>, LpmError> {
    let mut request_body = serde_json::json!({ "vaultId": vault_id });
    if let Some(platform) = platform {
        request_body["platform"] = serde_json::Value::String(platform.to_owned());
    }
    let response = reqwest::Client::new()
        .post(format!("{registry_url}/api/vault/platforms/credentials"))
        .bearer_auth(auth_token)
        .json(&request_body)
        .timeout(PLATFORM_TIMEOUT)
        .send()
        .await
        .map_err(|error| LpmError::Network(format!("failed to reach LPM: {error}")))?;
    let (status, body) = read_signed_lpm_response(response, auth_token).await?;
    if !status.is_success() {
        return Err(response_error(
            status,
            &body,
            "failed to load platform connection",
        ));
    }
    let data: PlatformCredentialsResponse = serde_json::from_slice(&body)
        .map_err(|error| LpmError::Script(format!("invalid LPM response: {error}")))?;
    Ok(data.connections)
}

async fn record_platform_audit(
    registry_url: &str,
    auth_token: &str,
    body: serde_json::Value,
) -> Result<(), LpmError> {
    let response = reqwest::Client::new()
        .post(format!("{registry_url}/api/vault/platforms/audit"))
        .bearer_auth(auth_token)
        .json(&body)
        .timeout(PLATFORM_TIMEOUT)
        .send()
        .await
        .map_err(|error| LpmError::Network(format!("failed to record env audit: {error}")))?;
    let (status, body) = read_signed_lpm_response(response, auth_token).await?;
    if !status.is_success() {
        return Err(response_error(status, &body, "failed to record env audit"));
    }
    Ok(())
}

fn parse_flag<'a>(args: &'a [&str], name: &str) -> Option<&'a str> {
    let prefix = format!("{name}=");
    for (index, arg) in args.iter().enumerate() {
        if let Some(value) = arg.strip_prefix(&prefix) {
            return Some(value);
        }
        if *arg == name
            && let Some(value) = args.get(index + 1)
        {
            return Some(value);
        }
    }
    None
}

fn resolve_env_name(
    project_dir: &std::path::Path,
    input: Option<&str>,
) -> Result<Option<String>, LpmError> {
    let Some(input) = input else {
        return Ok(None);
    };
    let config = lpm_runner::lpm_json::read_lpm_json(project_dir)
        .ok()
        .flatten();
    let empty = HashMap::new();
    let env_map = config.as_ref().map_or(&empty, |value| &value.env);
    let environments = config
        .as_ref()
        .and_then(|value| value.environments.as_ref());
    let resolved = lpm_env::resolver::resolve_checked(input, env_map, environments)
        .map_err(|error| LpmError::Script(format!("invalid environment name: {error}")))?;
    Ok(Some(resolved.canonical))
}

fn parse_targets(value: Option<&str>) -> Result<Option<Vec<String>>, LpmError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let mut targets = Vec::new();
    for target in value.split(',').filter(|target| !target.is_empty()) {
        if !matches!(target, "production" | "preview" | "development") {
            return Err(LpmError::Script(format!(
                "unsupported Vercel target '{target}'; use production, preview, or development"
            )));
        }
        if !targets.iter().any(|existing| existing == target) {
            targets.push(target.to_string());
        }
    }
    if targets.is_empty() {
        return Err(LpmError::Script("--target cannot be empty".into()));
    }
    Ok(Some(targets))
}

pub(super) async fn vars_connect(
    args: &[&str],
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
    let platform = args.first().copied().ok_or_else(|| {
        LpmError::Script("usage: lpm env connect vercel --project=<id> [--token=<token>]".into())
    })?;
    if platform != "vercel" {
        return Err(LpmError::Script(
            "Vercel is the only currently supported env platform".into(),
        ));
    }
    let project_id = parse_flag(args, "--project")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| LpmError::Script("missing --project flag".into()))?;
    let team_id = parse_flag(args, "--team").map(str::to_string);
    let label = parse_flag(args, "--label");
    let linked_env = resolve_env_name(project_dir, parse_flag(args, "--linked-env"))?;
    let targets = parse_targets(parse_flag(args, "--target"))?;

    let token_owned;
    let platform_token = if let Some(token) = parse_flag(args, "--token") {
        token
    } else {
        token_owned = cliclack::password("Paste Vercel API token")
            .interact()
            .map_err(|error| LpmError::Script(format!("prompt failed: {error}")))?;
        token_owned.as_str()
    };

    let config = VercelConnectionConfig {
        project_id: project_id.to_string(),
        team_id,
        target: targets,
        linked_env,
    };
    if !json_output {
        output::info("verifying the Vercel connection directly...");
    }
    VercelClient::new(platform_token.to_string(), config.clone())?
        .list()
        .await?;

    let vault_id =
        lpm_vault::vault_id::get_or_create_vault_id(project_dir).map_err(LpmError::Script)?;
    let (registry_url, auth_token) = super::auth::get_platform_auth(json_output).await?;
    let response = reqwest::Client::new()
        .post(format!("{registry_url}/api/vault/platforms/connect"))
        .bearer_auth(&auth_token)
        .json(&serde_json::json!({
            "vaultId": vault_id,
            "platform": platform,
            "token": platform_token,
            "connectionConfig": config,
            "label": label,
        }))
        .timeout(PLATFORM_TIMEOUT)
        .send()
        .await
        .map_err(|error| LpmError::Network(format!("failed to save connection: {error}")))?;
    let (status, body) = read_platform_response(response).await?;
    if !status.is_success() {
        return Err(response_error(status, &body, "connection failed"));
    }
    let result: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|error| LpmError::Script(format!("invalid LPM response: {error}")))?;
    if json_output {
        super::response::print_json_value(&super::response::success_envelope(result));
    } else {
        let status = result["status"].as_str().unwrap_or("connected");
        output::success(&format!("Vercel {} (project: {project_id})", status.bold()));
    }
    Ok(())
}

pub(super) async fn vars_platform_push(
    args: &[&str],
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
    let platform = parse_flag(args, "--to").ok_or_else(|| {
        LpmError::Script("missing --to flag. Usage: lpm env push --to vercel".into())
    })?;
    if platform != "vercel" {
        return Err(LpmError::Script(
            "Vercel is the only currently supported env platform".into(),
        ));
    }
    let clean = args.contains(&"--clean");
    let yes = args.iter().any(|arg| matches!(*arg, "--yes" | "-y"));
    let vault_id = lpm_vault::vault_id::read_vault_id(project_dir).ok_or_else(|| {
        LpmError::Script("no env project configured. Run `lpm env set` first".into())
    })?;
    let (registry_url, auth_token) = super::auth::get_platform_auth(json_output).await?;
    let mut connections =
        fetch_connections(&registry_url, &auth_token, &vault_id, Some(platform)).await?;
    let connection = connections
        .pop()
        .ok_or_else(|| LpmError::Script("No Vercel connection found".into()))?;
    let client = VercelClient::from_connection(&connection)?;
    let requested_env = parse_flag(args, "--env").or(client.config.linked_env.as_deref());
    let resolved_env = resolve_env_name(project_dir, requested_env)?;
    let local = lpm_runner::dotenv::load_project_env(project_dir, resolved_env.as_deref())?;

    if !json_output {
        output::info("comparing local env values with Vercel...");
    }
    let remote = client.list().await?;
    let diff = compute_diff(&remote, &local, clean);
    let orphan_count = if clean {
        0
    } else {
        remote
            .keys()
            .filter(|key| !local.contains_key(*key) && !is_vercel_managed_variable(key))
            .count()
    };
    if diff.added.is_empty() && diff.changed.is_empty() && diff.removed.is_empty() {
        if json_output {
            super::response::print_json_value(&serde_json::json!({
                "success": true,
                "status": "no_changes",
                "platform": platform,
                "orphans": orphan_count,
            }));
        } else {
            output::success("Vercel is already in sync");
            if orphan_count > 0 {
                output::warn(&format!(
                    "{orphan_count} platform-only value(s) preserved. Use --clean to remove."
                ));
            }
        }
        return Ok(());
    }

    if !json_output {
        println!();
        for key in &diff.added {
            println!("  {} {} {}", "+".green(), key.bold(), "(new)".dimmed());
        }
        for key in &diff.changed {
            println!("  {} {} {}", "~".yellow(), key.bold(), "(changed)".dimmed());
        }
        for key in &diff.removed {
            println!(
                "  {} {} {}",
                "-".red(),
                key.bold(),
                "(will be removed)".dimmed()
            );
        }
        if !diff.unchanged.is_empty() {
            println!("  {} {} unchanged", "=".dimmed(), diff.unchanged.len());
        }
        println!();
    }

    if !yes && !json_output {
        let confirmed = cliclack::confirm(format!(
            "Push {} added, {} changed, {} removed to Vercel?",
            diff.added.len(),
            diff.changed.len(),
            diff.removed.len()
        ))
        .initial_value(false)
        .interact()
        .map_err(|error| LpmError::Script(format!("prompt failed: {error}")))?;
        if !confirmed {
            output::info("cancelled");
            return Ok(());
        }
    }

    let result = client.apply(&diff, &local, &remote).await?;
    let env_name = resolved_env.as_deref().unwrap_or("default");
    let audit = record_platform_audit(
        &registry_url,
        &auth_token,
        serde_json::json!({
            "vaultId": vault_id,
            "platform": platform,
            "operation": "push",
            "env": env_name,
            "added": result.added,
            "updated": result.updated,
            "removed": result.removed,
        }),
    )
    .await;
    if json_output {
        super::response::print_json_value(&serde_json::json!({
            "success": true,
            "status": "synced",
            "platform": platform,
            "env": env_name,
            "added": result.added,
            "updated": result.updated,
            "removed": result.removed,
            "auditRecorded": audit.is_ok(),
        }));
    } else {
        output::success(&format!(
            "Vercel synced — {} added, {} updated, {} removed",
            result.added, result.updated, result.removed
        ));
        if let Err(error) = audit {
            output::warn(&format!(
                "Vercel was updated, but LPM could not record the audit entry: {error}"
            ));
        }
    }
    Ok(())
}

pub(super) async fn vars_platform_status(
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
    let vault_id = lpm_vault::vault_id::read_vault_id(project_dir).ok_or_else(|| {
        LpmError::Script("no env project configured. Run `lpm env set` first".into())
    })?;
    let (registry_url, auth_token) = super::auth::get_platform_auth(json_output).await?;
    let connections = fetch_connections(&registry_url, &auth_token, &vault_id, None).await?;
    if connections.is_empty() {
        if json_output {
            super::response::print_json_value(&serde_json::json!({
                "success": true,
                "platforms": [],
                "count": 0,
            }));
        } else {
            output::warn("no platform connections. Run `lpm env connect vercel` first.");
        }
        return Ok(());
    }

    let mut statuses = Vec::with_capacity(connections.len());
    for connection in connections {
        let label = connection.label.clone();
        let last_push_at = connection.last_push_at.clone();
        let client = match VercelClient::from_connection(&connection) {
            Ok(client) => client,
            Err(error) => {
                statuses.push(serde_json::json!({
                    "platform": connection.platform,
                    "label": label,
                    "status": "error",
                    "error": error.to_string(),
                    "lastPushAt": last_push_at,
                }));
                continue;
            }
        };
        let env_name = client.config.linked_env.as_deref().unwrap_or("default");
        let mode = (env_name != "default").then_some(env_name);
        let local = match lpm_runner::dotenv::load_project_env(project_dir, mode) {
            Ok(local) => local,
            Err(error) => {
                statuses.push(serde_json::json!({
                    "platform": connection.platform,
                    "label": label,
                    "env": env_name,
                    "status": "error",
                    "error": error.to_string(),
                    "lastPushAt": last_push_at,
                }));
                continue;
            }
        };
        match client.list().await {
            Ok(remote) => {
                let diff = compute_diff(&remote, &local, false);
                let mut drift_keys = diff
                    .added
                    .iter()
                    .chain(&diff.changed)
                    .chain(&diff.removed)
                    .cloned()
                    .collect::<Vec<_>>();
                drift_keys.sort_unstable();
                drift_keys.truncate(20);
                let status = if drift_keys.is_empty() {
                    "synced"
                } else {
                    "drifted"
                };
                statuses.push(serde_json::json!({
                    "platform": connection.platform,
                    "label": label,
                    "env": env_name,
                    "status": status,
                    "added": diff.added.len(),
                    "changed": diff.changed.len(),
                    "removed": diff.removed.len(),
                    "driftKeys": drift_keys,
                    "lastPushAt": last_push_at,
                }));
            }
            Err(error) => statuses.push(serde_json::json!({
                "platform": connection.platform,
                "label": label,
                "env": env_name,
                "status": "error",
                "error": error.to_string(),
                "lastPushAt": last_push_at,
            })),
        }
    }

    if json_output {
        super::response::print_json_value(&serde_json::json!({
            "success": true,
            "count": statuses.len(),
            "platforms": statuses,
        }));
        return Ok(());
    }
    println!();
    for status in statuses {
        let platform = status["platform"].as_str().unwrap_or("?");
        let env = status["env"].as_str().unwrap_or("default");
        let state = status["status"].as_str().unwrap_or("error");
        match state {
            "synced" => println!(
                "  {} {} [{}]  {}",
                "✓".green(),
                platform.bold(),
                env,
                "synced".green()
            ),
            "drifted" => println!(
                "  {} {} [{}]  {} — +{} ~{} -{}",
                "!".yellow(),
                platform.bold(),
                env,
                "drifted".yellow(),
                status["added"].as_u64().unwrap_or(0),
                status["changed"].as_u64().unwrap_or(0),
                status["removed"].as_u64().unwrap_or(0),
            ),
            _ => println!(
                "  {} {} [{}]  {}",
                "✗".red(),
                platform.bold(),
                env,
                status["error"].as_str().unwrap_or("unknown error").red()
            ),
        }
    }
    println!();
    Ok(())
}

pub(super) async fn vars_platform_pull(
    args: &[&str],
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
    let platform = parse_flag(args, "--from").ok_or_else(|| {
        LpmError::Script("missing --from flag. Usage: lpm env pull --from vercel".into())
    })?;
    if platform != "vercel" {
        return Err(LpmError::Script(
            "Vercel is the only currently supported env platform".into(),
        ));
    }
    let yes = args.iter().any(|arg| matches!(*arg, "--yes" | "-y"));
    let vault_id =
        lpm_vault::vault_id::get_or_create_vault_id(project_dir).map_err(LpmError::Script)?;
    let (registry_url, auth_token) = super::auth::get_platform_auth(json_output).await?;
    let mut connections =
        fetch_connections(&registry_url, &auth_token, &vault_id, Some(platform)).await?;
    let connection = connections
        .pop()
        .ok_or_else(|| LpmError::Script("No Vercel connection found".into()))?;
    let client = VercelClient::from_connection(&connection)?;
    let requested_env = parse_flag(args, "--env").or(client.config.linked_env.as_deref());
    let resolved_env = resolve_env_name(project_dir, requested_env)?;
    let env_name = resolved_env.as_deref().unwrap_or("default");
    if !json_output {
        output::info("pulling env values directly from Vercel...");
    }
    let remote = client.list().await?;
    if remote.is_empty() {
        if json_output {
            super::response::print_json_value(&serde_json::json!({
                "success": true,
                "status": "no_values",
                "platform": platform,
                "env": env_name,
                "count": 0,
            }));
        } else {
            output::warn("no env values found on Vercel");
        }
        return Ok(());
    }

    let mut values = remote
        .into_iter()
        .map(|(key, variable)| (key, variable.value))
        .collect::<Vec<_>>();
    values.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    if !json_output {
        println!();
        for (key, _) in &values {
            println!("    {}", key.bold());
        }
        println!();
    }
    if !yes && !json_output {
        let confirmed = cliclack::confirm(format!(
            "Import {} value(s) from Vercel into {env_name}?",
            values.len()
        ))
        .initial_value(true)
        .interact()
        .map_err(|error| LpmError::Script(format!("prompt failed: {error}")))?;
        if !confirmed {
            output::info("cancelled");
            return Ok(());
        }
    }
    let pairs = values
        .iter()
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect::<Vec<_>>();
    if env_name == "default" {
        lpm_vault::set(project_dir, &pairs).map_err(LpmError::Script)?;
    } else {
        lpm_vault::set_env(project_dir, env_name, &pairs).map_err(LpmError::Script)?;
    }
    let audit = record_platform_audit(
        &registry_url,
        &auth_token,
        serde_json::json!({
            "vaultId": vault_id,
            "platform": platform,
            "operation": "pull",
            "env": env_name,
            "imported": pairs.len(),
        }),
    )
    .await;
    if json_output {
        super::response::print_json_value(&serde_json::json!({
            "success": true,
            "status": "imported",
            "platform": platform,
            "env": env_name,
            "count": pairs.len(),
            "keys": values.iter().map(|(key, _)| key).collect::<Vec<_>>(),
            "auditRecorded": audit.is_ok(),
        }));
    } else {
        output::success(&format!(
            "imported {} value(s) from Vercel into {env_name}",
            pairs.len()
        ));
        if let Err(error) = audit {
            output::warn(&format!(
                "Values were imported, but LPM could not record the audit entry: {error}"
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn remote(entries: &[(&str, &str)]) -> HashMap<String, VercelVariable> {
        entries
            .iter()
            .map(|(key, value)| {
                (
                    (*key).to_string(),
                    VercelVariable {
                        id: format!("id-{key}"),
                        value: (*value).to_string(),
                        targets: vec!["production".into()],
                    },
                )
            })
            .collect()
    }

    fn client(targets: &[&str]) -> VercelClient {
        VercelClient {
            http: reqwest::Client::new(),
            api_url: VERCEL_API_URL.into(),
            token: "test-token".into(),
            config: VercelConnectionConfig {
                project_id: "test-project".into(),
                team_id: None,
                target: Some(targets.iter().map(|target| (*target).into()).collect()),
                linked_env: None,
            },
        }
    }

    #[test]
    fn diff_preserves_platform_only_values_without_clean() {
        let remote = remote(&[("UNCHANGED", "same"), ("ORPHAN", "remote")]);
        let local = HashMap::from([
            ("UNCHANGED".into(), "same".into()),
            ("NEW".into(), "new".into()),
        ]);

        let diff = compute_diff(&remote, &local, false);

        assert_eq!(diff.added, ["NEW"]);
        assert!(diff.removed.is_empty());
        assert_eq!(diff.unchanged, ["UNCHANGED"]);
    }

    #[test]
    fn diff_removes_platform_only_values_with_clean() {
        let remote = remote(&[("ORPHAN", "remote")]);

        let diff = compute_diff(&remote, &HashMap::new(), true);

        assert_eq!(diff.removed, ["ORPHAN"]);
    }

    #[test]
    fn managed_vercel_values_never_enter_the_diff() {
        let remote = remote(&[("VERCEL_URL", "remote")]);
        let local = HashMap::from([("VERCEL_ENV".into(), "production".into())]);

        let diff = compute_diff(&remote, &local, true);

        assert!(diff.added.is_empty());
        assert!(diff.removed.is_empty());
    }

    #[test]
    fn vercel_override_requires_an_acceptance_run_marker() {
        let _env = crate::test_env::ScopedEnv::update([
            ("ACCEPTANCE_RUN_ID", None),
            (
                "LPM_ACCEPTANCE_VERCEL_API_BASE_URL",
                Some("http://127.0.0.1:4173".into()),
            ),
        ]);

        assert_eq!(
            vercel_api_url().expect("resolve Vercel URL"),
            VERCEL_API_URL
        );
    }

    #[test]
    fn vercel_override_rejects_non_loopback_destinations() {
        let _env = crate::test_env::ScopedEnv::set([
            ("ACCEPTANCE_RUN_ID", "platform-test".into()),
            (
                "LPM_ACCEPTANCE_VERCEL_API_BASE_URL",
                "https://example.com".into(),
            ),
        ]);

        let error = vercel_api_url().expect_err("non-loopback override must fail closed");

        assert!(error.to_string().contains("must use a loopback host"));
    }

    #[test]
    fn mutation_refuses_a_variable_shared_with_an_unselected_target() {
        let variable = VercelVariable {
            id: "shared-id".into(),
            value: "secret".into(),
            targets: vec!["production".into(), "preview".into()],
        };

        let error = client(&["production"])
            .assert_mutation_targets("SHARED", &variable)
            .expect_err("a production sync must not mutate a preview value");

        assert!(error.to_string().contains("configured deployment targets"));
    }
}
