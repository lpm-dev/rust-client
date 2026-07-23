mod coolify;
mod github_actions;
mod railway;

use super::prelude::*;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

const VERCEL_API_URL: &str = "https://api.vercel.com";
const PLATFORM_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const PLATFORM_MUTATION_CONCURRENCY: usize = 8;
const PLATFORM_TOKEN_MAX_CHARS: usize = 10_000;
const PLATFORM_LABEL_MAX_CHARS: usize = 100;
const LINKED_ENV_MAX_CHARS: usize = 64;
const VERCEL_ID_MAX_CHARS: usize = 100;
const COOLIFY_URL_MAX_CHARS: usize = 2048;
const COOLIFY_APPLICATION_ID_MAX_CHARS: usize = 128;
const RAILWAY_ID_MAX_CHARS: usize = 128;

fn is_supported_platform(platform: &str) -> bool {
    matches!(
        platform,
        "vercel" | "coolify" | "railway" | "github-actions"
    )
}

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
struct PlatformVariable {
    id: String,
    value: String,
    scope: VariableScope,
}

#[derive(Debug, Default)]
struct PlatformState {
    readable: HashMap<String, PlatformVariable>,
    write_only: HashSet<String>,
}

impl PlatformState {
    fn from_readable(readable: HashMap<String, PlatformVariable>) -> Self {
        Self {
            readable,
            write_only: HashSet::new(),
        }
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
struct LocalPlatformValues {
    readable: HashMap<String, String>,
    write_only: HashMap<String, String>,
}

#[derive(Debug, Clone)]
enum VariableScope {
    Vercel {
        targets: Vec<String>,
    },
    Coolify {
        preview: bool,
        is_literal: bool,
        is_multiline: bool,
        is_shown_once: bool,
    },
    Railway,
    GitHubActions,
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

#[derive(Debug, Default)]
struct PlatformDiff {
    added: Vec<String>,
    changed: Vec<String>,
    removed: Vec<String>,
    unchanged: Vec<String>,
    write_only_added: Vec<String>,
    write_only_present: Vec<String>,
    write_only_removed: Vec<String>,
}

impl PlatformDiff {
    fn added_count(&self) -> usize {
        self.added.len() + self.write_only_added.len()
    }

    fn updated_count(&self) -> usize {
        self.changed.len() + self.write_only_present.len()
    }

    fn removed_count(&self) -> usize {
        self.removed.len() + self.write_only_removed.len()
    }

    fn has_push_mutations(&self) -> bool {
        self.added_count() > 0 || self.updated_count() > 0 || self.removed_count() > 0
    }

    fn has_known_drift(&self) -> bool {
        self.added_count() > 0 || !self.changed.is_empty() || self.removed_count() > 0
    }

    fn drift_keys(&self) -> Vec<String> {
        let mut keys = self
            .added
            .iter()
            .chain(&self.changed)
            .chain(&self.removed)
            .chain(&self.write_only_added)
            .chain(&self.write_only_removed)
            .cloned()
            .collect::<Vec<_>>();
        keys.sort_unstable();
        keys.dedup();
        keys.truncate(20);
        keys
    }
}
#[derive(Debug, Clone, Copy, Default)]
struct PlatformPushResult {
    added: usize,
    updated: usize,
    removed: usize,
}

impl PlatformPushResult {
    fn record(&mut self, kind: MutationKind) {
        match kind {
            MutationKind::Added => self.added += 1,
            MutationKind::Updated => self.updated += 1,
            MutationKind::Removed => self.removed += 1,
        }
    }

    fn from_mutation_outcomes(outcomes: Vec<MutationOutcome>) -> Result<Self, PlatformApplyError> {
        let mut result = Self::default();
        let mut first_error = None;
        let mut counts_known = true;
        for outcome in outcomes {
            match outcome {
                MutationOutcome::Applied(kind) => result.record(kind),
                MutationOutcome::Failed { error, committed } => {
                    if let Some(kind) = committed {
                        result.record(kind);
                    }
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                }
                MutationOutcome::Unknown(error) => {
                    counts_known = false;
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                }
            }
        }
        match first_error {
            Some(error) if counts_known => Err(PlatformApplyError::tracked(error, result)),
            Some(error) => Err(PlatformApplyError::untracked(error)),
            None => Ok(result),
        }
    }
}

#[derive(Debug)]
enum PlatformApplyError {
    Untracked(Box<LpmError>),
    Tracked {
        error: Box<LpmError>,
        applied: PlatformPushResult,
    },
}

impl PlatformApplyError {
    fn untracked(error: LpmError) -> Self {
        Self::Untracked(Box::new(error))
    }

    fn tracked(error: LpmError, applied: PlatformPushResult) -> Self {
        Self::Tracked {
            error: Box::new(error),
            applied,
        }
    }

    fn into_error(self) -> LpmError {
        match self {
            Self::Untracked(error) | Self::Tracked { error, .. } => *error,
        }
    }
}

#[derive(Debug)]
enum PlatformApplyError {
    Untracked(LpmError),
    Tracked {
        error: LpmError,
        applied: PlatformPushResult,
    },
}

impl PlatformApplyError {
    fn error(&self) -> &LpmError {
        match self {
            Self::Untracked(error) | Self::Tracked { error, .. } => error,
        }
    }
}

#[derive(Debug)]
enum VercelMutation {
    Add {
        key: String,
        value: String,
        targets: Vec<String>,
    },
    Update {
        id: String,
        key: String,
        value: String,
        targets: Vec<String>,
    },
    Remove {
        id: String,
        key: String,
    },
}

#[derive(Debug, Clone, Copy)]
enum MutationKind {
    Added,
    Updated,
    Removed,
}

#[derive(Debug)]
enum MutationOutcome {
    Applied(MutationKind),
    Failed {
        error: LpmError,
        committed: Option<MutationKind>,
    },
    Unknown(LpmError),
}

impl From<Result<MutationKind, LpmError>> for MutationOutcome {
    fn from(result: Result<MutationKind, LpmError>) -> Self {
        match result {
            Ok(kind) => Self::Applied(kind),
            Err(error) => Self::Failed {
                error,
                committed: None,
            },
        }
    }
}

struct VercelClient {
    http: reqwest::Client,
    api_url: String,
    token: String,
    config: VercelConnectionConfig,
}

impl VercelClient {
    fn new(token: String, config: VercelConnectionConfig) -> Result<Self, LpmError> {
        let http = lpm_http::client_builder_with_redirect_limit(5)
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

    async fn list(&self) -> Result<HashMap<String, PlatformVariable>, LpmError> {
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
                .map_err(|error| {
                    LpmError::Network(format!(
                        "Vercel list failed: {}",
                        lpm_http::display_error(&error)
                    ))
                })?;
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
                    PlatformVariable {
                        id: variable.id,
                        value: variable.value,
                        scope: VariableScope::Vercel {
                            targets: variable.target,
                        },
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
        remote: &HashMap<String, PlatformVariable>,
    ) -> Result<PlatformPushResult, PlatformApplyError> {
        let mut mutations =
            Vec::with_capacity(diff.added.len() + diff.changed.len() + diff.removed.len());
        for key in &diff.added {
            let value = local
                .get(key)
                .ok_or_else(|| LpmError::Script(format!("missing local value for {key}")))
                .map_err(PlatformApplyError::untracked)?;
            mutations.push(VercelMutation::Add {
                key: key.clone(),
                value: value.clone(),
                targets: self.selected_targets(),
            });
        }
        for key in &diff.changed {
            let value = local
                .get(key)
                .ok_or_else(|| LpmError::Script(format!("missing local value for {key}")))
                .map_err(PlatformApplyError::untracked)?;
            let variable = remote
                .get(key)
                .ok_or_else(|| LpmError::Script(format!("missing Vercel value for {key}")))
                .map_err(PlatformApplyError::untracked)?;
            self.assert_mutation_targets(key, variable)
                .map_err(PlatformApplyError::untracked)?;
            let VariableScope::Vercel { targets } = &variable.scope else {
                return Err(PlatformApplyError::untracked(LpmError::Script(format!(
                    "Vercel value {key} does not match the configured deployment targets"
                ))));
            };
            mutations.push(VercelMutation::Update {
                id: variable.id.clone(),
                key: key.clone(),
                value: value.clone(),
                targets: targets.clone(),
            });
        }
        for key in &diff.removed {
            let variable = remote
                .get(key)
                .ok_or_else(|| LpmError::Script(format!("missing Vercel value for {key}")))
                .map_err(PlatformApplyError::untracked)?;
            self.assert_mutation_targets(key, variable)
                .map_err(PlatformApplyError::untracked)?;
            mutations.push(VercelMutation::Remove {
                id: variable.id.clone(),
                key: key.clone(),
            });
        }

        let outcomes = futures::stream::iter(mutations)
            .map(|mutation| self.apply_one(mutation))
            .buffer_unordered(PLATFORM_MUTATION_CONCURRENCY)
            .collect::<Vec<_>>()
            .await;

        PlatformPushResult::from_mutation_outcomes(outcomes)
    }

    fn assert_mutation_targets(
        &self,
        key: &str,
        variable: &PlatformVariable,
    ) -> Result<(), LpmError> {
        let selected_targets = self.selected_targets().into_iter().collect::<HashSet<_>>();
        let VariableScope::Vercel { targets } = &variable.scope else {
            return Err(LpmError::Script(format!(
                "Vercel value {key} does not match the configured deployment targets"
            )));
        };
        if targets.is_empty()
            || !targets
                .iter()
                .all(|target| selected_targets.contains(target))
        {
            return Err(LpmError::Script(format!(
                "Vercel value {key} does not match the configured deployment targets"
            )));
        }
        Ok(())
    }

    async fn apply_one(&self, mutation: VercelMutation) -> MutationOutcome {
        let kind = mutation.kind();
        match self.send_mutation(&mutation).await {
            Ok(()) => MutationOutcome::Applied(kind),
            Err(error) => match self.mutation_is_applied(&mutation).await {
                Ok(true) => MutationOutcome::Applied(kind),
                Ok(false) => MutationOutcome::Failed {
                    error,
                    committed: None,
                },
                Err(reconciliation_error) => {
                    MutationOutcome::Unknown(append_platform_error_context(
                        error,
                        format!("Vercel final-state reconciliation failed: {reconciliation_error}"),
                    ))
                }
            },
        }
    }

    async fn send_mutation(&self, mutation: &VercelMutation) -> Result<(), LpmError> {
        let (operation, request) = match mutation {
            VercelMutation::Add {
                key,
                value,
                targets,
            } => (
                "create",
                self.http
                    .post(self.collection_url("v10"))
                    .bearer_auth(&self.token)
                    .json(&serde_json::json!({
                        "key": key,
                        "value": value,
                        "type": "encrypted",
                        "target": targets,
                    })),
            ),
            VercelMutation::Update { id, value, .. } => (
                "update",
                self.http
                    .patch(self.item_url(id))
                    .bearer_auth(&self.token)
                    .json(&serde_json::json!({ "value": value })),
            ),
            VercelMutation::Remove { id, .. } => (
                "delete",
                self.http.delete(self.item_url(id)).bearer_auth(&self.token),
            ),
        };

        let response = request.send().await.map_err(|error| {
            LpmError::Network(format!(
                "Vercel {operation} failed: {}",
                lpm_http::display_error(&error)
            ))
        })?;
        let (status, body) = read_platform_response(response).await?;
        if !status.is_success() {
            return Err(vercel_api_error(operation, status, &body));
        }
        Ok(())
    }

    async fn mutation_is_applied(&self, mutation: &VercelMutation) -> Result<bool, LpmError> {
        let variables = self.list().await?;
        Ok(match mutation {
            VercelMutation::Add {
                key,
                value,
                targets,
            } => variables.get(key).is_some_and(|variable| {
                variable.value == *value && variable_has_targets(variable, targets)
            }),
            VercelMutation::Update {
                id,
                key,
                value,
                targets,
            } => variables.get(key).is_some_and(|variable| {
                variable.id == *id
                    && variable.value == *value
                    && variable_has_targets(variable, targets)
            }),
            VercelMutation::Remove { key, .. } => !variables.contains_key(key),
        })
    }
}

impl VercelMutation {
    fn kind(&self) -> MutationKind {
        match self {
            Self::Add { .. } => MutationKind::Added,
            Self::Update { .. } => MutationKind::Updated,
            Self::Remove { .. } => MutationKind::Removed,
        }
    }
}

fn variable_has_targets(variable: &PlatformVariable, expected: &[String]) -> bool {
    let VariableScope::Vercel { targets } = &variable.scope else {
        return false;
    };
    if targets.len() != expected.len() {
        return false;
    }
    expected.iter().all(|target| targets.contains(target))
}

fn append_platform_error_context(error: LpmError, context: String) -> LpmError {
    match error {
        LpmError::Network(message) => LpmError::Network(format!("{message}; {context}")),
        LpmError::Script(message) => LpmError::Script(format!("{message}; {context}")),
        other => other,
    }
}

enum PlatformClient {
    Vercel(VercelClient),
    Coolify(coolify::CoolifyClient),
    GitHubActions(github_actions::GitHubActionsClient),
    Railway(railway::RailwayClient),
}

impl PlatformClient {
    fn from_connection(connection: &PlatformConnection) -> Result<Self, LpmError> {
        match connection.platform.as_str() {
            "vercel" => {
                let config = serde_json::from_value::<VercelConnectionConfig>(
                    connection.connection_config.clone(),
                )
                .map_err(|error| LpmError::Script(format!("invalid Vercel connection: {error}")))?;
                Ok(Self::Vercel(VercelClient::new(
                    connection.token.clone(),
                    config,
                )?))
            }
            "coolify" => {
                let config = serde_json::from_value::<coolify::CoolifyConnectionConfig>(
                    connection.connection_config.clone(),
                )
                .map_err(|error| {
                    LpmError::Script(format!("invalid Coolify connection: {error}"))
                })?;
                Ok(Self::Coolify(coolify::CoolifyClient::new(
                    connection.token.clone(),
                    config,
                )?))
            }
            "github-actions" => {
                let config =
                    serde_json::from_value::<github_actions::GitHubActionsConnectionConfig>(
                        connection.connection_config.clone(),
                    )
                    .map_err(|error| {
                        LpmError::Script(format!("invalid GitHub Actions connection: {error}"))
                    })?;
                Ok(Self::GitHubActions(
                    github_actions::GitHubActionsClient::new(connection.token.clone(), config)?,
                ))
            }
            "railway" => {
                let config = serde_json::from_value::<railway::RailwayConnectionConfig>(
                    connection.connection_config.clone(),
                )
                .map_err(|error| {
                    LpmError::Script(format!("invalid Railway connection: {error}"))
                })?;
                Ok(Self::Railway(railway::RailwayClient::new(
                    connection.token.clone(),
                    config,
                )?))
            }
            platform => Err(LpmError::Script(format!(
                "unsupported env platform '{platform}'; use vercel, coolify, railway, or github-actions"
            ))),
        }
    }

    fn display_name(&self) -> &'static str {
        match self {
            Self::Vercel(_) => "Vercel",
            Self::Coolify(_) => "Coolify",
            Self::GitHubActions(_) => "GitHub Actions",
            Self::Railway(_) => "Railway",
        }
    }

    fn linked_env(&self) -> Option<&str> {
        match self {
            Self::Vercel(client) => client.config.linked_env.as_deref(),
            Self::Coolify(client) => client.config().linked_env.as_deref(),
            Self::GitHubActions(client) => client.config().linked_env.as_deref(),
            Self::Railway(client) => client.config().linked_env.as_deref(),
        }
    }

    fn is_managed(&self, key: &str) -> bool {
        match self {
            Self::Vercel(_) => is_vercel_managed_variable(key),
            Self::Coolify(_) => coolify::CoolifyClient::is_managed(key),
            Self::GitHubActions(_) => false,
            Self::Railway(_) => railway::RailwayClient::is_managed(key),
        }
    }

    fn partition_local(
        &self,
        project_dir: &std::path::Path,
        local: &HashMap<String, String>,
    ) -> Result<LocalPlatformValues, LpmError> {
        match self {
            Self::GitHubActions(_) => {
                let config = lpm_runner::lpm_json::read_lpm_json(project_dir).map_err(|error| {
                    LpmError::Script(format!(
                        "failed to read lpm.json for GitHub Actions value classification: {error}"
                    ))
                })?;
                github_actions::partition_local_values(
                    local,
                    config
                        .as_ref()
                        .and_then(|configuration| configuration.env_schema.as_ref()),
                )
            }
            _ => Ok(LocalPlatformValues {
                readable: local.clone(),
                write_only: HashMap::new(),
            }),
        }
    }

    fn secret_verification(&self) -> &'static str {
        match self {
            Self::GitHubActions(_) => "names_only",
            _ => "exact",
        }
    }

    async fn list(&self) -> Result<PlatformState, LpmError> {
        match self {
            Self::Vercel(client) => client.list().await.map(PlatformState::from_readable),
            Self::Coolify(client) => client.list().await.map(PlatformState::from_readable),
            Self::GitHubActions(client) => client.list().await,
            Self::Railway(client) => client.list().await.map(PlatformState::from_readable),
        }
    }

    async fn apply(
        &self,
        diff: &PlatformDiff,
        local: &LocalPlatformValues,
        remote: &PlatformState,
        clean: bool,
    ) -> Result<PlatformPushResult, PlatformApplyError> {
        match self {
            Self::Vercel(client) => client.apply(diff, &local.readable, &remote.readable).await,
            Self::Coolify(client) => client.apply(diff, &local.readable, &remote.readable).await,
            Self::GitHubActions(client) => client.apply(diff, local, remote, clean).await,
            Self::Railway(client) => client
                .apply(diff, &local.readable, &remote.readable, clean)
                .await
                .map_err(PlatformApplyError::untracked),
        }
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
    client: &PlatformClient,
    remote: &PlatformState,
    local: &LocalPlatformValues,
    clean: bool,
) -> PlatformDiff {
    let mut added = Vec::new();
    let mut changed = Vec::new();
    let mut unchanged = Vec::new();
    for (key, value) in &local.readable {
        if client.is_managed(key) {
            continue;
        }
        match remote.readable.get(key) {
            None => added.push(key.clone()),
            Some(existing) if existing.value != *value => changed.push(key.clone()),
            Some(_) => unchanged.push(key.clone()),
        }
    }

    let mut removed: Vec<String> = remote
        .readable
        .keys()
        .filter(|key| {
            !client.is_managed(key)
                && (local.write_only.contains_key(*key)
                    || (clean && !local.readable.contains_key(*key)))
        })
        .cloned()
        .collect();
    let mut write_only_added = Vec::new();
    let mut write_only_present = Vec::new();
    for key in local.write_only.keys() {
        if remote.write_only.contains(key) {
            write_only_present.push(key.clone());
        } else {
            write_only_added.push(key.clone());
        }
    }
    let mut write_only_removed: Vec<String> = remote
        .write_only
        .iter()
        .filter(|key| {
            local.readable.contains_key(*key) || (clean && !local.write_only.contains_key(*key))
        })
        .cloned()
        .collect();
    added.sort_unstable();
    changed.sort_unstable();
    removed.sort_unstable();
    unchanged.sort_unstable();
    write_only_added.sort_unstable();
    write_only_present.sort_unstable();
    write_only_removed.sort_unstable();
    PlatformDiff {
        added,
        changed,
        removed,
        unchanged,
        write_only_added,
        write_only_present,
        write_only_removed,
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
    let client = lpm_http::client_builder()
        .build()
        .map_err(|error| LpmError::Network(format!("failed to build LPM client: {error}")))?;
    let response = client
        .post(format!("{registry_url}/api/vault/platforms/credentials"))
        .bearer_auth(auth_token)
        .json(&request_body)
        .timeout(PLATFORM_TIMEOUT)
        .send()
        .await
        .map_err(|error| {
            LpmError::Network(format!(
                "failed to reach LPM: {}",
                lpm_http::display_error(&error)
            ))
        })?;
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
    let client = lpm_http::client_builder()
        .build()
        .map_err(|error| LpmError::Network(format!("failed to build LPM client: {error}")))?;
    let response = client
        .post(format!("{registry_url}/api/vault/platforms/audit"))
        .bearer_auth(auth_token)
        .json(&body)
        .timeout(PLATFORM_TIMEOUT)
        .send()
        .await
        .map_err(|error| {
            LpmError::Network(format!(
                "failed to record env audit: {}",
                lpm_http::display_error(&error)
            ))
        })?;
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

fn validate_connect_field(
    flag: &str,
    value: &str,
    max_chars: usize,
    required: bool,
) -> Result<(), LpmError> {
    if required && value.is_empty() {
        return Err(LpmError::Script(format!("{flag} cannot be empty")));
    }
    if value.chars().count() > max_chars {
        return Err(LpmError::Script(format!(
            "{flag} must be at most {max_chars} characters"
        )));
    }
    Ok(())
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
        LpmError::Script(
            "usage: lpm env connect <vercel|coolify|railway|github-actions> [platform options] [--token=<token>]"
                .into(),
        )
    })?;
    let label = parse_flag(args, "--label");
    let linked_env = resolve_env_name(project_dir, parse_flag(args, "--linked-env"))?;
    let display_name = match platform {
        "vercel" => "Vercel",
        "coolify" => "Coolify",
        "github-actions" => "GitHub Actions",
        "railway" => "Railway",
        _ => {
            return Err(LpmError::Script(format!(
                "unsupported env platform '{platform}'; use vercel, coolify, railway, or github-actions"
            )));
        }
    };
    let platform_token = if let Some(token) = parse_flag(args, "--token") {
        token.to_owned()
    } else {
        cliclack::password(format!("Paste {display_name} API token"))
            .interact()
            .map_err(|error| LpmError::Script(format!("prompt failed: {error}")))?
    };
    if platform_token.is_empty() {
        return Err(LpmError::Script("--token cannot be empty".into()));
    }
    validate_connect_field("--token", &platform_token, PLATFORM_TOKEN_MAX_CHARS, true)?;
    if let Some(label) = label {
        validate_connect_field("--label", label, PLATFORM_LABEL_MAX_CHARS, false)?;
    }
    if let Some(linked_env) = &linked_env {
        validate_connect_field("--linked-env", linked_env, LINKED_ENV_MAX_CHARS, true)?;
    }

    let (client, config, target_description) = match platform {
        "vercel" => {
            let project_id = parse_flag(args, "--project")
                .filter(|value| !value.is_empty())
                .ok_or_else(|| LpmError::Script("missing --project flag".into()))?;
            validate_connect_field("--project", project_id, VERCEL_ID_MAX_CHARS, true)?;
            let team_id = parse_flag(args, "--team")
                .map(|value| {
                    validate_connect_field("--team", value, VERCEL_ID_MAX_CHARS, true)?;
                    Ok::<String, LpmError>(value.to_owned())
                })
                .transpose()?;
            let config = VercelConnectionConfig {
                project_id: project_id.to_owned(),
                team_id,
                target: parse_targets(parse_flag(args, "--target"))?,
                linked_env,
            };
            let client =
                PlatformClient::Vercel(VercelClient::new(platform_token.clone(), config.clone())?);
            (
                client,
                serde_json::to_value(config).map_err(|error| {
                    LpmError::Script(format!("failed to serialize Vercel connection: {error}"))
                })?,
                format!("project: {project_id}"),
            )
        }
        "coolify" => {
            let url = parse_flag(args, "--url")
                .filter(|value| !value.is_empty())
                .ok_or_else(|| LpmError::Script("missing --url flag".into()))?;
            validate_connect_field("--url", url, COOLIFY_URL_MAX_CHARS, true)?;
            let application_id = parse_flag(args, "--application")
                .filter(|value| !value.is_empty())
                .ok_or_else(|| LpmError::Script("missing --application flag".into()))?;
            validate_connect_field(
                "--application",
                application_id,
                COOLIFY_APPLICATION_ID_MAX_CHARS,
                true,
            )?;
            let config = coolify::CoolifyConnectionConfig {
                url: url.to_owned(),
                application_id: application_id.to_owned(),
                preview: args.contains(&"--preview"),
                linked_env,
            };
            let coolify_client = coolify::CoolifyClient::new(platform_token.clone(), config)?;
            let config = serde_json::to_value(coolify_client.config()).map_err(|error| {
                LpmError::Script(format!("failed to serialize Coolify connection: {error}"))
            })?;
            let client = PlatformClient::Coolify(coolify_client);
            (client, config, format!("application: {application_id}"))
        }
        "github-actions" => {
            let repository = parse_flag(args, "--repository")
                .filter(|value| !value.is_empty())
                .ok_or_else(|| LpmError::Script("missing --repository flag".into()))?;
            let environment = parse_flag(args, "--environment").map(str::to_owned);
            let github_client = github_actions::GitHubActionsClient::discover_config(
                platform_token.clone(),
                repository,
                environment,
                linked_env,
            )
            .await?;
            let config = serde_json::to_value(github_client.config()).map_err(|error| {
                LpmError::Script(format!(
                    "failed to serialize GitHub Actions connection: {error}"
                ))
            })?;
            let target = if let Some(environment) = &github_client.config().environment {
                format!(
                    "repository: {}, environment: {environment}",
                    github_client.config().repository
                )
            } else {
                format!(
                    "repository: {}, repository scope",
                    github_client.config().repository
                )
            };
            (PlatformClient::GitHubActions(github_client), config, target)
        }
        "railway" => {
            let project_id = parse_flag(args, "--project")
                .filter(|value| !value.is_empty())
                .ok_or_else(|| LpmError::Script("missing --project flag".into()))?;
            validate_connect_field("--project", project_id, RAILWAY_ID_MAX_CHARS, true)?;
            let environment_id = parse_flag(args, "--environment")
                .filter(|value| !value.is_empty())
                .ok_or_else(|| LpmError::Script("missing --environment flag".into()))?;
            validate_connect_field("--environment", environment_id, RAILWAY_ID_MAX_CHARS, true)?;
            let service_id = parse_flag(args, "--service")
                .map(|value| {
                    validate_connect_field("--service", value, RAILWAY_ID_MAX_CHARS, true)?;
                    Ok::<String, LpmError>(value.to_owned())
                })
                .transpose()?;
            let config = railway::RailwayConnectionConfig {
                project_id: project_id.to_owned(),
                environment_id: environment_id.to_owned(),
                service_id,
                project_token: args.contains(&"--project-token"),
                linked_env,
            };
            let client = PlatformClient::Railway(railway::RailwayClient::new(
                platform_token.clone(),
                config.clone(),
            )?);
            let config = serde_json::to_value(config).map_err(|error| {
                LpmError::Script(format!("failed to serialize Railway connection: {error}"))
            })?;
            let target = if let Some(service_id) = parse_flag(args, "--service") {
                format!(
                    "project: {project_id}, environment: {environment_id}, service: {service_id}"
                )
            } else {
                format!("project: {project_id}, environment: {environment_id}, shared variables")
            };
            (client, config, target)
        }
        _ => unreachable!("supported platform validated above"),
    };
    if !json_output {
        output::info(&format!(
            "verifying the {display_name} connection directly..."
        ));
    }
    client.list().await?;

    let vault_id =
        lpm_vault::vault_id::get_or_create_vault_id(project_dir).map_err(LpmError::Script)?;
    let (registry_url, auth_token) = super::auth::get_platform_auth(json_output).await?;
    let client = lpm_http::client_builder()
        .build()
        .map_err(|error| LpmError::Network(format!("failed to build LPM client: {error}")))?;
    let response = client
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
        .map_err(|error| {
            LpmError::Network(format!(
                "failed to save connection: {}",
                lpm_http::display_error(&error)
            ))
        })?;
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
        output::success_line(crate::install_ui::terminal_line!(
            "{} {} ({})",
            display_name,
            install_ui::bold(status),
            target_description
        ));
    }
    Ok(())
}

pub(super) async fn vars_platform_push(
    args: &[&str],
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
    let platform = parse_flag(args, "--to").ok_or_else(|| {
        LpmError::Script("missing --to flag. Usage: lpm env push --to <platform>".into())
    })?;
    if !is_supported_platform(platform) {
        return Err(LpmError::Script(
            "unsupported env platform; use vercel, coolify, railway, or github-actions".into(),
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
        .ok_or_else(|| LpmError::Script(format!("No {platform} connection found")))?;
    let client = PlatformClient::from_connection(&connection)?;
    let display_name = client.display_name();
    let requested_env = parse_flag(args, "--env").or(client.linked_env());
    let resolved_env = resolve_env_name(project_dir, requested_env)?;
    let local = lpm_runner::dotenv::load_project_env(project_dir, resolved_env.as_deref())?;
    let local = client.partition_local(project_dir, &local)?;

    if !json_output {
        output::info(&format!(
            "comparing local env values with {display_name}..."
        ));
    }
    let remote = client.list().await?;
    let diff = compute_diff(&client, &remote, &local, clean);
    let orphan_count = if clean {
        0
    } else {
        let readable = remote
            .readable
            .keys()
            .filter(|key| !local.readable.contains_key(*key) && !client.is_managed(key))
            .count();
        let write_only = remote
            .write_only
            .iter()
            .filter(|key| !local.write_only.contains_key(*key))
            .count();
        readable + write_only
    };
    if !diff.has_push_mutations() {
        if json_output {
            super::response::print_json_value(&serde_json::json!({
                "success": true,
                "status": "no_changes",
                "platform": platform,
                "orphans": orphan_count,
                "secretVerification": client.secret_verification(),
            }));
        } else {
            output::success(&format!("{display_name} is already in sync"));
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
            println!(
                "{}",
                install_ui::terminal_line!(
                    "  {} {} {}",
                    install_ui::green("+"),
                    install_ui::bold(key),
                    install_ui::dim("(new)"),
                )
            );
        }
        for key in &diff.changed {
            println!(
                "{}",
                install_ui::terminal_line!(
                    "  {} {} {}",
                    install_ui::yellow("~"),
                    install_ui::bold(key),
                    install_ui::dim("(changed)"),
                )
            );
        }
        for key in &diff.write_only_added {
            println!(
                "{}",
                install_ui::terminal_line!(
                    "  {} {} {}",
                    install_ui::green("+"),
                    install_ui::bold(key),
                    install_ui::dim("(new write-only secret)"),
                )
            );
        }
        for key in &diff.write_only_present {
            println!(
                "{}",
                install_ui::terminal_line!(
                    "  {} {} {}",
                    install_ui::yellow("~"),
                    install_ui::bold(key),
                    install_ui::dim("(write-only secret will be refreshed)"),
                )
            );
        }
        for key in &diff.removed {
            println!(
                "{}",
                install_ui::terminal_line!(
                    "  {} {} {}",
                    install_ui::red("-"),
                    install_ui::bold(key),
                    install_ui::dim("(will be removed)"),
                )
            );
        }
        for key in &diff.write_only_removed {
            println!(
                "{}",
                install_ui::terminal_line!(
                    "  {} {} {}",
                    install_ui::red("-"),
                    install_ui::bold(key),
                    install_ui::dim("(write-only secret will be removed)"),
                )
            );
        }
        if !diff.unchanged.is_empty() {
            println!("  {} {} unchanged", "=".dimmed(), diff.unchanged.len());
        }
        println!();
    }

    if !yes && !json_output {
        let confirmed = cliclack::confirm(format!(
            "Push {} added, {} changed, {} removed to {display_name}?",
            diff.added_count(),
            diff.updated_count(),
            diff.removed_count()
        ))
        .initial_value(false)
        .interact()
        .map_err(|error| LpmError::Script(format!("prompt failed: {error}")))?;
        if !confirmed {
            output::info("cancelled");
            return Ok(());
        }
    }

    let env_name = resolved_env.as_deref().unwrap_or("default");
    let result = match client.apply(&diff, &local, &remote, clean).await {
        Ok(result) => result,
        Err(error) => {
            if let PlatformApplyError::Tracked { applied, .. } = &error {
                let _ = record_platform_audit(
                    &registry_url,
                    &auth_token,
                    serde_json::json!({
                        "vaultId": vault_id,
                        "platform": platform,
                        "operation": "push_failed",
                        "env": env_name,
                        "added": applied.added,
                        "updated": applied.updated,
                        "removed": applied.removed,
                    }),
                )
                .await;
            }
            return Err(error.into_error());
        }
    };
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
            "secretVerification": client.secret_verification(),
            "auditRecorded": audit.is_ok(),
        }));
    } else {
        output::success(&format!(
            "{display_name} synced — {} added, {} updated, {} removed",
            result.added, result.updated, result.removed
        ));
        if let Err(error) = audit {
            output::warn(&format!(
                "{display_name} was updated, but LPM could not record the audit entry: {error}"
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
            output::warn(
                "no platform connections. Run `lpm env connect vercel`, `lpm env connect coolify`, `lpm env connect railway`, or `lpm env connect github-actions` first.",
            );
        }
        return Ok(());
    }

    let mut statuses = Vec::with_capacity(connections.len());
    for connection in connections {
        let label = connection.label.clone();
        let last_push_at = connection.last_push_at.clone();
        let client = match PlatformClient::from_connection(&connection) {
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
        let env_name = client.linked_env().unwrap_or("default");
        let mode = (env_name != "default").then_some(env_name);
        let loaded_local = match lpm_runner::dotenv::load_project_env(project_dir, mode) {
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
        let local = match client.partition_local(project_dir, &loaded_local) {
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
                let diff = compute_diff(&client, &remote, &local, true);
                let drift_keys = diff.drift_keys();
                let status = if diff.has_known_drift() {
                    "drifted"
                } else if client.secret_verification() == "names_only"
                    && !diff.write_only_present.is_empty()
                {
                    "names_only"
                } else {
                    "synced"
                };
                statuses.push(serde_json::json!({
                    "platform": connection.platform,
                    "label": label,
                    "env": env_name,
                    "status": status,
                    "added": diff.added_count(),
                    "changed": diff.changed.len(),
                    "removed": diff.removed_count(),
                    "secretVerification": client.secret_verification(),
                    "secretNamesPresent": diff.write_only_present.len(),
                    "secretNamesMissing": diff.write_only_added.len(),
                    "secretNamesExtra": diff.write_only_removed.len(),
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
                "{}",
                install_ui::terminal_line!(
                    "  {} {} [{}]  {}",
                    install_ui::green("✓"),
                    install_ui::bold(platform),
                    env,
                    install_ui::green("synced"),
                )
            ),
            "names_only" => println!(
                "{}",
                install_ui::terminal_line!(
                    "  {} {} [{}]  {}",
                    install_ui::green("✓"),
                    install_ui::bold(platform),
                    env,
                    install_ui::yellow(
                        "variables synced; secret names verified (values are write-only)"
                    ),
                )
            ),
            "drifted" => println!(
                "{}",
                install_ui::terminal_line!(
                    "  {} {} [{}]  {} — +{} ~{} -{}",
                    install_ui::yellow("!"),
                    install_ui::bold(platform),
                    env,
                    install_ui::yellow("drifted"),
                    status["added"].as_u64().unwrap_or(0),
                    status["changed"].as_u64().unwrap_or(0),
                    status["removed"].as_u64().unwrap_or(0),
                )
            ),
            _ => println!(
                "{}",
                install_ui::terminal_line!(
                    "  {} {} [{}]  {}",
                    install_ui::red("✗"),
                    install_ui::bold(platform),
                    env,
                    install_ui::red(status["error"].as_str().unwrap_or("unknown error")),
                )
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
        LpmError::Script("missing --from flag. Usage: lpm env pull --from <platform>".into())
    })?;
    if !is_supported_platform(platform) {
        return Err(LpmError::Script(
            "unsupported env platform; use vercel, coolify, railway, or github-actions".into(),
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
        .ok_or_else(|| LpmError::Script(format!("No {platform} connection found")))?;
    let client = PlatformClient::from_connection(&connection)?;
    let display_name = client.display_name();
    let requested_env = parse_flag(args, "--env").or(client.linked_env());
    let resolved_env = resolve_env_name(project_dir, requested_env)?;
    let env_name = resolved_env.as_deref().unwrap_or("default");
    if !json_output {
        output::info(&format!(
            "pulling env values directly from {display_name}..."
        ));
    }
    let remote = client.list().await?;
    let skipped_secrets = remote.write_only.len();
    if remote.readable.is_empty() {
        let status = if skipped_secrets > 0 {
            "no_readable_values"
        } else {
            "no_values"
        };
        if json_output {
            super::response::print_json_value(&serde_json::json!({
                "success": true,
                "status": status,
                "platform": platform,
                "env": env_name,
                "count": 0,
                "skippedSecrets": skipped_secrets,
                "secretVerification": client.secret_verification(),
            }));
        } else {
            if skipped_secrets > 0 {
                output::warn(&format!(
                    "no readable env values found on {display_name}; {skipped_secrets} write-only secret name(s) were skipped"
                ));
            } else {
                output::warn(&format!("no env values found on {display_name}"));
            }
        }
        return Ok(());
    }

    let mut values = remote
        .readable
        .into_iter()
        .map(|(key, variable)| (key, variable.value))
        .collect::<Vec<_>>();
    values.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    if !json_output {
        println!();
        for (key, _) in &values {
            println!(
                "{}",
                install_ui::terminal_line!("    {}", install_ui::bold(key))
            );
        }
        println!();
    }
    if !yes && !json_output {
        let confirmed = cliclack::confirm(crate::prompt::untrusted(format!(
            "Import {} value(s) from {display_name} into {env_name}?",
            values.len()
        )))
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
            "skippedSecrets": skipped_secrets,
            "secretVerification": client.secret_verification(),
            "auditRecorded": audit.is_ok(),
        }));
    } else {
        output::success(&format!(
            "imported {} value(s) from {display_name} into {env_name}",
            pairs.len()
        ));
        if skipped_secrets > 0 {
            output::warn(&format!(
                "{skipped_secrets} write-only GitHub Actions secret name(s) were not imported"
            ));
        }
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
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn remote(entries: &[(&str, &str)]) -> PlatformState {
        PlatformState::from_readable(
            entries
                .iter()
                .map(|(key, value)| {
                    (
                        (*key).to_string(),
                        PlatformVariable {
                            id: format!("id-{key}"),
                            value: (*value).to_string(),
                            scope: VariableScope::Vercel {
                                targets: vec!["production".into()],
                            },
                        },
                    )
                })
                .collect(),
        )
    }

    fn local(entries: &[(&str, &str)]) -> LocalPlatformValues {
        LocalPlatformValues {
            readable: entries
                .iter()
                .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
                .collect(),
            write_only: HashMap::new(),
        }
    }

    fn vercel_client(targets: &[&str]) -> VercelClient {
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

    fn vercel_client_at(api_url: String) -> VercelClient {
        VercelClient {
            http: reqwest::Client::new(),
            api_url,
            token: "test-token".into(),
            config: VercelConnectionConfig {
                project_id: "test-project".into(),
                team_id: None,
                target: Some(vec!["production".into()]),
                linked_env: None,
            },
        }
    }

    fn platform_client(targets: &[&str]) -> PlatformClient {
        PlatformClient::Vercel(vercel_client(targets))
    }

    #[test]
    fn platform_apply_error_preserves_original_error_classification() {
        let error = PlatformApplyError::tracked(
            LpmError::Network("connection reset".into()),
            PlatformPushResult::default(),
        )
        .into_error();

        assert_eq!(error.error_code(), "network");
        assert_eq!(error.to_string(), "network error: connection reset");
    }

    #[test]
    fn diff_preserves_platform_only_values_without_clean() {
        let remote = remote(&[("UNCHANGED", "same"), ("ORPHAN", "remote")]);
        let local = local(&[("UNCHANGED", "same"), ("NEW", "new")]);

        let diff = compute_diff(&platform_client(&["production"]), &remote, &local, false);

        assert_eq!(diff.added, ["NEW"]);
        assert!(diff.removed.is_empty());
        assert_eq!(diff.unchanged, ["UNCHANGED"]);
    }

    #[test]
    fn diff_removes_platform_only_values_with_clean() {
        let remote = remote(&[("ORPHAN", "remote")]);

        let diff = compute_diff(
            &platform_client(&["production"]),
            &remote,
            &LocalPlatformValues::default(),
            true,
        );

        assert_eq!(diff.removed, ["ORPHAN"]);
    }

    #[test]
    fn diff_moves_values_between_readable_and_write_only_namespaces() {
        let mut remote = remote(&[("BECAME_SECRET", "stale-plaintext")]);
        remote.write_only.insert("BECAME_PUBLIC".into());
        let local = LocalPlatformValues {
            readable: HashMap::from([("BECAME_PUBLIC".into(), "public-value".into())]),
            write_only: HashMap::from([("BECAME_SECRET".into(), "secret-value".into())]),
        };

        let diff = compute_diff(&platform_client(&["production"]), &remote, &local, false);

        assert_eq!(diff.added, ["BECAME_PUBLIC"]);
        assert_eq!(diff.removed, ["BECAME_SECRET"]);
        assert_eq!(diff.write_only_added, ["BECAME_SECRET"]);
        assert_eq!(diff.write_only_removed, ["BECAME_PUBLIC"]);
    }

    #[test]
    fn managed_vercel_values_never_enter_the_diff() {
        let remote = remote(&[("VERCEL_URL", "remote")]);
        let local = local(&[("VERCEL_ENV", "production")]);

        let diff = compute_diff(&platform_client(&["production"]), &remote, &local, true);

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
        let variable = PlatformVariable {
            id: "shared-id".into(),
            value: "secret".into(),
            scope: VariableScope::Vercel {
                targets: vec!["production".into(), "preview".into()],
            },
        };

        let error = vercel_client(&["production"])
            .assert_mutation_targets("SHARED", &variable)
            .expect_err("a production sync must not mutate a preview value");

        assert!(error.to_string().contains("configured deployment targets"));
    }

    #[tokio::test]
    async fn vercel_add_response_failure_is_counted_when_the_desired_value_exists() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v10/projects/test-project/env"))
            .respond_with(ResponseTemplate::new(503))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v10/projects/test-project/env"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "envs": [{
                    "id": "new-id",
                    "key": "NEW_SECRET",
                    "value": "new-value",
                    "target": ["production"]
                }]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let client = vercel_client_at(server.uri());
        let diff = PlatformDiff {
            added: vec!["NEW_SECRET".into()],
            ..PlatformDiff::default()
        };
        let local = HashMap::from([("NEW_SECRET".into(), "new-value".into())]);

        let result = client
            .apply(&diff, &local, &HashMap::new())
            .await
            .expect("final provider state proves the add committed");

        assert_eq!(result.added, 1);
    }

    #[tokio::test]
    async fn vercel_update_response_failure_is_counted_when_the_desired_value_exists() {
        let server = MockServer::start().await;
        Mock::given(method("PATCH"))
            .and(path("/v9/projects/test-project/env/id-CHANGED"))
            .respond_with(ResponseTemplate::new(503))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v10/projects/test-project/env"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "envs": [{
                    "id": "id-CHANGED",
                    "key": "CHANGED",
                    "value": "new-value",
                    "target": ["production"]
                }]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let client = vercel_client_at(server.uri());
        let diff = PlatformDiff {
            changed: vec!["CHANGED".into()],
            ..PlatformDiff::default()
        };
        let local = HashMap::from([("CHANGED".into(), "new-value".into())]);
        let remote = remote(&[("CHANGED", "old-value")]);

        let result = client
            .apply(&diff, &local, &remote)
            .await
            .expect("final provider state proves the update committed");

        assert_eq!(result.updated, 1);
    }

    #[tokio::test]
    async fn vercel_delete_response_failure_is_counted_when_the_value_is_absent() {
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/v9/projects/test-project/env/id-REMOVED"))
            .respond_with(ResponseTemplate::new(503))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v10/projects/test-project/env"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "envs": []
            })))
            .expect(1)
            .mount(&server)
            .await;
        let client = vercel_client_at(server.uri());
        let diff = PlatformDiff {
            removed: vec!["REMOVED".into()],
            ..PlatformDiff::default()
        };
        let remote = remote(&[("REMOVED", "old-value")]);

        let result = client
            .apply(&diff, &HashMap::new(), &remote)
            .await
            .expect("final provider state proves the delete committed");

        assert_eq!(result.removed, 1);
    }

    #[tokio::test]
    async fn vercel_mutation_suppresses_exact_counts_when_final_state_cannot_be_read() {
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/v9/projects/test-project/env/id-REMOVED"))
            .respond_with(ResponseTemplate::new(503))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v10/projects/test-project/env"))
            .respond_with(ResponseTemplate::new(503))
            .expect(1)
            .mount(&server)
            .await;
        let client = vercel_client_at(server.uri());
        let diff = PlatformDiff {
            removed: vec!["REMOVED".into()],
            ..PlatformDiff::default()
        };
        let remote = remote(&[("REMOVED", "old-value")]);

        let error = client
            .apply(&diff, &HashMap::new(), &remote)
            .await
            .expect_err("unreadable final state must suppress exact mutation counts");

        assert!(matches!(error, PlatformApplyError::Untracked(_)));
    }

    #[test]
    fn connect_field_validation_matches_server_bounds() {
        validate_connect_field("--application", "app-123", 128, true)
            .expect("valid field must pass");

        let empty =
            validate_connect_field("--application", "", 128, true).expect_err("empty must fail");
        let oversized = validate_connect_field("--application", &"a".repeat(129), 128, true)
            .expect_err("oversized field must fail");

        assert!(empty.to_string().contains("cannot be empty"));
        assert!(oversized.to_string().contains("at most 128 characters"));
    }
}
