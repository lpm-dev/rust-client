mod coolify;
mod fly;
mod github_actions;
mod railway;

use super::prelude::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use futures::StreamExt;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

const VERCEL_API_URL: &str = "https://api.vercel.com";
const PLATFORM_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const PLATFORM_MUTATION_CONCURRENCY: usize = 8;
const PLATFORM_STATUS_CONCURRENCY: usize = 8;
const PLATFORM_TOKEN_MAX_CHARS: usize = 10_000;
const PLATFORM_LABEL_MAX_CHARS: usize = 100;
const LINKED_ENV_MAX_CHARS: usize = 64;
const VERCEL_ID_MAX_CHARS: usize = 100;
const COOLIFY_URL_MAX_CHARS: usize = 2048;
const COOLIFY_APPLICATION_ID_MAX_CHARS: usize = 128;
const RAILWAY_ID_MAX_CHARS: usize = 128;
const PLATFORM_REQUEST_NONCE_HEADER: &str = "X-LPM-Platform-Request-Nonce";
const PLATFORM_REQUEST_NONCE_BYTES: usize = 32;

type SharedEnvironment = std::sync::Arc<HashMap<String, String>>;
type StatusEnvironmentCache<E> = HashMap<String, Result<SharedEnvironment, E>>;

fn is_supported_platform(platform: &str) -> bool {
    matches!(
        platform,
        "vercel" | "coolify" | "fly" | "railway" | "github-actions"
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
    id: String,
    platform: String,
    token: String,
    connection_config: serde_json::Value,
    label: Option<String>,
    last_push_at: Option<String>,
}

#[derive(Clone, Copy)]
enum PlatformRequestScope<'a> {
    Personal,
    Organization(&'a str),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct PlatformEnvelopeContext {
    request_nonce: String,
    vault_id: String,
    platform: Option<String>,
    scope: String,
    principal_id: String,
    organization_slug: Option<String>,
}

impl PlatformEnvelopeContext {
    fn validate(
        &self,
        expected_nonce: &str,
        expected_vault_id: &str,
        expected_platform: Option<&str>,
        expected_scope: PlatformRequestScope<'_>,
        expected_principal_id: Option<&str>,
    ) -> Result<(), LpmError> {
        if self.request_nonce != expected_nonce {
            return Err(LpmError::Script(
                "platform response does not match the request nonce".into(),
            ));
        }
        if self.vault_id != expected_vault_id {
            return Err(LpmError::Script(
                "platform response is bound to a different vault".into(),
            ));
        }
        if self.platform.as_deref() != expected_platform {
            return Err(LpmError::Script(
                "platform response is bound to a different platform selector".into(),
            ));
        }
        if self.principal_id.is_empty()
            || self.principal_id.len() > 128
            || self.principal_id.chars().any(char::is_control)
            || expected_principal_id.is_some_and(|expected| expected != self.principal_id)
        {
            return Err(LpmError::Script(
                "platform response is bound to a different principal".into(),
            ));
        }
        match expected_scope {
            PlatformRequestScope::Personal
                if self.scope != "personal" || self.organization_slug.is_some() =>
            {
                Err(LpmError::Script(
                    "platform response has a mismatched personal scope".into(),
                ))
            }
            PlatformRequestScope::Organization(slug)
                if self.scope != "organization"
                    || self.organization_slug.as_deref() != Some(slug) =>
            {
                Err(LpmError::Script(
                    "platform response has a mismatched organization scope".into(),
                ))
            }
            _ => Ok(()),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct PlatformConnectResponse {
    #[serde(flatten)]
    context: PlatformEnvelopeContext,
    status: String,
    connection_id: String,
    label: Option<String>,
}

impl PlatformConnectResponse {
    fn validate(&self) -> Result<(), LpmError> {
        if !matches!(self.status.as_str(), "created" | "updated") {
            return Err(LpmError::Script(
                "platform connect response has an unexpected status".into(),
            ));
        }
        if self.connection_id.is_empty()
            || self.connection_id.len() > 128
            || self.connection_id.chars().any(char::is_control)
        {
            return Err(LpmError::Script(
                "platform connect response omitted a valid connection ID".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PlatformCredentialsResponse {
    #[serde(flatten)]
    context: PlatformEnvelopeContext,
    connections: Vec<PlatformConnection>,
}

impl PlatformCredentialsResponse {
    fn validate_connections(&self, expected_platform: Option<&str>) -> Result<(), LpmError> {
        if expected_platform.is_some() && self.connections.len() != 1 {
            return Err(LpmError::Script(
                "platform response did not contain exactly one requested connection".into(),
            ));
        }
        let mut ids = HashSet::with_capacity(self.connections.len());
        let mut platforms = HashSet::with_capacity(self.connections.len());
        for connection in &self.connections {
            if connection.id.is_empty()
                || connection.id.len() > 128
                || connection.id.chars().any(char::is_control)
                || !ids.insert(connection.id.as_str())
            {
                return Err(LpmError::Script(
                    "platform response contained an invalid connection ID".into(),
                ));
            }
            if !is_supported_platform(&connection.platform)
                || !platforms.insert(connection.platform.as_str())
                || expected_platform.is_some_and(|expected| expected != connection.platform)
            {
                return Err(LpmError::Script(
                    "platform response contained a mismatched connection".into(),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PlatformAuditResponse {
    #[serde(flatten)]
    context: PlatformEnvelopeContext,
    operation: String,
    status: String,
    connection_id: String,
}

struct PlatformAuditExpectation<'a> {
    vault_id: &'a str,
    platform: &'a str,
    operation: &'a str,
    scope: PlatformRequestScope<'a>,
    principal_id: Option<&'a str>,
}

impl PlatformAuditResponse {
    fn validate_operation(
        &self,
        expected_operation: &str,
        expected_connection_id: &str,
    ) -> Result<(), LpmError> {
        if self.operation != expected_operation
            || self.status != "recorded"
            || self.connection_id != expected_connection_id
        {
            return Err(LpmError::Script(
                "platform audit response does not match the recorded operation".into(),
            ));
        }
        Ok(())
    }
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

enum PlatformLocalValues {
    Exact(std::sync::Arc<HashMap<String, String>>),
    Partitioned(LocalPlatformValues),
}

impl PlatformLocalValues {
    fn readable(&self) -> &HashMap<String, String> {
        match self {
            Self::Exact(values) => values,
            Self::Partitioned(values) => &values.readable,
        }
    }

    fn write_only(&self) -> &HashMap<String, String> {
        static EMPTY: std::sync::LazyLock<HashMap<String, String>> =
            std::sync::LazyLock::new(HashMap::new);
        match self {
            Self::Exact(_) => &EMPTY,
            Self::Partitioned(values) => &values.write_only,
        }
    }

    fn compute_diff(
        &self,
        client: &PlatformClient,
        remote: &PlatformState,
        clean: bool,
    ) -> PlatformDiff {
        compute_diff_from_maps(client, remote, self.readable(), self.write_only(), clean)
    }
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
        let mut seen_cursors = HashSet::new();
        let mut response_budget = super::response::PlatformResponseBudget::new();
        let mut received_items = 0usize;

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
            let (status, body) =
                read_platform_response_with_budget(response, &mut response_budget).await?;
            if !status.is_success() {
                return Err(vercel_api_error("list", status, &body));
            }
            let data: VercelListResponse = serde_json::from_slice(&body)
                .map_err(|error| LpmError::Script(format!("invalid Vercel response: {error}")))?;
            received_items = received_items.saturating_add(data.envs.len());
            if received_items > 10_000 {
                return Err(LpmError::Script(
                    "Vercel returned more than 10000 env values; refusing an unbounded sync".into(),
                ));
            }
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

            let next_cursor = data
                .pagination
                .and_then(|pagination| pagination.next)
                .and_then(json_scalar_string);
            let Some(next_cursor) = next_cursor else {
                return Ok(variables);
            };
            if !seen_cursors.insert(next_cursor.clone()) {
                return Err(LpmError::Script(
                    "Vercel repeated an env pagination cursor; refusing a pagination cycle".into(),
                ));
            }
            cursor = Some(next_cursor);
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
    Fly(fly::FlyClient),
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
            "fly" => {
                let config = serde_json::from_value::<fly::FlyConnectionConfig>(
                    connection.connection_config.clone(),
                )
                .map_err(|error| LpmError::Script(format!("invalid Fly.io connection: {error}")))?;
                Ok(Self::Fly(fly::FlyClient::new(
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
                "unsupported env platform '{platform}'; use vercel, coolify, fly, railway, or github-actions"
            ))),
        }
    }

    fn display_name(&self) -> &'static str {
        match self {
            Self::Vercel(_) => "Vercel",
            Self::Coolify(_) => "Coolify",
            Self::Fly(_) => "Fly.io",
            Self::GitHubActions(_) => "GitHub Actions",
            Self::Railway(_) => "Railway",
        }
    }

    fn linked_env(&self) -> Option<&str> {
        match self {
            Self::Vercel(client) => client.config.linked_env.as_deref(),
            Self::Coolify(client) => client.config().linked_env.as_deref(),
            Self::Fly(client) => client.config().linked_env.as_deref(),
            Self::GitHubActions(client) => client.config().linked_env.as_deref(),
            Self::Railway(client) => client.config().linked_env.as_deref(),
        }
    }

    fn is_managed(&self, key: &str) -> bool {
        match self {
            Self::Vercel(_) => is_vercel_managed_variable(key),
            Self::Coolify(_) => coolify::CoolifyClient::is_managed(key),
            Self::Fly(_) => fly::FlyClient::is_managed(key),
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
            Self::Fly(_) => Ok(fly::partition_local_values(local)),
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
            _ => Err(LpmError::Script(
                "exact-readable platforms do not partition local values".into(),
            )),
        }
    }

    fn prepare_local(
        &self,
        project_dir: &std::path::Path,
        local: std::sync::Arc<HashMap<String, String>>,
    ) -> Result<PlatformLocalValues, LpmError> {
        match self {
            Self::Fly(_) | Self::GitHubActions(_) => self
                .partition_local(project_dir, &local)
                .map(PlatformLocalValues::Partitioned),
            _ => Ok(PlatformLocalValues::Exact(local)),
        }
    }

    fn secret_verification(&self) -> &'static str {
        match self {
            Self::Fly(_) | Self::GitHubActions(_) => "names_only",
            _ => "exact",
        }
    }

    async fn list(&self) -> Result<PlatformState, LpmError> {
        match self {
            Self::Vercel(client) => client.list().await.map(PlatformState::from_readable),
            Self::Coolify(client) => client.list().await.map(PlatformState::from_readable),
            Self::Fly(client) => client.list().await,
            Self::GitHubActions(client) => client.list().await,
            Self::Railway(client) => client.list().await.map(PlatformState::from_readable),
        }
    }

    async fn apply(
        &self,
        diff: &PlatformDiff,
        local: &PlatformLocalValues,
        remote: &PlatformState,
        clean: bool,
    ) -> Result<PlatformPushResult, PlatformApplyError> {
        match (self, local) {
            (Self::Vercel(client), _) => {
                client.apply(diff, local.readable(), &remote.readable).await
            }
            (Self::Coolify(client), _) => {
                client.apply(diff, local.readable(), &remote.readable).await
            }
            (Self::Fly(client), PlatformLocalValues::Partitioned(local)) => {
                client.apply(diff, local, remote, clean).await
            }
            (Self::GitHubActions(client), PlatformLocalValues::Partitioned(local)) => {
                client.apply(diff, local, remote, clean).await
            }
            (Self::Railway(client), _) => client
                .apply(diff, local.readable(), &remote.readable, clean)
                .await
                .map_err(PlatformApplyError::untracked),
            _ => Err(PlatformApplyError::untracked(LpmError::Script(
                "platform local-value classification is inconsistent".into(),
            ))),
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

#[cfg(test)]
fn compute_diff(
    client: &PlatformClient,
    remote: &PlatformState,
    local: &LocalPlatformValues,
    clean: bool,
) -> PlatformDiff {
    compute_diff_from_maps(client, remote, &local.readable, &local.write_only, clean)
}

fn compute_diff_from_maps(
    client: &PlatformClient,
    remote: &PlatformState,
    readable: &HashMap<String, String>,
    write_only: &HashMap<String, String>,
    clean: bool,
) -> PlatformDiff {
    let mut added = Vec::new();
    let mut changed = Vec::new();
    let mut unchanged = Vec::new();
    for (key, value) in readable {
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
                && (write_only.contains_key(*key) || (clean && !readable.contains_key(*key)))
        })
        .cloned()
        .collect();
    let mut write_only_added = Vec::new();
    let mut write_only_present = Vec::new();
    for key in write_only.keys() {
        if remote.write_only.contains(key) {
            write_only_present.push(key.clone());
        } else {
            write_only_added.push(key.clone());
        }
    }
    let mut write_only_removed: Vec<String> = remote
        .write_only
        .iter()
        .filter(|key| readable.contains_key(*key) || (clean && !write_only.contains_key(*key)))
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

async fn read_platform_response_with_budget(
    response: reqwest::Response,
    budget: &mut super::response::PlatformResponseBudget,
) -> Result<(reqwest::StatusCode, Vec<u8>), LpmError> {
    let status = response.status();
    let body = super::response::read_capped_platform_body_with_budget(response, budget).await?;
    Ok((status, body))
}

async fn read_signed_lpm_response(
    response: reqwest::Response,
) -> Result<(reqwest::StatusCode, Vec<u8>), LpmError> {
    let status = response.status();
    let key_id = response
        .headers()
        .get(lpm_vault::signature::KEY_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let signature = response
        .headers()
        .get(lpm_vault::signature::SIGNATURE_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    #[cfg(all(debug_assertions, not(test)))]
    let local_development =
        lpm_vault::signature::is_local_development_key(response.url(), key_id.as_deref());
    let body = super::response::read_capped_platform_body(response).await?;
    if status.is_success() {
        #[cfg(not(test))]
        let verification = {
            #[cfg(debug_assertions)]
            if local_development {
                lpm_vault::signature::verify_response_with_test_key(
                    status.as_u16(),
                    &body,
                    key_id.as_deref(),
                    signature.as_deref(),
                )
            } else {
                lpm_vault::signature::verify_response(
                    status.as_u16(),
                    &body,
                    key_id.as_deref(),
                    signature.as_deref(),
                )
            }
            #[cfg(not(debug_assertions))]
            lpm_vault::signature::verify_response(
                status.as_u16(),
                &body,
                key_id.as_deref(),
                signature.as_deref(),
            )
        };
        #[cfg(test)]
        let verification = lpm_vault::signature::verify_response_with_test_key(
            status.as_u16(),
            &body,
            key_id.as_deref(),
            signature.as_deref(),
        );
        verification.map_err(|error| LpmError::Script(error.to_string()))?;
    }
    Ok((status, body))
}

fn generate_platform_request_nonce() -> Result<String, LpmError> {
    let mut nonce = [0u8; PLATFORM_REQUEST_NONCE_BYTES];
    rand::thread_rng()
        .try_fill_bytes(&mut nonce)
        .map_err(|error| {
            LpmError::Script(format!(
                "failed to generate platform request nonce: {error}"
            ))
        })?;
    Ok(URL_SAFE_NO_PAD.encode(nonce))
}

fn response_error(status: reqwest::StatusCode, body: &[u8], fallback: &str) -> LpmError {
    if status == reqwest::StatusCode::UNAUTHORIZED {
        return LpmError::AuthRequired;
    }
    let message = serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|value| value["error"].as_str().map(str::to_owned))
        .unwrap_or_else(|| format!("{fallback} (HTTP {status})"));
    LpmError::Script(message)
}

async fn fetch_connections_with_recovery(
    registry_client: &lpm_registry::RegistryClient,
    vault_id: &str,
    platform: Option<&str>,
    org_slug: Option<&str>,
    expected_principal_id: Option<&str>,
) -> Result<PlatformCredentialsResponse, LpmError> {
    let vault_id = vault_id.to_owned();
    let platform = platform.map(str::to_owned);
    let org_slug = org_slug.map(str::to_owned);
    let expected_principal_id = expected_principal_id.map(str::to_owned);
    super::auth::execute_lpm_with_bearer(registry_client, |registry_url, auth_token| {
        let vault_id = vault_id.clone();
        let platform = platform.clone();
        let org_slug = org_slug.clone();
        let expected_principal_id = expected_principal_id.clone();
        async move {
            fetch_connections(
                &registry_url,
                &auth_token,
                &vault_id,
                platform.as_deref(),
                request_scope(org_slug.as_deref()),
                expected_principal_id.as_deref(),
            )
            .await
        }
    })
    .await
}

async fn fetch_platform_context_with_recovery(
    registry_client: &lpm_registry::RegistryClient,
    vault_id: &str,
    platform: &str,
    org_slug: Option<&str>,
    expected_principal_id: Option<&str>,
) -> Result<PlatformEnvelopeContext, LpmError> {
    let vault_id = vault_id.to_owned();
    let platform = platform.to_owned();
    let org_slug = org_slug.map(str::to_owned);
    let expected_principal_id = expected_principal_id.map(str::to_owned);
    super::auth::execute_lpm_with_bearer(registry_client, |registry_url, auth_token| {
        let vault_id = vault_id.clone();
        let platform = platform.clone();
        let org_slug = org_slug.clone();
        let expected_principal_id = expected_principal_id.clone();
        async move {
            fetch_platform_context(
                &registry_url,
                &auth_token,
                &vault_id,
                &platform,
                request_scope(org_slug.as_deref()),
                expected_principal_id.as_deref(),
            )
            .await
        }
    })
    .await
}

async fn save_platform_connection(
    registry_url: &str,
    auth_token: &str,
    body: &serde_json::Value,
    vault_id: &str,
    platform: &str,
    scope: PlatformRequestScope<'_>,
    expected_principal_id: &str,
) -> Result<PlatformConnectResponse, LpmError> {
    let request_nonce = generate_platform_request_nonce()?;
    let client = lpm_http::client_builder()
        .build()
        .map_err(|error| LpmError::Network(format!("failed to build LPM client: {error}")))?;
    let response = client
        .post(format!("{registry_url}/api/vault/platforms/connect"))
        .bearer_auth(auth_token)
        .header(PLATFORM_REQUEST_NONCE_HEADER, &request_nonce)
        .json(body)
        .timeout(PLATFORM_TIMEOUT)
        .send()
        .await
        .map_err(|error| {
            LpmError::Network(format!(
                "failed to save connection: {}",
                lpm_http::display_error(&error)
            ))
        })?;
    let (status, body) = read_signed_lpm_response(response).await?;
    if !status.is_success() {
        return Err(response_error(status, &body, "connection failed"));
    }
    let response: PlatformConnectResponse = serde_json::from_slice(&body)
        .map_err(|error| LpmError::Script(format!("invalid LPM response: {error}")))?;
    response.context.validate(
        &request_nonce,
        vault_id,
        Some(platform),
        scope,
        Some(expected_principal_id),
    )?;
    response.validate()?;
    Ok(response)
}

async fn record_platform_audit_with_recovery(
    registry_client: &lpm_registry::RegistryClient,
    mut body: serde_json::Value,
    org_slug: Option<&str>,
    expected_principal_id: Option<&str>,
) -> Result<(), LpmError> {
    let vault_id = body
        .get("vaultId")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| LpmError::Script("platform audit omitted the vault ID".into()))?
        .to_owned();
    let platform = body
        .get("platform")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| LpmError::Script("platform audit omitted the platform".into()))?
        .to_owned();
    let operation = body
        .get("operation")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| LpmError::Script("platform audit omitted the operation".into()))?
        .to_owned();
    if let Some(org_slug) = org_slug {
        body["org"] = org_slug.into();
    }
    let org_slug = org_slug.map(str::to_owned);
    let expected_principal_id = expected_principal_id.map(str::to_owned);
    super::auth::execute_lpm_with_bearer(registry_client, |registry_url, auth_token| {
        let body = body.clone();
        let vault_id = vault_id.clone();
        let platform = platform.clone();
        let operation = operation.clone();
        let org_slug = org_slug.clone();
        let expected_principal_id = expected_principal_id.clone();
        async move {
            record_platform_audit(
                &registry_url,
                &auth_token,
                body,
                PlatformAuditExpectation {
                    vault_id: &vault_id,
                    platform: &platform,
                    operation: &operation,
                    scope: request_scope(org_slug.as_deref()),
                    principal_id: expected_principal_id.as_deref(),
                },
            )
            .await
        }
    })
    .await
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
    scope: PlatformRequestScope<'_>,
    expected_principal_id: Option<&str>,
) -> Result<PlatformCredentialsResponse, LpmError> {
    let request_nonce = generate_platform_request_nonce()?;
    let mut request_body = serde_json::json!({ "vaultId": vault_id });
    if let Some(platform) = platform {
        request_body["platform"] = serde_json::Value::String(platform.to_owned());
    }
    if let PlatformRequestScope::Organization(org_slug) = scope {
        request_body["org"] = serde_json::Value::String(org_slug.to_owned());
    }
    let client = lpm_http::client_builder()
        .build()
        .map_err(|error| LpmError::Network(format!("failed to build LPM client: {error}")))?;
    let response = client
        .post(format!("{registry_url}/api/vault/platforms/credentials"))
        .bearer_auth(auth_token)
        .header(PLATFORM_REQUEST_NONCE_HEADER, &request_nonce)
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
    let (status, body) = read_signed_lpm_response(response).await?;
    if !status.is_success() {
        return Err(response_error(
            status,
            &body,
            "failed to load platform connection",
        ));
    }
    let data: PlatformCredentialsResponse = serde_json::from_slice(&body)
        .map_err(|error| LpmError::Script(format!("invalid LPM response: {error}")))?;
    data.context.validate(
        &request_nonce,
        vault_id,
        platform,
        scope,
        expected_principal_id,
    )?;
    data.validate_connections(platform)?;
    Ok(data)
}

async fn fetch_platform_context(
    registry_url: &str,
    auth_token: &str,
    vault_id: &str,
    platform: &str,
    scope: PlatformRequestScope<'_>,
    expected_principal_id: Option<&str>,
) -> Result<PlatformEnvelopeContext, LpmError> {
    let request_nonce = generate_platform_request_nonce()?;
    let mut request_body = serde_json::json!({
        "vaultId": vault_id,
        "platform": platform,
        "contextOnly": true,
    });
    if let PlatformRequestScope::Organization(org_slug) = scope {
        request_body["org"] = serde_json::Value::String(org_slug.to_owned());
    }
    let client = lpm_http::client_builder()
        .build()
        .map_err(|error| LpmError::Network(format!("failed to build LPM client: {error}")))?;
    let response = client
        .post(format!("{registry_url}/api/vault/platforms/credentials"))
        .bearer_auth(auth_token)
        .header(PLATFORM_REQUEST_NONCE_HEADER, &request_nonce)
        .json(&request_body)
        .timeout(PLATFORM_TIMEOUT)
        .send()
        .await
        .map_err(|error| {
            LpmError::Network(format!(
                "failed to verify the LPM platform identity: {}",
                lpm_http::display_error(&error)
            ))
        })?;
    let (status, body) = read_signed_lpm_response(response).await?;
    if !status.is_success() {
        return Err(response_error(
            status,
            &body,
            "failed to verify the LPM platform identity",
        ));
    }
    let response: PlatformCredentialsResponse = serde_json::from_slice(&body)
        .map_err(|error| LpmError::Script(format!("invalid LPM response: {error}")))?;
    response.context.validate(
        &request_nonce,
        vault_id,
        Some(platform),
        scope,
        expected_principal_id,
    )?;
    if !response.connections.is_empty() {
        return Err(LpmError::Script(
            "platform identity response unexpectedly included credentials".into(),
        ));
    }
    Ok(response.context)
}

async fn record_platform_audit(
    registry_url: &str,
    auth_token: &str,
    mut body: serde_json::Value,
    expected: PlatformAuditExpectation<'_>,
) -> Result<(), LpmError> {
    let expected_connection_id = body
        .get("connectionId")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 128)
        .ok_or_else(|| LpmError::Script("platform audit omitted the connection ID".into()))?
        .to_owned();
    let expected_principal_id = expected
        .principal_id
        .ok_or_else(|| LpmError::Script("platform audit omitted the captured principal".into()))?;
    body["expectedPrincipalId"] = expected_principal_id.into();
    let request_nonce = generate_platform_request_nonce()?;
    let client = lpm_http::client_builder()
        .build()
        .map_err(|error| LpmError::Network(format!("failed to build LPM client: {error}")))?;
    let response = client
        .post(format!("{registry_url}/api/vault/platforms/audit"))
        .bearer_auth(auth_token)
        .header(PLATFORM_REQUEST_NONCE_HEADER, &request_nonce)
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
    let (status, body) = read_signed_lpm_response(response).await?;
    if !status.is_success() {
        return Err(response_error(status, &body, "failed to record env audit"));
    }
    let response: PlatformAuditResponse = serde_json::from_slice(&body)
        .map_err(|error| LpmError::Script(format!("invalid LPM response: {error}")))?;
    response.context.validate(
        &request_nonce,
        expected.vault_id,
        Some(expected.platform),
        expected.scope,
        Some(expected_principal_id),
    )?;
    response.validate_operation(expected.operation, &expected_connection_id)?;
    Ok(())
}

fn validate_platform_arguments(
    args: &[&str],
    value_flags: &[&str],
    boolean_flags: &[&str],
    usage: &str,
) -> Result<(), LpmError> {
    let mut seen = HashSet::new();
    let mut index = 0;
    while index < args.len() {
        let argument = args[index];
        if boolean_flags.contains(&argument) {
            if !seen.insert(argument) {
                return Err(LpmError::Script(usage.into()));
            }
            index += 1;
            continue;
        }
        if let Some((flag, value)) = argument.split_once('=') {
            if !value_flags.contains(&flag) || value.is_empty() || !seen.insert(flag) {
                return Err(LpmError::Script(usage.into()));
            }
            index += 1;
            continue;
        }
        if value_flags.contains(&argument) {
            if !seen.insert(argument) {
                return Err(LpmError::Script(usage.into()));
            }
            let Some(value) = args.get(index + 1) else {
                return Err(LpmError::Script(usage.into()));
            };
            if value.starts_with('-') {
                return Err(LpmError::Script(usage.into()));
            }
            index += 2;
            continue;
        }
        return Err(LpmError::Script(format!(
            "unknown platform argument: {argument}. {usage}"
        )));
    }
    Ok(())
}

fn reject_duplicate_confirmation_aliases(args: &[&str], usage: &str) -> Result<(), LpmError> {
    if args.contains(&"--yes") && args.contains(&"-y") {
        return Err(LpmError::Script(usage.into()));
    }
    Ok(())
}

pub(super) fn validate_platform_push_arguments(args: &[&str], usage: &str) -> Result<(), LpmError> {
    validate_platform_arguments(
        args,
        &["--to", "--org", "--env"],
        &["--clean", "--yes", "-y"],
        usage,
    )?;
    reject_duplicate_confirmation_aliases(args, usage)
}

pub(super) fn validate_platform_pull_arguments(args: &[&str], usage: &str) -> Result<(), LpmError> {
    validate_platform_arguments(args, &["--from", "--org", "--env"], &["--yes", "-y"], usage)?;
    reject_duplicate_confirmation_aliases(args, usage)
}

fn validate_platform_status_arguments(args: &[&str], usage: &str) -> Result<(), LpmError> {
    validate_platform_arguments(args, &["--org"], &[], usage)
}

fn validate_platform_connect_arguments(
    platform: &str,
    args: &[&str],
    usage: &str,
) -> Result<(), LpmError> {
    let common = ["--org", "--token", "--label", "--linked-env"];
    let (platform_values, booleans): (&[&str], &[&str]) = match platform {
        "vercel" => (&["--project", "--team", "--target"], &[]),
        "coolify" => (&["--url", "--application"], &["--preview"]),
        "fly" => (&["--app"], &[]),
        "github-actions" => (&["--repository", "--environment"], &[]),
        "railway" => (
            &["--project", "--environment", "--service"],
            &["--project-token"],
        ),
        _ => return Err(LpmError::Script(usage.into())),
    };
    let mut values = Vec::with_capacity(common.len() + platform_values.len());
    values.extend_from_slice(&common);
    values.extend_from_slice(platform_values);
    validate_platform_arguments(args, &values, booleans, usage)
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

fn parse_platform_org<'a>(args: &'a [&str], usage: &str) -> Result<Option<&'a str>, LpmError> {
    let mut organization = None;
    let mut index = 0;
    while index < args.len() {
        let argument = args[index];
        if argument == "--org" {
            index += 1;
            let slug = super::remote::parse_org_slug_value(args.get(index).copied(), usage)?;
            if organization.replace(slug).is_some() {
                return Err(LpmError::Script(usage.into()));
            }
        } else if let Some(slug) = argument.strip_prefix("--org=") {
            let slug = super::remote::parse_org_slug_value(Some(slug), usage)?;
            if organization.replace(slug).is_some() {
                return Err(LpmError::Script(usage.into()));
            }
        }
        index += 1;
    }
    Ok(organization)
}

fn request_scope(org_slug: Option<&str>) -> PlatformRequestScope<'_> {
    org_slug.map_or(
        PlatformRequestScope::Personal,
        PlatformRequestScope::Organization,
    )
}

fn expected_platform_principal(
    project_dir: &std::path::Path,
    registry_url: &str,
    org_slug: Option<&str>,
) -> Result<Option<String>, LpmError> {
    let manifest = super::sync_payload::CloudManifestSnapshot::read(project_dir)?;
    let principal = if let Some(slug) = org_slug {
        manifest
            .vault
            .org_sync_principal_for_registry(slug, registry_url)
            .map_err(LpmError::Script)?
    } else {
        manifest
            .vault
            .personal_expected_principal_for_registry(registry_url)
            .map_err(LpmError::Script)?
    };
    if org_slug.is_some() && principal.is_none() {
        return Err(LpmError::Script(
            "this checkout has no authenticated binding for that organization; pull or share the organization env project first"
                .into(),
        ));
    }
    Ok(principal)
}

fn required_platform_principal(
    project_dir: &std::path::Path,
    registry_url: &str,
    org_slug: Option<&str>,
) -> Result<String, LpmError> {
    expected_platform_principal(project_dir, registry_url, org_slug)?.ok_or_else(|| {
        LpmError::Script(
            "this checkout has no authenticated personal platform binding; reconnect the platform before using stored credentials"
                .into(),
        )
    })
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
    let config = lpm_runner::lpm_json::read_lpm_json(project_dir).map_err(LpmError::Script)?;
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
    registry_client: &lpm_registry::RegistryClient,
    args: &[&str],
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
    const USAGE: &str =
        "usage: lpm env connect <platform> [platform options] [--org <org-slug>] [--token=<token>]";
    let platform = args.first().copied().ok_or_else(|| {
        LpmError::Script(
            "usage: lpm env connect <vercel|coolify|fly|railway|github-actions> [platform options] [--token=<token>]"
                .into(),
        )
    })?;
    let org_slug = parse_platform_org(args, USAGE)?;
    let label = parse_flag(args, "--label");
    let linked_env = resolve_env_name(project_dir, parse_flag(args, "--linked-env"))?;
    let display_name = match platform {
        "vercel" => "Vercel",
        "coolify" => "Coolify",
        "fly" => "Fly.io",
        "github-actions" => "GitHub Actions",
        "railway" => "Railway",
        _ => {
            return Err(LpmError::Script(format!(
                "unsupported env platform '{platform}'; use vercel, coolify, fly, railway, or github-actions"
            )));
        }
    };
    validate_platform_connect_arguments(platform, &args[1..], USAGE)?;
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

    let vault_id =
        lpm_vault::vault_id::get_or_create_vault_id(project_dir).map_err(LpmError::Script)?;
    let expected_principal_id =
        expected_platform_principal(project_dir, registry_client.base_url(), org_slug)?;
    let platform_context = fetch_platform_context_with_recovery(
        registry_client,
        &vault_id,
        platform,
        org_slug,
        expected_principal_id.as_deref(),
    )
    .await?;
    let expected_principal_id = platform_context.principal_id;

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
        "fly" => {
            let app = parse_flag(args, "--app")
                .filter(|value| !value.is_empty())
                .ok_or_else(|| LpmError::Script("missing --app flag".into()))?;
            fly::validate_app_name(app)?;
            let fly_client =
                fly::FlyClient::discover_config(platform_token.clone(), app, linked_env).await?;
            let config = serde_json::to_value(fly_client.config()).map_err(|error| {
                LpmError::Script(format!("failed to serialize Fly.io connection: {error}"))
            })?;
            let target = format!(
                "app: {}, organization: {}",
                fly_client.config().app,
                fly_client.config().organization_slug
            );
            (PlatformClient::Fly(fly_client), config, target)
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

    let mut connection_body = serde_json::json!({
        "vaultId": vault_id,
        "platform": platform,
        "token": platform_token,
        "connectionConfig": config,
        "label": label,
        "expectedPrincipalId": expected_principal_id,
    });
    if let Some(org_slug) = org_slug {
        connection_body["org"] = org_slug.into();
    }
    let platform = platform.to_owned();
    let org_slug = org_slug.map(str::to_owned);
    let result =
        super::auth::execute_lpm_with_bearer(registry_client, |registry_url, auth_token| {
            let connection_body = connection_body.clone();
            let vault_id = vault_id.clone();
            let platform = platform.clone();
            let org_slug = org_slug.clone();
            let expected_principal_id = expected_principal_id.clone();
            async move {
                save_platform_connection(
                    &registry_url,
                    &auth_token,
                    &connection_body,
                    &vault_id,
                    &platform,
                    request_scope(org_slug.as_deref()),
                    &expected_principal_id,
                )
                .await
            }
        })
        .await?;
    if org_slug.is_none() {
        lpm_vault::vault_id::pin_personal_platform_principal_if_vault_matches(
            project_dir,
            &vault_id,
            lpm_vault::vault_id::SyncPrincipal {
                registry_url: registry_client.base_url(),
                principal_id: &result.context.principal_id,
            },
        )
        .map_err(LpmError::Script)?;
    }
    if json_output {
        super::response::print_json_value(&super::response::success_envelope(serde_json::json!({
            "status": result.status,
            "platform": platform,
        })));
    } else {
        let status = result.status.as_str();
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
    registry_client: &lpm_registry::RegistryClient,
    args: &[&str],
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
    const USAGE: &str = "usage: lpm env push --to <platform> [--org <org-slug>] [--env <environment>] [--clean] [--yes]";
    validate_platform_push_arguments(args, USAGE)?;
    let platform = parse_flag(args, "--to").ok_or_else(|| {
        LpmError::Script("missing --to flag. Usage: lpm env push --to <platform>".into())
    })?;
    let org_slug = parse_platform_org(args, USAGE)?;
    if !is_supported_platform(platform) {
        return Err(LpmError::Script(
            "unsupported env platform; use vercel, coolify, fly, railway, or github-actions".into(),
        ));
    }
    let clean = args.contains(&"--clean");
    let yes = args.iter().any(|arg| matches!(*arg, "--yes" | "-y"));
    let vault_id = lpm_vault::vault_id::read_vault_id(project_dir).ok_or_else(|| {
        LpmError::Script("no env project configured. Run `lpm env set` first".into())
    })?;
    let expected_principal_id = Some(required_platform_principal(
        project_dir,
        registry_client.base_url(),
        org_slug,
    )?);
    let mut credentials = fetch_connections_with_recovery(
        registry_client,
        &vault_id,
        Some(platform),
        org_slug,
        expected_principal_id.as_deref(),
    )
    .await?;
    let connection = credentials
        .connections
        .pop()
        .ok_or_else(|| LpmError::Script(format!("No {platform} connection found")))?;
    let connection_id = connection.id.clone();
    let client = PlatformClient::from_connection(&connection)?;
    let display_name = client.display_name();
    let requested_env = parse_flag(args, "--env").or(client.linked_env());
    let resolved_env = resolve_env_name(project_dir, requested_env)?;
    let local = std::sync::Arc::new(lpm_runner::dotenv::load_project_env(
        project_dir,
        resolved_env.as_deref(),
    )?);
    let local = client.prepare_local(project_dir, local)?;

    if !json_output {
        output::info(&format!(
            "comparing local env values with {display_name}..."
        ));
    }
    let remote = client.list().await?;
    let diff = local.compute_diff(&client, &remote, clean);
    let orphan_count = if clean {
        0
    } else {
        let readable = remote
            .readable
            .keys()
            .filter(|key| !local.readable().contains_key(*key) && !client.is_managed(key))
            .count();
        let write_only = remote
            .write_only
            .iter()
            .filter(|key| !local.write_only().contains_key(*key))
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
                let _ = record_platform_audit_with_recovery(
                    registry_client,
                    serde_json::json!({
                        "vaultId": vault_id,
                        "connectionId": connection_id,
                        "platform": platform,
                        "operation": "push_failed",
                        "env": env_name,
                        "added": applied.added,
                        "updated": applied.updated,
                        "removed": applied.removed,
                    }),
                    org_slug,
                    expected_principal_id.as_deref(),
                )
                .await;
            }
            return Err(error.into_error());
        }
    };
    let audit = record_platform_audit_with_recovery(
        registry_client,
        serde_json::json!({
            "vaultId": vault_id,
            "connectionId": connection_id,
            "platform": platform,
            "operation": "push",
            "env": env_name,
            "added": result.added,
            "updated": result.updated,
            "removed": result.removed,
        }),
        org_slug,
        expected_principal_id.as_deref(),
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

fn cached_status_environment<E>(
    cache: &mut StatusEnvironmentCache<E>,
    env_name: &str,
    load: impl FnOnce(Option<&str>) -> Result<HashMap<String, String>, E>,
) -> Result<SharedEnvironment, E>
where
    E: Clone,
{
    let mode = (env_name != "default").then_some(env_name);
    cache
        .entry(env_name.to_owned())
        .or_insert_with(|| load(mode).map(std::sync::Arc::new))
        .clone()
}

async fn collect_ordered_bounded<F, T>(
    jobs: impl IntoIterator<Item = F>,
    concurrency: usize,
) -> Vec<T>
where
    F: std::future::Future<Output = T>,
{
    futures::stream::iter(jobs)
        .buffered(concurrency.max(1))
        .collect()
        .await
}

pub(super) async fn vars_platform_status(
    registry_client: &lpm_registry::RegistryClient,
    args: &[&str],
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
    const USAGE: &str = "usage: lpm env status [--org <org-slug>]";
    validate_platform_status_arguments(args, USAGE)?;
    let org_slug = parse_platform_org(args, USAGE)?;
    let vault_id = lpm_vault::vault_id::read_vault_id(project_dir).ok_or_else(|| {
        LpmError::Script("no env project configured. Run `lpm env set` first".into())
    })?;
    let expected_principal_id = Some(required_platform_principal(
        project_dir,
        registry_client.base_url(),
        org_slug,
    )?);
    let credentials = fetch_connections_with_recovery(
        registry_client,
        &vault_id,
        None,
        org_slug,
        expected_principal_id.as_deref(),
    )
    .await?;
    let connections = credentials.connections;
    if connections.is_empty() {
        if json_output {
            super::response::print_json_value(&serde_json::json!({
                "success": true,
                "platforms": [],
                "count": 0,
            }));
        } else {
            output::warn(
                "no platform connections. Run `lpm env connect vercel`, `lpm env connect coolify`, `lpm env connect fly`, `lpm env connect railway`, or `lpm env connect github-actions` first.",
            );
        }
        return Ok(());
    }

    struct ReadyWork {
        platform: String,
        label: Option<String>,
        last_push_at: Option<String>,
        env_name: String,
        client: PlatformClient,
        local: PlatformLocalValues,
    }

    enum Work {
        Immediate(serde_json::Value),
        Ready(Box<ReadyWork>),
    }

    let mut prepared = Vec::with_capacity(connections.len());
    let mut local_cache = HashMap::new();
    for connection in connections {
        let label = connection.label.clone();
        let last_push_at = connection.last_push_at.clone();
        let client = match PlatformClient::from_connection(&connection) {
            Ok(client) => client,
            Err(error) => {
                prepared.push(Work::Immediate(serde_json::json!({
                    "platform": connection.platform,
                    "label": label,
                    "status": "error",
                    "error": error.to_string(),
                    "lastPushAt": last_push_at,
                })));
                continue;
            }
        };
        let env_name = client.linked_env().unwrap_or("default").to_owned();
        let loaded_local = match cached_status_environment(&mut local_cache, &env_name, |mode| {
            lpm_runner::dotenv::load_project_env(project_dir, mode)
                .map_err(|error| error.to_string())
        }) {
            Ok(local) => local,
            Err(error) => {
                prepared.push(Work::Immediate(serde_json::json!({
                    "platform": connection.platform,
                    "label": label,
                    "env": env_name,
                    "status": "error",
                    "error": error,
                    "lastPushAt": last_push_at,
                })));
                continue;
            }
        };
        let local = match client.prepare_local(project_dir, loaded_local) {
            Ok(local) => local,
            Err(error) => {
                prepared.push(Work::Immediate(serde_json::json!({
                    "platform": connection.platform,
                    "label": label,
                    "env": env_name,
                    "status": "error",
                    "error": error.to_string(),
                    "lastPushAt": last_push_at,
                })));
                continue;
            }
        };
        prepared.push(Work::Ready(Box::new(ReadyWork {
            platform: connection.platform,
            label,
            last_push_at,
            env_name,
            client,
            local,
        })));
    }

    let jobs = prepared.into_iter().map(|work| async move {
        match work {
            Work::Immediate(status) => status,
            Work::Ready(ready) => {
                let ReadyWork {
                    platform,
                    label,
                    last_push_at,
                    env_name,
                    client,
                    local,
                } = *ready;
                match client.list().await {
                    Ok(remote) => {
                        let diff = local.compute_diff(&client, &remote, true);
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
                        serde_json::json!({
                            "platform": platform,
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
                        })
                    }
                    Err(error) => serde_json::json!({
                        "platform": platform,
                        "label": label,
                        "env": env_name,
                        "status": "error",
                        "error": error.to_string(),
                        "lastPushAt": last_push_at,
                    }),
                }
            }
        }
    });
    let statuses = collect_ordered_bounded(jobs, PLATFORM_STATUS_CONCURRENCY).await;

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
    registry_client: &lpm_registry::RegistryClient,
    args: &[&str],
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
    const USAGE: &str =
        "usage: lpm env pull --from <platform> [--org <org-slug>] [--env <environment>] [--yes]";
    validate_platform_pull_arguments(args, USAGE)?;
    let platform = parse_flag(args, "--from").ok_or_else(|| {
        LpmError::Script("missing --from flag. Usage: lpm env pull --from <platform>".into())
    })?;
    let org_slug = parse_platform_org(args, USAGE)?;
    if !is_supported_platform(platform) {
        return Err(LpmError::Script(
            "unsupported env platform; use vercel, coolify, fly, railway, or github-actions".into(),
        ));
    }
    let yes = args.iter().any(|arg| matches!(*arg, "--yes" | "-y"));
    let vault_id =
        lpm_vault::vault_id::get_or_create_vault_id(project_dir).map_err(LpmError::Script)?;
    let expected_principal_id = Some(required_platform_principal(
        project_dir,
        registry_client.base_url(),
        org_slug,
    )?);
    let mut credentials = fetch_connections_with_recovery(
        registry_client,
        &vault_id,
        Some(platform),
        org_slug,
        expected_principal_id.as_deref(),
    )
    .await?;
    let connection = credentials
        .connections
        .pop()
        .ok_or_else(|| LpmError::Script(format!("No {platform} connection found")))?;
    let connection_id = connection.id.clone();
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
    let audit = record_platform_audit_with_recovery(
        registry_client,
        serde_json::json!({
            "vaultId": vault_id,
            "connectionId": connection_id,
            "platform": platform,
            "operation": "pull",
            "env": env_name,
            "imported": pairs.len(),
        }),
        org_slug,
        expected_principal_id.as_deref(),
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
                "{skipped_secrets} write-only {display_name} secret name(s) were not imported"
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
    use wiremock::matchers::{body_string_contains, method, path};
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

    const TEST_PLATFORM_AUTH_TOKEN: &str = "lpm-platform-test-token";
    const TEST_PLATFORM_NONCE_HEADER: &str = "x-lpm-platform-request-nonce";

    #[derive(Clone)]
    struct SignedConnectResponse;

    impl Respond for SignedConnectResponse {
        fn respond(&self, request: &Request) -> ResponseTemplate {
            let nonce = request
                .headers
                .get(TEST_PLATFORM_NONCE_HEADER)
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default();
            let body = serde_json::to_string(&serde_json::json!({
                "requestNonce": nonce,
                "vaultId": "vault-1",
                "platform": "vercel",
                "scope": "personal",
                "principalId": "user-1",
                "organizationSlug": null,
                "status": "created",
                "connectionId": "11111111-1111-4111-8111-111111111111",
                "label": null,
            }))
            .expect("test platform response should serialize");
            let (key_id, signature) =
                lpm_vault::signature::sign_response_for_test(200, body.as_bytes());
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "application/json")
                .insert_header(lpm_vault::signature::KEY_ID_HEADER, key_id.as_str())
                .insert_header(lpm_vault::signature::SIGNATURE_HEADER, signature.as_str())
                .set_body_string(body)
        }
    }

    #[derive(Clone)]
    struct SignedMismatchedCredentialsResponse;

    impl Respond for SignedMismatchedCredentialsResponse {
        fn respond(&self, request: &Request) -> ResponseTemplate {
            let nonce = request
                .headers
                .get(TEST_PLATFORM_NONCE_HEADER)
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default();
            let body = serde_json::to_string(&serde_json::json!({
                "requestNonce": nonce,
                "vaultId": "vault-1",
                "platform": "vercel",
                "scope": "personal",
                "principalId": "user-1",
                "organizationSlug": null,
                "connections": [{
                    "id": "11111111-1111-4111-8111-111111111111",
                    "platform": "railway",
                    "token": "platform-token",
                    "connectionConfig": {},
                    "label": null,
                    "lastPushAt": null,
                }],
            }))
            .expect("test platform response should serialize");
            let (key_id, signature) =
                lpm_vault::signature::sign_response_for_test(200, body.as_bytes());
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "application/json")
                .insert_header(lpm_vault::signature::KEY_ID_HEADER, key_id.as_str())
                .insert_header(lpm_vault::signature::SIGNATURE_HEADER, signature.as_str())
                .set_body_string(body)
        }
    }

    #[derive(Clone)]
    struct SignedMismatchedAuditResponse;

    impl Respond for SignedMismatchedAuditResponse {
        fn respond(&self, request: &Request) -> ResponseTemplate {
            let nonce = request
                .headers
                .get(TEST_PLATFORM_NONCE_HEADER)
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default();
            let body = serde_json::to_string(&serde_json::json!({
                "requestNonce": nonce,
                "vaultId": "vault-1",
                "platform": "vercel",
                "scope": "personal",
                "principalId": "user-1",
                "organizationSlug": null,
                "operation": "push",
                "status": "recorded",
                "connectionId": "22222222-2222-4222-8222-222222222222",
            }))
            .expect("test platform response should serialize");
            let (key_id, signature) =
                lpm_vault::signature::sign_response_for_test(200, body.as_bytes());
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "application/json")
                .insert_header(lpm_vault::signature::KEY_ID_HEADER, key_id.as_str())
                .insert_header(lpm_vault::signature::SIGNATURE_HEADER, signature.as_str())
                .set_body_string(body)
        }
    }

    #[derive(Clone)]
    struct SignedAuditResponse;

    impl Respond for SignedAuditResponse {
        fn respond(&self, request: &Request) -> ResponseTemplate {
            let nonce = request
                .headers
                .get(TEST_PLATFORM_NONCE_HEADER)
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default();
            let body = serde_json::to_string(&serde_json::json!({
                "requestNonce": nonce,
                "vaultId": "vault-1",
                "platform": "vercel",
                "scope": "personal",
                "principalId": "user-1",
                "organizationSlug": null,
                "operation": "push",
                "status": "recorded",
                "connectionId": "11111111-1111-4111-8111-111111111111",
            }))
            .expect("test platform response should serialize");
            let (key_id, signature) =
                lpm_vault::signature::sign_response_for_test(200, body.as_bytes());
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "application/json")
                .insert_header(lpm_vault::signature::KEY_ID_HEADER, key_id.as_str())
                .insert_header(lpm_vault::signature::SIGNATURE_HEADER, signature.as_str())
                .set_body_string(body)
        }
    }

    #[tokio::test]
    async fn save_platform_connection_sends_a_fresh_32_byte_request_nonce() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/vault/platforms/connect"))
            .respond_with(SignedConnectResponse)
            .expect(1)
            .mount(&server)
            .await;

        save_platform_connection(
            &server.uri(),
            TEST_PLATFORM_AUTH_TOKEN,
            &serde_json::json!({
                "vaultId": "vault-1",
                "platform": "vercel",
                "token": "platform-token",
                "connectionConfig": { "projectId": "project-1" },
                "label": null,
                "expectedPrincipalId": "user-1",
            }),
            "vault-1",
            "vercel",
            PlatformRequestScope::Personal,
            "user-1",
        )
        .await
        .expect("signed connection response should be accepted");

        let requests = server
            .received_requests()
            .await
            .expect("platform requests should be recorded");
        let nonce = requests[0]
            .headers
            .get(TEST_PLATFORM_NONCE_HEADER)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        assert!(
            nonce.len() == 43
                && nonce
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        );
    }

    #[tokio::test]
    async fn exact_platform_credentials_reject_an_inner_platform_substitution() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/vault/platforms/credentials"))
            .respond_with(SignedMismatchedCredentialsResponse)
            .expect(1)
            .mount(&server)
            .await;

        let result = fetch_connections(
            &server.uri(),
            TEST_PLATFORM_AUTH_TOKEN,
            "vault-1",
            Some("vercel"),
            PlatformRequestScope::Personal,
            Some("user-1"),
        )
        .await;

        assert!(result.is_err(), "accepted a substituted inner platform");
    }

    #[tokio::test]
    async fn platform_audit_rejects_a_substituted_connection_id() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/vault/platforms/audit"))
            .respond_with(SignedMismatchedAuditResponse)
            .expect(1)
            .mount(&server)
            .await;

        let result = record_platform_audit(
            &server.uri(),
            TEST_PLATFORM_AUTH_TOKEN,
            serde_json::json!({
                "vaultId": "vault-1",
                "platform": "vercel",
                "operation": "push",
                "connectionId": "11111111-1111-4111-8111-111111111111",
            }),
            PlatformAuditExpectation {
                vault_id: "vault-1",
                platform: "vercel",
                operation: "push",
                scope: PlatformRequestScope::Personal,
                principal_id: Some("user-1"),
            },
        )
        .await;

        assert!(result.is_err(), "accepted a substituted connection ID");
    }

    #[tokio::test]
    async fn platform_audit_sends_the_captured_principal() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/vault/platforms/audit"))
            .and(body_string_contains("\"expectedPrincipalId\":\"user-1\""))
            .respond_with(SignedAuditResponse)
            .expect(1)
            .mount(&server)
            .await;

        record_platform_audit(
            &server.uri(),
            TEST_PLATFORM_AUTH_TOKEN,
            serde_json::json!({
                "vaultId": "vault-1",
                "platform": "vercel",
                "operation": "push",
                "connectionId": "11111111-1111-4111-8111-111111111111",
            }),
            PlatformAuditExpectation {
                vault_id: "vault-1",
                platform: "vercel",
                operation: "push",
                scope: PlatformRequestScope::Personal,
                principal_id: Some("user-1"),
            },
        )
        .await
        .expect("platform audit should include the captured principal");
    }

    fn personal_platform_context() -> PlatformEnvelopeContext {
        PlatformEnvelopeContext {
            request_nonce: "request-nonce".into(),
            vault_id: "vault-1".into(),
            platform: Some("vercel".into()),
            scope: "personal".into(),
            principal_id: "user-1".into(),
            organization_slug: None,
        }
    }

    #[test]
    fn expected_platform_principal_reads_the_dedicated_personal_binding() {
        let project = tempfile::tempdir().expect("temporary project");
        std::fs::write(
            project.path().join("lpm.json"),
            r#"{
                "vault": "vault-1",
                "vaultSync": {
                    "personalPlatformBindings": {
                        "https://lpm.dev": {
                            "registryUrl": "https://lpm.dev",
                            "principalId": "account-a"
                        }
                    }
                }
            }"#,
        )
        .expect("seed platform principal binding");

        let principal = expected_platform_principal(project.path(), "https://lpm.dev", None)
            .expect("read platform principal binding");

        assert_eq!(principal.as_deref(), Some("account-a"));
    }

    #[test]
    fn stored_platform_credentials_require_a_personal_principal_binding() {
        let project = tempfile::tempdir().expect("temporary project");
        std::fs::write(project.path().join("lpm.json"), r#"{"vault":"vault-1"}"#)
            .expect("seed unbound project");

        let error = required_platform_principal(project.path(), "https://lpm.dev", None)
            .expect_err("unbound stored credentials must fail closed");

        assert!(error.to_string().contains("reconnect the platform"));
    }

    #[test]
    fn platform_response_context_rejects_bound_field_substitution() {
        let substitutions: [fn(&mut PlatformEnvelopeContext); 6] = [
            |context| context.request_nonce = "replayed-nonce".into(),
            |context| context.vault_id = "vault-2".into(),
            |context| context.platform = Some("railway".into()),
            |context| context.scope = "organization".into(),
            |context| context.principal_id = "user-2".into(),
            |context| context.organization_slug = Some("acme".into()),
        ];

        for substitute in substitutions {
            let mut context = personal_platform_context();
            substitute(&mut context);
            assert!(
                context
                    .validate(
                        "request-nonce",
                        "vault-1",
                        Some("vercel"),
                        PlatformRequestScope::Personal,
                        Some("user-1"),
                    )
                    .is_err()
            );
        }
    }

    #[test]
    fn organization_platform_context_requires_the_exact_slug_and_principal() {
        let context = PlatformEnvelopeContext {
            request_nonce: "request-nonce".into(),
            vault_id: "vault-1".into(),
            platform: None,
            scope: "organization".into(),
            principal_id: "organization-1".into(),
            organization_slug: Some("other".into()),
        };

        let error = context
            .validate(
                "request-nonce",
                "vault-1",
                None,
                PlatformRequestScope::Organization("acme"),
                Some("organization-1"),
            )
            .expect_err("a rebound organization slug must fail closed");

        assert!(error.to_string().contains("organization scope"));
    }

    #[test]
    fn platform_audit_response_requires_the_requested_operation_and_status() {
        let response = PlatformAuditResponse {
            context: personal_platform_context(),
            operation: "pull".into(),
            status: "recorded".into(),
            connection_id: "connection-1".into(),
        };

        response
            .validate_operation("push", "connection-1")
            .expect_err("a substituted audit operation must fail closed");
    }

    #[test]
    fn platform_organization_selector_rejects_missing_and_duplicate_values() {
        const USAGE: &str = "usage";
        for args in [
            &["--org"][..],
            &["--org", "--yes"][..],
            &["--org=acme", "--org", "other"][..],
        ] {
            assert!(
                parse_platform_org(args, USAGE).is_err(),
                "accepted {args:?}"
            );
        }
    }

    #[test]
    fn connect_and_status_reject_unknown_or_inapplicable_arguments() {
        const USAGE: &str = "usage";

        assert!(validate_platform_connect_arguments("vercel", &["--bogus"], USAGE).is_err());
        assert!(
            validate_platform_connect_arguments("fly", &["--project", "project-1"], USAGE).is_err()
        );
        assert!(validate_platform_status_arguments(&["--to", "vercel"], USAGE).is_err());
    }

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
    fn platform_status_loads_each_linked_environment_once() {
        let mut cache = HashMap::new();
        let mut load_count = 0;

        for _ in 0..3 {
            let values = cached_status_environment(&mut cache, "production", |_| {
                load_count += 1;
                Ok::<_, String>(HashMap::from([("TOKEN".into(), "value".into())]))
            })
            .expect("environment should load");
            assert_eq!(values.get("TOKEN").map(String::as_str), Some("value"));
        }

        assert_eq!(load_count, 1);
    }

    #[test]
    fn platform_status_caches_linked_environment_load_failures() {
        let mut cache = HashMap::new();
        let mut load_count = 0;

        for _ in 0..3 {
            let error = cached_status_environment(&mut cache, "production", |_| {
                load_count += 1;
                Err::<HashMap<String, String>, _>("decryption failed".to_string())
            })
            .expect_err("environment should fail to load");
            assert_eq!(error, "decryption failed");
        }

        assert_eq!(load_count, 1);
    }

    #[test]
    fn exact_platform_status_borrows_the_loaded_environment() {
        let loaded = std::sync::Arc::new(HashMap::from([("TOKEN".into(), "value".into())]));
        let client = platform_client(&["production"]);

        let values = client
            .prepare_local(std::path::Path::new("."), loaded.clone())
            .expect("Vercel values should be usable");

        let PlatformLocalValues::Exact(readable) = values else {
            panic!("Vercel status values should remain exact")
        };
        assert!(std::sync::Arc::ptr_eq(&readable, &loaded));
    }

    #[test]
    fn exact_platform_push_borrows_the_loaded_environment() {
        let loaded = std::sync::Arc::new(HashMap::from([("TOKEN".into(), "value".into())]));
        let client = platform_client(&["production"]);

        let values = client
            .prepare_local(std::path::Path::new("."), loaded.clone())
            .expect("Vercel values should be usable");

        let PlatformLocalValues::Exact(readable) = values else {
            panic!("Vercel push values should remain exact")
        };
        assert!(std::sync::Arc::ptr_eq(&readable, &loaded));
    }

    #[tokio::test]
    async fn platform_status_runs_remote_reads_with_bounded_ordered_concurrency() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let active = std::sync::Arc::new(AtomicUsize::new(0));
        let peak = std::sync::Arc::new(AtomicUsize::new(0));
        let jobs = (0..50).map(|index| {
            let active = active.clone();
            let peak = peak.clone();
            async move {
                let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(current, Ordering::SeqCst);
                tokio::task::yield_now().await;
                active.fetch_sub(1, Ordering::SeqCst);
                index
            }
        });

        let results = collect_ordered_bounded(jobs, PLATFORM_STATUS_CONCURRENCY).await;

        assert_eq!(results, (0..50).collect::<Vec<_>>());
        assert!(peak.load(Ordering::SeqCst) > 1);
        assert!(peak.load(Ordering::SeqCst) <= PLATFORM_STATUS_CONCURRENCY);
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
    fn fly_is_a_supported_env_platform() {
        assert!(is_supported_platform("fly"));
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
            .apply(&diff, &local, &remote.readable)
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
            .apply(&diff, &HashMap::new(), &remote.readable)
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
            .apply(&diff, &HashMap::new(), &remote.readable)
            .await
            .expect_err("unreadable final state must suppress exact mutation counts");

        assert!(matches!(error, PlatformApplyError::Untracked(_)));
    }

    #[tokio::test]
    async fn vercel_repeated_pagination_cursor_fails_closed() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v10/projects/test-project/env"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "envs": [],
                "pagination": { "next": "same-cursor" }
            })))
            .expect(2)
            .mount(&server)
            .await;
        let client = vercel_client_at(server.uri());

        let error = client
            .list()
            .await
            .expect_err("a repeated Vercel cursor must fail closed");

        assert!(error.to_string().contains("pagination cursor"));
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
