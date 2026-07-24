use super::{
    MutationKind, MutationOutcome, PLATFORM_MUTATION_CONCURRENCY, PLATFORM_TIMEOUT,
    PlatformApplyError, PlatformDiff, PlatformPushResult, PlatformVariable, VariableScope,
    read_platform_response,
};
use futures::StreamExt;
use lpm_common::LpmError;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

const MANAGED_VARIABLES: &[&str] = &[
    "COOLIFY_URL",
    "COOLIFY_FQDN",
    "COOLIFY_BRANCH",
    "COOLIFY_CONTAINER_ID",
    "SOURCE_COMMIT",
];

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct CoolifyConnectionConfig {
    pub(super) url: String,
    pub(super) application_id: String,
    #[serde(default)]
    pub(super) preview: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) linked_env: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CoolifyVariableResponse {
    uuid: String,
    key: String,
    #[serde(default)]
    value: Option<String>,
    #[serde(default)]
    real_value: Option<String>,
    #[serde(default)]
    is_preview: Option<bool>,
    #[serde(default)]
    is_literal: Option<bool>,
    #[serde(default)]
    is_multiline: Option<bool>,
    #[serde(default)]
    is_shown_once: Option<bool>,
    #[serde(default)]
    is_shared: Option<bool>,
}

#[derive(Debug, Clone, Copy)]
struct CoolifyVariableMetadata {
    is_literal: bool,
    is_multiline: bool,
    is_shown_once: bool,
}

#[derive(Debug, Deserialize)]
struct CoolifyCreateResponse {
    #[serde(default)]
    uuid: Option<String>,
}

#[derive(Debug)]
enum PostVariableResult {
    Created(Option<String>),
    Existing,
}

#[derive(Debug)]
enum OwnedCreateResult {
    Created(String),
    Existing,
}

#[derive(Debug)]
struct OwnedCreateFailure {
    error: LpmError,
    owned_ids: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
enum CoolifyCommitState {
    NotCommitted,
    Committed,
    Unknown,
}

#[derive(Debug)]
struct CoolifyAddFailure {
    error: LpmError,
    committed: CoolifyCommitState,
}

#[derive(Debug)]
enum CoolifyMutation {
    Add {
        key: String,
        value: String,
    },
    Update {
        id: String,
        key: String,
        value: String,
        metadata: CoolifyVariableMetadata,
    },
    Remove {
        id: String,
    },
}

pub(super) struct CoolifyClient {
    http: reqwest::Client,
    token: String,
    config: CoolifyConnectionConfig,
}

impl CoolifyClient {
    pub(super) fn new(
        token: String,
        mut config: CoolifyConnectionConfig,
    ) -> Result<Self, LpmError> {
        config.url = normalize_url(&config.url)?;
        let http = lpm_http::client_builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(PLATFORM_TIMEOUT)
            .build()
            .map_err(|error| {
                LpmError::Network(format!("failed to build Coolify client: {error}"))
            })?;
        Ok(Self {
            http,
            token,
            config,
        })
    }

    pub(super) fn config(&self) -> &CoolifyConnectionConfig {
        &self.config
    }

    pub(super) fn is_managed(key: &str) -> bool {
        MANAGED_VARIABLES.contains(&key)
    }

    fn collection_url(&self) -> String {
        let application_id = urlencoding::encode(&self.config.application_id);
        format!(
            "{}/api/v1/applications/{application_id}/envs",
            self.config.url
        )
    }

    fn item_url(&self, id: &str) -> String {
        let id = urlencoding::encode(id);
        format!("{}/{id}", self.collection_url())
    }

    async fn fetch_variables(&self) -> Result<Vec<CoolifyVariableResponse>, LpmError> {
        let response = self
            .http
            .get(self.collection_url())
            .bearer_auth(&self.token)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|error| {
                LpmError::Network(format!(
                    "Coolify list failed: {}",
                    lpm_http::display_error(&error)
                ))
            })?;
        let (status, body) = read_platform_response(response).await?;
        if !status.is_success() {
            return Err(coolify_api_error("list", status, &body));
        }
        serde_json::from_slice(&body)
            .map_err(|error| LpmError::Script(format!("invalid Coolify response: {error}")))
    }

    pub(super) async fn list(&self) -> Result<HashMap<String, PlatformVariable>, LpmError> {
        let variables = self.fetch_variables().await?;
        let mut result = HashMap::with_capacity(variables.len());
        for variable in variables {
            let is_preview =
                required_metadata_flag(variable.is_preview, "is_preview", &variable.key)?;
            if is_preview != self.config.preview || Self::is_managed(&variable.key) {
                continue;
            }
            if variable.uuid.is_empty() {
                return Err(LpmError::Script(format!(
                    "Coolify value {} has an invalid UUID",
                    variable.key
                )));
            }
            let metadata = variable.metadata()?;
            if metadata.is_shown_once {
                return Err(LpmError::Script(format!(
                    "Coolify value {} is shown-once and cannot be read; replace it with a readable application value before syncing",
                    variable.key
                )));
            }
            let raw_value = variable.value.ok_or_else(|| {
                let visibility = if variable.real_value.is_some() {
                    "Coolify exposed only a deployment-rendered value"
                } else {
                    "Coolify hid the value"
                };
                LpmError::Script(format!(
                    "{visibility} for {}; use a read:sensitive or root API token owned by a team administrator",
                    variable.key
                ))
            })?;
            if variable.is_shared == Some(true) || is_shared_reference(&raw_value) {
                return Err(LpmError::Script(format!(
                    "Coolify value {} is a shared-variable reference; convert it to a readable application value before syncing",
                    variable.key
                )));
            }
            let key = variable.key;
            if result.contains_key(&key) {
                return Err(LpmError::Script(format!(
                    "Coolify returned multiple values named {key} for the configured application target"
                )));
            }
            result.insert(
                key,
                PlatformVariable {
                    id: variable.uuid,
                    value: raw_value,
                    scope: VariableScope::Coolify {
                        preview: is_preview,
                        is_literal: metadata.is_literal,
                        is_multiline: metadata.is_multiline,
                        is_shown_once: metadata.is_shown_once,
                    },
                },
            );
        }
        Ok(result)
    }

    pub(super) async fn apply(
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
            mutations.push(CoolifyMutation::Add {
                key: key.clone(),
                value: value.clone(),
            });
        }
        for key in &diff.changed {
            let value = local
                .get(key)
                .ok_or_else(|| LpmError::Script(format!("missing local value for {key}")))
                .map_err(PlatformApplyError::untracked)?;
            let variable = remote
                .get(key)
                .ok_or_else(|| LpmError::Script(format!("missing Coolify value for {key}")))
                .map_err(PlatformApplyError::untracked)?;
            let metadata = self
                .mutation_metadata(key, variable)
                .map_err(PlatformApplyError::untracked)?;
            mutations.push(CoolifyMutation::Update {
                id: variable.id.clone(),
                key: key.clone(),
                value: value.clone(),
                metadata,
            });
        }
        for key in &diff.removed {
            let variable = remote
                .get(key)
                .ok_or_else(|| LpmError::Script(format!("missing Coolify value for {key}")))
                .map_err(PlatformApplyError::untracked)?;
            self.assert_mutation_scope(key, variable)
                .map_err(PlatformApplyError::untracked)?;
            mutations.push(CoolifyMutation::Remove {
                id: variable.id.clone(),
            });
        }

        let outcomes = futures::stream::iter(mutations)
            .map(|mutation| self.apply_one(mutation))
            .buffer_unordered(PLATFORM_MUTATION_CONCURRENCY)
            .collect::<Vec<_>>()
            .await;
        PlatformPushResult::from_mutation_outcomes(outcomes)
    }

    fn assert_mutation_scope(
        &self,
        key: &str,
        variable: &PlatformVariable,
    ) -> Result<(), LpmError> {
        match &variable.scope {
            VariableScope::Coolify { preview, .. } if *preview == self.config.preview => Ok(()),
            _ => Err(LpmError::Script(format!(
                "Coolify value {key} does not match the configured application target"
            ))),
        }
    }

    fn mutation_metadata(
        &self,
        key: &str,
        variable: &PlatformVariable,
    ) -> Result<CoolifyVariableMetadata, LpmError> {
        match &variable.scope {
            VariableScope::Coolify {
                preview,
                is_literal,
                is_multiline,
                is_shown_once,
            } if *preview == self.config.preview => Ok(CoolifyVariableMetadata {
                is_literal: *is_literal,
                is_multiline: *is_multiline,
                is_shown_once: *is_shown_once,
            }),
            _ => Err(LpmError::Script(format!(
                "Coolify value {key} does not match the configured application target"
            ))),
        }
    }

    async fn apply_one(&self, mutation: CoolifyMutation) -> MutationOutcome {
        match mutation {
            CoolifyMutation::Add { key, value } => {
                match self.create_with_preview_isolation(&key, &value).await {
                    Ok(()) => MutationOutcome::Applied(MutationKind::Added),
                    Err(CoolifyAddFailure {
                        error,
                        committed: CoolifyCommitState::Committed,
                    }) => MutationOutcome::Failed {
                        error,
                        committed: Some(MutationKind::Added),
                    },
                    Err(CoolifyAddFailure {
                        error,
                        committed: CoolifyCommitState::NotCommitted,
                    }) => MutationOutcome::Failed {
                        error,
                        committed: None,
                    },
                    Err(CoolifyAddFailure {
                        error,
                        committed: CoolifyCommitState::Unknown,
                    }) => MutationOutcome::Unknown(error),
                }
            }
            CoolifyMutation::Update {
                id,
                key,
                value,
                metadata,
            } => {
                let request = self
                    .http
                    .patch(self.collection_url())
                    .bearer_auth(&self.token)
                    .header(reqwest::header::ACCEPT, "application/json")
                    .json(&serde_json::json!({
                        "key": key,
                        "value": value,
                        "is_preview": self.config.preview,
                        "is_literal": metadata.is_literal,
                        "is_multiline": metadata.is_multiline,
                        "is_shown_once": metadata.is_shown_once,
                    }));
                match self.send_mutation("update", request).await {
                    Ok(_) => MutationOutcome::Applied(MutationKind::Updated),
                    Err(error) => match self.read_owned_value(&id, &key, self.config.preview).await
                    {
                        Ok(Some(observed)) if observed == value => {
                            MutationOutcome::Applied(MutationKind::Updated)
                        }
                        Ok(_) => MutationOutcome::Failed {
                            error,
                            committed: None,
                        },
                        Err(_) => MutationOutcome::Unknown(error),
                    },
                }
            }
            CoolifyMutation::Remove { id } => match self.delete_variable(&id).await {
                Ok(()) => MutationOutcome::Applied(MutationKind::Removed),
                Err(error) => match self.variable_exists(&id).await {
                    Ok(false) => MutationOutcome::Applied(MutationKind::Removed),
                    Ok(true) => MutationOutcome::Failed {
                        error,
                        committed: None,
                    },
                    Err(_) => MutationOutcome::Unknown(error),
                },
            },
        }
    }

    async fn create_with_preview_isolation(
        &self,
        key: &str,
        value: &str,
    ) -> Result<(), CoolifyAddFailure> {
        let sentinel = ownership_sentinel();
        if self.config.preview {
            let preview_id = match self
                .create_owned_variable(key, &sentinel, true, false)
                .await
            {
                Ok(OwnedCreateResult::Created(id)) => id,
                Ok(OwnedCreateResult::Existing) => {
                    return Err(CoolifyAddFailure {
                        error: LpmError::Script(format!(
                            "Coolify unexpectedly reported an existing preview value for {key}"
                        )),
                        committed: CoolifyCommitState::NotCommitted,
                    });
                }
                Err(failure) => {
                    let cleanup = self.cleanup_owned_ids(failure.owned_ids).await;
                    return Err(CoolifyAddFailure {
                        error: append_cleanup(failure.error, &cleanup),
                        committed: CoolifyCommitState::NotCommitted,
                    });
                }
            };
            return self
                .finalize_owned_add(key, value, true, preview_id, None)
                .await;
        }

        let guard_id = match self.create_owned_variable(key, &sentinel, true, true).await {
            Ok(OwnedCreateResult::Created(id)) => Some(id),
            Ok(OwnedCreateResult::Existing) => None,
            Err(failure) => {
                let cleanup = self.cleanup_owned_ids(failure.owned_ids).await;
                return Err(CoolifyAddFailure {
                    error: append_cleanup(failure.error, &cleanup),
                    committed: CoolifyCommitState::NotCommitted,
                });
            }
        };

        let production_id = match self
            .create_owned_variable(key, &sentinel, false, false)
            .await
        {
            Ok(OwnedCreateResult::Created(id)) => id,
            Ok(OwnedCreateResult::Existing) => {
                let cleanup = self.cleanup_owned_ids(guard_id.into_iter().collect()).await;
                return Err(CoolifyAddFailure {
                    error: append_cleanup(
                        LpmError::Script(format!(
                            "Coolify unexpectedly reported an existing production value for {key}"
                        )),
                        &cleanup,
                    ),
                    committed: CoolifyCommitState::NotCommitted,
                });
            }
            Err(failure) => {
                let mut owned_ids = failure.owned_ids;
                if let Some(guard_id) = guard_id {
                    owned_ids.push(guard_id);
                }
                let cleanup = self.cleanup_owned_ids(owned_ids).await;
                return Err(CoolifyAddFailure {
                    error: append_cleanup(failure.error, &cleanup),
                    committed: CoolifyCommitState::NotCommitted,
                });
            }
        };

        self.finalize_owned_add(key, value, false, production_id, guard_id)
            .await
    }

    async fn finalize_owned_add(
        &self,
        key: &str,
        value: &str,
        is_preview: bool,
        target_id: String,
        guard_id: Option<String>,
    ) -> Result<(), CoolifyAddFailure> {
        if let Err(update_error) = self.update_value(key, value, is_preview).await {
            match self.read_owned_value(&target_id, key, is_preview).await {
                Ok(Some(observed)) if observed == value => {}
                observed => {
                    let mut owned_ids = vec![target_id];
                    if let Some(guard_id) = guard_id {
                        owned_ids.push(guard_id);
                    }
                    let cleanup = self.cleanup_owned_ids(owned_ids).await;
                    let target_removed = cleanup.first().is_some_and(|(_, result)| result.is_ok());
                    let committed = match observed {
                        Ok(_) => CoolifyCommitState::NotCommitted,
                        Err(_) if target_removed => CoolifyCommitState::NotCommitted,
                        Err(_) => CoolifyCommitState::Unknown,
                    };
                    return Err(CoolifyAddFailure {
                        error: append_cleanup(update_error, &cleanup),
                        committed,
                    });
                }
            }
        }

        let Some(guard_id) = guard_id else {
            return Ok(());
        };
        if let Err(cleanup_error) = self.delete_variable(&guard_id).await {
            let production_rollback = self.delete_variable(&target_id).await;
            let guard_retry = self.delete_variable(&guard_id).await;
            let committed = if production_rollback.is_err() {
                CoolifyCommitState::Committed
            } else {
                CoolifyCommitState::NotCommitted
            };
            return Err(CoolifyAddFailure {
                error: LpmError::Script(format!(
                    "Coolify preview guard cleanup for {key} failed: {cleanup_error}; production rollback: {}; preview guard cleanup retry: {}",
                    mutation_result(&production_rollback),
                    mutation_result(&guard_retry)
                )),
                committed,
            });
        }
        Ok(())
    }

    async fn create_owned_variable(
        &self,
        key: &str,
        value: &str,
        is_preview: bool,
        allow_existing: bool,
    ) -> Result<OwnedCreateResult, OwnedCreateFailure> {
        let result = self
            .post_variable(key, value, is_preview, allow_existing)
            .await
            .map_err(|error| OwnedCreateFailure {
                error,
                owned_ids: Vec::new(),
            })?;
        match result {
            PostVariableResult::Created(Some(id)) => Ok(OwnedCreateResult::Created(id)),
            PostVariableResult::Created(None) => {
                let owned_ids = self
                    .owned_ids_for_value(key, value, is_preview)
                    .await
                    .map_err(|error| OwnedCreateFailure {
                        error: LpmError::Script(format!(
                            "Coolify created {key} but returned no usable UUID and ownership recovery failed: {error}"
                        )),
                        owned_ids: Vec::new(),
                    })?;
                if owned_ids.len() == 1 {
                    return Ok(OwnedCreateResult::Created(
                        owned_ids.first().cloned().expect("one owned ID"),
                    ));
                }
                Err(OwnedCreateFailure {
                    error: LpmError::Script(format!(
                        "Coolify created {key} but returned no usable UUID; ownership recovery found {} sentinel-matched values",
                        owned_ids.len()
                    )),
                    owned_ids,
                })
            }
            PostVariableResult::Existing => {
                if !allow_existing {
                    return Err(OwnedCreateFailure {
                        error: LpmError::Script(format!(
                            "Coolify unexpectedly reported an existing value for {key}"
                        )),
                        owned_ids: Vec::new(),
                    });
                }
                let preview_ids = self.preview_ids_for_key(key).await.map_err(|error| {
                    OwnedCreateFailure {
                        error: LpmError::Script(format!(
                            "Coolify preview guard conflicted for {key}, but the existing preview value could not be verified: {error}"
                        )),
                        owned_ids: Vec::new(),
                    }
                })?;
                if preview_ids.len() == 1 {
                    Ok(OwnedCreateResult::Existing)
                } else {
                    Err(OwnedCreateFailure {
                        error: LpmError::Script(format!(
                            "Coolify preview guard conflicted for {key}, but verification found {} preview values; refusing an ambiguous production create",
                            preview_ids.len()
                        )),
                        owned_ids: Vec::new(),
                    })
                }
            }
        }
    }

    async fn post_variable(
        &self,
        key: &str,
        value: &str,
        is_preview: bool,
        allow_existing: bool,
    ) -> Result<PostVariableResult, LpmError> {
        let request = self
            .http
            .post(self.collection_url())
            .bearer_auth(&self.token)
            .header(reqwest::header::ACCEPT, "application/json")
            .json(&serde_json::json!({
                "key": key,
                "value": value,
                "is_preview": is_preview,
                "is_literal": false,
                "is_multiline": false,
                "is_shown_once": false,
            }));
        let response = request.send().await.map_err(|error| {
            LpmError::Network(format!(
                "Coolify create failed: {}",
                lpm_http::display_error(&error)
            ))
        })?;
        let (status, body) = read_platform_response(response).await?;
        if allow_existing && status == reqwest::StatusCode::CONFLICT {
            return Ok(PostVariableResult::Existing);
        }
        if !status.is_success() {
            return Err(coolify_api_error("create", status, &body));
        }
        let id = serde_json::from_slice::<CoolifyCreateResponse>(&body)
            .ok()
            .and_then(|created| created.uuid)
            .filter(|id| !id.is_empty());
        Ok(PostVariableResult::Created(id))
    }

    async fn owned_ids_for_value(
        &self,
        key: &str,
        value: &str,
        expected_preview: bool,
    ) -> Result<Vec<String>, LpmError> {
        let variables = self.fetch_variables().await?;
        let mut ids = Vec::new();
        for variable in variables
            .into_iter()
            .filter(|variable| variable.key == key && variable.value.as_deref() == Some(value))
        {
            let is_preview =
                required_metadata_flag(variable.is_preview, "is_preview", &variable.key)?;
            if is_preview == expected_preview {
                if variable.uuid.is_empty() {
                    return Err(LpmError::Script(format!(
                        "Coolify value {} has an invalid UUID",
                        variable.key
                    )));
                }
                ids.push(variable.uuid);
            }
        }
        ids.sort_unstable();
        ids.dedup();
        Ok(ids)
    }

    async fn preview_ids_for_key(&self, key: &str) -> Result<Vec<String>, LpmError> {
        let variables = self.fetch_variables().await?;
        let mut ids = Vec::new();
        for variable in variables.into_iter().filter(|variable| variable.key == key) {
            let is_preview =
                required_metadata_flag(variable.is_preview, "is_preview", &variable.key)?;
            if !is_preview {
                continue;
            }
            if variable.uuid.is_empty() {
                return Err(LpmError::Script(format!(
                    "Coolify value {} has an invalid UUID",
                    variable.key
                )));
            }
            ids.push(variable.uuid);
        }
        ids.sort_unstable();
        ids.dedup();
        Ok(ids)
    }

    async fn read_owned_value(
        &self,
        id: &str,
        key: &str,
        expected_preview: bool,
    ) -> Result<Option<String>, LpmError> {
        let variables = self.fetch_variables().await?;
        let Some(variable) = variables.into_iter().find(|variable| variable.uuid == id) else {
            return Ok(None);
        };
        let is_preview = required_metadata_flag(variable.is_preview, "is_preview", &variable.key)?;
        if variable.key != key || is_preview != expected_preview {
            return Err(LpmError::Script(format!(
                "Coolify value {id} no longer matches the owned {key} target"
            )));
        }
        Ok(variable.value)
    }

    async fn variable_exists(&self, id: &str) -> Result<bool, LpmError> {
        Ok(self
            .fetch_variables()
            .await?
            .iter()
            .any(|variable| variable.uuid == id))
    }

    async fn update_value(&self, key: &str, value: &str, is_preview: bool) -> Result<(), LpmError> {
        let request = self
            .http
            .patch(self.collection_url())
            .bearer_auth(&self.token)
            .header(reqwest::header::ACCEPT, "application/json")
            .json(&serde_json::json!({
                "key": key,
                "value": value,
                "is_preview": is_preview,
                "is_literal": false,
                "is_multiline": false,
                "is_shown_once": false,
            }));
        self.send_mutation("update", request).await?;
        Ok(())
    }

    async fn cleanup_owned_ids(&self, ids: Vec<String>) -> Vec<(String, Result<(), LpmError>)> {
        let mut results = Vec::with_capacity(ids.len());
        for id in ids {
            let result = self.delete_variable(&id).await;
            results.push((id, result));
        }
        results
    }

    async fn delete_variable(&self, id: &str) -> Result<(), LpmError> {
        let request = self
            .http
            .delete(self.item_url(id))
            .bearer_auth(&self.token)
            .header(reqwest::header::ACCEPT, "application/json");
        self.send_mutation("delete", request).await?;
        Ok(())
    }

    async fn send_mutation(
        &self,
        operation: &str,
        request: reqwest::RequestBuilder,
    ) -> Result<Vec<u8>, LpmError> {
        let response = request.send().await.map_err(|error| {
            LpmError::Network(format!(
                "Coolify {operation} failed: {}",
                lpm_http::display_error(&error)
            ))
        })?;
        let (status, body) = read_platform_response(response).await?;
        if !status.is_success() {
            return Err(coolify_api_error(operation, status, &body));
        }
        Ok(body)
    }
}

impl CoolifyVariableResponse {
    fn metadata(&self) -> Result<CoolifyVariableMetadata, LpmError> {
        Ok(CoolifyVariableMetadata {
            is_literal: required_metadata_flag(self.is_literal, "is_literal", &self.key)?,
            is_multiline: required_metadata_flag(self.is_multiline, "is_multiline", &self.key)?,
            is_shown_once: required_metadata_flag(self.is_shown_once, "is_shown_once", &self.key)?,
        })
    }
}

fn required_metadata_flag(value: Option<bool>, field: &str, key: &str) -> Result<bool, LpmError> {
    value.ok_or_else(|| {
        LpmError::Script(format!(
            "Coolify value {key} is missing {field}; refusing to sync incomplete deployment metadata"
        ))
    })
}

fn is_shared_reference(value: &str) -> bool {
    ["{{team.", "{{project.", "{{environment.", "{{server."]
        .iter()
        .any(|prefix| value.contains(prefix))
}

fn mutation_result(result: &Result<(), LpmError>) -> String {
    match result {
        Ok(()) => "succeeded".into(),
        Err(error) => format!("failed ({error})"),
    }
}

fn ownership_sentinel() -> String {
    let mut bytes = [0_u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    format!("__lpm_env_ownership_{}", hex::encode(bytes))
}

fn append_cleanup(error: LpmError, cleanup: &[(String, Result<(), LpmError>)]) -> LpmError {
    if cleanup.iter().all(|(_, result)| result.is_ok()) {
        return error;
    }
    let summary = cleanup
        .iter()
        .map(|(id, result)| format!("{id}: {}", mutation_result(result)))
        .collect::<Vec<_>>()
        .join(", ");
    LpmError::Script(format!("{error}; owned-value cleanup: {summary}"))
}

fn normalize_url(value: &str) -> Result<String, LpmError> {
    let url = reqwest::Url::parse(value)
        .map_err(|error| LpmError::Script(format!("invalid Coolify URL: {error}")))?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err(LpmError::Script(
            "Coolify URL must not contain credentials".into(),
        ));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(LpmError::Script(
            "Coolify URL must not contain a query or fragment".into(),
        ));
    }
    if !matches!(url.path(), "" | "/") {
        return Err(LpmError::Script(
            "Coolify URL must not contain a path".into(),
        ));
    }
    let acceptance_loopback = cfg!(any(debug_assertions, feature = "acceptance-test-hooks"))
        && std::env::var("ACCEPTANCE_RUN_ID")
            .ok()
            .is_some_and(|value| !value.trim().is_empty())
        && url.scheme() == "http"
        && matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "::1"));
    if url.scheme() != "https" && !acceptance_loopback {
        return Err(LpmError::Script("Coolify URL must use HTTPS".into()));
    }
    Ok(value.trim_end_matches('/').to_string())
}

fn coolify_api_error(operation: &str, status: reqwest::StatusCode, body: &[u8]) -> LpmError {
    let detail = String::from_utf8_lossy(body);
    let detail = detail.trim();
    let suffix = if detail.is_empty() {
        String::new()
    } else {
        format!(": {}", detail.chars().take(300).collect::<String>())
    };
    LpmError::Script(format!(
        "Coolify {operation} failed with HTTP {status}{suffix}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_json, body_string_contains, header, method, path};
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

    use std::sync::Arc;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CaptureProductionSentinel {
        sentinel: Arc<Mutex<Option<String>>>,
    }

    impl Respond for CaptureProductionSentinel {
        fn respond(&self, request: &Request) -> ResponseTemplate {
            let body: serde_json::Value =
                serde_json::from_slice(&request.body).expect("production create JSON");
            *self.sentinel.lock().expect("sentinel lock") =
                body["value"].as_str().map(str::to_owned);
            ResponseTemplate::new(201).set_body_json(serde_json::json!({}))
        }
    }

    struct RecoverProductionSentinel {
        sentinel: Arc<Mutex<Option<String>>>,
    }

    impl Respond for RecoverProductionSentinel {
        fn respond(&self, _request: &Request) -> ResponseTemplate {
            let sentinel = self
                .sentinel
                .lock()
                .expect("sentinel lock")
                .clone()
                .expect("captured production sentinel");
            ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {
                    "uuid": "production-uuid",
                    "key": "NEW_SECRET",
                    "value": sentinel,
                    "real_value": sentinel,
                    "is_preview": false,
                    "is_literal": false,
                    "is_multiline": false,
                    "is_shown_once": false,
                    "is_shared": false
                }
            ]))
        }
    }

    struct StatusSequence {
        calls: Arc<AtomicUsize>,
        first: u16,
        subsequent: u16,
    }

    impl Respond for StatusSequence {
        fn respond(&self, _request: &Request) -> ResponseTemplate {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            ResponseTemplate::new(if call == 0 {
                self.first
            } else {
                self.subsequent
            })
        }
    }

    fn config(url: String) -> CoolifyConnectionConfig {
        CoolifyConnectionConfig {
            url,
            application_id: "application-123".into(),
            preview: false,
            linked_env: Some("production".into()),
        }
    }

    #[test]
    fn release_url_requires_https() {
        let _env = crate::test_env::ScopedEnv::update([("ACCEPTANCE_RUN_ID", None)]);

        let error = normalize_url("http://coolify.example.com").expect_err("HTTP must fail closed");

        assert!(error.to_string().contains("must use HTTPS"));
    }

    #[test]
    fn acceptance_http_url_requires_loopback() {
        let _env = crate::test_env::ScopedEnv::set([("ACCEPTANCE_RUN_ID", "coolify-test".into())]);

        let error = normalize_url("http://example.com").expect_err("remote HTTP must fail closed");

        assert!(error.to_string().contains("must use HTTPS"));
    }

    #[test]
    fn acceptance_loopback_url_is_normalized() {
        let _env = crate::test_env::ScopedEnv::set([("ACCEPTANCE_RUN_ID", "coolify-test".into())]);

        let url = normalize_url("http://127.0.0.1:4173/").expect("normalize loopback URL");

        assert_eq!(url, "http://127.0.0.1:4173");
    }

    #[test]
    fn url_rejects_credentials() {
        let error = normalize_url("https://user:password@coolify.example.com")
            .expect_err("credentials must fail closed");

        assert!(error.to_string().contains("must not contain credentials"));
    }

    #[test]
    fn url_rejects_paths() {
        let error =
            normalize_url("https://coolify.example.com/admin").expect_err("paths must fail closed");

        assert!(error.to_string().contains("must not contain a path"));
    }

    #[test]
    fn url_rejects_queries() {
        let error = normalize_url("https://coolify.example.com?target=other")
            .expect_err("queries must fail closed");

        assert!(error.to_string().contains("query or fragment"));
    }

    #[tokio::test]
    async fn list_uses_uuid_and_raw_stored_value() {
        let _env = crate::test_env::ScopedEnv::set([("ACCEPTANCE_RUN_ID", "coolify-list".into())]);
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/applications/application-123/envs"))
            .and(header("authorization", "Bearer coolify-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {
                    "id": 42,
                    "uuid": "env-uuid-42",
                    "key": "APPLICATION_SECRET",
                    "value": "$VARIABLE_REFERENCE",
                    "real_value": "resolved-secret",
                    "is_preview": false,
                    "is_literal": false,
                    "is_multiline": false,
                    "is_shown_once": false,
                    "is_shared": false
                }
            ])))
            .expect(1)
            .mount(&server)
            .await;
        let client =
            CoolifyClient::new("coolify-token".into(), config(server.uri())).expect("client");

        let variables = client.list().await.expect("list Coolify variables");

        let variable = variables
            .get("APPLICATION_SECRET")
            .expect("listed variable");
        assert_eq!(variable.id, "env-uuid-42");
        assert_eq!(variable.value, "$VARIABLE_REFERENCE");
    }

    #[tokio::test]
    async fn list_rejects_values_hidden_by_insufficient_permissions() {
        let _env =
            crate::test_env::ScopedEnv::set([("ACCEPTANCE_RUN_ID", "coolify-hidden".into())]);
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/applications/application-123/envs"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {
                    "uuid": "hidden-uuid",
                    "key": "HIDDEN_SECRET",
                    "is_preview": false,
                    "is_literal": false,
                    "is_multiline": false,
                    "is_shown_once": false,
                    "is_shared": false
                }
            ])))
            .expect(1)
            .mount(&server)
            .await;
        let client =
            CoolifyClient::new("coolify-token".into(), config(server.uri())).expect("client");

        let error = client
            .list()
            .await
            .expect_err("hidden values must fail closed");

        assert!(error.to_string().contains("read:sensitive"));
        assert!(error.to_string().contains("team administrator"));
    }

    #[tokio::test]
    async fn list_rejects_shown_once_values_before_sync() {
        let _env =
            crate::test_env::ScopedEnv::set([("ACCEPTANCE_RUN_ID", "coolify-shown-once".into())]);
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/applications/application-123/envs"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {
                    "uuid": "shown-once-uuid",
                    "key": "SHOWN_ONCE_SECRET",
                    "is_preview": false,
                    "is_literal": false,
                    "is_multiline": false,
                    "is_shown_once": true,
                    "is_shared": false
                }
            ])))
            .expect(1)
            .mount(&server)
            .await;
        let client =
            CoolifyClient::new("coolify-token".into(), config(server.uri())).expect("client");

        let error = client
            .list()
            .await
            .expect_err("shown-once values must fail closed");

        assert!(error.to_string().contains("shown-once"));
        assert!(error.to_string().contains("cannot be read"));
    }

    #[tokio::test]
    async fn list_rejects_shared_variable_references() {
        let _env =
            crate::test_env::ScopedEnv::set([("ACCEPTANCE_RUN_ID", "coolify-shared".into())]);
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/applications/application-123/envs"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {
                    "uuid": "shared-uuid",
                    "key": "SHARED_SECRET",
                    "value": "{{team.SHARED_SECRET}}",
                    "real_value": "resolved-secret",
                    "is_preview": false,
                    "is_literal": false,
                    "is_multiline": false,
                    "is_shown_once": false,
                    "is_shared": true
                }
            ])))
            .expect(1)
            .mount(&server)
            .await;
        let client =
            CoolifyClient::new("coolify-token".into(), config(server.uri())).expect("client");

        let error = client
            .list()
            .await
            .expect_err("shared references must fail closed");

        assert!(error.to_string().contains("shared-variable reference"));
    }

    #[tokio::test]
    async fn update_preserves_deployment_metadata_and_delete_uses_variable_uuid() {
        let _env =
            crate::test_env::ScopedEnv::set([("ACCEPTANCE_RUN_ID", "coolify-mutate".into())]);
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/applications/application-123/envs"))
            .and(header("authorization", "Bearer coolify-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {
                    "uuid": "changed-uuid",
                    "key": "CHANGED",
                    "value": "remote",
                    "real_value": "'remote'",
                    "is_preview": false,
                    "is_literal": true,
                    "is_multiline": true,
                    "is_shown_once": false,
                    "is_shared": false
                },
                {
                    "uuid": "removed-uuid",
                    "key": "REMOVED",
                    "value": "remote",
                    "real_value": "remote",
                    "is_preview": false,
                    "is_literal": false,
                    "is_multiline": false,
                    "is_shown_once": false,
                    "is_shared": false
                }
            ])))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path("/api/v1/applications/application-123/envs"))
            .and(header("authorization", "Bearer coolify-token"))
            .and(body_json(serde_json::json!({
                "key": "CHANGED",
                "value": "local",
                "is_preview": false,
                "is_literal": true,
                "is_multiline": true,
                "is_shown_once": false
            })))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "uuid": "changed-uuid",
                "key": "CHANGED",
                "value": "local",
                "is_preview": false,
                "is_literal": true,
                "is_multiline": true,
                "is_shown_once": false,
                "is_shared": false
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path(
                "/api/v1/applications/application-123/envs/removed-uuid",
            ))
            .and(header("authorization", "Bearer coolify-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "message": "Environment variable deleted."
            })))
            .expect(1)
            .mount(&server)
            .await;
        let client =
            CoolifyClient::new("coolify-token".into(), config(server.uri())).expect("client");
        let remote = client.list().await.expect("list Coolify variables");
        let local = HashMap::from([("CHANGED".into(), "local".into())]);
        let diff = PlatformDiff {
            added: Vec::new(),
            changed: vec!["CHANGED".into()],
            removed: vec!["REMOVED".into()],
            unchanged: Vec::new(),
        };

        let result = client
            .apply(&diff, &local, &remote)
            .await
            .expect("apply Coolify mutations");

        assert_eq!(result.updated, 1);
        assert_eq!(result.removed, 1);
    }

    #[tokio::test]
    async fn production_add_uses_an_owned_preview_guard_without_posting_the_secret() {
        let _env =
            crate::test_env::ScopedEnv::set([("ACCEPTANCE_RUN_ID", "coolify-isolation".into())]);
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/applications/application-123/envs"))
            .and(header("authorization", "Bearer coolify-token"))
            .and(body_string_contains("\"is_preview\":true"))
            .respond_with(
                ResponseTemplate::new(201)
                    .set_body_json(serde_json::json!({"uuid": "preview-guard-uuid"})),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v1/applications/application-123/envs"))
            .and(header("authorization", "Bearer coolify-token"))
            .and(body_string_contains("\"is_preview\":false"))
            .respond_with(
                ResponseTemplate::new(201)
                    .set_body_json(serde_json::json!({"uuid": "production-uuid"})),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path("/api/v1/applications/application-123/envs"))
            .and(header("authorization", "Bearer coolify-token"))
            .and(body_json(serde_json::json!({
                "key": "NEW_SECRET",
                "value": "production-value",
                "is_preview": false,
                "is_literal": false,
                "is_multiline": false,
                "is_shown_once": false
            })))
            .respond_with(ResponseTemplate::new(201))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path(
                "/api/v1/applications/application-123/envs/preview-guard-uuid",
            ))
            .and(header("authorization", "Bearer coolify-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "message": "Environment variable deleted."
            })))
            .expect(1)
            .mount(&server)
            .await;
        let client =
            CoolifyClient::new("coolify-token".into(), config(server.uri())).expect("client");
        let local = HashMap::from([("NEW_SECRET".into(), "production-value".into())]);
        let diff = PlatformDiff {
            added: vec!["NEW_SECRET".into()],
            changed: Vec::new(),
            removed: Vec::new(),
            unchanged: Vec::new(),
        };

        let result = client
            .apply(&diff, &local, &HashMap::new())
            .await
            .expect("production add preserves preview isolation");

        assert_eq!(result.added, 1);
        let requests = server
            .received_requests()
            .await
            .expect("received request log");
        let posted_values = requests
            .iter()
            .filter(|request| request.method.as_str() == "POST")
            .map(|request| {
                serde_json::from_slice::<serde_json::Value>(&request.body)
                    .expect("create request JSON")["value"]
                    .as_str()
                    .expect("create value")
                    .to_owned()
            })
            .collect::<Vec<_>>();
        assert!(
            !posted_values
                .iter()
                .any(|value| value == "production-value"),
            "the production secret must never be POSTed where Coolify can mirror it"
        );
    }

    #[tokio::test]
    async fn production_add_never_deletes_a_preexisting_preview_value() {
        let _env =
            crate::test_env::ScopedEnv::set([("ACCEPTANCE_RUN_ID", "coolify-conflict".into())]);
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/applications/application-123/envs"))
            .and(body_string_contains("\"is_preview\":true"))
            .respond_with(ResponseTemplate::new(409).set_body_json(serde_json::json!({
                "message": "Environment variable already exists."
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/applications/application-123/envs"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {
                    "uuid": "legitimate-preview-uuid",
                    "key": "NEW_SECRET",
                    "is_preview": true
                }
            ])))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v1/applications/application-123/envs"))
            .and(body_string_contains("\"is_preview\":false"))
            .respond_with(
                ResponseTemplate::new(201)
                    .set_body_json(serde_json::json!({"uuid": "production-uuid"})),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path("/api/v1/applications/application-123/envs"))
            .respond_with(ResponseTemplate::new(201))
            .expect(1)
            .mount(&server)
            .await;
        let client =
            CoolifyClient::new("coolify-token".into(), config(server.uri())).expect("client");
        let local = HashMap::from([("NEW_SECRET".into(), "production-value".into())]);
        let diff = PlatformDiff {
            added: vec!["NEW_SECRET".into()],
            changed: Vec::new(),
            removed: Vec::new(),
            unchanged: Vec::new(),
        };

        let result = client
            .apply(&diff, &local, &HashMap::new())
            .await
            .expect("existing preview must remain untouched");

        assert_eq!(result.added, 1);
        let requests = server
            .received_requests()
            .await
            .expect("received request log");
        assert!(
            requests
                .iter()
                .all(|request| request.method.as_str() != "DELETE"),
            "a 409 preview guard means LPM owns no preview value to delete"
        );
    }

    #[tokio::test]
    async fn preview_guard_conflict_without_a_verified_preview_fails_before_production_create() {
        let _env = crate::test_env::ScopedEnv::set([(
            "ACCEPTANCE_RUN_ID",
            "coolify-unverified-conflict".into(),
        )]);
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/applications/application-123/envs"))
            .and(body_string_contains("\"is_preview\":true"))
            .respond_with(ResponseTemplate::new(409))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/applications/application-123/envs"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .expect(1)
            .mount(&server)
            .await;
        let client =
            CoolifyClient::new("coolify-token".into(), config(server.uri())).expect("client");
        let local = HashMap::from([("NEW_SECRET".into(), "production-value".into())]);
        let diff = PlatformDiff {
            added: vec!["NEW_SECRET".into()],
            ..PlatformDiff::default()
        };

        let error = client
            .apply(&diff, &local, &HashMap::new())
            .await
            .expect_err("unverified conflict must fail closed");

        let PlatformApplyError::Tracked { applied, .. } = error else {
            panic!("no requested mutation was committed")
        };
        assert_eq!(applied.added, 0);
        let requests = server
            .received_requests()
            .await
            .expect("received request log");
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.method.as_str() == "POST")
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn malformed_create_response_recovers_only_the_sentinel_owned_production() {
        let _env =
            crate::test_env::ScopedEnv::set([("ACCEPTANCE_RUN_ID", "coolify-recovery".into())]);
        let server = MockServer::start().await;
        let sentinel = Arc::new(Mutex::new(None));
        Mock::given(method("POST"))
            .and(path("/api/v1/applications/application-123/envs"))
            .and(body_string_contains("\"is_preview\":true"))
            .respond_with(
                ResponseTemplate::new(201)
                    .set_body_json(serde_json::json!({"uuid": "preview-guard-uuid"})),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v1/applications/application-123/envs"))
            .and(body_string_contains("\"is_preview\":false"))
            .respond_with(CaptureProductionSentinel {
                sentinel: Arc::clone(&sentinel),
            })
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/applications/application-123/envs"))
            .respond_with(RecoverProductionSentinel {
                sentinel: Arc::clone(&sentinel),
            })
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path("/api/v1/applications/application-123/envs"))
            .respond_with(ResponseTemplate::new(201))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path(
                "/api/v1/applications/application-123/envs/preview-guard-uuid",
            ))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;
        let client =
            CoolifyClient::new("coolify-token".into(), config(server.uri())).expect("client");
        let local = HashMap::from([("NEW_SECRET".into(), "production-value".into())]);
        let diff = PlatformDiff {
            added: vec!["NEW_SECRET".into()],
            changed: Vec::new(),
            removed: Vec::new(),
            unchanged: Vec::new(),
        };

        let result = client
            .apply(&diff, &local, &HashMap::new())
            .await
            .expect("sentinel-owned production must be recovered");

        assert_eq!(result.added, 1);
    }

    #[tokio::test]
    async fn malformed_create_recovery_failure_cleans_only_the_owned_preview_guard() {
        let _env = crate::test_env::ScopedEnv::set([(
            "ACCEPTANCE_RUN_ID",
            "coolify-recovery-failure".into(),
        )]);
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/applications/application-123/envs"))
            .and(body_string_contains("\"is_preview\":true"))
            .respond_with(
                ResponseTemplate::new(201)
                    .set_body_json(serde_json::json!({"uuid": "preview-guard-uuid"})),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v1/applications/application-123/envs"))
            .and(body_string_contains("\"is_preview\":false"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({})))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/applications/application-123/envs"))
            .respond_with(ResponseTemplate::new(503))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path(
                "/api/v1/applications/application-123/envs/preview-guard-uuid",
            ))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;
        let client =
            CoolifyClient::new("coolify-token".into(), config(server.uri())).expect("client");
        let local = HashMap::from([("NEW_SECRET".into(), "production-value".into())]);
        let diff = PlatformDiff {
            added: vec!["NEW_SECRET".into()],
            ..PlatformDiff::default()
        };

        let error = client
            .apply(&diff, &local, &HashMap::new())
            .await
            .expect_err("failed ownership recovery must fail closed");

        let PlatformApplyError::Tracked { applied, .. } = error else {
            panic!("non-secret sentinel recovery failure has a known mutation count")
        };
        assert_eq!(applied.added, 0);
        let requests = server
            .received_requests()
            .await
            .expect("received request log");
        assert!(
            requests
                .iter()
                .filter(|request| request.method.as_str() == "POST")
                .all(|request| !String::from_utf8_lossy(&request.body).contains("production-value"))
        );
    }

    #[tokio::test]
    async fn failed_compensation_counts_a_committed_production_add() {
        let _env =
            crate::test_env::ScopedEnv::set([("ACCEPTANCE_RUN_ID", "coolify-compensation".into())]);
        let server = MockServer::start().await;
        let guard_deletes = Arc::new(AtomicUsize::new(0));
        Mock::given(method("POST"))
            .and(path("/api/v1/applications/application-123/envs"))
            .and(body_string_contains("\"is_preview\":true"))
            .respond_with(
                ResponseTemplate::new(201)
                    .set_body_json(serde_json::json!({"uuid": "preview-guard-uuid"})),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v1/applications/application-123/envs"))
            .and(body_string_contains("\"is_preview\":false"))
            .respond_with(
                ResponseTemplate::new(201)
                    .set_body_json(serde_json::json!({"uuid": "production-uuid"})),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path("/api/v1/applications/application-123/envs"))
            .respond_with(ResponseTemplate::new(201))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path(
                "/api/v1/applications/application-123/envs/preview-guard-uuid",
            ))
            .respond_with(StatusSequence {
                calls: Arc::clone(&guard_deletes),
                first: 503,
                subsequent: 200,
            })
            .expect(2)
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path(
                "/api/v1/applications/application-123/envs/production-uuid",
            ))
            .respond_with(ResponseTemplate::new(503))
            .expect(1)
            .mount(&server)
            .await;
        let client =
            CoolifyClient::new("coolify-token".into(), config(server.uri())).expect("client");
        let local = HashMap::from([("NEW_SECRET".into(), "production-value".into())]);
        let diff = PlatformDiff {
            added: vec!["NEW_SECRET".into()],
            ..PlatformDiff::default()
        };

        let error = client
            .apply(&diff, &local, &HashMap::new())
            .await
            .expect_err("failed production rollback must report the committed add");

        let PlatformApplyError::Tracked { applied, error } = error else {
            panic!("compensation result is authoritative")
        };
        assert_eq!(applied.added, 1);
        assert!(error.to_string().contains("production rollback"));
        assert_eq!(guard_deletes.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn list_refuses_redirects() {
        let _env =
            crate::test_env::ScopedEnv::set([("ACCEPTANCE_RUN_ID", "coolify-redirect".into())]);
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/applications/application-123/envs"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("location", format!("{}/credential-capture", server.uri())),
            )
            .expect(1)
            .mount(&server)
            .await;
        let client =
            CoolifyClient::new("coolify-token".into(), config(server.uri())).expect("client");

        let error = client.list().await.expect_err("redirect must fail closed");

        assert!(error.to_string().contains("HTTP 302"));
        let requests = server
            .received_requests()
            .await
            .expect("received request log");
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].url.path(),
            "/api/v1/applications/application-123/envs"
        );
    }
}
