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
    Created { id: String, recovered: bool },
    Existing,
}

#[derive(Debug)]
struct OwnedCreateFailure {
    error: LpmError,
    owned_ids: Vec<String>,
    committed: CoolifyCommitState,
}

#[derive(Debug, Clone, Copy)]
enum CoolifyCommitState {
    NotCommitted,
    Committed,
    Unknown,
}

#[derive(Debug)]
enum DeleteVariableOutcome {
    Removed,
    Present(LpmError),
    Unknown(LpmError),
}

#[derive(Debug)]
struct OwnedCleanupOutcome {
    id: String,
    outcome: DeleteVariableOutcome,
}

#[derive(Debug)]
struct CoolifyAddFailure {
    error: LpmError,
    committed: CoolifyCommitState,
}

struct OwnedAddContext<'a> {
    key: &'a str,
    value: &'a str,
    sentinel: &'a str,
    is_preview: bool,
    target_id: String,
    guard_id: Option<String>,
    target_recovered: bool,
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
                DeleteVariableOutcome::Removed => MutationOutcome::Applied(MutationKind::Removed),
                DeleteVariableOutcome::Present(error) => MutationOutcome::Failed {
                    error,
                    committed: None,
                },
                DeleteVariableOutcome::Unknown(error) => MutationOutcome::Unknown(error),
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
                Ok(OwnedCreateResult::Created { id, .. }) => id,
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
                        committed: commit_state_after_cleanup(failure.committed, &cleanup, &[]),
                    });
                }
            };
            return self
                .finalize_owned_add(OwnedAddContext {
                    key,
                    value,
                    sentinel: &sentinel,
                    is_preview: true,
                    target_id: preview_id,
                    guard_id: None,
                    target_recovered: false,
                })
                .await;
        }

        let guard_id = match self.create_owned_variable(key, &sentinel, true, true).await {
            Ok(OwnedCreateResult::Created { id, .. }) => Some(id),
            Ok(OwnedCreateResult::Existing) => None,
            Err(failure) => {
                let cleanup = self.cleanup_owned_ids(failure.owned_ids).await;
                return Err(CoolifyAddFailure {
                    error: append_cleanup(failure.error, &cleanup),
                    committed: commit_state_after_cleanup(failure.committed, &cleanup, &[]),
                });
            }
        };

        let (production_id, production_recovered) = match self
            .create_owned_variable(key, &sentinel, false, false)
            .await
        {
            Ok(OwnedCreateResult::Created { id, recovered }) => (id, recovered),
            Ok(OwnedCreateResult::Existing) => {
                let cleanup = self.cleanup_owned_ids(guard_id.into_iter().collect()).await;
                return Err(CoolifyAddFailure {
                    error: append_cleanup(
                        LpmError::Script(format!(
                            "Coolify unexpectedly reported an existing production value for {key}"
                        )),
                        &cleanup,
                    ),
                    committed: commit_state_after_cleanup(
                        CoolifyCommitState::NotCommitted,
                        &cleanup,
                        &[],
                    ),
                });
            }
            Err(failure) => {
                let production_ids = failure.owned_ids.clone();
                let mut owned_ids = failure.owned_ids;
                if let Some(guard_id) = guard_id {
                    owned_ids.push(guard_id);
                }
                let cleanup = self.cleanup_owned_ids(owned_ids).await;
                return Err(CoolifyAddFailure {
                    error: append_cleanup(failure.error, &cleanup),
                    committed: commit_state_after_cleanup(
                        failure.committed,
                        &cleanup,
                        &production_ids,
                    ),
                });
            }
        };

        self.finalize_owned_add(OwnedAddContext {
            key,
            value,
            sentinel: &sentinel,
            is_preview: false,
            target_id: production_id,
            guard_id,
            target_recovered: production_recovered,
        })
        .await
    }

    async fn finalize_owned_add(
        &self,
        context: OwnedAddContext<'_>,
    ) -> Result<(), CoolifyAddFailure> {
        let OwnedAddContext {
            key,
            value,
            sentinel,
            is_preview,
            target_id,
            guard_id,
            target_recovered,
        } = context;
        if !is_preview && (guard_id.is_none() || target_recovered) {
            let preview_ids = match self.owned_ids_for_value(key, sentinel, true).await {
                Ok(ids) => ids,
                Err(error) => {
                    let mut ids = vec![target_id.clone()];
                    if let Some(guard_id) = guard_id {
                        ids.push(guard_id);
                    }
                    let cleanup = self.cleanup_owned_ids(ids).await;
                    return Err(CoolifyAddFailure {
                        error: append_cleanup(
                            append_error_context(
                                error,
                                format!("Coolify could not reconcile preview ownership for {key}"),
                            ),
                            &cleanup,
                        ),
                        committed: commit_state_after_cleanup(
                            CoolifyCommitState::Unknown,
                            &cleanup,
                            std::slice::from_ref(&target_id),
                        ),
                    });
                }
            };
            let preview_cleanup = self.cleanup_owned_ids(preview_ids).await;
            if !cleanup_succeeded(&preview_cleanup) {
                let cleanup_error = cleanup_failure_error(
                    format!("Coolify preview sentinel cleanup for {key} failed"),
                    preview_cleanup,
                );
                let production_cleanup = self.cleanup_owned_ids(vec![target_id.clone()]).await;
                let production_state = commit_state_after_cleanup(
                    CoolifyCommitState::Committed,
                    &production_cleanup,
                    std::slice::from_ref(&target_id),
                );
                return Err(CoolifyAddFailure {
                    error: append_cleanup(cleanup_error, &production_cleanup),
                    committed: match production_state {
                        CoolifyCommitState::Committed => CoolifyCommitState::Committed,
                        CoolifyCommitState::NotCommitted | CoolifyCommitState::Unknown => {
                            CoolifyCommitState::Unknown
                        }
                    },
                });
            }
        }

        if let Err(update_error) = self.update_value(key, value, is_preview).await {
            match self.read_owned_value(&target_id, key, is_preview).await {
                Ok(Some(observed)) if observed == value => {}
                observed => {
                    let mut owned_ids = vec![target_id.clone()];
                    if let Some(guard_id) = guard_id {
                        owned_ids.push(guard_id);
                    }
                    let cleanup = self.cleanup_owned_ids(owned_ids).await;
                    let committed = match observed {
                        Ok(_) => commit_state_after_cleanup(
                            CoolifyCommitState::NotCommitted,
                            &cleanup,
                            std::slice::from_ref(&target_id),
                        ),
                        Err(_) => commit_state_after_cleanup(
                            CoolifyCommitState::Unknown,
                            &cleanup,
                            std::slice::from_ref(&target_id),
                        ),
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
        match self.delete_variable(&guard_id).await {
            DeleteVariableOutcome::Removed => {}
            guard_outcome => {
                let cleanup_error = delete_failure_error(
                    format!("Coolify preview guard cleanup for {key} failed"),
                    &guard_id,
                    guard_outcome,
                );
                let cleanup = self
                    .cleanup_owned_ids(vec![target_id.clone(), guard_id])
                    .await;
                let production_state = commit_state_after_cleanup(
                    CoolifyCommitState::Committed,
                    &cleanup,
                    std::slice::from_ref(&target_id),
                );
                return Err(CoolifyAddFailure {
                    error: append_cleanup(cleanup_error, &cleanup),
                    committed: match production_state {
                        CoolifyCommitState::Committed => CoolifyCommitState::Committed,
                        CoolifyCommitState::NotCommitted | CoolifyCommitState::Unknown => {
                            CoolifyCommitState::Unknown
                        }
                    },
                });
            }
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
        let result = match self
            .post_variable(key, value, is_preview, allow_existing)
            .await
        {
            Ok(result) => result,
            Err(error) => {
                return self
                    .recover_ambiguous_owned_create(key, value, is_preview, error)
                    .await;
            }
        };
        match result {
            PostVariableResult::Created(Some(id)) => Ok(OwnedCreateResult::Created {
                id,
                recovered: false,
            }),
            PostVariableResult::Created(None) => {
                self.recover_ambiguous_owned_create(
                    key,
                    value,
                    is_preview,
                    LpmError::Script(format!("Coolify created {key} but returned no usable UUID")),
                )
                .await
            }
            PostVariableResult::Existing => {
                if !allow_existing {
                    return Err(OwnedCreateFailure {
                        error: LpmError::Script(format!(
                            "Coolify unexpectedly reported an existing value for {key}"
                        )),
                        owned_ids: Vec::new(),
                        committed: CoolifyCommitState::NotCommitted,
                    });
                }
                let preview_ids = self.preview_ids_for_key(key).await.map_err(|error| {
                    OwnedCreateFailure {
                        error: LpmError::Script(format!(
                            "Coolify preview guard conflicted for {key}, but the existing preview value could not be verified: {error}"
                        )),
                        owned_ids: Vec::new(),
                        committed: CoolifyCommitState::Unknown,
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
                        committed: CoolifyCommitState::NotCommitted,
                    })
                }
            }
        }
    }

    async fn recover_ambiguous_owned_create(
        &self,
        key: &str,
        value: &str,
        is_preview: bool,
        error: LpmError,
    ) -> Result<OwnedCreateResult, OwnedCreateFailure> {
        let owned_ids = match self.owned_ids_for_value(key, value, is_preview).await {
            Ok(ids) => ids,
            Err(recovery_error) => {
                return Err(OwnedCreateFailure {
                    error: append_error_context(
                        error,
                        format!("Coolify ownership recovery for {key} failed: {recovery_error}"),
                    ),
                    owned_ids: Vec::new(),
                    committed: CoolifyCommitState::Unknown,
                });
            }
        };
        match owned_ids.as_slice() {
            [id] => Ok(OwnedCreateResult::Created {
                id: id.clone(),
                recovered: true,
            }),
            [] => Err(OwnedCreateFailure {
                error,
                owned_ids,
                committed: CoolifyCommitState::NotCommitted,
            }),
            _ => Err(OwnedCreateFailure {
                error: append_error_context(
                    error,
                    format!(
                        "Coolify ownership recovery for {key} found {} sentinel-matched values",
                        owned_ids.len()
                    ),
                ),
                owned_ids,
                committed: CoolifyCommitState::Committed,
            }),
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
        for variable in variables.into_iter().filter(|variable| variable.key == key) {
            let is_preview =
                required_metadata_flag(variable.is_preview, "is_preview", &variable.key)?;
            if is_preview != expected_preview {
                continue;
            }
            let observed = variable
                .value
                .as_deref()
                .ok_or_else(|| hidden_owned_value_error(&variable.key))?;
            if observed != value {
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
        let value = variable
            .value
            .ok_or_else(|| hidden_owned_value_error(key))?;
        Ok(Some(value))
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

    async fn cleanup_owned_ids(&self, ids: Vec<String>) -> Vec<OwnedCleanupOutcome> {
        let mut results = Vec::with_capacity(ids.len());
        for id in ids {
            let outcome = self.delete_variable(&id).await;
            results.push(OwnedCleanupOutcome { id, outcome });
        }
        results
    }

    async fn delete_variable(&self, id: &str) -> DeleteVariableOutcome {
        let request = self
            .http
            .delete(self.item_url(id))
            .bearer_auth(&self.token)
            .header(reqwest::header::ACCEPT, "application/json");
        let delete_error = match self.send_mutation("delete", request).await {
            Ok(_) => return DeleteVariableOutcome::Removed,
            Err(error) => error,
        };
        match self.variable_exists(id).await {
            Ok(false) => DeleteVariableOutcome::Removed,
            Ok(true) => DeleteVariableOutcome::Present(delete_error),
            Err(verification_error) => {
                let error = append_error_context(
                    delete_error,
                    format!(
                        "Coolify could not verify the final state of value {id}: {verification_error}"
                    ),
                );
                DeleteVariableOutcome::Unknown(error)
            }
        }
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

fn hidden_owned_value_error(key: &str) -> LpmError {
    LpmError::Script(format!(
        "Coolify raw value for {key} is hidden; authoritative ownership reconciliation is unavailable"
    ))
}

fn is_shared_reference(value: &str) -> bool {
    ["{{team.", "{{project.", "{{environment.", "{{server."]
        .iter()
        .any(|prefix| value.contains(prefix))
}

fn mutation_result(outcome: &DeleteVariableOutcome) -> String {
    match outcome {
        DeleteVariableOutcome::Removed => "removed".into(),
        DeleteVariableOutcome::Present(error) => format!("still present ({error})"),
        DeleteVariableOutcome::Unknown(error) => format!("final state unknown ({error})"),
    }
}

fn ownership_sentinel() -> String {
    let mut bytes = [0_u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    format!("__lpm_env_ownership_{}", hex::encode(bytes))
}

fn cleanup_succeeded(cleanup: &[OwnedCleanupOutcome]) -> bool {
    cleanup
        .iter()
        .all(|item| matches!(item.outcome, DeleteVariableOutcome::Removed))
}

fn cleanup_summary(cleanup: &[OwnedCleanupOutcome]) -> String {
    cleanup
        .iter()
        .map(|item| format!("{}: {}", item.id, mutation_result(&item.outcome)))
        .collect::<Vec<_>>()
        .join(", ")
}

fn delete_failure_error(context: String, id: &str, outcome: DeleteVariableOutcome) -> LpmError {
    match outcome {
        DeleteVariableOutcome::Removed => {
            LpmError::Script(format!("{context}; value {id} was already removed"))
        }
        DeleteVariableOutcome::Present(error) | DeleteVariableOutcome::Unknown(error) => {
            append_error_context(error, context)
        }
    }
}

fn cleanup_failure_error(context: String, cleanup: Vec<OwnedCleanupOutcome>) -> LpmError {
    let summary = cleanup_summary(&cleanup);
    let error = cleanup
        .into_iter()
        .find_map(|item| match item.outcome {
            DeleteVariableOutcome::Removed => None,
            DeleteVariableOutcome::Present(error) | DeleteVariableOutcome::Unknown(error) => {
                Some(error)
            }
        })
        .unwrap_or_else(|| LpmError::Script(context.clone()));
    append_error_context(error, format!("{context}: {summary}"))
}

fn commit_state_after_cleanup(
    initial: CoolifyCommitState,
    cleanup: &[OwnedCleanupOutcome],
    target_ids: &[String],
) -> CoolifyCommitState {
    if cleanup
        .iter()
        .any(|item| matches!(item.outcome, DeleteVariableOutcome::Unknown(_)))
    {
        return CoolifyCommitState::Unknown;
    }
    if !target_ids.is_empty() {
        let mut matched_targets = 0;
        for item in cleanup {
            if target_ids.contains(&item.id) {
                matched_targets += 1;
                if matches!(item.outcome, DeleteVariableOutcome::Present(_)) {
                    return CoolifyCommitState::Committed;
                }
            }
        }
        if matched_targets == target_ids.len() {
            return CoolifyCommitState::NotCommitted;
        }
    }
    if cleanup_succeeded(cleanup) {
        return match initial {
            CoolifyCommitState::Unknown => CoolifyCommitState::Unknown,
            CoolifyCommitState::NotCommitted | CoolifyCommitState::Committed => {
                CoolifyCommitState::NotCommitted
            }
        };
    }
    CoolifyCommitState::Unknown
}

fn append_error_context(error: LpmError, context: String) -> LpmError {
    match error {
        LpmError::Network(message) => LpmError::Network(format!("{message}; {context}")),
        LpmError::Script(message) => LpmError::Script(format!("{message}; {context}")),
        other => other,
    }
}

fn append_cleanup(error: LpmError, cleanup: &[OwnedCleanupOutcome]) -> LpmError {
    if cleanup_succeeded(cleanup) {
        return error;
    }
    append_error_context(
        error,
        format!("owned-value cleanup: {}", cleanup_summary(cleanup)),
    )
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
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

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

    struct CaptureProductionSentinelWithId {
        sentinel: Arc<Mutex<Option<String>>>,
    }

    impl Respond for CaptureProductionSentinelWithId {
        fn respond(&self, request: &Request) -> ResponseTemplate {
            let body: serde_json::Value =
                serde_json::from_slice(&request.body).expect("production create JSON");
            *self.sentinel.lock().expect("sentinel lock") =
                body["value"].as_str().map(str::to_owned);
            ResponseTemplate::new(201).set_body_json(serde_json::json!({"uuid": "production-uuid"}))
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

    struct GuardRaceVariables {
        sentinel: Arc<Mutex<Option<String>>>,
        list_calls: Arc<AtomicUsize>,
        mirrored_preview_exists: Arc<AtomicBool>,
    }

    impl Respond for GuardRaceVariables {
        fn respond(&self, _request: &Request) -> ResponseTemplate {
            if self.list_calls.fetch_add(1, Ordering::SeqCst) == 0 {
                return ResponseTemplate::new(200).set_body_json(serde_json::json!([
                    {
                        "uuid": "legitimate-preview-uuid",
                        "key": "NEW_SECRET",
                        "is_preview": true
                    }
                ]));
            }
            let sentinel = self
                .sentinel
                .lock()
                .expect("sentinel lock")
                .clone()
                .expect("captured production sentinel");
            let mut variables = vec![serde_json::json!({
                "uuid": "production-uuid",
                "key": "NEW_SECRET",
                "value": sentinel,
                "is_preview": false
            })];
            if self.mirrored_preview_exists.load(Ordering::SeqCst) {
                variables.push(serde_json::json!({
                    "uuid": "mirrored-preview-uuid",
                    "key": "NEW_SECRET",
                    "value": sentinel,
                    "is_preview": true
                }));
            }
            ResponseTemplate::new(200).set_body_json(variables)
        }
    }

    struct RemoveMirroredPreview {
        mirrored_preview_exists: Arc<AtomicBool>,
    }

    impl Respond for RemoveMirroredPreview {
        fn respond(&self, _request: &Request) -> ResponseTemplate {
            self.mirrored_preview_exists.store(false, Ordering::SeqCst);
            ResponseTemplate::new(200)
        }
    }

    async fn spawn_commit_then_disconnect_server(
        sentinel: &str,
        oversized_success_body: bool,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind raw Coolify server");
        let address = listener.local_addr().expect("raw Coolify address");
        let sentinel = sentinel.to_owned();
        let task = tokio::spawn(async move {
            let (mut create_stream, _) = listener.accept().await.expect("accept create");
            let mut create_request = Vec::new();
            loop {
                let mut chunk = [0_u8; 2048];
                let read = create_stream
                    .read(&mut chunk)
                    .await
                    .expect("read create request");
                if read == 0 {
                    break;
                }
                create_request.extend_from_slice(&chunk[..read]);
                if String::from_utf8_lossy(&create_request).contains(&sentinel) {
                    break;
                }
            }
            if oversized_success_body {
                let response = format!(
                    "HTTP/1.1 201 Created\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    super::super::super::response::MAX_PLATFORM_RESPONSE_BYTES + 1
                );
                create_stream
                    .write_all(response.as_bytes())
                    .await
                    .expect("write oversized success headers");
            }
            drop(create_stream);

            let (mut list_stream, _) = listener.accept().await.expect("accept recovery list");
            let mut list_request = Vec::new();
            while !list_request.windows(4).any(|window| window == b"\r\n\r\n") {
                let mut chunk = [0_u8; 1024];
                let read = list_stream
                    .read(&mut chunk)
                    .await
                    .expect("read recovery list request");
                if read == 0 {
                    break;
                }
                list_request.extend_from_slice(&chunk[..read]);
            }
            let body = serde_json::to_vec(&serde_json::json!([
                {
                    "uuid": "recovered-preview-uuid",
                    "key": "NEW_SECRET",
                    "value": sentinel,
                    "is_preview": true
                }
            ]))
            .expect("serialize recovery response");
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            list_stream
                .write_all(response.as_bytes())
                .await
                .expect("write recovery headers");
            list_stream
                .write_all(&body)
                .await
                .expect("write recovery body");
        });
        (format!("http://{address}"), task)
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
    fn cleanup_context_preserves_network_error_classification() {
        let cleanup = vec![OwnedCleanupOutcome {
            id: "owned-id".into(),
            outcome: DeleteVariableOutcome::Present(LpmError::Script("cleanup rejected".into())),
        }];

        let error = append_cleanup(LpmError::Network("connection reset".into()), &cleanup);

        assert_eq!(error.error_code(), "network");
        assert_eq!(
            error.to_string(),
            "network error: connection reset; owned-value cleanup: owned-id: still present (script error: cleanup rejected)"
        );
    }

    #[test]
    fn cleanup_context_does_not_duplicate_script_error_prefix() {
        let cleanup = vec![OwnedCleanupOutcome {
            id: "owned-id".into(),
            outcome: DeleteVariableOutcome::Unknown(LpmError::Network(
                "cleanup disconnected".into(),
            )),
        }];

        let error = append_cleanup(LpmError::Script("create rejected".into()), &cleanup);

        assert_eq!(
            error.to_string(),
            "script error: create rejected; owned-value cleanup: owned-id: final state unknown (network error: cleanup disconnected)"
        );
    }

    #[tokio::test]
    async fn committed_create_is_recovered_when_the_response_disconnects() {
        let _env = crate::test_env::ScopedEnv::set([(
            "ACCEPTANCE_RUN_ID",
            "coolify-create-disconnect".into(),
        )]);
        let sentinel = "__lpm_env_ownership_disconnect";
        let (url, server) = spawn_commit_then_disconnect_server(sentinel, false).await;
        let mut connection = config(url);
        connection.preview = true;
        let client = CoolifyClient::new("coolify-token".into(), connection).expect("client");

        let result = client
            .create_owned_variable("NEW_SECRET", sentinel, true, false)
            .await
            .expect("committed create must be recovered");

        assert!(matches!(
            result,
            OwnedCreateResult::Created { ref id, recovered: true }
                if id == "recovered-preview-uuid"
        ));
        server.await.expect("raw Coolify server");
    }

    #[tokio::test]
    async fn committed_create_is_recovered_when_the_success_body_exceeds_the_cap() {
        let _env = crate::test_env::ScopedEnv::set([(
            "ACCEPTANCE_RUN_ID",
            "coolify-create-body-failure".into(),
        )]);
        let sentinel = "__lpm_env_ownership_body_failure";
        let (url, server) = spawn_commit_then_disconnect_server(sentinel, true).await;
        let mut connection = config(url);
        connection.preview = true;
        let client = CoolifyClient::new("coolify-token".into(), connection).expect("client");

        let result = client
            .create_owned_variable("NEW_SECRET", sentinel, true, false)
            .await
            .expect("committed create must be recovered");

        assert!(matches!(
            result,
            OwnedCreateResult::Created { ref id, recovered: true }
                if id == "recovered-preview-uuid"
        ));
        server.await.expect("raw Coolify server");
    }

    #[tokio::test]
    async fn ambiguous_create_is_unknown_when_the_matching_value_is_hidden() {
        let _env = crate::test_env::ScopedEnv::set([(
            "ACCEPTANCE_RUN_ID",
            "coolify-hidden-create-recovery".into(),
        )]);
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/applications/application-123/envs"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {
                    "uuid": "hidden-preview-uuid",
                    "key": "NEW_SECRET",
                    "is_preview": true
                }
            ])))
            .expect(1)
            .mount(&server)
            .await;
        let client =
            CoolifyClient::new("coolify-token".into(), config(server.uri())).expect("client");

        let failure = client
            .recover_ambiguous_owned_create(
                "NEW_SECRET",
                "__lpm_env_ownership_hidden",
                true,
                LpmError::Network("create response disconnected".into()),
            )
            .await
            .expect_err("hidden matching value must remain ambiguous");

        assert!(matches!(failure.committed, CoolifyCommitState::Unknown));
    }

    #[tokio::test]
    async fn owned_value_read_fails_when_the_matching_value_is_hidden() {
        let _env = crate::test_env::ScopedEnv::set([(
            "ACCEPTANCE_RUN_ID",
            "coolify-hidden-owned-read".into(),
        )]);
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/applications/application-123/envs"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {
                    "uuid": "hidden-production-uuid",
                    "key": "NEW_SECRET",
                    "is_preview": false
                }
            ])))
            .expect(1)
            .mount(&server)
            .await;
        let client =
            CoolifyClient::new("coolify-token".into(), config(server.uri())).expect("client");

        let error = client
            .read_owned_value("hidden-production-uuid", "NEW_SECRET", false)
            .await
            .expect_err("hidden owned value must not look absent");

        assert!(error.to_string().contains("hidden"));
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
            ..PlatformDiff::default()
        };

        let result = client
            .apply(&diff, &local, &remote)
            .await
            .expect("apply Coolify mutations");

        assert_eq!(result.updated, 1);
        assert_eq!(result.removed, 1);
    }

    #[tokio::test]
    async fn delete_response_failure_is_counted_as_removed_when_the_value_is_authoritatively_absent()
     {
        let _env =
            crate::test_env::ScopedEnv::set([("ACCEPTANCE_RUN_ID", "coolify-delete-race".into())]);
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path(
                "/api/v1/applications/application-123/envs/removed-uuid",
            ))
            .respond_with(ResponseTemplate::new(503))
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

        let outcome = client.delete_variable("removed-uuid").await;

        assert!(matches!(outcome, DeleteVariableOutcome::Removed));
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
                    "value": "legitimate-preview-value",
                    "is_preview": true
                }
            ])))
            .expect(2)
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
    async fn production_add_removes_a_sentinel_mirrored_after_the_verified_guard_disappears() {
        let _env =
            crate::test_env::ScopedEnv::set([("ACCEPTANCE_RUN_ID", "coolify-guard-race".into())]);
        let server = MockServer::start().await;
        let sentinel = Arc::new(Mutex::new(None));
        let list_calls = Arc::new(AtomicUsize::new(0));
        let mirrored_preview_exists = Arc::new(AtomicBool::new(true));
        Mock::given(method("POST"))
            .and(path("/api/v1/applications/application-123/envs"))
            .and(body_string_contains("\"is_preview\":true"))
            .respond_with(ResponseTemplate::new(409))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v1/applications/application-123/envs"))
            .and(body_string_contains("\"is_preview\":false"))
            .respond_with(CaptureProductionSentinelWithId {
                sentinel: Arc::clone(&sentinel),
            })
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/applications/application-123/envs"))
            .respond_with(GuardRaceVariables {
                sentinel: Arc::clone(&sentinel),
                list_calls: Arc::clone(&list_calls),
                mirrored_preview_exists: Arc::clone(&mirrored_preview_exists),
            })
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path(
                "/api/v1/applications/application-123/envs/mirrored-preview-uuid",
            ))
            .respond_with(RemoveMirroredPreview {
                mirrored_preview_exists: Arc::clone(&mirrored_preview_exists),
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
        let client =
            CoolifyClient::new("coolify-token".into(), config(server.uri())).expect("client");
        let local = HashMap::from([("NEW_SECRET".into(), "production-value".into())]);
        let diff = PlatformDiff {
            added: vec!["NEW_SECRET".into()],
            ..PlatformDiff::default()
        };

        let result = client
            .apply(&diff, &local, &HashMap::new())
            .await
            .expect("the operation-owned mirrored sentinel must be removed");

        assert_eq!(result.added, 1);
        assert!(!mirrored_preview_exists.load(Ordering::SeqCst));
        assert!(list_calls.load(Ordering::SeqCst) >= 2);
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
            .expect(2)
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

        assert!(
            matches!(error, PlatformApplyError::Untracked(_)),
            "failed ownership recovery must suppress an exact mutation count"
        );
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
        Mock::given(method("GET"))
            .and(path("/api/v1/applications/application-123/envs"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {
                    "uuid": "preview-guard-uuid",
                    "key": "NEW_SECRET"
                },
                {
                    "uuid": "production-uuid",
                    "key": "NEW_SECRET"
                }
            ])))
            .expect(2)
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
        assert!(error.to_string().contains("production-uuid: still present"));
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
