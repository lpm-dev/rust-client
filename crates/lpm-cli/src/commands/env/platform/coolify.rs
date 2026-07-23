use super::{
    MutationKind, PLATFORM_MUTATION_CONCURRENCY, PLATFORM_TIMEOUT, PlatformDiff,
    PlatformPushResult, PlatformVariable, VariableScope, read_platform_response,
};
use futures::StreamExt;
use lpm_common::LpmError;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

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
    uuid: String,
}

#[derive(Debug)]
enum CoolifyMutation {
    Add {
        key: String,
        value: String,
    },
    Update {
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
    ) -> Result<PlatformPushResult, LpmError> {
        let mut mutations =
            Vec::with_capacity(diff.added.len() + diff.changed.len() + diff.removed.len());
        for key in &diff.added {
            let value = local
                .get(key)
                .ok_or_else(|| LpmError::Script(format!("missing local value for {key}")))?;
            mutations.push(CoolifyMutation::Add {
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
                .ok_or_else(|| LpmError::Script(format!("missing Coolify value for {key}")))?;
            let metadata = self.mutation_metadata(key, variable)?;
            mutations.push(CoolifyMutation::Update {
                key: key.clone(),
                value: value.clone(),
                metadata,
            });
        }
        for key in &diff.removed {
            let variable = remote
                .get(key)
                .ok_or_else(|| LpmError::Script(format!("missing Coolify value for {key}")))?;
            self.assert_mutation_scope(key, variable)?;
            mutations.push(CoolifyMutation::Remove {
                id: variable.id.clone(),
            });
        }

        let outcomes = futures::stream::iter(mutations)
            .map(|mutation| self.apply_one(mutation))
            .buffer_unordered(PLATFORM_MUTATION_CONCURRENCY)
            .collect::<Vec<_>>()
            .await;
        let mut completed = Vec::with_capacity(outcomes.len());
        for outcome in outcomes {
            completed.push(outcome?);
        }
        Ok(PlatformPushResult::from_outcomes(completed))
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

    async fn apply_one(&self, mutation: CoolifyMutation) -> Result<MutationKind, LpmError> {
        match mutation {
            CoolifyMutation::Add { key, value } => {
                self.create_with_preview_isolation(&key, &value).await?;
                Ok(MutationKind::Added)
            }
            CoolifyMutation::Update {
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
                self.send_mutation("update", request).await?;
                Ok(MutationKind::Updated)
            }
            CoolifyMutation::Remove { id } => {
                self.delete_variable(&id).await?;
                Ok(MutationKind::Removed)
            }
        }
    }

    async fn create_with_preview_isolation(&self, key: &str, value: &str) -> Result<(), LpmError> {
        if self.config.preview {
            self.create_variable(key, value, true).await?;
            return Ok(());
        }

        let previews_before = self.preview_ids_for_key(key).await?;
        let production_id = self.create_variable(key, value, false).await?;
        let previews_after = match self.preview_ids_for_key(key).await {
            Ok(previews) => previews,
            Err(error) => {
                return Err(self
                    .rollback_created_production(
                        &production_id,
                        format!("failed to verify Coolify preview isolation for {key}: {error}"),
                    )
                    .await);
            }
        };
        let mut created_previews = previews_after
            .difference(&previews_before)
            .cloned()
            .collect::<Vec<_>>();
        created_previews.sort_unstable();

        match created_previews.as_slice() {
            [] => Ok(()),
            [preview_id] => {
                if let Err(cleanup_error) = self.delete_variable(preview_id).await {
                    return Err(self
                        .rollback_after_preview_cleanup_failure(
                            key,
                            &production_id,
                            preview_id,
                            cleanup_error,
                        )
                        .await);
                }
                Ok(())
            }
            _ => Err(self
                .rollback_created_production(
                    &production_id,
                    format!(
                        "Coolify created multiple preview copies for {key}; refusing to delete ambiguous preview state"
                    ),
                )
                .await),
        }
    }

    async fn create_variable(
        &self,
        key: &str,
        value: &str,
        is_preview: bool,
    ) -> Result<String, LpmError> {
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
        let body = self.send_mutation("create", request).await?;
        let created: CoolifyCreateResponse = serde_json::from_slice(&body).map_err(|error| {
            LpmError::Script(format!(
                "invalid Coolify create response for {key}: {error}"
            ))
        })?;
        if created.uuid.is_empty() {
            return Err(LpmError::Script(format!(
                "Coolify create response for {key} has an invalid UUID"
            )));
        }
        Ok(created.uuid)
    }

    async fn preview_ids_for_key(&self, key: &str) -> Result<HashSet<String>, LpmError> {
        let variables = self.fetch_variables().await?;
        let mut ids = HashSet::new();
        for variable in variables.into_iter().filter(|variable| variable.key == key) {
            let is_preview =
                required_metadata_flag(variable.is_preview, "is_preview", &variable.key)?;
            if is_preview {
                if variable.uuid.is_empty() {
                    return Err(LpmError::Script(format!(
                        "Coolify value {} has an invalid UUID",
                        variable.key
                    )));
                }
                ids.insert(variable.uuid);
            }
        }
        Ok(ids)
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

    async fn rollback_created_production(&self, production_id: &str, cause: String) -> LpmError {
        match self.delete_variable(production_id).await {
            Ok(()) => LpmError::Script(format!("{cause}; the production value was rolled back")),
            Err(rollback_error) => LpmError::Script(format!(
                "{cause}; production rollback also failed: {rollback_error}"
            )),
        }
    }

    async fn rollback_after_preview_cleanup_failure(
        &self,
        key: &str,
        production_id: &str,
        preview_id: &str,
        cleanup_error: LpmError,
    ) -> LpmError {
        let production_rollback = self.delete_variable(production_id).await;
        let preview_retry = self.delete_variable(preview_id).await;
        match (production_rollback, preview_retry) {
            (Ok(()), Ok(())) => LpmError::Script(format!(
                "Coolify preview cleanup for {key} initially failed: {cleanup_error}; both created values were rolled back"
            )),
            (production, preview) => LpmError::Script(format!(
                "Coolify preview isolation failed for {key}: {cleanup_error}; production rollback: {}; preview cleanup retry: {}",
                mutation_result(&production),
                mutation_result(&preview)
            )),
        }
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
    use wiremock::matchers::{body_json, header, method, path};
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct PreviewMirrorSequence {
        calls: Arc<AtomicUsize>,
    }

    impl Respond for PreviewMirrorSequence {
        fn respond(&self, _request: &Request) -> ResponseTemplate {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            let variables = if call == 0 {
                serde_json::json!([])
            } else {
                serde_json::json!([
                    {
                        "uuid": "production-uuid",
                        "key": "NEW_SECRET",
                        "value": "production-value",
                        "real_value": "production-value",
                        "is_preview": false,
                        "is_literal": false,
                        "is_multiline": false,
                        "is_shown_once": false,
                        "is_shared": false
                    },
                    {
                        "uuid": "mirrored-preview-uuid",
                        "key": "NEW_SECRET",
                        "value": "production-value",
                        "real_value": "production-value",
                        "is_preview": true,
                        "is_literal": false,
                        "is_multiline": false,
                        "is_shown_once": false,
                        "is_shared": false
                    }
                ])
            };
            ResponseTemplate::new(200).set_body_json(variables)
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
    async fn production_add_removes_only_the_new_mirrored_preview_value() {
        let _env =
            crate::test_env::ScopedEnv::set([("ACCEPTANCE_RUN_ID", "coolify-isolation".into())]);
        let server = MockServer::start().await;
        let list_calls = Arc::new(AtomicUsize::new(0));
        Mock::given(method("GET"))
            .and(path("/api/v1/applications/application-123/envs"))
            .and(header("authorization", "Bearer coolify-token"))
            .respond_with(PreviewMirrorSequence {
                calls: Arc::clone(&list_calls),
            })
            .expect(2)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
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
            .respond_with(
                ResponseTemplate::new(201)
                    .set_body_json(serde_json::json!({"uuid": "production-uuid"})),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path(
                "/api/v1/applications/application-123/envs/mirrored-preview-uuid",
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
        assert_eq!(list_calls.load(Ordering::SeqCst), 2);
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
