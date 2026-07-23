use super::{
    MutationKind, PLATFORM_MUTATION_CONCURRENCY, PLATFORM_TIMEOUT, PlatformDiff,
    PlatformPushResult, PlatformVariable, VariableScope, read_platform_response,
};
use futures::{StreamExt, TryStreamExt};
use lpm_common::LpmError;
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
    value: String,
    #[serde(default)]
    real_value: Option<String>,
    #[serde(default)]
    is_preview: bool,
}

#[derive(Debug)]
enum CoolifyMutation {
    Add { key: String, value: String },
    Update { key: String, value: String },
    Remove { id: String },
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

    pub(super) async fn list(&self) -> Result<HashMap<String, PlatformVariable>, LpmError> {
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
        let variables: Vec<CoolifyVariableResponse> = serde_json::from_slice(&body)
            .map_err(|error| LpmError::Script(format!("invalid Coolify response: {error}")))?;
        let mut result = HashMap::with_capacity(variables.len());
        for variable in variables {
            if variable.is_preview != self.config.preview || Self::is_managed(&variable.key) {
                continue;
            }
            if variable.uuid.is_empty() {
                return Err(LpmError::Script(format!(
                    "Coolify value {} has an invalid UUID",
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
                    value: variable.real_value.unwrap_or(variable.value),
                    scope: VariableScope::Coolify {
                        preview: variable.is_preview,
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
            self.assert_mutation_scope(key, variable)?;
            mutations.push(CoolifyMutation::Update {
                key: key.clone(),
                value: value.clone(),
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

        let outcomes: Vec<MutationKind> = futures::stream::iter(mutations)
            .map(|mutation| self.apply_one(mutation))
            .buffer_unordered(PLATFORM_MUTATION_CONCURRENCY)
            .try_collect()
            .await?;
        Ok(PlatformPushResult::from_outcomes(outcomes))
    }

    fn assert_mutation_scope(
        &self,
        key: &str,
        variable: &PlatformVariable,
    ) -> Result<(), LpmError> {
        match &variable.scope {
            VariableScope::Coolify { preview } if *preview == self.config.preview => Ok(()),
            _ => Err(LpmError::Script(format!(
                "Coolify value {key} does not match the configured application target"
            ))),
        }
    }

    async fn apply_one(&self, mutation: CoolifyMutation) -> Result<MutationKind, LpmError> {
        let (operation, kind, request) = match mutation {
            CoolifyMutation::Add { key, value } => (
                "create",
                MutationKind::Added,
                self.http
                    .post(self.collection_url())
                    .bearer_auth(&self.token)
                    .header(reqwest::header::ACCEPT, "application/json")
                    .json(&serde_json::json!({
                        "key": key,
                        "value": value,
                        "is_preview": self.config.preview,
                    })),
            ),
            CoolifyMutation::Update { key, value } => (
                "update",
                MutationKind::Updated,
                self.http
                    .patch(self.collection_url())
                    .bearer_auth(&self.token)
                    .header(reqwest::header::ACCEPT, "application/json")
                    .json(&serde_json::json!({
                        "key": key,
                        "value": value,
                        "is_preview": self.config.preview,
                    })),
            ),
            CoolifyMutation::Remove { id } => (
                "delete",
                MutationKind::Removed,
                self.http
                    .delete(self.item_url(&id))
                    .bearer_auth(&self.token)
                    .header(reqwest::header::ACCEPT, "application/json"),
            ),
        };
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
        Ok(kind)
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
    use wiremock::{Mock, MockServer, ResponseTemplate};

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
    async fn list_uses_uuid_and_authoritative_real_value() {
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
                    "is_preview": false
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
        assert_eq!(variable.value, "resolved-secret");
    }

    #[tokio::test]
    async fn update_uses_collection_and_delete_uses_variable_uuid() {
        let _env =
            crate::test_env::ScopedEnv::set([("ACCEPTANCE_RUN_ID", "coolify-mutate".into())]);
        let server = MockServer::start().await;
        Mock::given(method("PATCH"))
            .and(path("/api/v1/applications/application-123/envs"))
            .and(header("authorization", "Bearer coolify-token"))
            .and(body_json(serde_json::json!({
                "key": "CHANGED",
                "value": "local",
                "is_preview": false
            })))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "uuid": "changed-uuid",
                "key": "CHANGED",
                "value": "local",
                "is_preview": false
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
        let remote = HashMap::from([
            (
                "CHANGED".into(),
                PlatformVariable {
                    id: "changed-uuid".into(),
                    value: "remote".into(),
                    scope: VariableScope::Coolify { preview: false },
                },
            ),
            (
                "REMOVED".into(),
                PlatformVariable {
                    id: "removed-uuid".into(),
                    value: "remote".into(),
                    scope: VariableScope::Coolify { preview: false },
                },
            ),
        ]);
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
