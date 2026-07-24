use std::collections::HashMap;

use lpm_common::LpmError;
use reqwest::header::{ACCEPT, AUTHORIZATION, HeaderName, HeaderValue};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use super::{
    PLATFORM_TIMEOUT, PlatformDiff, PlatformPushResult, PlatformVariable, VariableScope,
    read_platform_response,
};

pub(super) const RAILWAY_API_URL: &str = "https://backboard.railway.com/graphql/v2";
pub(super) const VARIABLES_QUERY: &str = "query variables($projectId: String!, $environmentId: String!, $serviceId: String, $unrendered: Boolean) { variables(projectId: $projectId, environmentId: $environmentId, serviceId: $serviceId, unrendered: $unrendered) }";
pub(super) const VARIABLE_COLLECTION_UPSERT_MUTATION: &str = "mutation variableCollectionUpsert($input: VariableCollectionUpsertInput!) { variableCollectionUpsert(input: $input) }";

const PROJECT_ACCESS_TOKEN: HeaderName = HeaderName::from_static("project-access-token");
const MANAGED_VARIABLES: &[&str] = &[
    "RAILWAY_PUBLIC_DOMAIN",
    "RAILWAY_PRIVATE_DOMAIN",
    "RAILWAY_TCP_PROXY_DOMAIN",
    "RAILWAY_TCP_PROXY_PORT",
    "RAILWAY_TCP_APPLICATION_PORT",
    "RAILWAY_PROJECT_NAME",
    "RAILWAY_PROJECT_ID",
    "RAILWAY_ENVIRONMENT_NAME",
    "RAILWAY_ENVIRONMENT_ID",
    "RAILWAY_SERVICE_NAME",
    "RAILWAY_SERVICE_ID",
    "RAILWAY_REPLICA_ID",
    "RAILWAY_REPLICA_REGION",
    "RAILWAY_DEPLOYMENT_ID",
    "RAILWAY_SNAPSHOT_ID",
    "RAILWAY_VOLUME_NAME",
    "RAILWAY_VOLUME_MOUNT_PATH",
    "RAILWAY_GIT_COMMIT_SHA",
    "RAILWAY_GIT_AUTHOR",
    "RAILWAY_GIT_BRANCH",
    "RAILWAY_GIT_REPO_NAME",
    "RAILWAY_GIT_REPO_OWNER",
    "RAILWAY_GIT_COMMIT_MESSAGE",
];

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct RailwayConnectionConfig {
    pub(super) project_id: String,
    pub(super) environment_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) service_id: Option<String>,
    #[serde(default)]
    pub(super) project_token: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) linked_env: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GraphqlError {
    message: String,
}

#[derive(Debug, Deserialize)]
struct GraphqlResponse<T> {
    data: Option<T>,
    #[serde(default)]
    errors: Vec<GraphqlError>,
}

#[derive(Debug, Deserialize)]
struct VariablesData {
    variables: HashMap<String, String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpsertData {
    variable_collection_upsert: bool,
}

pub(super) struct RailwayClient {
    http: reqwest::Client,
    api_url: String,
    token: HeaderValue,
    config: RailwayConnectionConfig,
}

impl RailwayClient {
    pub(super) fn new(token: String, config: RailwayConnectionConfig) -> Result<Self, LpmError> {
        let mut token = HeaderValue::from_str(&token)
            .map_err(|_| LpmError::Script("Railway token contains invalid characters".into()))?;
        token.set_sensitive(true);
        let http = lpm_http::client_builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(PLATFORM_TIMEOUT)
            .build()
            .map_err(|error| {
                LpmError::Network(format!("failed to build Railway client: {error}"))
            })?;
        Ok(Self {
            http,
            api_url: railway_api_url()?,
            token,
            config,
        })
    }

    pub(super) fn config(&self) -> &RailwayConnectionConfig {
        &self.config
    }

    pub(super) fn is_managed(key: &str) -> bool {
        MANAGED_VARIABLES.contains(&key)
    }

    pub(super) async fn list(&self) -> Result<HashMap<String, PlatformVariable>, LpmError> {
        let data: VariablesData = self
            .execute(
                "list",
                VARIABLES_QUERY,
                serde_json::Value::Object(self.target_variables(true)),
            )
            .await?;
        let mut variables = HashMap::with_capacity(data.variables.len());
        for (key, value) in data.variables {
            if Self::is_managed(&key) {
                continue;
            }
            variables.insert(
                key.clone(),
                PlatformVariable {
                    id: key,
                    value,
                    scope: VariableScope::Railway,
                },
            );
        }
        Ok(variables)
    }

    pub(super) async fn apply(
        &self,
        diff: &PlatformDiff,
        local: &HashMap<String, String>,
        remote: &HashMap<String, PlatformVariable>,
        clean: bool,
    ) -> Result<PlatformPushResult, LpmError> {
        let local_values = local
            .iter()
            .filter(|(key, _)| !Self::is_managed(key))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect::<HashMap<_, _>>();
        let mut desired = if clean {
            HashMap::with_capacity(local_values.len())
        } else {
            remote
                .iter()
                .map(|(key, variable)| (key.clone(), variable.value.clone()))
                .collect()
        };
        desired.extend(
            local_values
                .iter()
                .map(|(key, value)| (key.clone(), value.clone())),
        );

        let mut input = self.target_variables(false);
        input.insert(
            "variables".into(),
            serde_json::to_value(&local_values).map_err(|error| {
                LpmError::Script(format!("failed to serialize Railway values: {error}"))
            })?,
        );
        input.insert("replace".into(), serde_json::Value::Bool(clean));
        let data: UpsertData = self
            .execute(
                "bulk upsert",
                VARIABLE_COLLECTION_UPSERT_MUTATION,
                serde_json::json!({ "input": input }),
            )
            .await?;
        if !data.variable_collection_upsert {
            return Err(LpmError::Script(
                "Railway bulk upsert returned an unsuccessful result".into(),
            ));
        }

        let observed = self.list().await?;
        let observed_values = observed
            .into_iter()
            .map(|(key, variable)| (key, variable.value))
            .collect::<HashMap<_, _>>();
        if observed_values != desired {
            return Err(LpmError::Script(
                "Railway synchronization verification failed; the authoritative values do not match the requested state"
                    .into(),
            ));
        }

        Ok(PlatformPushResult {
            added: diff.added.len(),
            updated: diff.changed.len(),
            removed: diff.removed.len(),
        })
    }

    fn target_variables(
        &self,
        include_unrendered: bool,
    ) -> serde_json::Map<String, serde_json::Value> {
        let mut variables = serde_json::Map::from_iter([
            (
                "projectId".into(),
                serde_json::Value::String(self.config.project_id.clone()),
            ),
            (
                "environmentId".into(),
                serde_json::Value::String(self.config.environment_id.clone()),
            ),
        ]);
        if let Some(service_id) = &self.config.service_id {
            variables.insert(
                "serviceId".into(),
                serde_json::Value::String(service_id.clone()),
            );
        }
        if include_unrendered {
            variables.insert("unrendered".into(), serde_json::Value::Bool(true));
        }
        variables
    }

    async fn execute<T: DeserializeOwned>(
        &self,
        operation: &str,
        query: &str,
        variables: serde_json::Value,
    ) -> Result<T, LpmError> {
        let mut request = self
            .http
            .post(&self.api_url)
            .header(ACCEPT, "application/json")
            .json(&serde_json::json!({ "query": query, "variables": variables }));
        request = if self.config.project_token {
            request.header(PROJECT_ACCESS_TOKEN, self.token.clone())
        } else {
            let bearer = format!(
                "Bearer {}",
                self.token
                    .to_str()
                    .map_err(|_| LpmError::Script("Railway token is not valid text".into()))?
            );
            let mut bearer = HeaderValue::from_str(&bearer).map_err(|_| {
                LpmError::Script("Railway token contains invalid characters".into())
            })?;
            bearer.set_sensitive(true);
            request.header(AUTHORIZATION, bearer)
        };
        let response = request.send().await.map_err(|error| {
            LpmError::Network(format!(
                "Railway {operation} failed: {}",
                lpm_http::display_error(&error)
            ))
        })?;
        let (status, body) = read_platform_response(response).await?;
        if !status.is_success() {
            return Err(railway_http_error(operation, status, &body));
        }
        let response: GraphqlResponse<T> = serde_json::from_slice(&body)
            .map_err(|error| LpmError::Script(format!("invalid Railway response: {error}")))?;
        if !response.errors.is_empty() {
            let detail = response
                .errors
                .iter()
                .map(|error| error.message.as_str())
                .collect::<Vec<_>>()
                .join("; ");
            return Err(LpmError::Script(format!(
                "Railway {operation} failed: {}",
                detail.chars().take(500).collect::<String>()
            )));
        }
        response.data.ok_or_else(|| {
            LpmError::Script(format!("Railway {operation} response did not include data"))
        })
    }
}

pub(super) fn railway_api_url() -> Result<String, LpmError> {
    if !cfg!(any(debug_assertions, feature = "acceptance-test-hooks")) {
        return Ok(RAILWAY_API_URL.into());
    }
    let Some(candidate) = std::env::var_os("LPM_ACCEPTANCE_RAILWAY_API_URL") else {
        return Ok(RAILWAY_API_URL.into());
    };
    if std::env::var("ACCEPTANCE_RUN_ID")
        .ok()
        .is_none_or(|value| value.trim().is_empty())
    {
        return Ok(RAILWAY_API_URL.into());
    }
    let candidate = candidate.to_string_lossy();
    let parsed = reqwest::Url::parse(&candidate)
        .map_err(|error| LpmError::Script(format!("invalid acceptance Railway URL: {error}")))?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(LpmError::Script(
            "the acceptance Railway URL must not contain credentials".into(),
        ));
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(LpmError::Script(
            "the acceptance Railway URL must not contain a query or fragment".into(),
        ));
    }
    if !matches!(parsed.host_str(), Some("127.0.0.1" | "localhost" | "::1")) {
        return Err(LpmError::Script(
            "the acceptance Railway URL must use a loopback host".into(),
        ));
    }
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(LpmError::Script(
            "the acceptance Railway URL must use HTTP or HTTPS".into(),
        ));
    }
    if parsed.path() != "/graphql/v2" {
        return Err(LpmError::Script(
            "the acceptance Railway URL must end with /graphql/v2".into(),
        ));
    }
    Ok(candidate.into_owned())
}

fn railway_http_error(operation: &str, status: reqwest::StatusCode, body: &[u8]) -> LpmError {
    let detail = String::from_utf8_lossy(body);
    let detail = detail.trim();
    let suffix = if detail.is_empty() {
        String::new()
    } else {
        format!(": {}", detail.chars().take(300).collect::<String>())
    };
    LpmError::Script(format!(
        "Railway {operation} failed with HTTP {status}{suffix}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    use wiremock::matchers::{body_json, header, header_exists, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn config(project_token: bool) -> RailwayConnectionConfig {
        RailwayConnectionConfig {
            project_id: "project-123".into(),
            environment_id: "environment-123".into(),
            service_id: Some("service-123".into()),
            project_token,
            linked_env: Some("production".into()),
        }
    }

    #[test]
    fn release_endpoint_is_fixed() {
        let _env = crate::test_env::ScopedEnv::update([
            ("ACCEPTANCE_RUN_ID", None),
            (
                "LPM_ACCEPTANCE_RAILWAY_API_URL",
                Some("http://127.0.0.1:4173/graphql/v2".into()),
            ),
        ]);

        assert_eq!(
            railway_api_url().expect("resolve Railway API URL"),
            RAILWAY_API_URL
        );
    }

    #[test]
    fn acceptance_override_rejects_non_loopback_destinations() {
        let _env = crate::test_env::ScopedEnv::set([
            ("ACCEPTANCE_RUN_ID", "railway-test".into()),
            (
                "LPM_ACCEPTANCE_RAILWAY_API_URL",
                "https://example.com/graphql/v2".into(),
            ),
        ]);

        let error = railway_api_url().expect_err("non-loopback override must fail closed");

        assert!(error.to_string().contains("must use a loopback host"));
    }

    #[test]
    fn acceptance_override_rejects_non_http_schemes() {
        let _env = crate::test_env::ScopedEnv::set([
            (
                "ACCEPTANCE_RUN_ID",
                std::ffi::OsString::from("railway-test"),
            ),
            (
                "LPM_ACCEPTANCE_RAILWAY_API_URL",
                std::ffi::OsString::from("ftp://127.0.0.1/graphql/v2"),
            ),
        ]);

        let error = railway_api_url().expect_err("non-HTTP scheme must fail closed");

        assert!(error.to_string().contains("must use HTTP or HTTPS"));
    }

    #[test]
    fn dockerfile_path_remains_a_user_managed_variable() {
        assert!(!RailwayClient::is_managed("RAILWAY_DOCKERFILE_PATH"));
    }

    #[test]
    fn port_remains_a_user_managed_variable() {
        assert!(!RailwayClient::is_managed("PORT"));
    }

    #[test]
    fn undocumented_railway_prefix_remains_user_managed() {
        assert!(!RailwayClient::is_managed("RAILWAY_ENVIRONMENT"));
    }

    #[tokio::test]
    async fn list_uses_unrendered_values_and_bearer_auth() {
        let server = MockServer::start().await;
        let _env = crate::test_env::ScopedEnv::set([
            (
                "ACCEPTANCE_RUN_ID",
                std::ffi::OsString::from("railway-list"),
            ),
            (
                "LPM_ACCEPTANCE_RAILWAY_API_URL",
                std::ffi::OsString::from(format!("{}/graphql/v2", server.uri())),
            ),
        ]);
        Mock::given(method("POST"))
            .and(path("/graphql/v2"))
            .and(header("authorization", "Bearer railway-token"))
            .and(body_json(serde_json::json!({
                "query": VARIABLES_QUERY,
                "variables": {
                    "projectId": "project-123",
                    "environmentId": "environment-123",
                    "serviceId": "service-123",
                    "unrendered": true
                }
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "variables": {
                        "APPLICATION_SECRET": "${{Shared.SECRET}}",
                        "RAILWAY_SERVICE_ID": "managed-service-id"
                    }
                }
            })))
            .expect(1)
            .mount(&server)
            .await;
        let client = RailwayClient::new("railway-token".into(), config(false)).expect("client");

        let variables = client.list().await.expect("list Railway variables");

        assert_eq!(
            variables
                .get("APPLICATION_SECRET")
                .expect("application variable")
                .value,
            "${{Shared.SECRET}}"
        );
        assert!(!variables.contains_key("RAILWAY_SERVICE_ID"));
    }

    #[tokio::test]
    async fn shared_variable_target_omits_service_id() {
        let server = MockServer::start().await;
        let _env = crate::test_env::ScopedEnv::set([
            (
                "ACCEPTANCE_RUN_ID",
                std::ffi::OsString::from("railway-shared"),
            ),
            (
                "LPM_ACCEPTANCE_RAILWAY_API_URL",
                std::ffi::OsString::from(format!("{}/graphql/v2", server.uri())),
            ),
        ]);
        Mock::given(method("POST"))
            .and(path("/graphql/v2"))
            .and(body_json(serde_json::json!({
                "query": VARIABLES_QUERY,
                "variables": {
                    "projectId": "project-123",
                    "environmentId": "environment-123",
                    "unrendered": true
                }
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": { "variables": {} }
            })))
            .expect(1)
            .mount(&server)
            .await;
        let mut shared_config = config(false);
        shared_config.service_id = None;
        let client = RailwayClient::new("railway-token".into(), shared_config).expect("client");

        client.list().await.expect("list shared Railway variables");
    }

    #[tokio::test]
    async fn redirects_are_rejected_without_forwarding_the_token() {
        let redirect_target = MockServer::start().await;
        let source = MockServer::start().await;
        let _env = crate::test_env::ScopedEnv::set([
            (
                "ACCEPTANCE_RUN_ID",
                std::ffi::OsString::from("railway-redirect"),
            ),
            (
                "LPM_ACCEPTANCE_RAILWAY_API_URL",
                std::ffi::OsString::from(format!("{}/graphql/v2", source.uri())),
            ),
        ]);
        Mock::given(method("POST"))
            .and(path("/graphql/v2"))
            .respond_with(
                ResponseTemplate::new(307)
                    .insert_header("location", format!("{}/capture", redirect_target.uri())),
            )
            .expect(1)
            .mount(&source)
            .await;
        Mock::given(method("POST"))
            .and(path("/capture"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&redirect_target)
            .await;
        let client = RailwayClient::new("railway-token".into(), config(false)).expect("client");

        let error = client
            .list()
            .await
            .expect_err("Railway redirects must fail closed");

        assert!(error.to_string().contains("HTTP 307"));
    }

    #[tokio::test]
    async fn project_tokens_use_only_project_access_header() {
        let server = MockServer::start().await;
        let _env = crate::test_env::ScopedEnv::set([
            (
                "ACCEPTANCE_RUN_ID",
                std::ffi::OsString::from("railway-project-token"),
            ),
            (
                "LPM_ACCEPTANCE_RAILWAY_API_URL",
                std::ffi::OsString::from(format!("{}/graphql/v2", server.uri())),
            ),
        ]);
        Mock::given(method("POST"))
            .and(path("/graphql/v2"))
            .and(header("project-access-token", "railway-project-token"))
            .and(header_exists("content-type"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": { "variables": {} }
            })))
            .expect(1)
            .mount(&server)
            .await;
        let client =
            RailwayClient::new("railway-project-token".into(), config(true)).expect("client");

        client.list().await.expect("list with a project token");

        let requests = server
            .received_requests()
            .await
            .expect("received request log");
        assert!(requests[0].headers.get("authorization").is_none());
    }

    #[tokio::test]
    async fn graphql_errors_fail_even_with_http_200() {
        let server = MockServer::start().await;
        let _env = crate::test_env::ScopedEnv::set([
            (
                "ACCEPTANCE_RUN_ID",
                std::ffi::OsString::from("railway-errors"),
            ),
            (
                "LPM_ACCEPTANCE_RAILWAY_API_URL",
                std::ffi::OsString::from(format!("{}/graphql/v2", server.uri())),
            ),
        ]);
        Mock::given(method("POST"))
            .and(path("/graphql/v2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "errors": [{ "message": "environment not found" }]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let client = RailwayClient::new("railway-token".into(), config(false)).expect("client");

        let error = client
            .list()
            .await
            .expect_err("GraphQL errors must fail closed");

        assert!(error.to_string().contains("environment not found"));
    }

    #[tokio::test]
    async fn bulk_upsert_is_verified_by_an_authoritative_reread() {
        let server = MockServer::start().await;
        let _env = crate::test_env::ScopedEnv::set([
            (
                "ACCEPTANCE_RUN_ID",
                std::ffi::OsString::from("railway-upsert"),
            ),
            (
                "LPM_ACCEPTANCE_RAILWAY_API_URL",
                std::ffi::OsString::from(format!("{}/graphql/v2", server.uri())),
            ),
        ]);
        Mock::given(method("POST"))
            .and(path("/graphql/v2"))
            .and(body_json(serde_json::json!({
                "query": VARIABLE_COLLECTION_UPSERT_MUTATION,
                "variables": {
                    "input": {
                        "projectId": "project-123",
                        "environmentId": "environment-123",
                        "serviceId": "service-123",
                        "variables": {
                            "CHANGED": "local",
                            "NEW_VALUE": "new"
                        },
                        "replace": false
                    }
                }
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": { "variableCollectionUpsert": true }
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/graphql/v2"))
            .and(body_json(serde_json::json!({
                "query": VARIABLES_QUERY,
                "variables": {
                    "projectId": "project-123",
                    "environmentId": "environment-123",
                    "serviceId": "service-123",
                    "unrendered": true
                }
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "variables": {
                        "CHANGED": "local",
                        "NEW_VALUE": "new",
                        "PLATFORM_ONLY": "remote-only"
                    }
                }
            })))
            .expect(1)
            .mount(&server)
            .await;
        let client = RailwayClient::new("railway-token".into(), config(false)).expect("client");
        let local = HashMap::from([
            ("CHANGED".into(), "local".into()),
            ("NEW_VALUE".into(), "new".into()),
        ]);
        let remote = HashMap::from([
            (
                "CHANGED".into(),
                PlatformVariable {
                    id: "CHANGED".into(),
                    value: "remote".into(),
                    scope: VariableScope::Railway,
                },
            ),
            (
                "PLATFORM_ONLY".into(),
                PlatformVariable {
                    id: "PLATFORM_ONLY".into(),
                    value: "remote-only".into(),
                    scope: VariableScope::Railway,
                },
            ),
        ]);
        let diff = PlatformDiff {
            added: vec!["NEW_VALUE".into()],
            changed: vec!["CHANGED".into()],
            removed: Vec::new(),
            unchanged: Vec::new(),
            ..PlatformDiff::default()
        };

        let result = client
            .apply(&diff, &local, &remote, false)
            .await
            .expect("apply and verify Railway values");

        assert_eq!(result.added, 1);
        assert_eq!(result.updated, 1);
        assert_eq!(result.removed, 0);
    }

    #[tokio::test]
    async fn clean_push_replaces_the_collection_with_only_local_values() {
        let server = MockServer::start().await;
        let _env = crate::test_env::ScopedEnv::set([
            (
                "ACCEPTANCE_RUN_ID",
                std::ffi::OsString::from("railway-clean"),
            ),
            (
                "LPM_ACCEPTANCE_RAILWAY_API_URL",
                std::ffi::OsString::from(format!("{}/graphql/v2", server.uri())),
            ),
        ]);
        Mock::given(method("POST"))
            .and(path("/graphql/v2"))
            .and(body_json(serde_json::json!({
                "query": VARIABLE_COLLECTION_UPSERT_MUTATION,
                "variables": {
                    "input": {
                        "projectId": "project-123",
                        "environmentId": "environment-123",
                        "serviceId": "service-123",
                        "variables": {
                            "LOCAL_ONLY": "local"
                        },
                        "replace": true
                    }
                }
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": { "variableCollectionUpsert": true }
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/graphql/v2"))
            .and(body_json(serde_json::json!({
                "query": VARIABLES_QUERY,
                "variables": {
                    "projectId": "project-123",
                    "environmentId": "environment-123",
                    "serviceId": "service-123",
                    "unrendered": true
                }
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "variables": {
                        "LOCAL_ONLY": "local"
                    }
                }
            })))
            .expect(1)
            .mount(&server)
            .await;
        let client = RailwayClient::new("railway-token".into(), config(false)).expect("client");
        let local = HashMap::from([("LOCAL_ONLY".into(), "local".into())]);
        let remote = HashMap::from([(
            "REMOTE_ONLY".into(),
            PlatformVariable {
                id: "REMOTE_ONLY".into(),
                value: "remote".into(),
                scope: VariableScope::Railway,
            },
        )]);
        let diff = PlatformDiff {
            added: vec!["LOCAL_ONLY".into()],
            changed: Vec::new(),
            removed: vec!["REMOTE_ONLY".into()],
            unchanged: Vec::new(),
            ..PlatformDiff::default()
        };

        let result = client
            .apply(&diff, &local, &remote, true)
            .await
            .expect("replace Railway variables");

        assert_eq!(result.removed, 1);
    }

    #[tokio::test]
    async fn verified_reread_rejects_partial_mutation() {
        let server = MockServer::start().await;
        let _env = crate::test_env::ScopedEnv::set([
            (
                "ACCEPTANCE_RUN_ID",
                std::ffi::OsString::from("railway-partial"),
            ),
            (
                "LPM_ACCEPTANCE_RAILWAY_API_URL",
                std::ffi::OsString::from(format!("{}/graphql/v2", server.uri())),
            ),
        ]);
        Mock::given(method("POST"))
            .and(path("/graphql/v2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": { "variableCollectionUpsert": true }
            })))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/graphql/v2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": { "variables": {} }
            })))
            .expect(1)
            .mount(&server)
            .await;
        let client = RailwayClient::new("railway-token".into(), config(false)).expect("client");
        let local = HashMap::from([("NEW_VALUE".into(), "new".into())]);
        let diff = PlatformDiff {
            added: vec!["NEW_VALUE".into()],
            changed: Vec::new(),
            removed: Vec::new(),
            unchanged: Vec::new(),
            ..PlatformDiff::default()
        };

        let error = client
            .apply(&diff, &local, &HashMap::new(), true)
            .await
            .expect_err("partial mutation must not report success");

        assert!(error.to_string().contains("verification failed"));
    }
}
