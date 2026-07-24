use std::collections::{HashMap, HashSet};

use lpm_common::LpmError;
use reqwest::header::{ACCEPT, AUTHORIZATION, HeaderValue, USER_AGENT};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use super::{
    LocalPlatformValues, PLATFORM_TIMEOUT, PlatformApplyError, PlatformDiff, PlatformPushResult,
    PlatformState, read_platform_response,
};

pub(super) const FLY_API_URL: &str = "https://api.fly.io/graphql";
pub(super) const APP_QUERY: &str = "query app($appName: String!) { app(name: $appName) { id name organization { id slug } secrets { name digest } } }";
pub(super) const SET_SECRETS_MUTATION: &str = "mutation setSecrets($input: SetSecretsInput!) { setSecrets(input: $input) { release { id version } } }";
pub(super) const UNSET_SECRETS_MUTATION: &str = "mutation unsetSecrets($input: UnsetSecretsInput!) { unsetSecrets(input: $input) { release { id version } } }";

const FLY_USER_AGENT: &str = "lpm-env-fly";
const FLY_APP_NAME_MAX_CHARS: usize = 63;
const FLY_IDENTITY_MAX_CHARS: usize = 128;
const FLY_SECRET_NAME_MAX_CHARS: usize = 256;
const MANAGED_VARIABLES: &[&str] = &[
    "FLY_ALLOC_ID",
    "FLY_APP_NAME",
    "FLY_IMAGE_REF",
    "FLY_MACHINE_ID",
    "FLY_MACHINE_VERSION",
    "FLY_PRIVATE_IP",
    "FLY_PROCESS_GROUP",
    "FLY_PUBLIC_IP",
    "FLY_REGION",
    "FLY_VM_MEMORY_MB",
];

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct FlyConnectionConfig {
    pub(super) app: String,
    pub(super) app_id: String,
    pub(super) organization_id: String,
    pub(super) organization_slug: String,
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
struct AppData {
    app: Option<FlyApp>,
}

#[derive(Debug, Deserialize)]
struct FlyApp {
    id: String,
    name: String,
    organization: FlyOrganization,
    #[serde(default)]
    secrets: Vec<FlySecret>,
}

#[derive(Debug, Deserialize)]
struct FlyOrganization {
    id: String,
    slug: String,
}

#[derive(Debug, Deserialize)]
struct FlySecret {
    name: String,
    #[serde(default)]
    digest: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SetSecretsData {
    set_secrets: SecretMutationPayload,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UnsetSecretsData {
    unset_secrets: SecretMutationPayload,
}

#[derive(Debug, Deserialize)]
struct SecretMutationPayload {
    #[serde(default)]
    release: Option<FlyRelease>,
}

#[derive(Debug, Deserialize)]
struct FlyRelease {
    id: String,
    #[serde(default)]
    version: Option<u64>,
}

pub(super) struct FlyClient {
    http: reqwest::Client,
    api_url: String,
    authorization: HeaderValue,
    config: FlyConnectionConfig,
}

impl FlyClient {
    pub(super) fn new(token: String, config: FlyConnectionConfig) -> Result<Self, LpmError> {
        validate_app_name(&config.app)?;
        validate_identity_field("app ID", &config.app_id)?;
        validate_identity_field("organization ID", &config.organization_id)?;
        validate_identity_field("organization slug", &config.organization_slug)?;
        Self::build(token, config)
    }

    fn build(token: String, config: FlyConnectionConfig) -> Result<Self, LpmError> {
        let http = lpm_http::client_builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(PLATFORM_TIMEOUT)
            .build()
            .map_err(|error| {
                LpmError::Network(format!("failed to build Fly.io client: {error}"))
            })?;
        Ok(Self {
            http,
            api_url: fly_api_url()?,
            authorization: authorization_header(&token)?,
            config,
        })
    }

    pub(super) async fn discover_config(
        token: String,
        app: &str,
        linked_env: Option<String>,
    ) -> Result<Self, LpmError> {
        validate_app_name(app)?;
        let bootstrap = FlyConnectionConfig {
            app: app.to_owned(),
            app_id: String::new(),
            organization_id: String::new(),
            organization_slug: String::new(),
            linked_env,
        };
        let mut client = Self::build(token, bootstrap)?;
        let observed = client.fetch_app().await?;
        validate_app_name(&observed.name)?;
        validate_identity_field("app ID", &observed.id)?;
        validate_identity_field("organization ID", &observed.organization.id)?;
        validate_identity_field("organization slug", &observed.organization.slug)?;
        if observed.name != app {
            return Err(LpmError::Script(format!(
                "Fly.io returned app {} while {app} was requested",
                observed.name
            )));
        }
        client.config = FlyConnectionConfig {
            app: observed.name,
            app_id: observed.id,
            organization_id: observed.organization.id,
            organization_slug: observed.organization.slug,
            linked_env: client.config.linked_env.take(),
        };
        Ok(client)
    }

    pub(super) fn config(&self) -> &FlyConnectionConfig {
        &self.config
    }

    pub(super) fn is_managed(key: &str) -> bool {
        MANAGED_VARIABLES.contains(&key)
    }

    pub(super) async fn list(&self) -> Result<PlatformState, LpmError> {
        let app = self.fetch_app().await?;
        self.assert_binding(&app)?;
        let mut names = HashSet::with_capacity(app.secrets.len());
        for secret in app.secrets {
            if Self::is_managed(&secret.name) {
                continue;
            }
            validate_secret_name(&secret.name)?;
            if !names.insert(secret.name.clone()) {
                return Err(LpmError::Script(format!(
                    "Fly.io returned multiple secrets named {}",
                    secret.name
                )));
            }
            let _ = secret.digest;
        }
        Ok(PlatformState {
            readable: HashMap::new(),
            write_only: names,
        })
    }

    pub(super) async fn apply(
        &self,
        diff: &PlatformDiff,
        local: &LocalPlatformValues,
        remote: &PlatformState,
        clean: bool,
    ) -> Result<PlatformPushResult, PlatformApplyError> {
        let fresh = self.list().await.map_err(PlatformApplyError::untracked)?;
        if fresh.write_only != remote.write_only {
            return Err(PlatformApplyError::untracked(LpmError::Script(
                "Fly.io secrets changed after comparison; rerun the push before mutating the app"
                    .into(),
            )));
        }

        let mut desired = if clean {
            HashSet::with_capacity(local.write_only.len())
        } else {
            remote.write_only.clone()
        };
        desired.extend(local.write_only.keys().cloned());

        let mut applied = PlatformPushResult::default();
        if !local.write_only.is_empty()
            && (!diff.write_only_added.is_empty() || !diff.write_only_present.is_empty())
        {
            self.set_secrets(&local.write_only)
                .await
                .map_err(PlatformApplyError::untracked)?;
            applied.added = diff.write_only_added.len();
            applied.updated = diff.write_only_present.len();
        }

        if !diff.write_only_removed.is_empty() {
            let after_set = self
                .list()
                .await
                .map_err(|error| PlatformApplyError::tracked(error, applied))?;
            let mut expected_after_set = remote.write_only.clone();
            expected_after_set.extend(local.write_only.keys().cloned());
            if after_set.write_only != expected_after_set {
                return Err(PlatformApplyError::tracked(
                    LpmError::Script(
                        "Fly.io secrets changed during synchronization; no removals were attempted"
                            .into(),
                    ),
                    applied,
                ));
            }
            self.unset_secrets(&diff.write_only_removed)
                .await
                .map_err(|error| PlatformApplyError::tracked(error, applied))?;
            applied.removed = diff.write_only_removed.len();
        }

        let observed = self
            .list()
            .await
            .map_err(|error| PlatformApplyError::tracked(error, applied))?;
        if observed.write_only != desired {
            return Err(PlatformApplyError::tracked(
                LpmError::Script(
                    "Fly.io synchronization verification failed; the authoritative secret names do not match the requested state"
                        .into(),
                ),
                applied,
            ));
        }
        Ok(applied)
    }

    fn assert_binding(&self, app: &FlyApp) -> Result<(), LpmError> {
        if app.name != self.config.app
            || app.id != self.config.app_id
            || app.organization.id != self.config.organization_id
        {
            return Err(LpmError::Script(
                "Fly.io app identity changed; reconnect the app before synchronizing env values"
                    .into(),
            ));
        }
        Ok(())
    }

    async fn fetch_app(&self) -> Result<FlyApp, LpmError> {
        let data: AppData = self
            .execute(
                "inspect app",
                APP_QUERY,
                serde_json::json!({ "appName": self.config.app }),
            )
            .await?;
        data.app.ok_or_else(|| {
            LpmError::Script(format!(
                "Fly.io app '{}' was not found or is not accessible",
                self.config.app
            ))
        })
    }

    async fn set_secrets(&self, values: &HashMap<String, String>) -> Result<(), LpmError> {
        let mut values = values.iter().collect::<Vec<_>>();
        values.sort_unstable_by(|left, right| left.0.cmp(right.0));
        let secrets = values
            .into_iter()
            .map(|(key, value)| serde_json::json!({ "key": key, "value": value }))
            .collect::<Vec<_>>();
        let data: SetSecretsData = self
            .execute(
                "set secrets",
                SET_SECRETS_MUTATION,
                serde_json::json!({
                    "input": {
                        "appId": self.config.app,
                        "secrets": secrets,
                    }
                }),
            )
            .await?;
        validate_release("set secrets", data.set_secrets.release)?;
        Ok(())
    }

    async fn unset_secrets(&self, keys: &[String]) -> Result<(), LpmError> {
        let data: UnsetSecretsData = self
            .execute(
                "unset secrets",
                UNSET_SECRETS_MUTATION,
                serde_json::json!({
                    "input": {
                        "appId": self.config.app,
                        "keys": keys,
                    }
                }),
            )
            .await?;
        validate_release("unset secrets", data.unset_secrets.release)?;
        Ok(())
    }

    async fn execute<T: DeserializeOwned>(
        &self,
        operation: &str,
        query: &str,
        variables: serde_json::Value,
    ) -> Result<T, LpmError> {
        let response = self
            .http
            .post(&self.api_url)
            .header(ACCEPT, "application/json")
            .header(AUTHORIZATION, self.authorization.clone())
            .header(USER_AGENT, FLY_USER_AGENT)
            .json(&serde_json::json!({ "query": query, "variables": variables }))
            .send()
            .await
            .map_err(|error| {
                LpmError::Network(format!(
                    "Fly.io {operation} failed: {}",
                    lpm_http::display_error(&error)
                ))
            })?;
        let (status, body) = read_platform_response(response).await?;
        if !status.is_success() {
            return Err(fly_http_error(operation, status, &body));
        }
        let response: GraphqlResponse<T> = serde_json::from_slice(&body)
            .map_err(|error| LpmError::Script(format!("invalid Fly.io response: {error}")))?;
        if !response.errors.is_empty() {
            let detail = response
                .errors
                .iter()
                .map(|error| error.message.as_str())
                .collect::<Vec<_>>()
                .join("; ");
            return Err(LpmError::Script(format!(
                "Fly.io {operation} failed: {}",
                detail.chars().take(500).collect::<String>()
            )));
        }
        response.data.ok_or_else(|| {
            LpmError::Script(format!("Fly.io {operation} response did not include data"))
        })
    }
}

pub(super) fn partition_local_values(local: &HashMap<String, String>) -> LocalPlatformValues {
    LocalPlatformValues {
        readable: HashMap::new(),
        write_only: local
            .iter()
            .filter(|(key, _)| !FlyClient::is_managed(key))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
    }
}

pub(super) fn validate_app_name(value: &str) -> Result<(), LpmError> {
    let bytes = value.as_bytes();
    if bytes.is_empty() {
        return Err(LpmError::Script("--app cannot be empty".into()));
    }
    if bytes.len() > FLY_APP_NAME_MAX_CHARS {
        return Err(LpmError::Script(format!(
            "--app must be at most {FLY_APP_NAME_MAX_CHARS} characters"
        )));
    }
    if !bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit()
        || !bytes[bytes.len() - 1].is_ascii_lowercase() && !bytes[bytes.len() - 1].is_ascii_digit()
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
    {
        return Err(LpmError::Script(
            "--app must use lowercase letters, digits, and interior hyphens".into(),
        ));
    }
    Ok(())
}

fn validate_identity_field(field: &str, value: &str) -> Result<(), LpmError> {
    if value.is_empty()
        || value.chars().count() > FLY_IDENTITY_MAX_CHARS
        || value.chars().any(char::is_control)
    {
        return Err(LpmError::Script(format!(
            "Fly.io {field} must be a non-empty, control-free value of at most {FLY_IDENTITY_MAX_CHARS} characters"
        )));
    }
    Ok(())
}

fn validate_secret_name(value: &str) -> Result<(), LpmError> {
    if value.is_empty()
        || value.chars().count() > FLY_SECRET_NAME_MAX_CHARS
        || value.chars().any(char::is_control)
    {
        return Err(LpmError::Script(format!(
            "Fly.io returned an invalid secret name; names must be non-empty, control-free, and at most {FLY_SECRET_NAME_MAX_CHARS} characters"
        )));
    }
    Ok(())
}

pub(super) fn fly_api_url() -> Result<String, LpmError> {
    if !cfg!(any(debug_assertions, feature = "acceptance-test-hooks")) {
        return Ok(FLY_API_URL.into());
    }
    let Some(candidate) = std::env::var_os("LPM_ACCEPTANCE_FLY_API_URL") else {
        return Ok(FLY_API_URL.into());
    };
    if std::env::var("ACCEPTANCE_RUN_ID")
        .ok()
        .is_none_or(|value| value.trim().is_empty())
    {
        return Ok(FLY_API_URL.into());
    }
    let candidate = candidate.to_string_lossy();
    let parsed = reqwest::Url::parse(&candidate)
        .map_err(|error| LpmError::Script(format!("invalid acceptance Fly.io URL: {error}")))?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(LpmError::Script(
            "the acceptance Fly.io URL must not contain credentials".into(),
        ));
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(LpmError::Script(
            "the acceptance Fly.io URL must not contain a query or fragment".into(),
        ));
    }
    if !matches!(parsed.host_str(), Some("127.0.0.1" | "localhost" | "::1")) {
        return Err(LpmError::Script(
            "the acceptance Fly.io URL must use a loopback host".into(),
        ));
    }
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(LpmError::Script(
            "the acceptance Fly.io URL must use HTTP or HTTPS".into(),
        ));
    }
    if parsed.path() != "/graphql" {
        return Err(LpmError::Script(
            "the acceptance Fly.io URL must end with /graphql".into(),
        ));
    }
    Ok(candidate.into_owned())
}

fn authorization_header(token: &str) -> Result<HeaderValue, LpmError> {
    let mut token = token.trim();
    loop {
        let Some((scheme, value)) = token.split_once(' ') else {
            break;
        };
        if !scheme.eq_ignore_ascii_case("bearer") && !scheme.eq_ignore_ascii_case("flyv1") {
            break;
        }
        token = value.trim();
    }
    if token.is_empty() {
        return Err(LpmError::Script("Fly.io token cannot be empty".into()));
    }
    let has_macaroon = token
        .split(',')
        .any(|part| matches!(part.trim().split('_').next(), Some("fm1r" | "fm1a" | "fm2")));
    let scheme = if has_macaroon { "FlyV1" } else { "Bearer" };
    let mut header = HeaderValue::from_str(&format!("{scheme} {token}"))
        .map_err(|_| LpmError::Script("Fly.io token contains invalid characters".into()))?;
    header.set_sensitive(true);
    Ok(header)
}

fn validate_release(operation: &str, release: Option<FlyRelease>) -> Result<(), LpmError> {
    let Some(release) = release else {
        return Err(LpmError::Script(format!(
            "Fly.io {operation} did not return a release acknowledgement"
        )));
    };
    if release.id.is_empty() {
        return Err(LpmError::Script(format!(
            "Fly.io {operation} returned an empty release ID"
        )));
    }
    let _ = release.version;
    Ok(())
}

fn fly_http_error(operation: &str, status: reqwest::StatusCode, body: &[u8]) -> LpmError {
    let detail = String::from_utf8_lossy(body);
    let detail = detail.trim();
    let suffix = if detail.is_empty() {
        String::new()
    } else {
        format!(": {}", detail.chars().take(300).collect::<String>())
    };
    LpmError::Script(format!(
        "Fly.io {operation} failed with HTTP {status}{suffix}"
    ))
}

#[cfg(test)]
mod tests {
    use wiremock::matchers::{body_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    fn config() -> FlyConnectionConfig {
        FlyConnectionConfig {
            app: "lpm-example".into(),
            app_id: "app_123".into(),
            organization_id: "org_123".into(),
            organization_slug: "personal".into(),
            linked_env: Some("production".into()),
        }
    }

    fn acceptance_env(server: &MockServer, marker: &str) -> crate::test_env::ScopedEnv {
        crate::test_env::ScopedEnv::set([
            ("ACCEPTANCE_RUN_ID", marker.into()),
            (
                "LPM_ACCEPTANCE_FLY_API_URL",
                format!("{}/graphql", server.uri()).into(),
            ),
        ])
    }

    fn app_response(
        app_id: &str,
        organization_id: &str,
        secrets: serde_json::Value,
    ) -> serde_json::Value {
        serde_json::json!({
            "data": {
                "app": {
                    "id": app_id,
                    "name": "lpm-example",
                    "organization": {
                        "id": organization_id,
                        "slug": "personal",
                    },
                    "secrets": secrets,
                }
            }
        })
    }

    fn release_response(field: &str) -> serde_json::Value {
        serde_json::json!({
            "data": {
                field: {
                    "release": {
                        "id": "release_123",
                        "version": 7,
                    }
                }
            }
        })
    }

    #[test]
    fn app_name_rejects_noncanonical_values() {
        let error = validate_app_name("Example_App").expect_err("invalid app name must fail");

        assert!(error.to_string().contains("lowercase letters"));
    }

    #[test]
    fn connection_identity_fields_are_bounded_and_control_free() {
        assert!(validate_identity_field("app ID", "app_123").is_ok());
        assert!(validate_identity_field("app ID", "").is_err());
        assert!(validate_identity_field("app ID", "app\u{85}123").is_err());
        assert!(validate_identity_field("app ID", &"a".repeat(129)).is_err());
    }

    #[test]
    fn macaroon_tokens_use_the_flyv1_authorization_scheme() {
        let header = authorization_header("Bearer fm2_test-token").expect("authorization header");

        assert_eq!(
            header.to_str().expect("text header"),
            "FlyV1 fm2_test-token"
        );
    }

    #[test]
    fn oauth_tokens_use_the_bearer_authorization_scheme() {
        let header = authorization_header("fo1_test-token").expect("authorization header");

        assert_eq!(
            header.to_str().expect("text header"),
            "Bearer fo1_test-token"
        );
    }

    #[test]
    fn all_user_values_are_partitioned_as_write_only_secrets() {
        let local = HashMap::from([
            ("DATABASE_URL".into(), "postgres://example".into()),
            ("FLY_APP_NAME".into(), "managed".into()),
        ]);

        let partitioned = partition_local_values(&local);

        assert!(partitioned.readable.is_empty());
        assert_eq!(
            partitioned.write_only,
            HashMap::from([("DATABASE_URL".into(), "postgres://example".into())])
        );
    }

    #[test]
    fn release_endpoint_is_fixed() {
        let _env = crate::test_env::ScopedEnv::update([
            ("ACCEPTANCE_RUN_ID", None),
            (
                "LPM_ACCEPTANCE_FLY_API_URL",
                Some("http://127.0.0.1:4173/graphql".into()),
            ),
        ]);

        assert_eq!(fly_api_url().expect("resolve Fly.io URL"), FLY_API_URL);
    }

    #[test]
    fn acceptance_override_rejects_non_loopback_destinations() {
        let _env = crate::test_env::ScopedEnv::set([
            ("ACCEPTANCE_RUN_ID", "fly-test".into()),
            (
                "LPM_ACCEPTANCE_FLY_API_URL",
                "https://example.com/graphql".into(),
            ),
        ]);

        let error = fly_api_url().expect_err("non-loopback override must fail closed");

        assert!(error.to_string().contains("loopback"));
    }

    #[tokio::test]
    async fn list_uses_fly_auth_and_rejects_duplicate_secret_names() {
        let server = MockServer::start().await;
        let _env = acceptance_env(&server, "fly-duplicate-secrets");
        Mock::given(method("POST"))
            .and(path("/graphql"))
            .and(header("authorization", "FlyV1 fm2_acceptance-token"))
            .and(header("user-agent", FLY_USER_AGENT))
            .and(body_json(serde_json::json!({
                "query": APP_QUERY,
                "variables": { "appName": "lpm-example" }
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(app_response(
                "app_123",
                "org_123",
                serde_json::json!([
                    { "name": "API_TOKEN", "digest": "digest-1" },
                    { "name": "API_TOKEN", "digest": "digest-2" }
                ]),
            )))
            .expect(1)
            .mount(&server)
            .await;
        let client =
            FlyClient::new("fm2_acceptance-token".into(), config()).expect("Fly.io client");

        let error = client
            .list()
            .await
            .expect_err("duplicate secret names must fail closed");

        assert!(error.to_string().contains("multiple secrets"));
    }

    #[tokio::test]
    async fn graphql_errors_at_http_200_fail_closed() {
        let server = MockServer::start().await;
        let _env = acceptance_env(&server, "fly-graphql-error");
        Mock::given(method("POST"))
            .and(path("/graphql"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": null,
                "errors": [{ "message": "permission denied" }]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let client = FlyClient::new("fo1_acceptance-token".into(), config()).expect("client");

        let error = client
            .list()
            .await
            .expect_err("GraphQL errors must fail closed");

        assert!(error.to_string().contains("permission denied"));
    }

    #[tokio::test]
    async fn app_transfer_fails_before_secret_mutation() {
        let server = MockServer::start().await;
        let _env = acceptance_env(&server, "fly-identity-change");
        Mock::given(method("POST"))
            .and(path("/graphql"))
            .and(body_json(serde_json::json!({
                "query": APP_QUERY,
                "variables": { "appName": "lpm-example" }
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(app_response(
                "app_123",
                "org_attacker",
                serde_json::json!([]),
            )))
            .expect(1)
            .mount(&server)
            .await;
        let client = FlyClient::new("fo1_acceptance-token".into(), config()).expect("client");
        let local = LocalPlatformValues {
            readable: HashMap::new(),
            write_only: HashMap::from([("API_TOKEN".into(), "secret".into())]),
        };
        let diff = PlatformDiff {
            write_only_added: vec!["API_TOKEN".into()],
            ..PlatformDiff::default()
        };

        let error = client
            .apply(&diff, &local, &PlatformState::default(), false)
            .await
            .expect_err("organization transfer must fail before mutation");

        let PlatformApplyError::Untracked(error) = error else {
            panic!("identity change must remain untracked");
        };
        assert!(error.to_string().contains("identity changed"));
        assert_eq!(server.received_requests().await.expect("requests").len(), 1);
    }

    #[tokio::test]
    async fn redirects_are_rejected_without_forwarding_the_token() {
        let redirect_target = MockServer::start().await;
        let server = MockServer::start().await;
        let _env = acceptance_env(&server, "fly-redirect");
        Mock::given(method("POST"))
            .and(path("/graphql"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("location", format!("{}/capture", redirect_target.uri())),
            )
            .expect(1)
            .mount(&server)
            .await;
        let client = FlyClient::new("fo1_acceptance-token".into(), config()).expect("client");

        let error = client
            .list()
            .await
            .expect_err("redirect must not be followed");

        assert!(error.to_string().contains("HTTP 302"));
        assert!(
            redirect_target
                .received_requests()
                .await
                .expect("redirect requests")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn bulk_set_sends_the_exact_sorted_secret_payload() {
        let server = MockServer::start().await;
        let _env = acceptance_env(&server, "fly-set-secrets");
        Mock::given(method("POST"))
            .and(path("/graphql"))
            .and(header("authorization", "Bearer fo1_acceptance-token"))
            .and(header("user-agent", FLY_USER_AGENT))
            .and(body_json(serde_json::json!({
                "query": SET_SECRETS_MUTATION,
                "variables": {
                    "input": {
                        "appId": "lpm-example",
                        "secrets": [
                            { "key": "ALPHA", "value": "one" },
                            { "key": "ZULU", "value": "two" }
                        ]
                    }
                }
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(release_response("setSecrets")))
            .expect(1)
            .mount(&server)
            .await;
        let client = FlyClient::new("fo1_acceptance-token".into(), config()).expect("client");

        client
            .set_secrets(&HashMap::from([
                ("ZULU".into(), "two".into()),
                ("ALPHA".into(), "one".into()),
            ]))
            .await
            .expect("set Fly.io secrets");
    }

    #[tokio::test]
    async fn bulk_unset_sends_the_exact_secret_name_payload() {
        let server = MockServer::start().await;
        let _env = acceptance_env(&server, "fly-unset-secrets");
        Mock::given(method("POST"))
            .and(path("/graphql"))
            .and(body_json(serde_json::json!({
                "query": UNSET_SECRETS_MUTATION,
                "variables": {
                    "input": {
                        "appId": "lpm-example",
                        "keys": ["PLATFORM_ONE", "PLATFORM_TWO"]
                    }
                }
            })))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(release_response("unsetSecrets")),
            )
            .expect(1)
            .mount(&server)
            .await;
        let client = FlyClient::new("fo1_acceptance-token".into(), config()).expect("client");

        client
            .unset_secrets(&["PLATFORM_ONE".into(), "PLATFORM_TWO".into()])
            .await
            .expect("unset Fly.io secrets");
    }

    #[tokio::test]
    async fn mutation_without_a_release_acknowledgement_fails_closed() {
        let server = MockServer::start().await;
        let _env = acceptance_env(&server, "fly-missing-release");
        Mock::given(method("POST"))
            .and(path("/graphql"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": { "setSecrets": { "release": null } }
            })))
            .expect(1)
            .mount(&server)
            .await;
        let client = FlyClient::new("fo1_acceptance-token".into(), config()).expect("client");

        let error = client
            .set_secrets(&HashMap::from([("API_TOKEN".into(), "secret".into())]))
            .await
            .expect_err("missing release acknowledgement must fail closed");

        assert!(error.to_string().contains("release acknowledgement"));
    }

    #[tokio::test]
    async fn stale_comparison_fails_before_secret_mutation() {
        let server = MockServer::start().await;
        let _env = acceptance_env(&server, "fly-stale-comparison");
        Mock::given(method("POST"))
            .and(path("/graphql"))
            .and(body_json(serde_json::json!({
                "query": APP_QUERY,
                "variables": { "appName": "lpm-example" }
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(app_response(
                "app_123",
                "org_123",
                serde_json::json!([{ "name": "EXTERNAL", "digest": "digest" }]),
            )))
            .expect(1)
            .mount(&server)
            .await;
        let client = FlyClient::new("fo1_acceptance-token".into(), config()).expect("client");
        let local = LocalPlatformValues {
            readable: HashMap::new(),
            write_only: HashMap::from([("API_TOKEN".into(), "secret".into())]),
        };
        let diff = PlatformDiff {
            write_only_added: vec!["API_TOKEN".into()],
            ..PlatformDiff::default()
        };

        let error = client
            .apply(&diff, &local, &PlatformState::default(), false)
            .await
            .expect_err("stale comparison must fail before mutation");

        let PlatformApplyError::Untracked(error) = error else {
            panic!("stale comparison must remain untracked");
        };
        assert!(error.to_string().contains("changed after comparison"));
    }

    #[tokio::test]
    async fn authoritative_reread_rejects_partial_secret_mutation() {
        let server = MockServer::start().await;
        let _env = acceptance_env(&server, "fly-partial-mutation");
        Mock::given(method("POST"))
            .and(path("/graphql"))
            .and(body_json(serde_json::json!({
                "query": APP_QUERY,
                "variables": { "appName": "lpm-example" }
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(app_response(
                "app_123",
                "org_123",
                serde_json::json!([]),
            )))
            .expect(2)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/graphql"))
            .and(body_json(serde_json::json!({
                "query": SET_SECRETS_MUTATION,
                "variables": {
                    "input": {
                        "appId": "lpm-example",
                        "secrets": [{ "key": "API_TOKEN", "value": "secret" }]
                    }
                }
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(release_response("setSecrets")))
            .expect(1)
            .mount(&server)
            .await;
        let client = FlyClient::new("fo1_acceptance-token".into(), config()).expect("client");
        let local = LocalPlatformValues {
            readable: HashMap::new(),
            write_only: HashMap::from([("API_TOKEN".into(), "secret".into())]),
        };
        let diff = PlatformDiff {
            write_only_added: vec!["API_TOKEN".into()],
            ..PlatformDiff::default()
        };

        let error = client
            .apply(&diff, &local, &PlatformState::default(), false)
            .await
            .expect_err("partial mutation must fail authoritative verification");

        let PlatformApplyError::Tracked { error, applied } = error else {
            panic!("partial mutation must return tracked counts");
        };
        assert!(error.to_string().contains("verification failed"));
        assert_eq!(applied.added, 1);
        assert_eq!(applied.updated, 0);
        assert_eq!(applied.removed, 0);
    }
}
