use std::collections::{HashMap, HashSet};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use crypto_box::PublicKey;
use lpm_common::LpmError;
use lpm_env::EnvSchema;
use reqwest::header::{ACCEPT, AUTHORIZATION, HeaderValue, USER_AGENT};
use serde::{Deserialize, Serialize};

use super::{
    LocalPlatformValues, PLATFORM_TIMEOUT, PlatformApplyError, PlatformDiff, PlatformPushResult,
    PlatformState, PlatformVariable, VariableScope, read_platform_response,
};

const GITHUB_API_URL: &str = "https://api.github.com";
const GITHUB_API_VERSION: &str = "2022-11-28";
const GITHUB_USER_AGENT: &str = "lpm-env-github-actions";
const GITHUB_VALUE_NAME_MAX_CHARS: usize = 100;
const GITHUB_VALUE_MAX_BYTES: usize = 48 * 1024;
const GITHUB_PAGE_SIZE: usize = 100;
const GITHUB_MAX_PAGES: usize = 20;
const GITHUB_REPOSITORY_MAX_CHARS: usize = 140;
const GITHUB_ENVIRONMENT_MAX_CHARS: usize = 255;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct GitHubActionsConnectionConfig {
    pub(super) repository: String,
    pub(super) repository_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) environment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) linked_env: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RepositoryResponse {
    id: u64,
    full_name: String,
}

#[derive(Debug, Deserialize)]
struct ActionsPublicKey {
    key_id: String,
    key: String,
}

#[derive(Debug, Deserialize)]
struct NamedSecret {
    name: String,
}

#[derive(Debug, Deserialize)]
struct ActionsSecretList {
    total_count: usize,
    #[serde(default)]
    secrets: Vec<NamedSecret>,
}

#[derive(Debug, Deserialize)]
struct ActionsVariable {
    name: String,
    value: String,
}

#[derive(Debug, Deserialize)]
struct ActionsVariableList {
    total_count: usize,
    #[serde(default)]
    variables: Vec<ActionsVariable>,
}

pub(super) struct GitHubActionsClient {
    http: reqwest::Client,
    api_url: String,
    authorization: HeaderValue,
    config: GitHubActionsConnectionConfig,
}

impl GitHubActionsClient {
    pub(super) fn new(
        token: String,
        config: GitHubActionsConnectionConfig,
    ) -> Result<Self, LpmError> {
        validate_repository(&config.repository)?;
        validate_repository_id(&config.repository_id)?;
        if let Some(environment) = &config.environment {
            validate_environment(environment)?;
        }
        let mut authorization = HeaderValue::from_str(&format!("Bearer {token}"))
            .map_err(|_| LpmError::Script("GitHub token contains invalid characters".into()))?;
        authorization.set_sensitive(true);
        let http = lpm_http::client_builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(PLATFORM_TIMEOUT)
            .build()
            .map_err(|error| {
                LpmError::Network(format!("failed to build GitHub Actions client: {error}"))
            })?;
        Ok(Self {
            http,
            api_url: github_api_url()?,
            authorization,
            config,
        })
    }

    pub(super) fn config(&self) -> &GitHubActionsConnectionConfig {
        &self.config
    }

    pub(super) async fn discover_config(
        token: String,
        repository: &str,
        environment: Option<String>,
        linked_env: Option<String>,
    ) -> Result<Self, LpmError> {
        validate_repository(repository)?;
        if let Some(environment) = &environment {
            validate_environment(environment)?;
        }
        let provisional = GitHubActionsConnectionConfig {
            repository: repository.to_string(),
            repository_id: "1".into(),
            environment,
            linked_env,
        };
        let mut client = Self::new(token, provisional)?;
        let repository = client.fetch_repository().await?;
        if !repository
            .full_name
            .eq_ignore_ascii_case(&client.config.repository)
        {
            return Err(LpmError::Script(format!(
                "GitHub returned repository {} while {} was requested",
                repository.full_name, client.config.repository
            )));
        }
        client.config.repository = repository.full_name;
        client.config.repository_id = repository.id.to_string();
        Ok(client)
    }

    pub(super) async fn list(&self) -> Result<PlatformState, LpmError> {
        self.verify_repository_binding().await?;
        let (variables, write_only) =
            tokio::try_join!(self.list_variables(), self.list_secret_names())?;
        Ok(PlatformState {
            readable: variables,
            write_only,
        })
    }

    pub(super) async fn apply(
        &self,
        diff: &PlatformDiff,
        local: &LocalPlatformValues,
        _remote: &PlatformState,
        clean: bool,
    ) -> Result<PlatformPushResult, PlatformApplyError> {
        self.verify_repository_binding()
            .await
            .map_err(|error| PlatformApplyError::tracked(error, PlatformPushResult::default()))?;
        let encrypted_secrets = self
            .encrypt_secrets_for_push(diff, local)
            .await
            .map_err(|error| PlatformApplyError::tracked(error, PlatformPushResult::default()))?;
        let mut applied = PlatformPushResult::default();

        for key in &diff.added {
            let value = local.readable.get(key).ok_or_else(|| {
                PlatformApplyError::tracked(
                    LpmError::Script(format!("missing local value for {key}")),
                    applied,
                )
            })?;
            if let Err(error) = self.create_variable(key, value).await {
                return Err(PlatformApplyError::tracked(error, applied));
            }
            applied.added += 1;
        }
        for key in &diff.changed {
            let value = local.readable.get(key).ok_or_else(|| {
                PlatformApplyError::tracked(
                    LpmError::Script(format!("missing local value for {key}")),
                    applied,
                )
            })?;
            if let Err(error) = self.update_variable(key, value).await {
                return Err(PlatformApplyError::tracked(error, applied));
            }
            applied.updated += 1;
        }
        for (key, encrypted_value, key_id, is_new) in encrypted_secrets {
            if let Err(error) = self.upsert_secret(&key, &encrypted_value, &key_id).await {
                return Err(PlatformApplyError::tracked(error, applied));
            }
            if is_new {
                applied.added += 1;
            } else {
                applied.updated += 1;
            }
        }
        for key in &diff.removed {
            if let Err(error) = self.delete_variable(key).await {
                return Err(PlatformApplyError::tracked(error, applied));
            }
            applied.removed += 1;
        }
        for key in &diff.write_only_removed {
            if let Err(error) = self.delete_secret(key).await {
                return Err(PlatformApplyError::tracked(error, applied));
            }
            applied.removed += 1;
        }

        let observed = self
            .list()
            .await
            .map_err(|error| PlatformApplyError::tracked(error, applied))?;
        if !state_matches_local(&observed, local, clean) {
            return Err(PlatformApplyError::tracked(
                LpmError::Script(
                    "GitHub Actions synchronization verification failed; readable variables or secret-name coverage do not match the requested state"
                        .into(),
                ),
                applied,
            ));
        }
        Ok(applied)
    }

    async fn fetch_repository(&self) -> Result<RepositoryResponse, LpmError> {
        self.get_json("repository verification", &self.repository_url()?)
            .await
    }

    async fn verify_repository_binding(&self) -> Result<(), LpmError> {
        let observed = self.fetch_repository().await?;
        if observed.id.to_string() != self.config.repository_id
            || observed.full_name != self.config.repository
        {
            return Err(LpmError::Script(format!(
                "GitHub repository binding changed: expected {} (ID {}), received {} (ID {}); reconnect before syncing",
                self.config.repository, self.config.repository_id, observed.full_name, observed.id
            )));
        }
        Ok(())
    }

    async fn list_variables(&self) -> Result<HashMap<String, PlatformVariable>, LpmError> {
        let mut result = HashMap::new();
        let mut expected_total = None;
        let variables_url = self.variables_url()?;
        for page in 1..=GITHUB_MAX_PAGES {
            let url = format!("{}?per_page={GITHUB_PAGE_SIZE}&page={page}", variables_url);
            let data: ActionsVariableList = self.get_json("variable list", &url).await?;
            validate_page_total(data.total_count, expected_total, "variables")?;
            expected_total = Some(data.total_count);
            for variable in data.variables {
                validate_value_name(&variable.name)?;
                if result.contains_key(&variable.name) {
                    return Err(LpmError::Script(format!(
                        "GitHub returned duplicate Actions variable {}",
                        variable.name
                    )));
                }
                let name = variable.name;
                result.insert(
                    name.clone(),
                    PlatformVariable {
                        id: name,
                        value: variable.value,
                        scope: VariableScope::GitHubActions,
                    },
                );
            }
            let expected = expected_total.unwrap_or_default();
            if result.len() == expected {
                return Ok(result);
            }
            if page == GITHUB_MAX_PAGES {
                return Err(pagination_limit_error("variables"));
            }
        }
        Ok(result)
    }

    async fn list_secret_names(&self) -> Result<HashSet<String>, LpmError> {
        let mut result = HashSet::new();
        let mut expected_total = None;
        let secrets_url = self.secrets_url()?;
        for page in 1..=GITHUB_MAX_PAGES {
            let url = format!("{}?per_page={GITHUB_PAGE_SIZE}&page={page}", secrets_url);
            let data: ActionsSecretList = self.get_json("secret list", &url).await?;
            validate_page_total(data.total_count, expected_total, "secrets")?;
            expected_total = Some(data.total_count);
            for secret in data.secrets {
                validate_value_name(&secret.name)?;
                if !result.insert(secret.name.clone()) {
                    return Err(LpmError::Script(format!(
                        "GitHub returned duplicate Actions secret {}",
                        secret.name
                    )));
                }
            }
            let expected = expected_total.unwrap_or_default();
            if result.len() == expected {
                return Ok(result);
            }
            if page == GITHUB_MAX_PAGES {
                return Err(pagination_limit_error("secrets"));
            }
        }
        Ok(result)
    }

    async fn encrypt_secrets_for_push(
        &self,
        diff: &PlatformDiff,
        local: &LocalPlatformValues,
    ) -> Result<Vec<(String, String, String, bool)>, LpmError> {
        let secret_count = diff.write_only_added.len() + diff.write_only_present.len();
        if secret_count == 0 {
            return Ok(Vec::new());
        }
        let public_key: ActionsPublicKey = self
            .get_json(
                "secret public-key lookup",
                &format!("{}/public-key", self.secrets_url()?),
            )
            .await?;
        if public_key.key_id.is_empty() {
            return Err(LpmError::Script(
                "GitHub returned an empty Actions public-key ID".into(),
            ));
        }
        let key_bytes = BASE64.decode(public_key.key.as_bytes()).map_err(|_| {
            LpmError::Script("GitHub returned an invalid Actions public key".into())
        })?;
        let public_key_bytes: [u8; 32] = key_bytes.try_into().map_err(|_| {
            LpmError::Script("GitHub returned an invalid Actions public-key length".into())
        })?;
        let mut encrypted = Vec::with_capacity(secret_count);
        for (keys, is_new) in [
            (&diff.write_only_added, true),
            (&diff.write_only_present, false),
        ] {
            for key in keys {
                let value = local.write_only.get(key).ok_or_else(|| {
                    LpmError::Script(format!("missing local secret value for {key}"))
                })?;
                let ciphertext = seal_secret(&public_key_bytes, value.as_bytes())?;
                encrypted.push((
                    key.clone(),
                    BASE64.encode(ciphertext),
                    public_key.key_id.clone(),
                    is_new,
                ));
            }
        }
        Ok(encrypted)
    }

    async fn create_variable(&self, name: &str, value: &str) -> Result<(), LpmError> {
        let url = self.variables_url()?;
        self.send_mutation(
            "variable create",
            self.request(reqwest::Method::POST, &url)
                .json(&serde_json::json!({ "name": name, "value": value })),
        )
        .await
    }

    async fn update_variable(&self, name: &str, value: &str) -> Result<(), LpmError> {
        let url = format!("{}/{}", self.variables_url()?, urlencoding::encode(name));
        self.send_mutation(
            "variable update",
            self.request(reqwest::Method::PATCH, &url)
                .json(&serde_json::json!({ "name": name, "value": value })),
        )
        .await
    }

    async fn delete_variable(&self, name: &str) -> Result<(), LpmError> {
        let url = format!("{}/{}", self.variables_url()?, urlencoding::encode(name));
        self.send_mutation(
            "variable delete",
            self.request(reqwest::Method::DELETE, &url),
        )
        .await
    }

    async fn upsert_secret(
        &self,
        name: &str,
        encrypted_value: &str,
        key_id: &str,
    ) -> Result<(), LpmError> {
        let url = format!("{}/{}", self.secrets_url()?, urlencoding::encode(name));
        self.send_mutation(
            "secret upsert",
            self.request(reqwest::Method::PUT, &url)
                .json(&serde_json::json!({
                    "encrypted_value": encrypted_value,
                    "key_id": key_id,
                })),
        )
        .await
    }

    async fn delete_secret(&self, name: &str) -> Result<(), LpmError> {
        let url = format!("{}/{}", self.secrets_url()?, urlencoding::encode(name));
        self.send_mutation("secret delete", self.request(reqwest::Method::DELETE, &url))
            .await
    }

    async fn get_json<T: serde::de::DeserializeOwned>(
        &self,
        operation: &str,
        url: &str,
    ) -> Result<T, LpmError> {
        let response = self
            .request(reqwest::Method::GET, url)
            .send()
            .await
            .map_err(|error| {
                LpmError::Network(format!(
                    "GitHub Actions {operation} failed: {}",
                    lpm_http::display_error(&error)
                ))
            })?;
        let (status, body) = read_platform_response(response).await?;
        if !status.is_success() {
            return Err(github_api_error(operation, status, &body));
        }
        serde_json::from_slice(&body).map_err(|error| {
            LpmError::Script(format!(
                "invalid GitHub Actions {operation} response: {error}"
            ))
        })
    }

    async fn send_mutation(
        &self,
        operation: &str,
        request: reqwest::RequestBuilder,
    ) -> Result<(), LpmError> {
        let response = request.send().await.map_err(|error| {
            LpmError::Network(format!(
                "GitHub Actions {operation} failed: {}",
                lpm_http::display_error(&error)
            ))
        })?;
        let (status, body) = read_platform_response(response).await?;
        if !status.is_success() {
            return Err(github_api_error(operation, status, &body));
        }
        Ok(())
    }

    fn request(&self, method: reqwest::Method, url: &str) -> reqwest::RequestBuilder {
        self.http
            .request(method, url)
            .header(AUTHORIZATION, self.authorization.clone())
            .header(ACCEPT, "application/vnd.github+json")
            .header("x-github-api-version", GITHUB_API_VERSION)
            .header(USER_AGENT, GITHUB_USER_AGENT)
    }

    fn repository_url(&self) -> Result<String, LpmError> {
        let (owner, repository) = split_repository(&self.config.repository).ok_or_else(|| {
            LpmError::Script("stored GitHub repository binding is invalid".into())
        })?;
        Ok(format!(
            "{}/repos/{}/{}",
            self.api_url,
            urlencoding::encode(owner),
            urlencoding::encode(repository)
        ))
    }

    fn variables_url(&self) -> Result<String, LpmError> {
        match &self.config.environment {
            Some(environment) => Ok(format!(
                "{}/repositories/{}/environments/{}/variables",
                self.api_url,
                self.config.repository_id,
                urlencoding::encode(environment)
            )),
            None => Ok(format!("{}/actions/variables", self.repository_url()?)),
        }
    }

    fn secrets_url(&self) -> Result<String, LpmError> {
        match &self.config.environment {
            Some(environment) => Ok(format!(
                "{}/repositories/{}/environments/{}/secrets",
                self.api_url,
                self.config.repository_id,
                urlencoding::encode(environment)
            )),
            None => Ok(format!("{}/actions/secrets", self.repository_url()?)),
        }
    }
}

pub(super) fn partition_local_values(
    local: &HashMap<String, String>,
    schema: Option<&EnvSchema>,
) -> Result<LocalPlatformValues, LpmError> {
    let mut folded_names = HashSet::with_capacity(local.len());
    for key in local.keys() {
        let folded = key.to_ascii_uppercase();
        if !folded_names.insert(folded) {
            return Err(LpmError::Script(
                "GitHub Actions value names contain a case-insensitive collision".into(),
            ));
        }
    }

    let mut partitioned = LocalPlatformValues {
        readable: HashMap::with_capacity(local.len()),
        write_only: HashMap::with_capacity(local.len()),
    };
    for (key, value) in local {
        validate_value_name(key)?;
        if value.len() > GITHUB_VALUE_MAX_BYTES {
            return Err(LpmError::Script(format!(
                "GitHub Actions value {key} exceeds the {GITHUB_VALUE_MAX_BYTES}-byte limit"
            )));
        }
        let is_readable = schema
            .and_then(|schema| schema.vars.get(key))
            .is_some_and(|rule| rule.client && !rule.secret);
        if is_readable {
            partitioned.readable.insert(key.clone(), value.clone());
        } else {
            partitioned.write_only.insert(key.clone(), value.clone());
        }
    }
    Ok(partitioned)
}

fn state_matches_local(remote: &PlatformState, local: &LocalPlatformValues, clean: bool) -> bool {
    let readable_matches = local.readable.iter().all(|(key, value)| {
        remote
            .readable
            .get(key)
            .is_some_and(|remote| remote.value == *value)
    });
    let secret_names_match = local
        .write_only
        .keys()
        .all(|key| remote.write_only.contains(key));
    let namespaces_disjoint = local
        .readable
        .keys()
        .all(|key| !remote.write_only.contains(key))
        && local
            .write_only
            .keys()
            .all(|key| !remote.readable.contains_key(key));
    let exact_namespaces = !clean
        || (remote.readable.len() == local.readable.len()
            && remote.write_only.len() == local.write_only.len());
    readable_matches && secret_names_match && namespaces_disjoint && exact_namespaces
}

fn seal_secret(public_key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, LpmError> {
    PublicKey::from(*public_key)
        .seal(&mut crypto_box::aead::OsRng, plaintext)
        .map_err(|_| LpmError::Script("failed to encrypt GitHub Actions secret".into()))
}

fn validate_value_name(name: &str) -> Result<(), LpmError> {
    let valid_length = !name.is_empty() && name.chars().count() <= GITHUB_VALUE_NAME_MAX_CHARS;
    let mut chars = name.chars();
    let valid_first = chars
        .next()
        .is_some_and(|first| first == '_' || first.is_ascii_uppercase());
    let valid_rest = chars.all(|character| {
        character == '_' || character.is_ascii_uppercase() || character.is_ascii_digit()
    });
    if !valid_length || !valid_first || !valid_rest || name.starts_with("GITHUB_") {
        return Err(LpmError::Script(format!(
            "invalid GitHub Actions value name '{name}'; use canonical uppercase letters, digits, and underscores, do not start with a digit, and do not use the GITHUB_ prefix"
        )));
    }
    Ok(())
}

fn validate_repository(repository: &str) -> Result<(), LpmError> {
    if repository.chars().count() > GITHUB_REPOSITORY_MAX_CHARS {
        return Err(LpmError::Script(format!(
            "--repository must be at most {GITHUB_REPOSITORY_MAX_CHARS} characters"
        )));
    }
    let (owner, name) = split_repository(repository)
        .ok_or_else(|| LpmError::Script("--repository must use the owner/name format".into()))?;
    let valid_owner = owner
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || character == '-')
        && !owner.starts_with('-')
        && !owner.ends_with('-');
    let valid_name = name
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.'));
    if !valid_owner || !valid_name {
        return Err(LpmError::Script(
            "--repository contains characters GitHub does not accept".into(),
        ));
    }
    Ok(())
}

fn split_repository(repository: &str) -> Option<(&str, &str)> {
    let (owner, name) = repository.split_once('/')?;
    if owner.is_empty() || name.is_empty() || name.contains('/') {
        return None;
    }
    Some((owner, name))
}

fn validate_repository_id(repository_id: &str) -> Result<(), LpmError> {
    if repository_id.is_empty()
        || repository_id.len() > 20
        || repository_id.starts_with('0')
        || !repository_id.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(LpmError::Script(
            "GitHub Actions repository ID must be a positive decimal integer of at most 20 digits"
                .into(),
        ));
    }
    Ok(())
}

fn validate_environment(environment: &str) -> Result<(), LpmError> {
    if environment.is_empty()
        || environment.chars().count() > GITHUB_ENVIRONMENT_MAX_CHARS
        || environment.chars().any(char::is_control)
    {
        return Err(LpmError::Script(format!(
            "--environment must contain 1 to {GITHUB_ENVIRONMENT_MAX_CHARS} non-control characters"
        )));
    }
    Ok(())
}

fn validate_page_total(
    total: usize,
    expected: Option<usize>,
    namespace: &str,
) -> Result<(), LpmError> {
    let maximum = GITHUB_PAGE_SIZE * GITHUB_MAX_PAGES;
    if total > maximum {
        return Err(pagination_limit_error(namespace));
    }
    if expected.is_some_and(|expected| expected != total) {
        return Err(LpmError::Script(format!(
            "GitHub Actions {namespace} changed during pagination; retry the operation"
        )));
    }
    Ok(())
}

fn pagination_limit_error(namespace: &str) -> LpmError {
    LpmError::Script(format!(
        "GitHub Actions returned more than {GITHUB_MAX_PAGES} pages of {namespace}; refusing an unbounded sync"
    ))
}

fn github_api_url() -> Result<String, LpmError> {
    if !cfg!(any(debug_assertions, feature = "acceptance-test-hooks")) {
        return Ok(GITHUB_API_URL.into());
    }
    let Some(candidate) = std::env::var_os("LPM_ACCEPTANCE_GITHUB_API_BASE_URL") else {
        return Ok(GITHUB_API_URL.into());
    };
    if std::env::var("ACCEPTANCE_RUN_ID")
        .ok()
        .is_none_or(|value| value.trim().is_empty())
    {
        return Ok(GITHUB_API_URL.into());
    }
    let candidate = candidate.to_string_lossy();
    let parsed = reqwest::Url::parse(&candidate)
        .map_err(|error| LpmError::Script(format!("invalid acceptance GitHub URL: {error}")))?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(LpmError::Script(
            "the acceptance GitHub URL must not contain credentials".into(),
        ));
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(LpmError::Script(
            "the acceptance GitHub URL must not contain a query or fragment".into(),
        ));
    }
    if !matches!(parsed.host_str(), Some("127.0.0.1" | "localhost" | "::1")) {
        return Err(LpmError::Script(
            "the acceptance GitHub URL must use a loopback host".into(),
        ));
    }
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(LpmError::Script(
            "the acceptance GitHub URL must use HTTP or HTTPS".into(),
        ));
    }
    if !matches!(parsed.path(), "" | "/") {
        return Err(LpmError::Script(
            "the acceptance GitHub URL must not contain a path".into(),
        ));
    }
    Ok(candidate.trim_end_matches('/').to_string())
}

fn github_api_error(operation: &str, status: reqwest::StatusCode, body: &[u8]) -> LpmError {
    let detail = serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|value| {
            value
                .get("message")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
        .unwrap_or_else(|| String::from_utf8_lossy(body).trim().to_string());
    let suffix = if detail.is_empty() {
        String::new()
    } else {
        format!(": {}", detail.chars().take(300).collect::<String>())
    };
    LpmError::Script(format!(
        "GitHub Actions {operation} failed with HTTP {status}{suffix}"
    ))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as BASE64;
    use crypto_box::SecretKey;
    use lpm_env::{EnvSchema, EnvVarRule};
    use wiremock::matchers::{body_partial_json, header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    fn values(entries: &[(&str, &str)]) -> HashMap<String, String> {
        entries
            .iter()
            .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
            .collect()
    }

    fn config(environment: Option<&str>) -> GitHubActionsConnectionConfig {
        GitHubActionsConnectionConfig {
            repository: "lpm-dev/example".into(),
            repository_id: "123".into(),
            environment: environment.map(str::to_owned),
            linked_env: Some("production".into()),
        }
    }

    fn acceptance_env(server: &MockServer, marker: &str) -> crate::test_env::ScopedEnv {
        crate::test_env::ScopedEnv::set([
            ("ACCEPTANCE_RUN_ID", marker.into()),
            ("LPM_ACCEPTANCE_GITHUB_API_BASE_URL", server.uri().into()),
        ])
    }

    fn repository_response(id: u64, full_name: &str) -> serde_json::Value {
        serde_json::json!({ "id": id, "full_name": full_name })
    }

    #[test]
    fn schema_partition_exposes_only_explicit_non_secret_client_values() {
        let mut schema = EnvSchema::default();
        schema.vars.insert(
            "PUBLIC_ORIGIN".into(),
            EnvVarRule {
                client: true,
                ..EnvVarRule::default()
            },
        );
        schema.vars.insert(
            "AMBIGUOUS_TOKEN".into(),
            EnvVarRule {
                client: true,
                secret: true,
                ..EnvVarRule::default()
            },
        );
        let local = values(&[
            ("PUBLIC_ORIGIN", "https://example.test"),
            ("AMBIGUOUS_TOKEN", "ambiguous"),
            ("UNDECLARED_TOKEN", "secure-default"),
        ]);

        let partitioned = partition_local_values(&local, Some(&schema))
            .expect("valid GitHub Actions value partition");

        assert_eq!(
            partitioned.readable,
            values(&[("PUBLIC_ORIGIN", "https://example.test")])
        );
        assert_eq!(
            partitioned.write_only,
            values(&[
                ("AMBIGUOUS_TOKEN", "ambiguous"),
                ("UNDECLARED_TOKEN", "secure-default"),
            ])
        );
    }

    #[test]
    fn absent_schema_defaults_every_value_to_a_secret() {
        let local = values(&[("API_TOKEN", "secret"), ("PUBLIC_ORIGIN", "origin")]);

        let partitioned =
            partition_local_values(&local, None).expect("valid GitHub Actions value partition");

        assert!(partitioned.readable.is_empty());
        assert_eq!(partitioned.write_only, local);
    }

    #[test]
    fn github_names_must_be_canonical_uppercase_and_not_reserved() {
        for invalid in [
            "lowercase",
            "1STARTS_WITH_NUMBER",
            "GITHUB_TOKEN",
            "WITH-HYPHEN",
            "WITH SPACE",
            "",
        ] {
            let error = validate_value_name(invalid).expect_err("invalid name must fail");
            assert!(
                error.to_string().contains(invalid) || invalid.is_empty(),
                "error should identify the invalid name: {error}"
            );
        }
    }

    #[test]
    fn github_name_partition_rejects_case_insensitive_collisions() {
        let local = values(&[("API_TOKEN", "first"), ("api_token", "second")]);

        let error = partition_local_values(&local, None)
            .expect_err("case-insensitive collision must fail before mutation");

        assert!(error.to_string().contains("case-insensitive"));
    }

    #[test]
    fn connection_identity_fields_are_bounded_and_control_free() {
        assert!(validate_repository_id("12345678901234567890").is_ok());
        assert!(validate_repository_id("123456789012345678901").is_err());
        assert!(validate_environment("production").is_ok());
        assert!(validate_environment("production\u{85}preview").is_err());
    }

    #[test]
    fn sealed_secret_round_trips_with_libsodium_compatible_box() {
        let recipient = SecretKey::generate(&mut crypto_box::aead::OsRng);
        let plaintext = b"acceptance-secret-value";

        let encrypted = seal_secret(recipient.public_key().as_bytes(), plaintext)
            .expect("seal GitHub Actions secret");
        let decrypted = recipient.unseal(&encrypted).expect("unseal secret");

        assert_eq!(decrypted, plaintext);
        assert!(
            !encrypted
                .windows(plaintext.len())
                .any(|window| window == plaintext)
        );
    }

    #[test]
    fn release_endpoint_is_fixed() {
        let _env = crate::test_env::ScopedEnv::update([
            ("ACCEPTANCE_RUN_ID", None),
            (
                "LPM_ACCEPTANCE_GITHUB_API_BASE_URL",
                Some("http://127.0.0.1:4173".into()),
            ),
        ]);

        assert_eq!(
            github_api_url().expect("resolve GitHub URL"),
            GITHUB_API_URL
        );
    }

    #[test]
    fn acceptance_override_rejects_non_loopback_destinations() {
        let _env = crate::test_env::ScopedEnv::set([
            ("ACCEPTANCE_RUN_ID", "github-test".into()),
            (
                "LPM_ACCEPTANCE_GITHUB_API_BASE_URL",
                "https://example.com".into(),
            ),
        ]);

        let error = github_api_url().expect_err("non-loopback override must fail closed");

        assert!(error.to_string().contains("loopback"));
    }

    #[tokio::test]
    async fn repository_scope_lists_readable_variables_and_secret_names() {
        let server = MockServer::start().await;
        let _env = acceptance_env(&server, "github-repository-list");
        Mock::given(method("GET"))
            .and(path("/repos/lpm-dev/example"))
            .and(header("authorization", "Bearer github-token"))
            .and(header("accept", "application/vnd.github+json"))
            .and(header("x-github-api-version", GITHUB_API_VERSION))
            .and(header("user-agent", GITHUB_USER_AGENT))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(repository_response(123, "lpm-dev/example")),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/lpm-dev/example/actions/variables"))
            .and(query_param("per_page", "100"))
            .and(query_param("page", "1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "total_count": 1,
                "variables": [{ "name": "PUBLIC_ORIGIN", "value": "https://example.test" }]
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/lpm-dev/example/actions/secrets"))
            .and(query_param("per_page", "100"))
            .and(query_param("page", "1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "total_count": 1,
                "secrets": [{ "name": "API_TOKEN" }]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let client = GitHubActionsClient::new("github-token".into(), config(None)).expect("client");

        let state = client.list().await.expect("list GitHub Actions values");

        assert_eq!(
            state
                .readable
                .get("PUBLIC_ORIGIN")
                .map(|variable| variable.value.as_str()),
            Some("https://example.test")
        );
        assert_eq!(state.write_only, HashSet::from(["API_TOKEN".into()]));
    }

    #[tokio::test]
    async fn environment_scope_uses_repository_id_and_encoded_environment() {
        let server = MockServer::start().await;
        let _env = acceptance_env(&server, "github-environment-list");
        Mock::given(method("GET"))
            .and(path("/repos/lpm-dev/example"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(repository_response(123, "lpm-dev/example")),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/repositories/123/environments/production%20preview/variables",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "total_count": 0,
                "variables": []
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/repositories/123/environments/production%20preview/secrets",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "total_count": 0,
                "secrets": []
            })))
            .expect(1)
            .mount(&server)
            .await;
        let client =
            GitHubActionsClient::new("github-token".into(), config(Some("production preview")))
                .expect("client");

        client.list().await.expect("list environment values");
    }

    #[tokio::test]
    async fn repository_identity_change_fails_before_value_requests() {
        let server = MockServer::start().await;
        let _env = acceptance_env(&server, "github-binding-change");
        Mock::given(method("GET"))
            .and(path("/repos/lpm-dev/example"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(repository_response(999, "attacker/example")),
            )
            .expect(1)
            .mount(&server)
            .await;
        let client = GitHubActionsClient::new("github-token".into(), config(None)).expect("client");

        let error = client
            .list()
            .await
            .expect_err("changed repository binding must fail closed");

        assert!(error.to_string().contains("binding changed"));
        assert_eq!(server.received_requests().await.expect("requests").len(), 1);
    }

    #[tokio::test]
    async fn redirects_are_rejected_without_forwarding_the_token() {
        let redirect_target = MockServer::start().await;
        let server = MockServer::start().await;
        let _env = acceptance_env(&server, "github-redirect");
        Mock::given(method("GET"))
            .and(path("/repos/lpm-dev/example"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("location", format!("{}/capture", redirect_target.uri())),
            )
            .expect(1)
            .mount(&server)
            .await;
        let client = GitHubActionsClient::new("github-token".into(), config(None)).expect("client");

        let error = client
            .list()
            .await
            .expect_err("redirect must not be followed");

        assert!(error.to_string().contains("HTTP 302"));
        assert!(
            redirect_target
                .received_requests()
                .await
                .expect("redirect target requests")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn pagination_above_the_bound_fails_closed() {
        let server = MockServer::start().await;
        let _env = acceptance_env(&server, "github-pagination");
        Mock::given(method("GET"))
            .and(path("/repos/lpm-dev/example"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(repository_response(123, "lpm-dev/example")),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/lpm-dev/example/actions/variables"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "total_count": 2001,
                "variables": []
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/lpm-dev/example/actions/secrets"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "total_count": 0,
                "secrets": []
            })))
            .mount(&server)
            .await;
        let client = GitHubActionsClient::new("github-token".into(), config(None)).expect("client");

        let error = client
            .list()
            .await
            .expect_err("unbounded pagination must fail closed");

        assert!(error.to_string().contains("more than 20 pages"));
    }

    #[tokio::test]
    async fn secret_upsert_sends_only_a_sealed_box_ciphertext() {
        let recipient = SecretKey::generate(&mut crypto_box::aead::OsRng);
        let public_key = BASE64.encode(recipient.public_key().as_bytes());
        let server = MockServer::start().await;
        let _env = acceptance_env(&server, "github-secret-upsert");
        Mock::given(method("GET"))
            .and(path("/repos/lpm-dev/example"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(repository_response(123, "lpm-dev/example")),
            )
            .expect(2)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/lpm-dev/example/actions/secrets/public-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "key_id": "key-123",
                "key": public_key
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path("/repos/lpm-dev/example/actions/secrets/API_TOKEN"))
            .and(body_partial_json(
                serde_json::json!({ "key_id": "key-123" }),
            ))
            .respond_with(ResponseTemplate::new(201))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/lpm-dev/example/actions/variables"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "total_count": 0,
                "variables": []
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/lpm-dev/example/actions/secrets"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "total_count": 1,
                "secrets": [{ "name": "API_TOKEN" }]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let client = GitHubActionsClient::new("github-token".into(), config(None)).expect("client");
        let local = LocalPlatformValues {
            readable: HashMap::new(),
            write_only: values(&[("API_TOKEN", "plaintext-must-not-leak")]),
        };
        let diff = PlatformDiff {
            write_only_added: vec!["API_TOKEN".into()],
            ..PlatformDiff::default()
        };

        let result = client
            .apply(&diff, &local, &PlatformState::default(), false)
            .await
            .expect("upsert secret");
        let requests = server.received_requests().await.expect("requests");
        let request = requests
            .iter()
            .find(|request| request.method == reqwest::Method::PUT)
            .expect("secret PUT request");
        let body: serde_json::Value =
            serde_json::from_slice(&request.body).expect("secret request JSON");
        let ciphertext = BASE64
            .decode(body["encrypted_value"].as_str().expect("encrypted_value"))
            .expect("base64 ciphertext");
        let decrypted = recipient.unseal(&ciphertext).expect("sealed-box plaintext");

        assert_eq!(result.added, 1);
        assert_eq!(decrypted, b"plaintext-must-not-leak");
        assert!(!String::from_utf8_lossy(&request.body).contains("plaintext-must-not-leak"));
    }

    #[tokio::test]
    async fn partial_mutation_reports_exact_applied_counts() {
        let recipient = SecretKey::generate(&mut crypto_box::aead::OsRng);
        let server = MockServer::start().await;
        let _env = acceptance_env(&server, "github-partial-mutation");
        Mock::given(method("GET"))
            .and(path("/repos/lpm-dev/example"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(repository_response(123, "lpm-dev/example")),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/lpm-dev/example/actions/secrets/public-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "key_id": "key-123",
                "key": BASE64.encode(recipient.public_key().as_bytes())
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/repos/lpm-dev/example/actions/variables"))
            .respond_with(ResponseTemplate::new(201))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path("/repos/lpm-dev/example/actions/secrets/API_TOKEN"))
            .respond_with(
                ResponseTemplate::new(403)
                    .set_body_json(serde_json::json!({ "message": "forbidden" })),
            )
            .expect(1)
            .mount(&server)
            .await;
        let client = GitHubActionsClient::new("github-token".into(), config(None)).expect("client");
        let local = LocalPlatformValues {
            readable: values(&[("PUBLIC_ORIGIN", "https://example.test")]),
            write_only: values(&[("API_TOKEN", "secret")]),
        };
        let diff = PlatformDiff {
            added: vec!["PUBLIC_ORIGIN".into()],
            write_only_added: vec!["API_TOKEN".into()],
            ..PlatformDiff::default()
        };

        let error = client
            .apply(&diff, &local, &PlatformState::default(), false)
            .await
            .expect_err("partial mutation must fail");

        match error {
            PlatformApplyError::Tracked { error, applied } => {
                assert!(error.to_string().contains("HTTP 403"));
                assert_eq!(applied.added, 1);
                assert_eq!(applied.updated, 0);
                assert_eq!(applied.removed, 0);
            }
            PlatformApplyError::Untracked(error) => {
                panic!("expected tracked GitHub mutation failure, got {error}")
            }
        }
    }
}
