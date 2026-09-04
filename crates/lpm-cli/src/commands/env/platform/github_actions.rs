use std::collections::{HashMap, HashSet};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use crypto_box::PublicKey;
use lpm_common::LpmError;
use lpm_env::EnvSchema;
use reqwest::header::{ACCEPT, AUTHORIZATION, HeaderValue, USER_AGENT};
use serde::{Deserialize, Serialize};

use super::super::github::{
    github_api_url, split_repository, validate_repository, validate_repository_id,
};

use super::{
    LocalPlatformValues, MutationKind, MutationOutcome, PLATFORM_TIMEOUT, PlatformApplyError,
    PlatformDiff, PlatformPushResult, PlatformState, PlatformVariable, VariableScope,
    append_platform_error_context, read_platform_response,
};

const GITHUB_API_VERSION: &str = "2022-11-28";
const GITHUB_USER_AGENT: &str = "lpm-env-github-actions";
const GITHUB_VALUE_NAME_MAX_CHARS: usize = 100;
const GITHUB_VALUE_MAX_BYTES: usize = 48 * 1024;
const GITHUB_PAGE_SIZE: usize = 100;
const GITHUB_MAX_PAGES: usize = 20;
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

#[derive(Debug)]
struct GitHubMutationFailure {
    error: LpmError,
    ambiguous: bool,
}

impl From<LpmError> for GitHubMutationFailure {
    fn from(error: LpmError) -> Self {
        Self {
            error,
            ambiguous: false,
        }
    }
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
        validate_repository(&config.repository, "--repository")?;
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
        validate_repository(repository, "--repository")?;
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
            record_outcome(
                &mut applied,
                self.reconcile_variable_mutation(
                    self.create_variable(key, value).await,
                    key,
                    Some(value),
                    MutationKind::Added,
                )
                .await,
            )?;
        }
        for key in &diff.changed {
            let value = local.readable.get(key).ok_or_else(|| {
                PlatformApplyError::tracked(
                    LpmError::Script(format!("missing local value for {key}")),
                    applied,
                )
            })?;
            record_outcome(
                &mut applied,
                self.reconcile_variable_mutation(
                    self.update_variable(key, value).await,
                    key,
                    Some(value),
                    MutationKind::Updated,
                )
                .await,
            )?;
        }
        for (key, encrypted_value, key_id, is_new) in encrypted_secrets {
            let kind = if is_new {
                MutationKind::Added
            } else {
                MutationKind::Updated
            };
            record_outcome(
                &mut applied,
                self.reconcile_secret_upsert(
                    self.upsert_secret(&key, &encrypted_value, &key_id).await,
                    &key,
                    is_new,
                    kind,
                )
                .await,
            )?;
        }
        for key in &diff.removed {
            record_outcome(
                &mut applied,
                self.reconcile_variable_mutation(
                    self.delete_variable(key).await,
                    key,
                    None,
                    MutationKind::Removed,
                )
                .await,
            )?;
        }
        for key in &diff.write_only_removed {
            record_outcome(
                &mut applied,
                self.reconcile_secret_delete(
                    self.delete_secret(key).await,
                    key,
                    MutationKind::Removed,
                )
                .await,
            )?;
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

    async fn reconcile_variable_mutation(
        &self,
        result: Result<(), GitHubMutationFailure>,
        name: &str,
        expected_value: Option<&str>,
        kind: MutationKind,
    ) -> MutationOutcome {
        let failure = match result {
            Ok(()) => return MutationOutcome::Applied(kind),
            Err(failure) if !failure.ambiguous => {
                return MutationOutcome::Failed {
                    error: failure.error,
                    committed: None,
                };
            }
            Err(failure) => failure,
        };
        match self.list_variables().await {
            Ok(variables) => {
                let applied = match expected_value {
                    Some(value) => variables
                        .get(name)
                        .is_some_and(|variable| variable.value == value),
                    None => !variables.contains_key(name),
                };
                if applied {
                    MutationOutcome::Applied(kind)
                } else {
                    MutationOutcome::Failed {
                        error: failure.error,
                        committed: None,
                    }
                }
            }
            Err(reconciliation_error) => MutationOutcome::Unknown(append_platform_error_context(
                failure.error,
                format!(
                    "GitHub Actions final-state reconciliation for {name} failed: {reconciliation_error}"
                ),
            )),
        }
    }

    async fn reconcile_secret_upsert(
        &self,
        result: Result<(), GitHubMutationFailure>,
        name: &str,
        is_new: bool,
        kind: MutationKind,
    ) -> MutationOutcome {
        let failure = match result {
            Ok(()) => return MutationOutcome::Applied(kind),
            Err(failure) if !failure.ambiguous => {
                return MutationOutcome::Failed {
                    error: failure.error,
                    committed: None,
                };
            }
            Err(failure) => failure,
        };
        if !is_new {
            return MutationOutcome::Unknown(append_platform_error_context(
                failure.error,
                format!(
                    "GitHub Actions secret {name} is write-only, so its final value cannot be reconciled"
                ),
            ));
        }
        match self.list_secret_names().await {
            Ok(secrets) if secrets.contains(name) => MutationOutcome::Applied(kind),
            Ok(_) => MutationOutcome::Failed {
                error: failure.error,
                committed: None,
            },
            Err(reconciliation_error) => MutationOutcome::Unknown(append_platform_error_context(
                failure.error,
                format!(
                    "GitHub Actions final-state reconciliation for secret {name} failed: {reconciliation_error}"
                ),
            )),
        }
    }

    async fn reconcile_secret_delete(
        &self,
        result: Result<(), GitHubMutationFailure>,
        name: &str,
        kind: MutationKind,
    ) -> MutationOutcome {
        let failure = match result {
            Ok(()) => return MutationOutcome::Applied(kind),
            Err(failure) if !failure.ambiguous => {
                return MutationOutcome::Failed {
                    error: failure.error,
                    committed: None,
                };
            }
            Err(failure) => failure,
        };
        match self.list_secret_names().await {
            Ok(secrets) if !secrets.contains(name) => MutationOutcome::Applied(kind),
            Ok(_) => MutationOutcome::Failed {
                error: failure.error,
                committed: None,
            },
            Err(reconciliation_error) => MutationOutcome::Unknown(append_platform_error_context(
                failure.error,
                format!(
                    "GitHub Actions final-state reconciliation for secret {name} failed: {reconciliation_error}"
                ),
            )),
        }
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
        let mut response_budget = super::super::response::PlatformResponseBudget::new();
        let variables_url = self.variables_url()?;
        for page in 1..=GITHUB_MAX_PAGES {
            let url = format!("{}?per_page={GITHUB_PAGE_SIZE}&page={page}", variables_url);
            let data: ActionsVariableList = self
                .get_json_with_budget("variable list", &url, &mut response_budget)
                .await?;
            validate_page_total(data.total_count, expected_total, "variables")?;
            expected_total = Some(data.total_count);
            for variable in data.variables {
                validate_value_name(&variable.name)?;
                validate_value_size(&variable.name, &variable.value)?;
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
        let mut response_budget = super::super::response::PlatformResponseBudget::new();
        let secrets_url = self.secrets_url()?;
        for page in 1..=GITHUB_MAX_PAGES {
            let url = format!("{}?per_page={GITHUB_PAGE_SIZE}&page={page}", secrets_url);
            let data: ActionsSecretList = self
                .get_json_with_budget("secret list", &url, &mut response_budget)
                .await?;
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

    async fn create_variable(&self, name: &str, value: &str) -> Result<(), GitHubMutationFailure> {
        let url = self.variables_url()?;
        self.send_mutation(
            "variable create",
            self.request(reqwest::Method::POST, &url)
                .json(&serde_json::json!({ "name": name, "value": value })),
        )
        .await
    }

    async fn update_variable(&self, name: &str, value: &str) -> Result<(), GitHubMutationFailure> {
        let url = format!("{}/{}", self.variables_url()?, urlencoding::encode(name));
        self.send_mutation(
            "variable update",
            self.request(reqwest::Method::PATCH, &url)
                .json(&serde_json::json!({ "name": name, "value": value })),
        )
        .await
    }

    async fn delete_variable(&self, name: &str) -> Result<(), GitHubMutationFailure> {
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
    ) -> Result<(), GitHubMutationFailure> {
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

    async fn delete_secret(&self, name: &str) -> Result<(), GitHubMutationFailure> {
        let url = format!("{}/{}", self.secrets_url()?, urlencoding::encode(name));
        self.send_mutation("secret delete", self.request(reqwest::Method::DELETE, &url))
            .await
    }

    async fn get_json<T: serde::de::DeserializeOwned>(
        &self,
        operation: &str,
        url: &str,
    ) -> Result<T, LpmError> {
        self.get_json_with_budget(
            operation,
            url,
            &mut super::super::response::PlatformResponseBudget::new(),
        )
        .await
    }

    async fn get_json_with_budget<T: serde::de::DeserializeOwned>(
        &self,
        operation: &str,
        url: &str,
        response_budget: &mut super::super::response::PlatformResponseBudget,
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
        let (status, body) =
            super::read_platform_response_with_budget(response, response_budget).await?;
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
    ) -> Result<(), GitHubMutationFailure> {
        let response = request
            .send()
            .await
            .map_err(|error| GitHubMutationFailure {
                error: LpmError::Network(format!(
                    "GitHub Actions {operation} failed: {}",
                    lpm_http::display_error(&error)
                )),
                ambiguous: true,
            })?;
        let response_status = response.status();
        let (status, body) =
            read_platform_response(response)
                .await
                .map_err(|error| GitHubMutationFailure {
                    error,
                    ambiguous: response_status.is_success() || response_status.is_server_error(),
                })?;
        if !status.is_success() {
            return Err(GitHubMutationFailure {
                error: github_api_error(operation, status, &body),
                ambiguous: status.is_server_error(),
            });
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

fn record_outcome(
    applied: &mut PlatformPushResult,
    outcome: MutationOutcome,
) -> Result<(), PlatformApplyError> {
    match outcome {
        MutationOutcome::Applied(kind) => {
            applied.record(kind);
            Ok(())
        }
        MutationOutcome::Failed { error, committed } => {
            if let Some(kind) = committed {
                applied.record(kind);
            }
            Err(PlatformApplyError::tracked(error, *applied))
        }
        MutationOutcome::Unknown(error) => Err(PlatformApplyError::untracked(error)),
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

fn validate_value_size(name: &str, value: &str) -> Result<(), LpmError> {
    if value.len() > GITHUB_VALUE_MAX_BYTES {
        return Err(LpmError::Script(format!(
            "GitHub Actions value {name} exceeds the {GITHUB_VALUE_MAX_BYTES}-byte limit"
        )));
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
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

    async fn read_raw_request(stream: &mut tokio::net::TcpStream) -> Vec<u8> {
        let mut request = Vec::new();
        let mut expected_len = None;
        loop {
            let mut chunk = [0_u8; 2048];
            let read = stream.read(&mut chunk).await.expect("read raw request");
            if read == 0 {
                break;
            }
            request.extend_from_slice(&chunk[..read]);
            if expected_len.is_none()
                && let Some(header_end) = request.windows(4).position(|part| part == b"\r\n\r\n")
            {
                let headers = String::from_utf8_lossy(&request[..header_end]);
                let content_length = headers.lines().find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())
                        .flatten()
                });
                expected_len = Some(header_end + 4 + content_length.unwrap_or_default());
            }
            if expected_len.is_some_and(|expected| request.len() >= expected) {
                break;
            }
        }
        request
    }

    enum RawResponse {
        Disconnect,
        Json(serde_json::Value),
        Status(u16, serde_json::Value),
        TruncatedSuccess,
        TruncatedStatus(u16),
    }

    async fn write_raw_response(stream: &mut tokio::net::TcpStream, response: RawResponse) {
        let (status, body) = match response {
            RawResponse::Disconnect => return,
            RawResponse::Json(body) => (200, serde_json::to_vec(&body).expect("serialize JSON")),
            RawResponse::Status(status, body) => {
                (status, serde_json::to_vec(&body).expect("serialize JSON"))
            }
            RawResponse::TruncatedSuccess => {
                stream
                    .write_all(
                        b"HTTP/1.1 201 Created\r\nContent-Length: 100\r\nConnection: close\r\n\r\n{}",
                    )
                    .await
                    .expect("write truncated GitHub response");
                return;
            }
            RawResponse::TruncatedStatus(status) => {
                let headers = format!(
                    "HTTP/1.1 {status} Test\r\nContent-Length: 100\r\nConnection: close\r\n\r\n{{}}"
                );
                stream
                    .write_all(headers.as_bytes())
                    .await
                    .expect("write truncated GitHub error response");
                return;
            }
        };
        let headers = format!(
            "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream
            .write_all(headers.as_bytes())
            .await
            .expect("write raw GitHub headers");
        stream
            .write_all(&body)
            .await
            .expect("write raw GitHub body");
    }

    async fn spawn_raw_github_server<F>(
        request_count: usize,
        mut response_for: F,
    ) -> (String, tokio::task::JoinHandle<()>)
    where
        F: FnMut(&str) -> RawResponse + Send + 'static,
    {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind raw GitHub server");
        let address = listener.local_addr().expect("raw GitHub address");
        let task = tokio::spawn(async move {
            for _ in 0..request_count {
                let (mut stream, _) = listener.accept().await.expect("accept GitHub request");
                let request = read_raw_request(&mut stream).await;
                let request_line = String::from_utf8_lossy(&request)
                    .lines()
                    .next()
                    .expect("raw GitHub request line")
                    .to_owned();
                write_raw_response(&mut stream, response_for(&request_line)).await;
            }
        });
        (format!("http://{address}"), task)
    }

    async fn spawn_committed_variable_server(
        mutation_response: RawResponse,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let mut mutation_response = Some(mutation_response);
        spawn_raw_github_server(6, move |request_line| {
            if request_line.starts_with("POST ") && request_line.contains("/actions/variables ") {
                return mutation_response
                    .take()
                    .expect("single GitHub variable create");
            }
            if request_line.contains("/actions/variables?") {
                return RawResponse::Json(serde_json::json!({
                    "total_count": 1,
                    "variables": [{
                        "name": "PUBLIC_ORIGIN",
                        "value": "https://example.test"
                    }]
                }));
            }
            if request_line.contains("/actions/secrets?") {
                return RawResponse::Json(serde_json::json!({
                    "total_count": 0,
                    "secrets": []
                }));
            }
            if request_line.contains("/repos/lpm-dev/example ") {
                return RawResponse::Json(repository_response(123, "lpm-dev/example"));
            }
            panic!("unexpected raw GitHub request: {request_line}");
        })
        .await
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
            "https://api.github.com"
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
    async fn oversized_remote_variable_value_fails_closed() {
        let server = MockServer::start().await;
        let _env = acceptance_env(&server, "github-oversized-remote-value");
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
            .and(path("/repos/lpm-dev/example/actions/variables"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "total_count": 1,
                "variables": [{
                    "name": "OVERSIZED_VALUE",
                    "value": "x".repeat(GITHUB_VALUE_MAX_BYTES + 1)
                }]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let client = GitHubActionsClient::new("github-token".into(), config(None)).expect("client");

        let error = client
            .list()
            .await
            .expect_err("an oversized remote value must fail closed");

        assert!(error.to_string().contains("exceeds the 49152-byte limit"));
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
    async fn committed_variable_create_is_counted_after_the_response_disconnects() {
        let (api_url, server) = spawn_committed_variable_server(RawResponse::Disconnect).await;
        let _env = crate::test_env::ScopedEnv::set([
            ("ACCEPTANCE_RUN_ID", "github-create-disconnect".into()),
            ("LPM_ACCEPTANCE_GITHUB_API_BASE_URL", api_url.into()),
        ]);
        let client = GitHubActionsClient::new("github-token".into(), config(None)).expect("client");
        let local = LocalPlatformValues {
            readable: values(&[("PUBLIC_ORIGIN", "https://example.test")]),
            write_only: HashMap::new(),
        };
        let diff = PlatformDiff {
            added: vec!["PUBLIC_ORIGIN".into()],
            ..PlatformDiff::default()
        };

        let result = client
            .apply(&diff, &local, &PlatformState::default(), false)
            .await
            .expect("authoritative final state must recover the committed create");

        assert_eq!(result.added, 1);
        server.await.expect("raw GitHub server");
    }

    #[tokio::test]
    async fn committed_variable_create_is_counted_after_success_body_read_fails() {
        let (api_url, server) =
            spawn_committed_variable_server(RawResponse::TruncatedSuccess).await;
        let _env = crate::test_env::ScopedEnv::set([
            ("ACCEPTANCE_RUN_ID", "github-create-truncated".into()),
            ("LPM_ACCEPTANCE_GITHUB_API_BASE_URL", api_url.into()),
        ]);
        let client = GitHubActionsClient::new("github-token".into(), config(None)).expect("client");
        let local = LocalPlatformValues {
            readable: values(&[("PUBLIC_ORIGIN", "https://example.test")]),
            write_only: HashMap::new(),
        };
        let diff = PlatformDiff {
            added: vec!["PUBLIC_ORIGIN".into()],
            ..PlatformDiff::default()
        };

        let result = client
            .apply(&diff, &local, &PlatformState::default(), false)
            .await
            .expect("authoritative final state must recover the committed create");

        assert_eq!(result.added, 1);
        server.await.expect("raw GitHub server");
    }

    #[tokio::test]
    async fn committed_variable_create_is_counted_after_a_server_error_response() {
        let (api_url, server) = spawn_committed_variable_server(RawResponse::Status(
            503,
            serde_json::json!({ "message": "temporarily unavailable" }),
        ))
        .await;
        let _env = crate::test_env::ScopedEnv::set([
            ("ACCEPTANCE_RUN_ID", "github-create-server-error".into()),
            ("LPM_ACCEPTANCE_GITHUB_API_BASE_URL", api_url.into()),
        ]);
        let client = GitHubActionsClient::new("github-token".into(), config(None)).expect("client");
        let local = LocalPlatformValues {
            readable: values(&[("PUBLIC_ORIGIN", "https://example.test")]),
            write_only: HashMap::new(),
        };
        let diff = PlatformDiff {
            added: vec!["PUBLIC_ORIGIN".into()],
            ..PlatformDiff::default()
        };

        let result = client
            .apply(&diff, &local, &PlatformState::default(), false)
            .await
            .expect("server-error response must be reconciled authoritatively");

        assert_eq!(result.added, 1);
        server.await.expect("raw GitHub server");
    }

    #[tokio::test]
    async fn committed_variable_create_is_counted_after_a_truncated_server_error_response() {
        let (api_url, server) =
            spawn_committed_variable_server(RawResponse::TruncatedStatus(503)).await;
        let _env = crate::test_env::ScopedEnv::set([
            (
                "ACCEPTANCE_RUN_ID",
                "github-create-truncated-server-error".into(),
            ),
            ("LPM_ACCEPTANCE_GITHUB_API_BASE_URL", api_url.into()),
        ]);
        let client = GitHubActionsClient::new("github-token".into(), config(None)).expect("client");
        let local = LocalPlatformValues {
            readable: values(&[("PUBLIC_ORIGIN", "https://example.test")]),
            write_only: HashMap::new(),
        };
        let diff = PlatformDiff {
            added: vec!["PUBLIC_ORIGIN".into()],
            ..PlatformDiff::default()
        };

        let result = client
            .apply(&diff, &local, &PlatformState::default(), false)
            .await
            .expect("truncated server-error response must be reconciled authoritatively");

        assert_eq!(result.added, 1);
        server.await.expect("raw GitHub server");
    }

    #[tokio::test]
    async fn ambiguous_existing_secret_update_suppresses_exact_counts() {
        let recipient = SecretKey::generate(&mut crypto_box::aead::OsRng);
        let public_key = BASE64.encode(recipient.public_key().as_bytes());
        let mut secret_update_pending = true;
        let (api_url, server) = spawn_raw_github_server(3, move |request_line| {
            if request_line.contains("/repos/lpm-dev/example ") {
                return RawResponse::Json(repository_response(123, "lpm-dev/example"));
            }
            if request_line.contains("/actions/secrets/public-key ") {
                return RawResponse::Json(serde_json::json!({
                    "key_id": "key-123",
                    "key": public_key
                }));
            }
            if request_line.starts_with("PUT ")
                && request_line.contains("/actions/secrets/API_TOKEN ")
                && secret_update_pending
            {
                secret_update_pending = false;
                return RawResponse::Disconnect;
            }
            panic!("unexpected raw GitHub request: {request_line}");
        })
        .await;
        let _env = crate::test_env::ScopedEnv::set([
            (
                "ACCEPTANCE_RUN_ID",
                "github-secret-update-disconnect".into(),
            ),
            ("LPM_ACCEPTANCE_GITHUB_API_BASE_URL", api_url.into()),
        ]);
        let client = GitHubActionsClient::new("github-token".into(), config(None)).expect("client");
        let local = LocalPlatformValues {
            readable: HashMap::new(),
            write_only: values(&[("API_TOKEN", "rotated-secret")]),
        };
        let diff = PlatformDiff {
            write_only_present: vec!["API_TOKEN".into()],
            ..PlatformDiff::default()
        };

        let error = client
            .apply(&diff, &local, &PlatformState::default(), false)
            .await
            .expect_err("a write-only update cannot be reconciled by name");

        assert!(matches!(error, PlatformApplyError::Untracked(_)));
        server.await.expect("raw GitHub server");
    }

    #[tokio::test]
    async fn ambiguous_variable_delete_is_counted_when_final_state_confirms_absence() {
        let mut delete_pending = true;
        let (api_url, server) = spawn_raw_github_server(6, move |request_line| {
            if request_line.starts_with("DELETE ")
                && request_line.contains("/actions/variables/REMOVED ")
                && delete_pending
            {
                delete_pending = false;
                return RawResponse::Disconnect;
            }
            if request_line.contains("/actions/variables?") {
                return RawResponse::Json(serde_json::json!({
                    "total_count": 0,
                    "variables": []
                }));
            }
            if request_line.contains("/actions/secrets?") {
                return RawResponse::Json(serde_json::json!({
                    "total_count": 0,
                    "secrets": []
                }));
            }
            if request_line.contains("/repos/lpm-dev/example ") {
                return RawResponse::Json(repository_response(123, "lpm-dev/example"));
            }
            panic!("unexpected raw GitHub request: {request_line}");
        })
        .await;
        let _env = crate::test_env::ScopedEnv::set([
            ("ACCEPTANCE_RUN_ID", "github-delete-disconnect".into()),
            ("LPM_ACCEPTANCE_GITHUB_API_BASE_URL", api_url.into()),
        ]);
        let client = GitHubActionsClient::new("github-token".into(), config(None)).expect("client");
        let diff = PlatformDiff {
            removed: vec!["REMOVED".into()],
            ..PlatformDiff::default()
        };
        let remote = PlatformState::from_readable(HashMap::from([(
            "REMOVED".into(),
            PlatformVariable {
                id: "REMOVED".into(),
                value: "old-value".into(),
                scope: VariableScope::GitHubActions,
            },
        )]));

        let result = client
            .apply(&diff, &LocalPlatformValues::default(), &remote, false)
            .await
            .expect("authoritative final state must recover the committed delete");

        assert_eq!(result.removed, 1);
        server.await.expect("raw GitHub server");
    }

    #[tokio::test]
    async fn ambiguous_variable_create_suppresses_counts_when_reconciliation_fails() {
        let mut create_pending = true;
        let (api_url, server) = spawn_raw_github_server(3, move |request_line| {
            if request_line.starts_with("POST ")
                && request_line.contains("/actions/variables ")
                && create_pending
            {
                create_pending = false;
                return RawResponse::Disconnect;
            }
            if request_line.contains("/actions/variables?") {
                return RawResponse::Status(
                    503,
                    serde_json::json!({ "message": "temporarily unavailable" }),
                );
            }
            if request_line.contains("/repos/lpm-dev/example ") {
                return RawResponse::Json(repository_response(123, "lpm-dev/example"));
            }
            panic!("unexpected raw GitHub request: {request_line}");
        })
        .await;
        let _env = crate::test_env::ScopedEnv::set([
            ("ACCEPTANCE_RUN_ID", "github-reconciliation-failure".into()),
            ("LPM_ACCEPTANCE_GITHUB_API_BASE_URL", api_url.into()),
        ]);
        let client = GitHubActionsClient::new("github-token".into(), config(None)).expect("client");
        let local = LocalPlatformValues {
            readable: values(&[("PUBLIC_ORIGIN", "https://example.test")]),
            write_only: HashMap::new(),
        };
        let diff = PlatformDiff {
            added: vec!["PUBLIC_ORIGIN".into()],
            ..PlatformDiff::default()
        };

        let error = client
            .apply(&diff, &local, &PlatformState::default(), false)
            .await
            .expect_err("unreadable final state must suppress exact mutation counts");

        assert!(matches!(error, PlatformApplyError::Untracked(_)));
        server.await.expect("raw GitHub server");
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
