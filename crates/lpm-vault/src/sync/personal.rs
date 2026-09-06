use std::collections::{HashMap, HashSet};

use super::SyncError;
use super::envelope::{SyncEnvelopePolicy, SyncScope};
use super::http::{
    SyncHttpResponse, read_capped_error_text, read_capped_json, read_capped_json_with_size_limit,
    send_authenticated_sync_request, sync_http_client, sync_request_timeout, url_path_segment,
};
use crate::crypto;

/// Response from push endpoint.
///
/// Carries both success-path fields (`version`, `status`) and the structured
/// error-path fields the server sends with 4xx responses
/// (`error`, `code`, `server_version`, `hint`). The error envelope is shared
/// across the personal sync route and the org sync route. Two codes that
/// command-layer callers may want to switch on:
///
///   - `vault_version_conflict` — caller's `expectedVersion` did not match
///     the server's current version. Already produced by the existing CAS path.
///   - `vault_expected_version_required` — caller omitted `expectedVersion`
///     against an existing row. The server refuses the overwrite. Hint asks
///     the user to pull first then retry.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PushResponse {
    pub version: Option<i32>,
    pub principal_id: Option<String>,
    pub content_key_version: Option<i32>,
    pub status: Option<String>,
    pub error: Option<String>,
    pub code: Option<String>,
    pub server_version: Option<i32>,
    pub hint: Option<String>,
}

/// Render a server-supplied error envelope into a single user-facing string.
/// Appends `hint` when present so the CLI surface shows both the cause and
/// the actionable remediation in one message.
pub(super) fn format_push_error(result: &PushResponse, status: reqwest::StatusCode) -> String {
    let base = result
        .error
        .clone()
        .unwrap_or_else(|| format!("server error: {status}"));
    match result.hint.as_deref() {
        Some(hint) if !hint.is_empty() => format!("{base}\n\nHint: {hint}"),
        _ => base,
    }
}

/// Response from pull endpoint.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PullResponse {
    pub vault_id: Option<String>,
    pub encrypted_blob: Option<String>,
    pub wrapped_key: Option<String>,
    pub version: Option<i32>,
    pub crypto_version: Option<i32>,
    pub principal_id: Option<String>,
    pub error: Option<String>,
}

/// Remote vault entry from list endpoint.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteVault {
    pub vault_id: String,
    pub version: Option<i32>,
    pub updated_at: Option<String>,
}

/// Response from list vaults endpoint.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListVaultsResponse {
    pub vaults: Vec<RemoteVault>,
    #[serde(default)]
    pub next_cursor: Option<String>,
}

const MAX_REMOTE_PROJECTS: usize = 10_000;
const MAX_REMOTE_PROJECT_PAGES: usize = 101;
const MAX_REMOTE_LIST_RESPONSE_BYTES: usize = 10 * 1024 * 1024;
const MAX_REMOTE_LIST_CURSOR_BYTES: usize = 160;

pub(super) async fn list_remote_from_url(
    url: &str,
    auth_token: &str,
) -> Result<Vec<RemoteVault>, SyncError> {
    let client = sync_http_client()?;
    let base_url = reqwest::Url::parse(url).map_err(|e| format!("invalid env list URL: {e}"))?;
    let mut projects = Vec::new();
    let mut cursor: Option<String> = None;
    let mut seen_cursors = HashSet::new();
    let mut cumulative_response_bytes = 0usize;

    for _ in 0..MAX_REMOTE_PROJECT_PAGES {
        let mut page_url = base_url.clone();
        if let Some(current_cursor) = cursor.as_deref() {
            page_url
                .query_pairs_mut()
                .append_pair("cursor", current_cursor);
        }
        let response = client
            .get(page_url)
            .bearer_auth(auth_token)
            .timeout(std::time::Duration::from_secs(30))
            .send()
            .await
            .map_err(super::http::network_error)?;

        if !response.status().is_success() {
            let status = response.status();
            let body = read_capped_error_text(response).await;
            return Err(SyncError::http(status, format!("server error: {body}")));
        }

        let remaining_response_bytes = MAX_REMOTE_LIST_RESPONSE_BYTES
            .checked_sub(cumulative_response_bytes)
            .ok_or("env project list response accounting overflowed")?;
        let (data, response_bytes): (ListVaultsResponse, usize) =
            read_capped_json_with_size_limit(response, remaining_response_bytes).await?;
        cumulative_response_bytes = cumulative_response_bytes
            .checked_add(response_bytes)
            .filter(|total| *total <= MAX_REMOTE_LIST_RESPONSE_BYTES)
            .ok_or_else(|| {
                format!(
                    "env project list exceeds the cumulative response limit of \
                     {MAX_REMOTE_LIST_RESPONSE_BYTES} bytes"
                )
            })?;
        if projects
            .len()
            .checked_add(data.vaults.len())
            .is_none_or(|total| total > MAX_REMOTE_PROJECTS)
        {
            return Err(format!(
                "env project list exceeds the supported {MAX_REMOTE_PROJECTS}-project limit"
            )
            .into());
        }
        projects.extend(data.vaults);

        let Some(next_cursor) = data.next_cursor else {
            return Ok(projects);
        };
        if next_cursor.is_empty()
            || next_cursor.len() > MAX_REMOTE_LIST_CURSOR_BYTES
            || !seen_cursors.insert(next_cursor.clone())
        {
            return Err("env project pagination returned an invalid cursor".into());
        }
        cursor = Some(next_cursor);
    }

    Err("env project pagination exceeded the supported page limit".into())
}

/// List all cloud env projects for the authenticated user.
pub async fn list_remote(
    registry_url: &str,
    auth_token: &str,
) -> Result<Vec<RemoteVault>, SyncError> {
    list_remote_from_url(&format!("{registry_url}/api/vaults"), auth_token).await
}

/// Push a vault to the cloud (personal sync).
pub async fn push(
    registry_url: &str,
    auth_token: &str,
    vault_id: &str,
    secrets: &HashMap<String, String>,
    expected_version: Option<i32>,
    force: bool,
) -> Result<PushResponse, SyncError> {
    let secrets_json =
        serde_json::to_string(secrets).map_err(|e| format!("failed to serialize secrets: {e}"))?;

    push_raw(
        registry_url,
        auth_token,
        vault_id,
        &secrets_json,
        expected_version,
        force,
        None,
    )
    .await
}

/// Optional metadata sent alongside a vault push.
pub struct PushMetadata<'a> {
    /// Project name (from package.json, lpm.json, or directory name).
    pub name: Option<&'a str>,
    /// Env schema from `lpm.json` `envSchema` field (as a JSON value).
    pub schema: Option<&'a serde_json::Value>,
}

/// Revision, principal, and request metadata for a personal vault push.
#[derive(Default)]
pub struct PersonalPushOptions<'a> {
    pub expected_version: Option<i32>,
    pub expected_principal_id: Option<&'a str>,
    pub force: bool,
    pub metadata: Option<&'a PushMetadata<'a>>,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct PersonalPushRequest<'a> {
    encrypted_blob: &'a str,
    wrapped_key: &'a str,
    crypto_version: i32,
    ciphertext_revision: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    expected_version: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expected_principal_id: Option<&'a str>,
    #[serde(skip_serializing_if = "is_false")]
    force: bool,
    #[serde(skip_serializing_if = "is_false")]
    recreate_missing: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    schema: Option<&'a serde_json::Value>,
}

const fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteVaultRevision {
    pub version: i32,
    pub principal_id: String,
}

#[derive(serde::Deserialize)]
struct AuthenticatedPrincipal {
    id: String,
}

async fn read_authenticated_principal(
    client: &reqwest::Client,
    registry_url: &str,
    auth_token: &str,
) -> Result<String, SyncError> {
    let response = client
        .get(format!("{registry_url}/api/user/me"))
        .bearer_auth(auth_token)
        .timeout(sync_request_timeout(std::time::Duration::from_secs(30)))
        .send()
        .await
        .map_err(super::http::network_error)?;
    let status = response.status();
    if !status.is_success() {
        let body = read_capped_error_text(response).await;
        return Err(SyncError::http(
            status,
            format!("failed to resolve the authenticated account: {body}"),
        ));
    }
    let principal: AuthenticatedPrincipal = read_capped_json(response).await?;
    if principal.id.is_empty()
        || principal.id.len() > 128
        || principal.id.chars().any(char::is_control)
    {
        return Err("authenticated account response contained an invalid principal ID".into());
    }
    Ok(principal.id)
}

async fn read_current_push_version(
    client: &reqwest::Client,
    sync_url: &str,
    auth_token: &str,
    vault_id: &str,
) -> Result<Option<RemoteVaultRevision>, SyncError> {
    match send_authenticated_sync_request(
        client
            .get(format!("{sync_url}?versionOnly=true"))
            .bearer_auth(auth_token)
            .timeout(sync_request_timeout(std::time::Duration::from_secs(30))),
        vault_id,
        SyncScope::Personal,
        SyncEnvelopePolicy::Inspect,
    )
    .await?
    {
        SyncHttpResponse::Success(result) => Ok(Some(RemoteVaultRevision {
            version: result
                .version
                .ok_or("version preflight response omitted the vault version")?,
            principal_id: result
                .principal_id
                .ok_or("version preflight response omitted the principal ID")?,
        })),
        SyncHttpResponse::Error { status, response } => {
            if status == reqwest::StatusCode::NOT_FOUND && response.outcome == "missing" {
                Ok(None)
            } else {
                let message = response
                    .error
                    .unwrap_or_else(|| format!("server error: {status}"));
                Err(SyncError::http(status, message))
            }
        }
    }
}

pub async fn personal_version_preflight(
    registry_url: &str,
    auth_token: &str,
    vault_id: &str,
) -> Result<Option<RemoteVaultRevision>, SyncError> {
    let client = sync_http_client()?;
    let url = format!(
        "{registry_url}/api/vaults/{}/sync",
        url_path_segment(vault_id)
    );
    read_current_push_version(client, &url, auth_token, vault_id).await
}

/// Push pre-serialized JSON to the cloud. Used when pushing all environments.
pub async fn push_raw(
    registry_url: &str,
    auth_token: &str,
    vault_id: &str,
    secrets_json: &str,
    expected_version: Option<i32>,
    force: bool,
    metadata: Option<&PushMetadata<'_>>,
) -> Result<PushResponse, SyncError> {
    push_raw_with_options(
        registry_url,
        auth_token,
        vault_id,
        secrets_json,
        PersonalPushOptions {
            expected_version,
            expected_principal_id: None,
            force,
            metadata,
        },
    )
    .await
}

pub async fn push_raw_with_options(
    registry_url: &str,
    auth_token: &str,
    vault_id: &str,
    secrets_json: &str,
    options: PersonalPushOptions<'_>,
) -> Result<PushResponse, SyncError> {
    const MAX_FORCE_PUSH_ATTEMPTS: usize = 3;

    if options.expected_principal_id.is_some_and(str::is_empty) {
        return Err("expected personal cloud env principal is empty".into());
    }

    let client = sync_http_client()?;
    let url = format!(
        "{registry_url}/api/vaults/{}/sync",
        url_path_segment(vault_id)
    );
    let attempt_limit = if options.force {
        MAX_FORCE_PUSH_ATTEMPTS
    } else {
        1
    };
    let mut stable_principal_id = options.expected_principal_id.map(str::to_owned);
    let mut forced_recreation_floor = options.expected_version;

    for attempt in 0..attempt_limit {
        let preflight = if options.force {
            read_current_push_version(client, &url, auth_token, vault_id).await?
        } else {
            None
        };
        if let Some(remote) = &preflight {
            match stable_principal_id.as_deref() {
                Some(principal_id) if principal_id != remote.principal_id => {
                    return Err("personal cloud vault principal changed during force push".into());
                }
                None => stable_principal_id = Some(remote.principal_id.clone()),
                _ => {}
            }
            if let Some(durable_version) = options.expected_version
                && remote.version < durable_version
            {
                return Err(format!(
                    "cloud env version {} is older than the durable local version {durable_version}",
                    remote.version
                )
                .into());
            }
        }

        if stable_principal_id.is_none() {
            stable_principal_id =
                Some(read_authenticated_principal(client, registry_url, auth_token).await?);
        }

        let base_revision =
            preflight
                .as_ref()
                .map(|revision| revision.version)
                .or(if options.force {
                    forced_recreation_floor
                } else {
                    options.expected_version
                });
        let recreate_missing = options.force && preflight.is_none() && base_revision.is_some();
        let target_revision = crypto::next_sync_revision(base_revision)?;
        let principal_id = stable_principal_id
            .as_deref()
            .ok_or("personal cloud env principal is unavailable")?;
        let (encrypted_blob, wrapped_key) =
            crypto::encrypt_vault_for_sync(secrets_json, principal_id, vault_id, target_revision)?;
        let body = PersonalPushRequest {
            encrypted_blob: &encrypted_blob,
            wrapped_key: &wrapped_key,
            crypto_version: crypto::CURRENT_CRYPTO_VERSION,
            ciphertext_revision: target_revision,
            expected_version: base_revision,
            expected_principal_id: stable_principal_id.as_deref(),
            force: options.force,
            recreate_missing,
            name: options.metadata.and_then(|value| value.name),
            schema: options.metadata.and_then(|value| value.schema),
        };

        match send_authenticated_sync_request(
            client
                .post(&url)
                .bearer_auth(auth_token)
                .json(&body)
                .timeout(sync_request_timeout(std::time::Duration::from_secs(30))),
            vault_id,
            SyncScope::Personal,
            SyncEnvelopePolicy::Write,
        )
        .await?
        {
            SyncHttpResponse::Success(result) => {
                if result.version != Some(target_revision) {
                    return Err("vault push committed an unexpected ciphertext revision".into());
                }
                if stable_principal_id.as_deref().is_some_and(|principal_id| {
                    result.principal_id.as_deref() != Some(principal_id)
                }) {
                    return Err("vault push response is bound to a different principal".into());
                }

                return Ok(PushResponse {
                    version: result.version,
                    principal_id: result.principal_id,
                    content_key_version: result.content_key_version,
                    status: result.status,
                    error: result.error,
                    code: result.code,
                    server_version: result.server_version,
                    hint: result.hint,
                });
            }
            SyncHttpResponse::Error { status, response } => {
                let result = PushResponse {
                    version: response.version,
                    principal_id: response.principal_id,
                    content_key_version: response.content_key_version,
                    status: response.status,
                    error: response.error,
                    code: response.code,
                    server_version: response.server_version,
                    hint: response.hint,
                };
                let retryable_conflict = status == reqwest::StatusCode::CONFLICT
                    && matches!(
                        result.code.as_deref(),
                        Some(
                            "vault_version_conflict"
                                | "vault_expected_version_required"
                                | "vault_ciphertext_revision_mismatch"
                                | "vault_creation_conflict"
                                | "vault_recreation_intent_required"
                        )
                    );
                if options.force && retryable_conflict {
                    if preflight.is_none()
                        && let Some(server_version) = result.server_version
                        && server_version > 0
                    {
                        if let Some(retained_floor) = forced_recreation_floor
                            && server_version < retained_floor
                        {
                            return Err(format!(
                                "cloud env version {server_version} is older than the durable local version {retained_floor}"
                            )
                            .into());
                        }
                        forced_recreation_floor = Some(server_version);
                    }
                    if attempt + 1 < attempt_limit {
                        continue;
                    }
                    return Err(SyncError::http(
                        status,
                        format!(
                            "force push could not acquire a stable cloud revision after \
                             {attempt_limit} attempts; retry when concurrent writes stop"
                        ),
                    ));
                }
                return Err(SyncError::http(status, format_push_error(&result, status)));
            }
        }
    }

    Err("force push exhausted its bounded conflict retries".into())
}

/// Pull a vault from the cloud (personal sync).
pub async fn pull(
    registry_url: &str,
    auth_token: &str,
    vault_id: &str,
) -> Result<(HashMap<String, String>, i32), SyncError> {
    pull_bound_to_principal(registry_url, auth_token, vault_id, None).await
}

pub async fn pull_bound_to_principal(
    registry_url: &str,
    auth_token: &str,
    vault_id: &str,
    expected_principal_id: Option<&str>,
) -> Result<(HashMap<String, String>, i32), SyncError> {
    let client = sync_http_client()?;
    let url = format!(
        "{registry_url}/api/vaults/{}/sync",
        url_path_segment(vault_id)
    );

    let result = match send_authenticated_sync_request(
        client
            .get(&url)
            .bearer_auth(auth_token)
            .timeout(sync_request_timeout(std::time::Duration::from_secs(30))),
        vault_id,
        SyncScope::Personal,
        SyncEnvelopePolicy::Pull,
    )
    .await?
    {
        SyncHttpResponse::Success(result) => result,
        SyncHttpResponse::Error { status, response } => {
            let message = response
                .error
                .unwrap_or_else(|| format!("server error: {status}"));
            return Err(SyncError::http(status, message));
        }
    };

    validate_expected_principal(&result, expected_principal_id)?;
    let principal_id = result
        .principal_id
        .as_deref()
        .ok_or("server returned no authenticated principal ID")?;
    let encrypted_blob = result
        .encrypted_blob
        .ok_or("server returned no encrypted data")?;
    let wrapped_key = result.wrapped_key.ok_or("server returned no wrapped key")?;
    let version = result
        .version
        .ok_or("server returned no authenticated revision")?;
    let crypto_version = result
        .crypto_version
        .ok_or("server returned no authenticated crypto version")?;

    let result = crypto::decrypt_vault_from_sync(
        &encrypted_blob,
        &wrapped_key,
        principal_id,
        vault_id,
        version,
        crypto_version,
    )?;
    let secrets = crate::selected_environment::parse(&result, "default")
        .map_err(|error| format!("failed to parse decrypted secrets: {error}"))?
        .into_selected()
        .unwrap_or_default();

    Ok((secrets, version))
}

#[derive(Debug)]
pub struct PulledPersonalVault {
    pub raw_json: String,
    pub version: i32,
    pub principal_id: String,
}

/// Pull and return the raw decrypted JSON (for callers that handle environments themselves).
pub async fn pull_raw(
    registry_url: &str,
    auth_token: &str,
    vault_id: &str,
) -> Result<(String, i32), SyncError> {
    let pulled = pull_raw_bound(registry_url, auth_token, vault_id).await?;
    Ok((pulled.raw_json, pulled.version))
}

pub async fn pull_raw_bound(
    registry_url: &str,
    auth_token: &str,
    vault_id: &str,
) -> Result<PulledPersonalVault, SyncError> {
    pull_raw_bound_to_principal(registry_url, auth_token, vault_id, None).await
}

pub async fn pull_raw_bound_to_principal(
    registry_url: &str,
    auth_token: &str,
    vault_id: &str,
    expected_principal_id: Option<&str>,
) -> Result<PulledPersonalVault, SyncError> {
    pull_raw_authenticated(registry_url, auth_token, vault_id, expected_principal_id).await
}

/// Pull the authoritative plaintext and version without an implicit migration
/// write. Rotation must perform exactly one CAS write against the version it
/// just read.
pub async fn pull_raw_for_rotation(
    registry_url: &str,
    auth_token: &str,
    vault_id: &str,
) -> Result<(String, i32), SyncError> {
    let pulled = pull_raw_for_rotation_bound(registry_url, auth_token, vault_id).await?;
    Ok((pulled.raw_json, pulled.version))
}

pub async fn pull_raw_for_rotation_bound(
    registry_url: &str,
    auth_token: &str,
    vault_id: &str,
) -> Result<PulledPersonalVault, SyncError> {
    pull_raw_for_rotation_bound_to_principal(registry_url, auth_token, vault_id, None).await
}

pub async fn pull_raw_for_rotation_bound_to_principal(
    registry_url: &str,
    auth_token: &str,
    vault_id: &str,
    expected_principal_id: Option<&str>,
) -> Result<PulledPersonalVault, SyncError> {
    pull_raw_authenticated(registry_url, auth_token, vault_id, expected_principal_id).await
}

async fn pull_raw_authenticated(
    registry_url: &str,
    auth_token: &str,
    vault_id: &str,
    expected_principal_id: Option<&str>,
) -> Result<PulledPersonalVault, SyncError> {
    let client = sync_http_client()?;
    let url = format!(
        "{registry_url}/api/vaults/{}/sync",
        url_path_segment(vault_id)
    );

    let result = match send_authenticated_sync_request(
        client
            .get(&url)
            .bearer_auth(auth_token)
            .timeout(sync_request_timeout(std::time::Duration::from_secs(30))),
        vault_id,
        SyncScope::Personal,
        SyncEnvelopePolicy::Pull,
    )
    .await?
    {
        SyncHttpResponse::Success(result) => result,
        SyncHttpResponse::Error { status, response } => {
            let message = response
                .error
                .unwrap_or_else(|| format!("server error: {status}"));
            return Err(SyncError::http(status, message));
        }
    };

    validate_expected_principal(&result, expected_principal_id)?;
    let encrypted_blob = result
        .encrypted_blob
        .ok_or("server returned no encrypted data")?;
    let wrapped_key = result.wrapped_key.ok_or("server returned no wrapped key")?;
    let version = result
        .version
        .ok_or("server returned no authenticated revision")?;
    let principal_id = result
        .principal_id
        .ok_or("server returned no authenticated principal ID")?;
    let crypto_version = result
        .crypto_version
        .ok_or("server returned no authenticated crypto version")?;

    let result = crypto::decrypt_vault_from_sync(
        &encrypted_blob,
        &wrapped_key,
        &principal_id,
        vault_id,
        version,
        crypto_version,
    )?;

    Ok(PulledPersonalVault {
        raw_json: result,
        version,
        principal_id,
    })
}

/// Pull secrets for a specific environment from the cloud vault.
///
/// Unlike [`pull`] which always returns "default", this extracts the
/// requested environment from the multi-env payload. Returns an empty
/// map if the requested env doesn't exist in the cloud vault.
pub async fn pull_env(
    registry_url: &str,
    auth_token: &str,
    vault_id: &str,
    env_name: &str,
) -> Result<(HashMap<String, String>, i32), SyncError> {
    pull_env_bound_to_principal(registry_url, auth_token, vault_id, env_name, None).await
}

pub async fn pull_env_bound_to_principal(
    registry_url: &str,
    auth_token: &str,
    vault_id: &str,
    env_name: &str,
    expected_principal_id: Option<&str>,
) -> Result<(HashMap<String, String>, i32), SyncError> {
    let pulled =
        pull_raw_bound_to_principal(registry_url, auth_token, vault_id, expected_principal_id)
            .await?;
    let raw_json = pulled.raw_json;
    let version = pulled.version;

    let secrets = crate::selected_environment::parse(&raw_json, env_name)
        .map_err(|error| format!("failed to parse decrypted secrets: {error}"))?
        .into_selected()
        .unwrap_or_default();
    Ok((secrets, version))
}

fn validate_expected_principal(
    response: &super::envelope::AuthenticatedSyncResponse,
    expected_principal_id: Option<&str>,
) -> Result<(), SyncError> {
    let principal_id = response
        .principal_id
        .as_deref()
        .ok_or("server returned no authenticated principal ID")?;
    if expected_principal_id.is_some_and(|expected| expected != principal_id) {
        return Err(
			"this env checkout is bound to a different account; use a separate checkout when switching accounts"
				.into(),
		);
    }
    Ok(())
}

#[cfg(test)]
fn take_environment(
    mut wrapper: HashMap<String, HashMap<String, HashMap<String, String>>>,
    env_name: &str,
) -> Option<HashMap<String, String>> {
    let mut environments = wrapper.remove("environments")?;
    Some(environments.remove(env_name).unwrap_or_default())
}

#[cfg(test)]
// These tests hold the crate-wide env lock across mocked HTTP awaits so env
// mutation stays isolated for the whole request/response round-trip.
#[allow(clippy::await_holding_lock)]
mod tests {
    use super::*;
    use crate::signature;
    #[cfg(debug_assertions)]
    use crate::sync::test_support::IsolatedVaultKeyEnv;
    #[cfg(debug_assertions)]
    use crate::sync::test_support::{
        SignedEnvelopeResponse, SignedSyncResponse, TestSyncScope, env_lock_guard,
        signed_envelope_response, signed_envelope_response_with, signed_ok_response,
        signed_sync_ok_response, signed_sync_ok_response_with,
    };
    #[cfg(debug_assertions)]
    use std::sync::{Arc, Mutex as StdMutex};
    use wiremock::matchers::{header, method, path, query_param, query_param_is_missing};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    #[cfg(debug_assertions)]
    use wiremock::{Request, Respond};

    #[cfg(debug_assertions)]
    type EnvelopeMutator = fn(&mut serde_json::Value);

    #[cfg(debug_assertions)]
    fn personal_binding(vault_id: &str) -> serde_json::Value {
        serde_json::json!({
            "scope": "personal",
            "principalId": "personal-test-principal",
            "callerUserId": "personal-test-principal",
            "vaultId": vault_id,
        })
    }

    #[cfg(debug_assertions)]
    fn substitute_vault_id(body: &mut serde_json::Value) {
        body["binding"]["vaultId"] = "vault-other".into();
    }

    #[cfg(debug_assertions)]
    fn replay_request_nonce(body: &mut serde_json::Value) {
        body["requestNonce"] = "A".repeat(43).into();
    }

    #[cfg(debug_assertions)]
    fn substitute_scope(body: &mut serde_json::Value) {
        body["binding"] = serde_json::json!({
            "scope": "organization",
            "principalId": "00000000-0000-4000-8000-000000000001",
            "callerUserId": "caller",
            "organizationSlug": "acme",
            "vaultId": "vault-envelope",
        });
    }

    #[cfg(debug_assertions)]
    fn remove_envelope_version(body: &mut serde_json::Value) {
        body.as_object_mut()
            .expect("test envelope should be an object")
            .remove("envelopeVersion");
    }

    #[cfg(debug_assertions)]
    fn remove_server_version(body: &mut serde_json::Value) {
        body["data"]
            .as_object_mut()
            .expect("test envelope data should be an object")
            .remove("revision");
    }

    #[cfg(debug_assertions)]
    fn substitute_server_version(body: &mut serde_json::Value) {
        body["data"]["revision"] = 6.into();
    }

    #[cfg(debug_assertions)]
    fn clear_version(body: &mut serde_json::Value) {
        body["data"]["revision"] = 0.into();
    }

    #[cfg(debug_assertions)]
    fn downgrade_crypto_version(body: &mut serde_json::Value) {
        body["data"]["cryptoVersion"] = 1.into();
    }

    #[tokio::test]
    async fn list_remote_rejects_an_oversized_declared_response() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 1024];
            let _ = socket.read(&mut request).await;
            socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 10485761\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();
        });

        let error = match list_remote(&format!("http://{addr}"), "auth-token").await {
            Ok(_) => panic!("an oversized list response must be rejected"),
            Err(error) => error,
        };

        assert!(
            error.to_string().contains("response too large"),
            "unexpected error: {error}"
        );
    }

    #[tokio::test]
    async fn list_remote_collects_all_cursor_pages() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/vaults"))
            .and(query_param_is_missing("cursor"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "vaults": [{ "vaultId": "project-1", "version": 1 }],
                "nextCursor": "cursor-2"
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/vaults"))
            .and(query_param("cursor", "cursor-2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "vaults": [{ "vaultId": "project-2", "version": 2 }],
                "nextCursor": null
            })))
            .expect(1)
            .mount(&server)
            .await;

        let projects = list_remote(&server.uri(), "auth-token")
            .await
            .expect("all env project pages should load");

        assert_eq!(
            projects
                .iter()
                .map(|project| project.vault_id.as_str())
                .collect::<Vec<_>>(),
            ["project-1", "project-2"]
        );
    }

    #[tokio::test]
    async fn list_remote_applies_remaining_budget_before_decoding_the_next_page() {
        let server = MockServer::start().await;
        let large_id = "x".repeat(5_500_000);

        Mock::given(method("GET"))
            .and(path("/api/vaults"))
            .and(query_param_is_missing("cursor"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "vaults": [{ "vaultId": format!("first-{large_id}") }],
                "nextCursor": "second"
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/vaults"))
            .and(query_param("cursor", "second"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "vaults": [{ "vaultId": format!("second-{large_id}") }],
                "nextCursor": null
            })))
            .expect(1)
            .mount(&server)
            .await;

        let error = match list_remote(&server.uri(), "auth-token").await {
            Ok(_) => panic!("cumulative list bytes must remain globally bounded"),
            Err(error) => error,
        };

        assert!(
            error.to_string().contains("response too large"),
            "unexpected error: {error}"
        );
    }

    #[tokio::test]
    async fn list_remote_rejects_an_oversized_cursor_before_requesting_it() {
        let server = MockServer::start().await;
        let oversized_cursor = "x".repeat(161);

        Mock::given(method("GET"))
            .and(path("/api/vaults"))
            .and(query_param_is_missing("cursor"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "vaults": [],
                "nextCursor": oversized_cursor
            })))
            .expect(1)
            .mount(&server)
            .await;

        let error = match list_remote(&server.uri(), "auth-token").await {
            Ok(_) => panic!("oversized cursors must be rejected locally"),
            Err(error) => error,
        };

        assert!(
            error.to_string().contains("invalid cursor"),
            "unexpected error: {error}"
        );
    }

    #[tokio::test]
    async fn list_remote_rejects_multi_cursor_cycles() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/vaults"))
            .and(query_param_is_missing("cursor"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "vaults": [],
                "nextCursor": "cursor-a"
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/vaults"))
            .and(query_param("cursor", "cursor-a"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "vaults": [],
                "nextCursor": "cursor-b"
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/vaults"))
            .and(query_param("cursor", "cursor-b"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "vaults": [],
                "nextCursor": "cursor-a"
            })))
            .mount(&server)
            .await;

        let error = match list_remote(&server.uri(), "auth-token").await {
            Ok(_) => panic!("cursor cycles must be rejected before the page limit"),
            Err(error) => error,
        };

        assert!(
            error.to_string().contains("invalid cursor"),
            "unexpected error: {error}"
        );
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn pull_rejects_protocol_v1_without_a_migration_write() {
        let _guard = env_lock_guard();
        let _isolated = IsolatedVaultKeyEnv::new();

        let auth_token = "auth-token";
        let secrets_json = r#"{"DATABASE_URL":"postgres://legacy"}"#;
        let retired_wrapping_key = [0x31; 32];
        let aes_key = crypto::generate_aes_key();
        let encrypted_blob =
            crypto::encrypt(&aes_key, secrets_json.as_bytes()).expect("encrypt retired payload");
        let wrapped_key = crypto::wrap_key(&retired_wrapping_key, &aes_key)
            .expect("wrap key for retired payload");

        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/vaults/vault-legacy/sync"))
            .and(header("authorization", &*format!("Bearer {auth_token}")))
            .respond_with(signed_sync_ok_response(
                serde_json::json!({
                    "encryptedBlob": encrypted_blob,
                    "wrappedKey": wrapped_key,
                    "version": 9,
                    "cryptoVersion": 1,
                }),
                auth_token,
                "vault-legacy",
                TestSyncScope::Personal,
            ))
            .expect(1)
            .mount(&server)
            .await;

        let migration_hits = Arc::new(StdMutex::new(0u32));
        let hits_for_responder = Arc::clone(&migration_hits);

        #[derive(Clone)]
        struct CountingMigrationResponder {
            hits: Arc<StdMutex<u32>>,
            response: SignedSyncResponse,
        }
        impl Respond for CountingMigrationResponder {
            fn respond(&self, request: &Request) -> ResponseTemplate {
                *self.hits.lock().unwrap() += 1;
                self.response.respond(request)
            }
        }

        Mock::given(method("POST"))
            .and(path("/api/vaults/vault-legacy/sync"))
            .respond_with(CountingMigrationResponder {
                hits: hits_for_responder,
                response: signed_sync_ok_response(
                    serde_json::json!({
                        "version": 10,
                        "cryptoVersion": crypto::CURRENT_CRYPTO_VERSION,
                        "status": "synced",
                    }),
                    auth_token,
                    "vault-legacy",
                    TestSyncScope::Personal,
                ),
            })
            .expect(0)
            .mount(&server)
            .await;

        let error = pull(&server.uri(), auth_token, "vault-legacy")
            .await
            .expect_err("network pulls must reject revision-unbound protocol v1 ciphertext");

        assert!(
            error.to_string().contains("unsupported crypto version"),
            "{error}"
        );
        assert_eq!(
            *migration_hits.lock().unwrap(),
            0,
            "rejected remote legacy ciphertext must never trigger a migration write"
        );
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn pull_rejects_a_different_bound_principal_before_decryption() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/vaults/vault-principal/sync"))
            .respond_with(signed_sync_ok_response(
                serde_json::json!({
                    "encryptedBlob": "not-valid-ciphertext",
                    "wrappedKey": "not-valid-wrapped-key",
                    "version": 7,
                    "cryptoVersion": crypto::CURRENT_CRYPTO_VERSION,
                }),
                "auth-token",
                "vault-principal",
                TestSyncScope::Personal,
            ))
            .expect(1)
            .mount(&server)
            .await;

        let error = pull_raw_bound_to_principal(
            &server.uri(),
            "auth-token",
            "vault-principal",
            Some("different-principal"),
        )
        .await
        .expect_err("a response-selected principal must not replace the local binding");

        assert!(error.to_string().contains("different account"), "{error}");
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn push_raw_rejects_a_signed_non_json_conflict_body() {
        let _guard = env_lock_guard();
        let _isolated = IsolatedVaultKeyEnv::new();
        let server = MockServer::start().await;
        let body = "vault version conflict";
        let (key_id, response_signature) = signature::sign_response_for_test(409, body.as_bytes());

        Mock::given(method("POST"))
            .and(path("/api/vaults/vault-123/sync"))
            .and(header("authorization", "Bearer auth-token"))
            .respond_with(
                ResponseTemplate::new(409)
                    .insert_header(signature::KEY_ID_HEADER, key_id.as_str())
                    .insert_header(signature::SIGNATURE_HEADER, response_signature.as_str())
                    .set_body_string(body),
            )
            .expect(1)
            .mount(&server)
            .await;

        let result = push_raw_with_options(
            &server.uri(),
            "auth-token",
            "vault-123",
            r#"{"API_KEY":"secret-value"}"#,
            PersonalPushOptions {
                expected_version: Some(3),
                expected_principal_id: Some("personal-test-principal"),
                force: false,
                metadata: None,
            },
        )
        .await;

        let error = result.expect_err("a non-envelope conflict must fail closed");
        assert!(
            error.to_string().contains("response parse error"),
            "{error}"
        );
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn bound_force_push_reads_the_current_revision_before_encrypting() {
        #[derive(Clone)]
        struct CapturePushResponder {
            body: Arc<StdMutex<Option<serde_json::Value>>>,
            response: SignedSyncResponse,
        }

        impl Respond for CapturePushResponder {
            fn respond(&self, request: &Request) -> ResponseTemplate {
                let body = serde_json::from_slice(&request.body)
                    .expect("force push body should be valid JSON");
                *self.body.lock().unwrap() = Some(body);
                self.response.respond(request)
            }
        }

        let _guard = env_lock_guard();
        let _isolated = IsolatedVaultKeyEnv::new();
        let server = MockServer::start().await;
        let captured_body = Arc::new(StdMutex::new(None));

        Mock::given(method("GET"))
            .and(path("/api/vaults/vault-force/sync"))
            .and(query_param("versionOnly", "true"))
            .respond_with(signed_sync_ok_response(
                serde_json::json!({ "version": 7 }),
                "auth-token",
                "vault-force",
                TestSyncScope::Personal,
            ))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/vaults/vault-force/sync"))
            .respond_with(CapturePushResponder {
                body: Arc::clone(&captured_body),
                response: signed_sync_ok_response(
                    serde_json::json!({
                        "version": 8,
                        "status": "synced",
                    }),
                    "auth-token",
                    "vault-force",
                    TestSyncScope::Personal,
                ),
            })
            .expect(1)
            .mount(&server)
            .await;

        let result = push_raw_with_options(
            &server.uri(),
            "auth-token",
            "vault-force",
            r#"{"API_KEY":"secret"}"#,
            PersonalPushOptions {
                expected_version: None,
                expected_principal_id: Some("personal-test-principal"),
                force: true,
                metadata: None,
            },
        )
        .await
        .expect("force push should bind the revision observed from the server");

        assert_eq!(result.version, Some(8));
        let body = captured_body
            .lock()
            .unwrap()
            .clone()
            .expect("force push body should be captured");
        assert_eq!(body["force"], true);
        assert_eq!(body["expectedVersion"], 7);
        assert_eq!(body["expectedPrincipalId"], "personal-test-principal");
        assert_eq!(body["ciphertextRevision"], 8);
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn bound_force_push_rejects_a_remote_revision_below_the_durable_checkpoint() {
        let _guard = env_lock_guard();
        let _isolated = IsolatedVaultKeyEnv::new();
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/vaults/vault-rollback/sync"))
            .and(query_param("versionOnly", "true"))
            .respond_with(signed_sync_ok_response(
                serde_json::json!({ "version": 4 }),
                "auth-token",
                "vault-rollback",
                TestSyncScope::Personal,
            ))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/vaults/vault-rollback/sync"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;

        let error = push_raw_with_options(
            &server.uri(),
            "auth-token",
            "vault-rollback",
            r#"{"API_KEY":"secret"}"#,
            PersonalPushOptions {
                expected_version: Some(5),
                expected_principal_id: Some("personal-test-principal"),
                force: true,
                metadata: None,
            },
        )
        .await
        .expect_err("force push must reject a remote rollback before posting ciphertext");

        assert!(
            error
                .to_string()
                .contains("older than the durable local version 5"),
            "{error}"
        );
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn force_push_repreflights_and_reencrypts_after_a_version_race() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        #[derive(Clone)]
        struct RacingPreflightResponder {
            calls: Arc<AtomicUsize>,
            first: SignedSyncResponse,
            second: SignedSyncResponse,
        }

        impl Respond for RacingPreflightResponder {
            fn respond(&self, request: &Request) -> ResponseTemplate {
                match self.calls.fetch_add(1, Ordering::SeqCst) {
                    0 => self.first.respond(request),
                    _ => self.second.respond(request),
                }
            }
        }

        #[derive(Clone)]
        struct RacingPushResponder {
            calls: Arc<AtomicUsize>,
            second_body: Arc<StdMutex<Option<serde_json::Value>>>,
            conflict: SignedEnvelopeResponse,
            success: SignedSyncResponse,
        }

        impl Respond for RacingPushResponder {
            fn respond(&self, request: &Request) -> ResponseTemplate {
                if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    return self.conflict.respond(request);
                }
                let body = serde_json::from_slice(&request.body)
                    .expect("retried force push body should be valid JSON");
                *self.second_body.lock().unwrap() = Some(body);
                self.success.respond(request)
            }
        }

        let _guard = env_lock_guard();
        let _isolated = IsolatedVaultKeyEnv::new();
        let server = MockServer::start().await;
        let preflight_calls = Arc::new(AtomicUsize::new(0));
        let push_calls = Arc::new(AtomicUsize::new(0));
        let second_body = Arc::new(StdMutex::new(None));

        Mock::given(method("GET"))
            .and(path("/api/vaults/vault-force-race/sync"))
            .and(query_param("versionOnly", "true"))
            .respond_with(RacingPreflightResponder {
                calls: Arc::clone(&preflight_calls),
                first: signed_sync_ok_response(
                    serde_json::json!({ "version": 5 }),
                    "auth-token",
                    "vault-force-race",
                    TestSyncScope::Personal,
                ),
                second: signed_sync_ok_response(
                    serde_json::json!({ "version": 6 }),
                    "auth-token",
                    "vault-force-race",
                    TestSyncScope::Personal,
                ),
            })
            .expect(2)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/vaults/vault-force-race/sync"))
            .respond_with(RacingPushResponder {
                calls: Arc::clone(&push_calls),
                second_body: Arc::clone(&second_body),
                conflict: signed_envelope_response(
                    409,
                    "vault.write",
                    "revisionConflict",
                    personal_binding("vault-force-race"),
                    serde_json::json!({ "currentRevision": 6 }),
                ),
                success: signed_sync_ok_response(
                    serde_json::json!({
                        "version": 7,
                        "status": "synced",
                    }),
                    "auth-token",
                    "vault-force-race",
                    TestSyncScope::Personal,
                ),
            })
            .expect(2)
            .mount(&server)
            .await;

        let result = push_raw(
            &server.uri(),
            "auth-token",
            "vault-force-race",
            r#"{"API_KEY":"secret"}"#,
            None,
            true,
            None,
        )
        .await
        .expect("force push should recover from one concurrent writer");

        assert_eq!(result.version, Some(7));
        assert_eq!(preflight_calls.load(Ordering::SeqCst), 2);
        assert_eq!(push_calls.load(Ordering::SeqCst), 2);
        let body = second_body
            .lock()
            .unwrap()
            .clone()
            .expect("retried force push body should be captured");
        assert_eq!(body["expectedVersion"], 6);
        assert_eq!(body["ciphertextRevision"], 7);
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn force_push_rejects_unrelated_not_found_preflight_responses() {
        let _guard = env_lock_guard();
        let _isolated = IsolatedVaultKeyEnv::new();
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/vaults/vault-force/sync"))
            .and(query_param("versionOnly", "true"))
            .respond_with(ResponseTemplate::new(404).set_body_string("route missing"))
            .expect(1)
            .mount(&server)
            .await;
        let result = push_raw(
            &server.uri(),
            "auth-token",
            "vault-force",
            r#"{"API_KEY":"secret"}"#,
            None,
            true,
            None,
        )
        .await;

        let error = result.expect_err("an unsigned preflight rejection must fail closed");
        assert!(error.to_string().contains(signature::SIGNATURE_HEADER));
        assert_eq!(
            server
                .received_requests()
                .await
                .expect("record force preflight requests")
                .len(),
            1,
            "an unrelated 404 must stop before the push"
        );
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn force_push_creates_revision_one_only_for_exact_missing_vault_response() {
        #[derive(Clone)]
        struct CapturePushResponder {
            body: Arc<StdMutex<Option<serde_json::Value>>>,
            response: SignedSyncResponse,
        }

        impl Respond for CapturePushResponder {
            fn respond(&self, request: &Request) -> ResponseTemplate {
                *self.body.lock().unwrap() = Some(
                    serde_json::from_slice(&request.body)
                        .expect("force push body should be valid JSON"),
                );
                self.response.respond(request)
            }
        }

        let _guard = env_lock_guard();
        let _isolated = IsolatedVaultKeyEnv::new();
        let server = MockServer::start().await;
        let captured_body = Arc::new(StdMutex::new(None));

        Mock::given(method("GET"))
            .and(path("/api/vaults/vault-force-new/sync"))
            .and(query_param("versionOnly", "true"))
            .respond_with(signed_envelope_response(
                404,
                "vault.inspect",
                "missing",
                personal_binding("vault-force-new"),
                serde_json::json!({ "retainedRevision": 0 }),
            ))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/user/me"))
            .and(header("authorization", "Bearer auth-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "personal-test-principal"
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/vaults/vault-force-new/sync"))
            .respond_with(CapturePushResponder {
                body: Arc::clone(&captured_body),
                response: signed_sync_ok_response(
                    serde_json::json!({ "version": 1, "status": "synced" }),
                    "auth-token",
                    "vault-force-new",
                    TestSyncScope::Personal,
                ),
            })
            .expect(1)
            .mount(&server)
            .await;

        push_raw(
            &server.uri(),
            "auth-token",
            "vault-force-new",
            r#"{"API_KEY":"secret"}"#,
            None,
            true,
            None,
        )
        .await
        .expect("an exact missing-vault response should permit creation");

        let body = captured_body
            .lock()
            .unwrap()
            .clone()
            .expect("force push body should be captured");
        assert!(body.get("expectedVersion").is_none());
        assert_eq!(body["expectedPrincipalId"], "personal-test-principal");
        assert_eq!(body["ciphertextRevision"], 1);
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn bound_force_push_recreates_an_exactly_missing_vault_for_the_same_principal() {
        #[derive(Clone)]
        struct CapturePushResponder {
            body: Arc<StdMutex<Option<serde_json::Value>>>,
            response: SignedSyncResponse,
        }

        impl Respond for CapturePushResponder {
            fn respond(&self, request: &Request) -> ResponseTemplate {
                *self.body.lock().unwrap() = Some(
                    serde_json::from_slice(&request.body)
                        .expect("force push body should be valid JSON"),
                );
                self.response.respond(request)
            }
        }

        let _guard = env_lock_guard();
        let _isolated = IsolatedVaultKeyEnv::new();
        let server = MockServer::start().await;
        let captured_body = Arc::new(StdMutex::new(None));

        Mock::given(method("GET"))
            .and(path("/api/vaults/vault-force-bound/sync"))
            .and(query_param("versionOnly", "true"))
            .respond_with(signed_envelope_response(
                404,
                "vault.inspect",
                "missing",
                personal_binding("vault-force-bound"),
                serde_json::json!({ "retainedRevision": 0 }),
            ))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/vaults/vault-force-bound/sync"))
            .respond_with(CapturePushResponder {
                body: Arc::clone(&captured_body),
                response: signed_sync_ok_response(
                    serde_json::json!({ "version": 1, "status": "synced" }),
                    "auth-token",
                    "vault-force-bound",
                    TestSyncScope::Personal,
                ),
            })
            .expect(1)
            .mount(&server)
            .await;

        push_raw_with_options(
            &server.uri(),
            "auth-token",
            "vault-force-bound",
            r#"{"API_KEY":"secret"}"#,
            PersonalPushOptions {
                expected_version: None,
                expected_principal_id: Some("personal-test-principal"),
                force: true,
                metadata: None,
            },
        )
        .await
        .expect("a bound force push should recreate an exactly missing vault");

        let body = captured_body
            .lock()
            .unwrap()
            .clone()
            .expect("force push body should be captured");
        assert!(body.get("expectedVersion").is_none());
        assert_eq!(body["expectedPrincipalId"], "personal-test-principal");
        assert_eq!(body["ciphertextRevision"], 1);
    }

    /// 2xx responses without an X-LPM-Signature header must be rejected before
    /// any parsing — pull side. Old servers that haven't been updated to sign
    /// responses surface here, with a message that points at the upgrade path.
    #[tokio::test]
    async fn pull_rejects_unsigned_success_response() {
        let server = MockServer::start().await;

        // Note: the legacy unsigned shape — ResponseTemplate::set_body_json
        // is what an unupdated origin would send. No X-LPM-Signature header.
        Mock::given(method("GET"))
            .and(path("/api/vaults/vault-123/sync"))
            .and(header("authorization", "Bearer auth-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "encryptedBlob": "ignored",
                "wrappedKey": "ignored",
                "version": 1
            })))
            .mount(&server)
            .await;

        let result = pull_raw(&server.uri(), "auth-token", "vault-123").await;

        let err = result.expect_err("missing signature must fail-closed");
        assert!(
            err.to_string().contains(signature::SIGNATURE_HEADER),
            "error should name the missing header so users can act, got: {err:?}"
        );
        assert!(
            err.to_string().contains("missing"),
            "error should say the header is missing, got: {err:?}"
        );
    }

    /// Tampered or replayed responses (correct shape, wrong signature) must be
    /// rejected before any parsing. A successful-looking body that fails
    /// verification cannot reach the decryption path.
    #[tokio::test]
    async fn pull_rejects_tampered_body_with_mismatched_signature() {
        let server = MockServer::start().await;

        // Mint a signature against ONE body, but send a DIFFERENT body —
        // simulates a TLS-terminating intermediary swapping the response.
        let original_body = serde_json::json!({
            "encryptedBlob": "ignored",
            "wrappedKey": "ignored",
            "version": 1
        });
        let original_body = serde_json::to_string(&original_body).unwrap();
        let (key_id, original_signature) =
            signature::sign_response_for_test(200, original_body.as_bytes());

        let tampered_body = serde_json::json!({
            "encryptedBlob": "ignored",
            "wrappedKey": "ignored",
            "version": 999
        });
        let tampered_body_str = serde_json::to_string(&tampered_body).unwrap();

        Mock::given(method("GET"))
            .and(path("/api/vaults/vault-123/sync"))
            .and(header("authorization", "Bearer auth-token"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Content-Type", "application/json")
                    .insert_header(signature::KEY_ID_HEADER, key_id.as_str())
                    .insert_header(signature::SIGNATURE_HEADER, original_signature.as_str())
                    .set_body_string(tampered_body_str),
            )
            .mount(&server)
            .await;

        let result = pull_raw(&server.uri(), "auth-token", "vault-123").await;

        let err = result.expect_err("mismatched signature must fail-closed");
        assert!(
            err.to_string().contains("does not match") || err.to_string().contains("tampering"),
            "mismatch error should be specific, got: {err:?}"
        );
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn push_rejects_unsigned_error_responses() {
        let _guard = env_lock_guard();
        let _isolated = IsolatedVaultKeyEnv::new();
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/api/vaults/vault-123/sync"))
            .and(header("authorization", "Bearer auth-token"))
            .respond_with(ResponseTemplate::new(409).set_body_json(serde_json::json!({
                "error": "Version conflict",
                "code": "vault_version_conflict",
                "serverVersion": 7,
                "expectedVersion": 3
            })))
            .expect(1)
            .mount(&server)
            .await;

        let result = push_raw_with_options(
            &server.uri(),
            "auth-token",
            "vault-123",
            r#"{"K":"v"}"#,
            PersonalPushOptions {
                expected_version: Some(3),
                expected_principal_id: Some("personal-test-principal"),
                force: false,
                metadata: None,
            },
        )
        .await;

        let error = result.expect_err("unsigned conflict state must fail closed");
        assert!(error.to_string().contains(signature::SIGNATURE_HEADER));
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn push_rejects_a_replayed_signed_unauthorized_response() {
        let _guard = env_lock_guard();
        let _isolated = IsolatedVaultKeyEnv::new();
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/api/vaults/vault-123/sync"))
            .respond_with(signed_envelope_response_with(
                401,
                "vault.write",
                "rejected",
                personal_binding("vault-123"),
                serde_json::json!({
                    "code": "authentication_required",
                    "message": "Authentication is required",
                }),
                replay_request_nonce,
            ))
            .expect(1)
            .mount(&server)
            .await;

        let error = push_raw_with_options(
            &server.uri(),
            "auth-token",
            "vault-123",
            r#"{"K":"v"}"#,
            PersonalPushOptions {
                expected_version: Some(3),
                expected_principal_id: Some("personal-test-principal"),
                force: false,
                metadata: None,
            },
        )
        .await
        .expect_err("a signed unauthorized response from another request must fail closed");

        assert!(error.to_string().contains("request nonce"), "{error}");
    }

    /// Push success path must verify the signature before returning the
    /// PushResponse. Mirror of the pull test on the response-write surface.
    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn push_rejects_unsigned_success_response() {
        let _guard = env_lock_guard();
        let _isolated = IsolatedVaultKeyEnv::new();
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/api/vaults/vault-123/sync"))
            .and(header("authorization", "Bearer auth-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "vaultId": "vault-123",
                "version": 4,
                "status": "synced"
            })))
            .mount(&server)
            .await;

        let result = push_raw_with_options(
            &server.uri(),
            "auth-token",
            "vault-123",
            r#"{"K":"v"}"#,
            PersonalPushOptions {
                expected_version: Some(3),
                expected_principal_id: Some("personal-test-principal"),
                force: false,
                metadata: None,
            },
        )
        .await;

        let err = result.expect_err("missing signature on push must fail-closed");
        assert!(err.to_string().contains(signature::SIGNATURE_HEADER));
    }

    /// `pull` (the higher-level wrapper) must not bypass verification.
    /// Belt-and-braces test alongside `pull_raw` since the two functions
    /// duplicate the request loop and a future refactor could drift them.
    #[tokio::test]
    async fn pull_top_level_rejects_unsigned_success_response() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/vaults/vault-123/sync"))
            .and(header("authorization", "Bearer auth-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "encryptedBlob": "ignored",
                "wrappedKey": "ignored",
                "version": 1
            })))
            .mount(&server)
            .await;

        let result = pull(&server.uri(), "auth-token", "vault-123").await;

        let err = result.expect_err("pull must require signature too");
        assert!(err.to_string().contains(signature::SIGNATURE_HEADER));
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn pull_env_rejects_a_retired_flat_vault_payload() {
        let _guard = env_lock_guard();

        // Hermetic env: force file-backed wrapping key + isolated HOME so
        // the in-process `crypto::encrypt_vault_for_sync` call below
        // doesn't hit the real keyring (unreliable on Linux CI without
        // a D-Bus / secret-service session).
        let _vault_env = IsolatedVaultKeyEnv::new();

        let server = MockServer::start().await;
        let secrets_json = serde_json::json!({
            "API_KEY": "legacy-secret",
            "NODE_ENV": "production"
        })
        .to_string();
        let (encrypted_blob, wrapped_key) = crypto::encrypt_vault_for_sync(
            &secrets_json,
            "personal-test-principal",
            "vault-123",
            7,
        )
        .expect("vault payload should encrypt");

        Mock::given(method("GET"))
            .and(path("/api/vaults/vault-123/sync"))
            .and(header("authorization", "Bearer auth-token"))
            .respond_with(signed_sync_ok_response(
                serde_json::json!({
                    "encryptedBlob": encrypted_blob,
                    "wrappedKey": wrapped_key,
                    "version": 7,
                    "cryptoVersion": crypto::CURRENT_CRYPTO_VERSION
                }),
                "auth-token",
                "vault-123",
                TestSyncScope::Personal,
            ))
            .expect(1)
            .mount(&server)
            .await;

        let error = pull_env(&server.uri(), "auth-token", "vault-123", "staging")
            .await
            .expect_err("retired flat vault payloads must fail closed");

        assert!(
            error.to_string().contains("unknown field `API_KEY`"),
            "{error}"
        );
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn pull_env_rejects_malformed_unselected_environment() {
        let _guard = env_lock_guard();
        let _vault_env = IsolatedVaultKeyEnv::new();
        let server = MockServer::start().await;
        let secrets_json = r#"{"environments":{"default":{"BROKEN":1},"staging":{"TOKEN":"ok"}}}"#;
        let (encrypted_blob, wrapped_key) =
            crypto::encrypt_vault_for_sync(secrets_json, "personal-test-principal", "vault-123", 8)
                .expect("vault payload should encrypt");

        Mock::given(method("GET"))
            .and(path("/api/vaults/vault-123/sync"))
            .and(header("authorization", "Bearer auth-token"))
            .respond_with(signed_sync_ok_response(
                serde_json::json!({
                    "encryptedBlob": encrypted_blob,
                    "wrappedKey": wrapped_key,
                    "version": 8,
                    "cryptoVersion": crypto::CURRENT_CRYPTO_VERSION
                }),
                "auth-token",
                "vault-123",
                TestSyncScope::Personal,
            ))
            .expect(1)
            .mount(&server)
            .await;

        let error = pull_env(&server.uri(), "auth-token", "vault-123", "staging")
            .await
            .expect_err("malformed authenticated payloads must fail environment pulls");

        assert!(
            error
                .to_string()
                .contains("failed to parse decrypted secrets")
        );
    }

    #[test]
    fn environment_extraction_moves_the_selected_secret_map() {
        let secret = "x".repeat(1024);
        let secret_pointer = secret.as_ptr();
        let environments = HashMap::from([(
            "production".to_string(),
            HashMap::from([("TOKEN".to_string(), secret)]),
        )]);
        let wrapper = HashMap::from([("environments".to_string(), environments)]);

        let extracted = take_environment(wrapper, "production")
            .expect("environment wrapper should be recognized");

        assert_eq!(extracted["TOKEN"].as_ptr(), secret_pointer);
    }

    #[test]
    fn environment_extraction_distinguishes_missing_wrapper_from_missing_env() {
        let missing_wrapper = HashMap::from([("metadata".to_string(), HashMap::new())]);
        assert!(take_environment(missing_wrapper, "default").is_none());

        let wrapper = HashMap::from([(
            "environments".to_string(),
            HashMap::from([("default".to_string(), HashMap::new())]),
        )]);
        assert_eq!(take_environment(wrapper, "staging"), Some(HashMap::new()));
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn pull_raw_times_out_when_server_stalls() {
        let _guard = env_lock_guard();
        let server = MockServer::start().await;
        let original_timeout = std::env::var_os("LPM_TEST_SYNC_TIMEOUT_MS");

        unsafe { std::env::set_var("LPM_TEST_SYNC_TIMEOUT_MS", "50") };

        Mock::given(method("GET"))
            .and(path("/api/vaults/vault-123/sync"))
            .and(header("authorization", "Bearer auth-token"))
            .respond_with(
                signed_ok_response(
                    serde_json::json!({
                        "encryptedBlob": "ignored",
                        "wrappedKey": "ignored",
                        "version": 1
                    }),
                    "auth-token",
                )
                .set_delay(std::time::Duration::from_secs(2)),
            )
            .expect(1)
            .mount(&server)
            .await;

        let started_at = std::time::Instant::now();
        let result = pull_raw(&server.uri(), "auth-token", "vault-123").await;
        let elapsed = started_at.elapsed();

        match original_timeout {
            Some(value) => unsafe { std::env::set_var("LPM_TEST_SYNC_TIMEOUT_MS", value) },
            None => unsafe { std::env::remove_var("LPM_TEST_SYNC_TIMEOUT_MS") },
        }

        assert!(
            elapsed < std::time::Duration::from_secs(1),
            "pull_raw should respect the configured request timeout, took {elapsed:?}"
        );
        assert!(
            result.is_err(),
            "pull_raw should fail when the sync endpoint stalls"
        );
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn push_raw_times_out_when_server_stalls() {
        let _guard = env_lock_guard();
        let _isolated = IsolatedVaultKeyEnv::new();
        let server = MockServer::start().await;
        let original_timeout = std::env::var_os("LPM_TEST_SYNC_TIMEOUT_MS");

        unsafe { std::env::set_var("LPM_TEST_SYNC_TIMEOUT_MS", "50") };

        Mock::given(method("POST"))
            .and(path("/api/vaults/vault-123/sync"))
            .and(header("authorization", "Bearer auth-token"))
            .respond_with(
                signed_ok_response(
                    serde_json::json!({
                        "status": "updated",
                        "version": 4
                    }),
                    "auth-token",
                )
                .set_delay(std::time::Duration::from_secs(2)),
            )
            .expect(1)
            .mount(&server)
            .await;

        let started_at = std::time::Instant::now();
        let result = push_raw_with_options(
            &server.uri(),
            "auth-token",
            "vault-123",
            r#"{"environments":{"default":{"KEY":"value"}}}"#,
            PersonalPushOptions {
                expected_version: Some(3),
                expected_principal_id: Some("personal-test-principal"),
                force: false,
                metadata: None,
            },
        )
        .await;
        let elapsed = started_at.elapsed();

        match original_timeout {
            Some(value) => unsafe { std::env::set_var("LPM_TEST_SYNC_TIMEOUT_MS", value) },
            None => unsafe { std::env::remove_var("LPM_TEST_SYNC_TIMEOUT_MS") },
        }

        assert!(
            elapsed < std::time::Duration::from_secs(1),
            "push_raw should respect the configured request timeout, took {elapsed:?}"
        );
        assert!(
            result.is_err(),
            "push_raw should fail when the sync endpoint stalls"
        );
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn force_push_version_preflight_times_out_when_server_stalls() {
        let _guard = env_lock_guard();
        let _isolated = IsolatedVaultKeyEnv::new();
        let server = MockServer::start().await;
        let original_timeout = std::env::var_os("LPM_TEST_SYNC_TIMEOUT_MS");

        unsafe { std::env::set_var("LPM_TEST_SYNC_TIMEOUT_MS", "50") };

        Mock::given(method("GET"))
            .and(path("/api/vaults/vault-123/sync"))
            .and(query_param("versionOnly", "true"))
            .and(header("authorization", "Bearer auth-token"))
            .respond_with(ResponseTemplate::new(200).set_delay(std::time::Duration::from_secs(2)))
            .expect(1)
            .mount(&server)
            .await;

        let started_at = std::time::Instant::now();
        let result = push_raw(
            &server.uri(),
            "auth-token",
            "vault-123",
            r#"{"environments":{"default":{"KEY":"value"}}}"#,
            Some(9),
            true,
            None,
        )
        .await;
        let elapsed = started_at.elapsed();

        match original_timeout {
            Some(value) => unsafe { std::env::set_var("LPM_TEST_SYNC_TIMEOUT_MS", value) },
            None => unsafe { std::env::remove_var("LPM_TEST_SYNC_TIMEOUT_MS") },
        }

        assert!(
            elapsed < std::time::Duration::from_secs(1),
            "force-push version preflight should time out, took {elapsed:?}"
        );
        assert!(result.is_err(), "a stalled version preflight must fail");
    }

    #[test]
    fn format_push_error_appends_hint_when_present() {
        let response = PushResponse {
            version: None,
            principal_id: None,
            content_key_version: None,
            status: None,
            error: Some(
                "Vault exists on the server. Pull first then push with the synced version, or pass --force to overwrite.".into(),
            ),
            code: Some("vault_expected_version_required".into()),
            server_version: Some(7),
            hint: Some("Run `lpm env pull` then retry the push.".into()),
        };

        let rendered = format_push_error(&response, reqwest::StatusCode::CONFLICT);
        assert!(rendered.contains("Vault exists on the server"));
        assert!(
            rendered.contains("Hint: Run `lpm env pull` then retry the push."),
            "hint must be surfaced so the user sees the remediation in one message: {rendered}"
        );
    }

    #[test]
    fn format_push_error_falls_back_to_error_only_when_hint_absent() {
        let response = PushResponse {
            version: None,
            principal_id: None,
            content_key_version: None,
            status: None,
            error: Some("Version conflict".into()),
            code: Some("vault_version_conflict".into()),
            server_version: Some(9),
            hint: None,
        };

        let rendered = format_push_error(&response, reqwest::StatusCode::CONFLICT);
        assert_eq!(rendered, "Version conflict");
    }

    #[test]
    fn format_push_error_falls_back_to_status_when_error_field_missing() {
        let response = PushResponse {
            version: None,
            principal_id: None,
            content_key_version: None,
            status: None,
            error: None,
            code: None,
            server_version: None,
            hint: None,
        };

        let rendered = format_push_error(&response, reqwest::StatusCode::CONFLICT);
        assert!(
            rendered.contains("409"),
            "fallback must include the HTTP status so the user has something actionable: {rendered}"
        );
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn push_raw_maps_the_signed_expected_revision_outcome_on_conflict() {
        let _guard = env_lock_guard();
        let _isolated = IsolatedVaultKeyEnv::new();

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/vaults/vault-1/sync"))
            .respond_with(signed_envelope_response(
                409,
                "vault.write",
                "expectedRevisionRequired",
                personal_binding("vault-1"),
                serde_json::json!({ "currentRevision": 7 }),
            ))
            .expect(1)
            .mount(&server)
            .await;

        let err = push_raw_with_options(
            &server.uri(),
            "auth-token",
            "vault-1",
            r#"{"API_KEY":"v"}"#,
            PersonalPushOptions {
                expected_version: None,
                expected_principal_id: Some("personal-test-principal"),
                force: false,
                metadata: None,
            },
        )
        .await
        .expect_err("server 409 must propagate as Err");

        assert!(
            err.to_string()
                .contains("current vault revision is required"),
            "the authenticated outcome must map to an actionable error: {err}"
        );
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn pull_raw_sends_a_32_byte_unpadded_base64url_request_nonce() {
        let _guard = env_lock_guard();
        let _isolated = IsolatedVaultKeyEnv::new();
        let server = MockServer::start().await;
        let (encrypted_blob, wrapped_key) = crypto::encrypt_vault_for_sync(
            r#"{"API_KEY":"secret"}"#,
            "personal-test-principal",
            "vault-envelope",
            7,
        )
        .expect("encrypt authenticated sync fixture");

        Mock::given(method("GET"))
            .and(path("/api/vaults/vault-envelope/sync"))
            .respond_with(signed_sync_ok_response(
                serde_json::json!({
                    "encryptedBlob": encrypted_blob,
                    "wrappedKey": wrapped_key,
                    "version": 7,
                    "cryptoVersion": crypto::CURRENT_CRYPTO_VERSION,
                }),
                "auth-token",
                "vault-envelope",
                TestSyncScope::Personal,
            ))
            .expect(1)
            .mount(&server)
            .await;

        pull_raw_for_rotation(&server.uri(), "auth-token", "vault-envelope")
            .await
            .expect("valid authenticated envelope should decrypt");

        let requests = server
            .received_requests()
            .await
            .expect("record authenticated sync request");
        let nonce = requests[0]
            .headers
            .get("x-lpm-vault-request-nonce")
            .and_then(|value| value.to_str().ok())
            .expect("authenticated sync request should include a nonce");
        assert!(
            nonce.len() == 43
                && nonce
                    .bytes()
                    .all(|byte| { byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_') }),
            "nonce must encode 32 random bytes as unpadded base64url: {nonce}"
        );
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn pull_raw_rejects_signed_envelopes_with_invalid_request_bindings() {
        let _guard = env_lock_guard();
        let _isolated = IsolatedVaultKeyEnv::new();
        let (encrypted_blob, wrapped_key) = crypto::encrypt_vault_for_sync(
            r#"{"API_KEY":"secret"}"#,
            "personal-test-principal",
            "vault-envelope",
            7,
        )
        .expect("encrypt authenticated sync fixture");
        let invalid_envelopes: [(&str, EnvelopeMutator); 7] = [
            ("cross-vault substitution", substitute_vault_id),
            ("replayed request nonce", replay_request_nonce),
            ("scope substitution", substitute_scope),
            ("missing envelope version", remove_envelope_version),
            ("missing server version", remove_server_version),
            ("server version substitution", substitute_server_version),
            ("non-positive version", clear_version),
        ];

        for (name, mutate) in invalid_envelopes {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/api/vaults/vault-envelope/sync"))
                .respond_with(signed_sync_ok_response_with(
                    serde_json::json!({
                        "encryptedBlob": encrypted_blob.clone(),
                        "wrappedKey": wrapped_key.clone(),
                        "version": 7,
                        "cryptoVersion": crypto::CURRENT_CRYPTO_VERSION,
                    }),
                    "auth-token",
                    "vault-envelope",
                    TestSyncScope::Personal,
                    mutate,
                ))
                .expect(1)
                .mount(&server)
                .await;

            let result = pull_raw_for_rotation(&server.uri(), "auth-token", "vault-envelope").await;

            assert!(
                result.is_err(),
                "client accepted invalid authenticated sync envelope: {name}"
            );
        }
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn push_raw_rejects_a_signed_crypto_version_downgrade() {
        let _guard = env_lock_guard();
        let _isolated = IsolatedVaultKeyEnv::new();
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/api/vaults/vault-envelope/sync"))
            .respond_with(signed_sync_ok_response_with(
                serde_json::json!({
                    "version": 8,
                    "cryptoVersion": crypto::CURRENT_CRYPTO_VERSION,
                    "status": "synced",
                }),
                "auth-token",
                "vault-envelope",
                TestSyncScope::Personal,
                downgrade_crypto_version,
            ))
            .expect(1)
            .mount(&server)
            .await;

        let result = push_raw_with_options(
            &server.uri(),
            "auth-token",
            "vault-envelope",
            r#"{"API_KEY":"secret"}"#,
            PersonalPushOptions {
                expected_version: Some(7),
                expected_principal_id: Some("personal-test-principal"),
                force: false,
                metadata: None,
            },
        )
        .await;

        assert!(result.is_err(), "client accepted a signed crypto downgrade");
    }
}
