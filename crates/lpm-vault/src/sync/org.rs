use super::SyncError;
use super::envelope::{SyncEnvelopePolicy, SyncScope};
use super::http::{
    SyncHttpResponse, send_authenticated_sync_request, sync_http_client, url_path_segment,
};
use super::personal::{
    PushMetadata, PushResponse, RemoteVault, format_push_error, list_remote_from_url,
};
use super::public_key::{
    MemberPublicKey, SharingKeyScope, get_org_member_key_access_with_client,
    public_key_fingerprint, resolve_local_public_key_state,
};
#[cfg(all(test, debug_assertions))]
use super::recipient_set::acceptance_digest;
#[cfg(test)]
use super::recipient_set::prepare_recipients;
use super::recipient_set::{
    PreparedRecipient, enforce_recipient_trust, prepare_authenticated_recipients,
};
use crate::crypto;

const fn is_false(value: &bool) -> bool {
    !*value
}

/// Decrypted organization env payload and its remote concurrency epochs.
#[derive(Debug)]
pub struct PulledOrgVault {
    /// Complete decrypted JSON payload.
    pub raw_json: String,
    /// Ciphertext version used for compare-and-swap writes.
    pub version: i32,
    /// Version of the organization content key that encrypted the payload.
    pub content_key_version: i32,
    pub principal_id: String,
    pub caller_user_id: String,
}

struct AuthenticatedOrgVaultKey {
    encrypted_blob: String,
    version: i32,
    crypto_version: i32,
    content_key_version: i32,
    principal_id: String,
    caller_user_id: String,
    content_key: [u8; 32],
}

/// Inputs for one organization env project write.
#[derive(Clone, Copy)]
pub struct OrgPushRequest<'a> {
    /// Organization slug that owns the env project.
    pub org_slug: &'a str,
    /// Stable project identifier from `lpm.json`.
    pub vault_id: &'a str,
    /// Complete plaintext JSON payload to encrypt.
    pub secrets_json: &'a str,
    /// Last server version observed by the caller.
    pub expected_version: Option<i32>,
    /// Declares that an absent remote row must continue from its durable server floor.
    pub recreate_missing: bool,
    /// Optional project name and schema projection.
    pub metadata: Option<&'a PushMetadata<'a>>,
    /// Digest that explicitly accepts an exact changed recipient-key set.
    pub recipient_set_acceptance: Option<&'a str>,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct WrappedMemberKey<'recipient> {
    user_id: &'recipient str,
    wrapped_key: String,
    public_key_version: i32,
    public_key_fingerprint: &'recipient str,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct OrgUpdateRequest<'a> {
    encrypted_blob: &'a str,
    expected_organization_id: &'a str,
    expected_caller_user_id: &'a str,
    crypto_version: i32,
    ciphertext_revision: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    wrapped_keys: Option<&'a [WrappedMemberKey<'a>]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expected_version: Option<i32>,
    #[serde(skip_serializing_if = "is_false")]
    force: bool,
    #[serde(skip_serializing_if = "is_false")]
    recreate_missing: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    schema: Option<&'a serde_json::Value>,
}

/// List all shared vaults for an org.
pub async fn list_org_vaults(
    registry_url: &str,
    auth_token: &str,
    org_slug: &str,
) -> Result<Vec<RemoteVault>, SyncError> {
    let url = format!(
        "{registry_url}/api/orgs/{}/vaults",
        url_path_segment(org_slug)
    );
    list_remote_from_url(&url, auth_token).await
}

pub async fn org_version_preflight_bound_to_principal(
    registry_url: &str,
    auth_token: &str,
    org_slug: &str,
    vault_id: &str,
    expected_principal_id: &str,
) -> Result<Option<i32>, SyncError> {
    let client = sync_http_client()?;
    let url = format!(
        "{registry_url}/api/orgs/{}/vaults/{}?versionOnly=true",
        url_path_segment(org_slug),
        url_path_segment(vault_id)
    );
    match send_authenticated_sync_request(
        client
            .get(url)
            .bearer_auth(auth_token)
            .timeout(std::time::Duration::from_secs(30)),
        vault_id,
        SyncScope::Organization(org_slug),
        SyncEnvelopePolicy::Inspect,
    )
    .await?
    {
        SyncHttpResponse::Success(result) => {
            let principal_id = result
                .principal_id
                .as_deref()
                .ok_or("organization env version response omitted the principal ID")?;
            if principal_id != expected_principal_id {
                return Err(
                    "this env checkout is bound to a different organization; use a separate checkout when switching organizations"
                        .into(),
                );
            }
            Ok(Some(result.version.ok_or(
                "organization env version response omitted the vault version",
            )?))
        }
        SyncHttpResponse::Error { status, response } => {
            if status == reqwest::StatusCode::NOT_FOUND && response.outcome == "missing" {
                return Ok(None);
            }
            let message = response
                .error
                .unwrap_or_else(|| format!("server error: {status}"));
            Err(SyncError::http(status, message))
        }
    }
}

// ── Org Vault Sync ───────────────────────────────────────────────

/// Pull an org vault.
pub async fn pull_org(
    registry_url: &str,
    auth_token: &str,
    org_slug: &str,
    vault_id: &str,
    private_key: &[u8; 32],
) -> Result<PulledOrgVault, SyncError> {
    pull_org_bound_to_principal(
        registry_url,
        auth_token,
        org_slug,
        vault_id,
        private_key,
        None,
    )
    .await
}

pub async fn pull_org_bound_to_principal(
    registry_url: &str,
    auth_token: &str,
    org_slug: &str,
    vault_id: &str,
    private_key: &[u8; 32],
    expected_principal_id: Option<&str>,
) -> Result<PulledOrgVault, SyncError> {
    let client = sync_http_client()?;
    pull_org_with_content_key(
        client,
        registry_url,
        auth_token,
        org_slug,
        vault_id,
        Some(private_key),
        expected_principal_id,
    )
    .await
}

pub async fn pull_org_with_scoped_key_bound_to_principal(
    registry_url: &str,
    auth_token: &str,
    org_slug: &str,
    vault_id: &str,
    expected_principal_id: Option<&str>,
) -> Result<PulledOrgVault, SyncError> {
    let client = sync_http_client()?;
    pull_org_with_content_key(
        client,
        registry_url,
        auth_token,
        org_slug,
        vault_id,
        None,
        expected_principal_id,
    )
    .await
}

async fn pull_org_with_content_key(
    client: &reqwest::Client,
    registry_url: &str,
    auth_token: &str,
    org_slug: &str,
    vault_id: &str,
    private_key: Option<&[u8; 32]>,
    expected_principal_id: Option<&str>,
) -> Result<PulledOrgVault, SyncError> {
    let current = fetch_org_with_content_key(
        client,
        registry_url,
        auth_token,
        org_slug,
        vault_id,
        private_key,
        expected_principal_id,
    )
    .await?;
    let plaintext = crypto::decrypt_vault_payload(
        &current.content_key,
        &current.encrypted_blob,
        crypto::VaultScope::Organization(org_slug),
        &current.principal_id,
        vault_id,
        current.version,
        current.crypto_version,
    )?;
    let json = String::from_utf8(plaintext).map_err(|e| format!("utf8 error: {e}"))?;

    Ok(PulledOrgVault {
        raw_json: json,
        version: current.version,
        content_key_version: current.content_key_version,
        principal_id: current.principal_id,
        caller_user_id: current.caller_user_id,
    })
}

/// Authenticate and decrypt the current project before preparing its content key for CI.
pub async fn prepare_org_ci_escrow(
    registry_url: &str,
    auth_token: &str,
    org_slug: &str,
    vault_id: &str,
    expected_principal_id: &str,
) -> Result<super::ci::OrganizationCiEscrow, SyncError> {
    use elliptic_curve::zeroize::{Zeroize, Zeroizing};
    let mut current = fetch_org_with_content_key(
        sync_http_client()?,
        registry_url,
        auth_token,
        org_slug,
        vault_id,
        None,
        Some(expected_principal_id),
    )
    .await?;
    let result = crypto::decrypt_vault_payload(
        &current.content_key,
        &current.encrypted_blob,
        crypto::VaultScope::Organization(org_slug),
        &current.principal_id,
        vault_id,
        current.version,
        current.crypto_version,
    )
    .map(|plaintext| {
        drop(Zeroizing::new(plaintext));
        super::ci::OrganizationCiEscrow {
            registry_url: registry_url.to_owned(),
            org_slug: org_slug.to_owned(),
            vault_id: vault_id.to_owned(),
            principal_id: current.principal_id,
            caller_user_id: current.caller_user_id,
            version: current.version,
            content_key_version: current.content_key_version,
            content_key_hex: Zeroizing::new(hex::encode(current.content_key)),
        }
    });
    current.content_key.zeroize();
    result.map_err(SyncError::from)
}

async fn fetch_org_with_content_key(
    client: &reqwest::Client,
    registry_url: &str,
    auth_token: &str,
    org_slug: &str,
    vault_id: &str,
    private_key: Option<&[u8; 32]>,
    expected_principal_id: Option<&str>,
) -> Result<AuthenticatedOrgVaultKey, SyncError> {
    let url = format!(
        "{registry_url}/api/orgs/{}/vaults/{}",
        url_path_segment(org_slug),
        url_path_segment(vault_id)
    );

    let data = match send_authenticated_sync_request(
        client
            .get(&url)
            .bearer_auth(auth_token)
            .timeout(std::time::Duration::from_secs(30)),
        vault_id,
        SyncScope::Organization(org_slug),
        SyncEnvelopePolicy::Pull,
    )
    .await?
    {
        SyncHttpResponse::Success(data) => data,
        SyncHttpResponse::Error { status, response } => {
            let code = response.code.clone();
            let rewrap_identity = (code.as_deref() == Some("vault_member_needs_rewrap"))
                .then(|| {
                    Some((
                        response.principal_id.clone()?,
                        response.caller_user_id.clone()?,
                    ))
                })
                .flatten();
            let (organization_id, caller_user_id) = rewrap_identity.unzip();
            return Err(SyncError::http_with_rewrap_identity(
                status,
                code,
                organization_id,
                caller_user_id,
                response
                    .error
                    .unwrap_or_else(|| format!("server error: {status}")),
            ));
        }
    };

    let principal_id = data
        .principal_id
        .ok_or("organization env response omitted the principal ID")?;
    if expected_principal_id.is_some_and(|expected| expected != principal_id) {
        return Err(
			"this env checkout is bound to a different organization; use a separate checkout when switching organizations"
				.into(),
		);
    }
    let encrypted_blob = data
        .encrypted_blob
        .ok_or("organization env response omitted encrypted data")?;
    let wrapped_key = data
        .wrapped_key
        .ok_or("organization env response omitted the wrapped key")?;
    let version = data
        .version
        .ok_or("organization env response omitted the vault version")?;
    let crypto_version = data
        .crypto_version
        .ok_or("organization env response omitted the crypto version")?;
    let content_key_version = data
        .content_key_version
        .ok_or("organization env response omitted the content-key version")?;
    let recipient_public_key_version = data
        .recipient_public_key_version
        .ok_or("organization env response omitted the recipient key version")?;
    let recipient_public_key_fingerprint = data
        .recipient_public_key_fingerprint
        .ok_or("organization env response omitted the recipient key fingerprint")?;
    let caller_user_id = data
        .caller_user_id
        .ok_or("organization env response omitted the authenticated caller ID")?;
    let scoped_local_key = if private_key.is_none() {
        let scope = SharingKeyScope::new(registry_url, &caller_user_id)?;
        Some(resolve_local_public_key_state(&scope)?)
    } else {
        None
    };
    let private_key = private_key
        .or_else(|| scoped_local_key.as_ref().map(|local| &local.private_key))
        .ok_or("organization env pull could not resolve the local sharing key")?;

    let local_public_key =
        x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(*private_key));
    let local_fingerprint = public_key_fingerprint(local_public_key.as_bytes());
    if recipient_public_key_fingerprint != local_fingerprint {
        return Err(
            "organization env wrap targets a different local sharing-key fingerprint; rotate or restore the correct sharing key before retrying"
                .into(),
        );
    }
    if content_key_version <= 0 || recipient_public_key_version <= 0 {
        return Err("organization env response contains an invalid key/version binding".into());
    }

    // Unwrap AES key with our X25519 private key, then decrypt
    let content_key = crypto::unwrap_key_from_sender(&wrapped_key, private_key)?;

    Ok(AuthenticatedOrgVaultKey {
        encrypted_blob,
        version,
        crypto_version,
        content_key_version,
        principal_id,
        caller_user_id,
        content_key,
    })
}

/// Push an organization env project while preserving the caller's key-management boundary.
pub async fn push_org(
    registry_url: &str,
    auth_token: &str,
    request: OrgPushRequest<'_>,
    private_key: &[u8; 32],
) -> Result<PushResponse, SyncError> {
    let client = sync_http_client()?;
    let access =
        get_org_member_key_access_with_client(client, registry_url, auth_token, request.org_slug)
            .await?;
    push_org_with_member_access_boundary(
        client,
        registry_url,
        auth_token,
        request,
        private_key,
        &access,
    )
    .await
}

pub async fn push_org_with_access(
    registry_url: &str,
    auth_token: &str,
    request: OrgPushRequest<'_>,
    private_key: &[u8; 32],
    access: &super::public_key::OrgMemberKeyAccess,
) -> Result<PushResponse, SyncError> {
    let client = sync_http_client()?;
    push_org_with_member_access_boundary(
        client,
        registry_url,
        auth_token,
        request,
        private_key,
        access,
    )
    .await
}

async fn push_org_with_member_access_boundary(
    client: &reqwest::Client,
    registry_url: &str,
    auth_token: &str,
    request: OrgPushRequest<'_>,
    private_key: &[u8; 32],
    access: &super::public_key::OrgMemberKeyAccess,
) -> Result<PushResponse, SyncError> {
    if access.can_replace_wrapped_keys {
        return push_org_with_member_access(
            client,
            registry_url,
            auth_token,
            request,
            &access.organization_id,
            &access.caller_user_id,
            &access.members,
        )
        .await;
    }

    let expected_version = request.expected_version.ok_or_else(|| {
        "organization maintainers must pull the current env project before updating it".to_string()
    })?;
    let current = fetch_org_with_content_key(
        client,
        registry_url,
        auth_token,
        request.org_slug,
        request.vault_id,
        Some(private_key),
        Some(&access.organization_id),
    )
    .await?;
    if current.principal_id != access.organization_id {
        return Err("organization principal changed during env update; fetch current organization access and retry".into());
    }
    if current.caller_user_id != access.caller_user_id {
        return Err("authenticated caller changed during env update; fetch current organization access and retry".into());
    }
    if current.version != expected_version {
        return Err(format!(
            "organization env version changed from {expected_version} to {}; pull and retry",
            current.version
        )
        .into());
    }
    crypto::authenticate_vault_payload(
        &current.content_key,
        &current.encrypted_blob,
        crypto::VaultScope::Organization(request.org_slug),
        &current.principal_id,
        request.vault_id,
        current.version,
        current.crypto_version,
    )?;
    let target_revision = crypto::next_sync_revision(Some(expected_version))?;
    let encrypted_blob = crypto::encrypt_vault_payload(
        &current.content_key,
        request.secrets_json.as_bytes(),
        crypto::VaultScope::Organization(request.org_slug),
        &access.organization_id,
        request.vault_id,
        target_revision,
    )?;
    post_org_update(
        client,
        registry_url,
        auth_token,
        PreparedOrgUpdate {
            request,
            organization_id: &access.organization_id,
            caller_user_id: &access.caller_user_id,
            encrypted_blob,
            wrapped_keys: None,
        },
    )
    .await
}

/// Push an org vault with proper X25519 key wrapping for all members.
pub async fn push_org_with_keys(
    registry_url: &str,
    auth_token: &str,
    request: OrgPushRequest<'_>,
) -> Result<PushResponse, SyncError> {
    let client = sync_http_client()?;
    let access =
        get_org_member_key_access_with_client(client, registry_url, auth_token, request.org_slug)
            .await?;
    push_org_with_keys_with_access(client, registry_url, auth_token, request, &access).await
}

pub async fn push_org_with_keys_and_access(
    registry_url: &str,
    auth_token: &str,
    request: OrgPushRequest<'_>,
    access: &super::public_key::OrgMemberKeyAccess,
) -> Result<PushResponse, SyncError> {
    let client = sync_http_client()?;
    push_org_with_keys_with_access(client, registry_url, auth_token, request, access).await
}

async fn push_org_with_keys_with_access(
    client: &reqwest::Client,
    registry_url: &str,
    auth_token: &str,
    request: OrgPushRequest<'_>,
    access: &super::public_key::OrgMemberKeyAccess,
) -> Result<PushResponse, SyncError> {
    if !access.can_replace_wrapped_keys {
        return Err("only organization owners and admins can replace wrapped content keys".into());
    }
    push_org_with_member_access(
        client,
        registry_url,
        auth_token,
        request,
        &access.organization_id,
        &access.caller_user_id,
        &access.members,
    )
    .await
}

async fn push_org_with_member_access(
    client: &reqwest::Client,
    registry_url: &str,
    auth_token: &str,
    request: OrgPushRequest<'_>,
    organization_id: &str,
    caller_user_id: &str,
    members: &[MemberPublicKey],
) -> Result<PushResponse, SyncError> {
    const MAX_RECREATION_ATTEMPTS: usize = 3;

    let recipients = prepare_authenticated_recipients(members)?;
    enforce_recipient_trust(
        registry_url,
        organization_id,
        request.org_slug,
        &recipients,
        request.recipient_set_acceptance,
    )?;
    let retained_floor = request.expected_version;
    let mut expected_version = request.expected_version;
    let attempt_limit = if request.recreate_missing {
        MAX_RECREATION_ATTEMPTS
    } else {
        1
    };
    let aes_key = crypto::generate_aes_key();
    let wrapped_keys = wrap_keys_for_members(&aes_key, &recipients)?;

    for attempt in 0..attempt_limit {
        let attempt_request = OrgPushRequest {
            expected_version,
            ..request
        };
        let target_revision = crypto::next_sync_revision(expected_version)?;
        let encrypted_blob = crypto::encrypt_vault_payload(
            &aes_key,
            request.secrets_json.as_bytes(),
            crypto::VaultScope::Organization(request.org_slug),
            organization_id,
            request.vault_id,
            target_revision,
        )?;

        match post_org_update(
            client,
            registry_url,
            auth_token,
            PreparedOrgUpdate {
                request: attempt_request,
                organization_id,
                caller_user_id,
                encrypted_blob,
                wrapped_keys: Some(&wrapped_keys),
            },
        )
        .await
        {
            Ok(result) => return Ok(result),
            Err(error) if request.recreate_missing => {
                let Some(server_floor) = error.recreation_conflict_floor() else {
                    return Err(error);
                };
                if let Some(retained_floor) = retained_floor
                    && server_floor < retained_floor
                {
                    return Err(format!(
                        "cloud env version {server_floor} is older than the durable local version {retained_floor}"
                    )
                    .into());
                }
                if attempt + 1 == attempt_limit {
                    return Err(SyncError::http(
                        reqwest::StatusCode::CONFLICT,
                        format!(
                            "organization env recreation could not acquire a stable cloud revision after {attempt_limit} attempts; retry when concurrent writes stop"
                        ),
                    ));
                }
                expected_version = Some(server_floor);
            }
            Err(error) => return Err(error),
        }
    }

    Err("organization env recreation exhausted its bounded conflict retries".into())
}

struct PreparedOrgUpdate<'request, 'identity, 'recipient> {
    request: OrgPushRequest<'request>,
    organization_id: &'identity str,
    caller_user_id: &'identity str,
    encrypted_blob: String,
    wrapped_keys: Option<&'recipient [WrappedMemberKey<'recipient>]>,
}

async fn post_org_update(
    client: &reqwest::Client,
    registry_url: &str,
    auth_token: &str,
    update: PreparedOrgUpdate<'_, '_, '_>,
) -> Result<PushResponse, SyncError> {
    let PreparedOrgUpdate {
        request,
        organization_id,
        caller_user_id,
        encrypted_blob,
        wrapped_keys,
    } = update;
    let target_revision = crypto::next_sync_revision(request.expected_version)?;
    let url = format!(
        "{registry_url}/api/orgs/{}/vaults/{}",
        url_path_segment(request.org_slug),
        url_path_segment(request.vault_id)
    );

    let body = OrgUpdateRequest {
        encrypted_blob: &encrypted_blob,
        expected_organization_id: organization_id,
        expected_caller_user_id: caller_user_id,
        crypto_version: crypto::CURRENT_CRYPTO_VERSION,
        ciphertext_revision: target_revision,
        wrapped_keys,
        expected_version: request.expected_version,
        force: request.recreate_missing,
        recreate_missing: request.recreate_missing,
        name: request.metadata.and_then(|value| value.name),
        schema: request.metadata.and_then(|value| value.schema),
    };

    let result = match send_authenticated_sync_request(
        client
            .post(&url)
            .bearer_auth(auth_token)
            .json(&body)
            .timeout(std::time::Duration::from_secs(30)),
        request.vault_id,
        SyncScope::Organization(request.org_slug),
        SyncEnvelopePolicy::Write,
    )
    .await?
    {
        SyncHttpResponse::Success(result) => result,
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
            let message = format_push_error(&result, status);
            return Err(SyncError::http_with_sync_conflict(
                status,
                result.code,
                result.server_version,
                message,
            ));
        }
    };
    if result.version != Some(target_revision) {
        return Err("organization env push committed an unexpected ciphertext revision".into());
    }
    if result.principal_id.as_deref() != Some(organization_id) {
        return Err("organization env push response is bound to a different principal".into());
    }

    Ok(PushResponse {
        version: result.version,
        principal_id: result.principal_id,
        content_key_version: result.content_key_version,
        status: result.status,
        error: result.error,
        code: result.code,
        server_version: result.server_version,
        hint: result.hint,
    })
}

fn wrap_keys_for_members<'recipient>(
    aes_key: &[u8; 32],
    recipients: &'recipient [PreparedRecipient],
) -> Result<Vec<WrappedMemberKey<'recipient>>, String> {
    let mut wrapped_keys = Vec::with_capacity(recipients.len());

    tracing::warn!(
        target: "lpm_vault::sync",
        recipient_count = recipients.len(),
        "wrapping vault AES key for {} organization member recipient(s)",
        recipients.len()
    );

    for recipient in recipients {
        let wrapped = crypto::wrap_key_for_recipient(aes_key, &recipient.public_key)?;
        wrapped_keys.push(WrappedMemberKey {
            user_id: &recipient.binding.user_id,
            wrapped_key: wrapped,
            public_key_version: recipient.binding.public_key_version,
            public_key_fingerprint: &recipient.binding.public_key_fingerprint,
        });
    }

    if wrapped_keys.is_empty() {
        return Err(
            "no org members have valid public keys. Each member needs to run `lpm env share --org <slug>` once to generate their keypair.".into(),
        );
    }

    Ok(wrapped_keys)
}
#[cfg(test)]
#[expect(
    clippy::await_holding_lock,
    reason = "process-wide environment mutations must remain isolated across mocked HTTP awaits"
)]
mod tests {
    use super::*;
    #[cfg(debug_assertions)]
    const TEST_ORGANIZATION_ID: &str = "00000000-0000-4000-8000-000000000001";
    #[cfg(debug_assertions)]
    use crate::sync::test_support::{
        IsolatedVaultKeyEnv, SignedEnvelopeResponse, SignedSyncResponse, TestSyncScope,
        env_lock_guard, signed_envelope_response, signed_envelope_response_with,
        signed_sync_ok_response, signed_sync_ok_response_with,
    };
    use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
    #[cfg(debug_assertions)]
    use sha2::{Digest, Sha256};
    #[cfg(debug_assertions)]
    use std::sync::{Arc, Mutex as StdMutex};
    #[cfg(debug_assertions)]
    use wiremock::matchers::{header, method, path};
    #[cfg(debug_assertions)]
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

    #[cfg(debug_assertions)]
    fn substitute_organization_slug(body: &mut serde_json::Value) {
        body["binding"]["organizationSlug"] = "other-org".into();
    }

    #[cfg(debug_assertions)]
    fn substitute_organization_principal(body: &mut serde_json::Value) {
        body["binding"]["principalId"] = "00000000-0000-4000-8000-000000000002".into();
    }

    #[cfg(debug_assertions)]
    fn substitute_caller_user(body: &mut serde_json::Value) {
        body["binding"]["callerUserId"] = "other-caller".into();
    }

    #[cfg(debug_assertions)]
    fn set_maintainer_caller_user(body: &mut serde_json::Value) {
        body["binding"]["callerUserId"] = "user-maintainer".into();
    }

    #[cfg(debug_assertions)]
    fn remove_caller_user(body: &mut serde_json::Value) {
        body["binding"]
            .as_object_mut()
            .expect("signed binding must be an object")
            .remove("callerUserId");
    }

    #[cfg(debug_assertions)]
    fn invalidate_caller_user(body: &mut serde_json::Value) {
        body["binding"]["callerUserId"] = "caller\nsubstitution".into();
    }

    #[cfg(debug_assertions)]
    fn organization_binding(vault_id: &str, caller_user_id: &str) -> serde_json::Value {
        serde_json::json!({
            "scope": "organization",
            "principalId": TEST_ORGANIZATION_ID,
            "callerUserId": caller_user_id,
            "organizationSlug": "acme",
            "vaultId": vault_id,
        })
    }

    #[cfg(debug_assertions)]
    fn signed_member_inventory(
        caller_user_id: &str,
        can_replace_wrapped_keys: bool,
        members: serde_json::Value,
    ) -> crate::sync::test_support::SignedEnvelopeResponse {
        signed_envelope_response(
            200,
            "organization.memberKeys.read",
            "current",
            serde_json::json!({
                "scope": "organization",
                "principalId": TEST_ORGANIZATION_ID,
                "callerUserId": caller_user_id,
                "organizationSlug": "acme",
            }),
            serde_json::json!({
                "capability": if can_replace_wrapped_keys {
                    "replaceWrappedKeysAllowed"
                } else {
                    "replaceWrappedKeysForbidden"
                },
                "members": members,
            }),
        )
    }

    fn registered_member(
        user_id: &str,
        role: &str,
        public_key: [u8; 32],
        public_key_version: i32,
    ) -> MemberPublicKey {
        MemberPublicKey::with_test_key(user_id, role, public_key, public_key_version)
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn pull_rejects_a_different_bound_organization_before_decryption() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/orgs/acme/vaults/vault-principal"))
            .respond_with(signed_sync_ok_response(
                serde_json::json!({
                    "encryptedBlob": "not-valid-ciphertext",
                    "wrappedKey": "not-valid-wrapped-key",
                    "version": 7,
                    "cryptoVersion": crypto::CURRENT_CRYPTO_VERSION,
                    "contentKeyVersion": 1,
                    "recipientPublicKeyVersion": 1,
                    "recipientPublicKeyFingerprint": "a".repeat(64),
                }),
                "auth-token",
                "vault-principal",
                TestSyncScope::Organization("acme".into()),
            ))
            .expect(1)
            .mount(&server)
            .await;

        let error = pull_org_bound_to_principal(
            &server.uri(),
            "auth-token",
            "acme",
            "vault-principal",
            &[7u8; 32],
            Some("00000000-0000-4000-8000-000000000002"),
        )
        .await
        .expect_err("a response-selected organization must not replace the local binding");

        assert!(
            error.to_string().contains("different organization"),
            "{error}"
        );
    }

    #[cfg(debug_assertions)]
    fn encrypted_org_pull_body(
        private_key: &[u8; 32],
        payload: &str,
        org_slug: &str,
        vault_id: &str,
        version: i32,
        content_key_version: i32,
        fingerprint: String,
    ) -> serde_json::Value {
        let public_key =
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(*private_key));
        let content_key = crypto::generate_aes_key();
        serde_json::json!({
            "encryptedBlob": crypto::encrypt_vault_payload(
                &content_key,
                payload.as_bytes(),
                crypto::VaultScope::Organization(org_slug),
                TEST_ORGANIZATION_ID,
                vault_id,
                version,
            )
                .expect("encrypt org pull fixture"),
            "wrappedKey": crypto::wrap_key_for_recipient(&content_key, public_key.as_bytes())
                .expect("wrap org pull fixture key"),
            "version": version,
            "cryptoVersion": crypto::CURRENT_CRYPTO_VERSION,
            "contentKeyVersion": content_key_version,
            "recipientPublicKeyVersion": 4,
            "recipientPublicKeyFingerprint": fingerprint,
        })
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn pull_org_returns_plaintext_and_bound_versions_for_current_recipient_key() {
        let private_key = [11u8; 32];
        let public_key =
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(private_key));
        let body = encrypted_org_pull_body(
            &private_key,
            r#"{"environments":{"default":{"TOKEN":"secret"}}}"#,
            "acme",
            "vault-1",
            8,
            3,
            public_key_fingerprint(public_key.as_bytes()),
        );
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/orgs/acme/vaults/vault-1"))
            .respond_with(signed_sync_ok_response(
                body,
                "auth-token",
                "vault-1",
                TestSyncScope::Organization("acme".into()),
            ))
            .expect(1)
            .mount(&server)
            .await;

        let pulled = pull_org(&server.uri(), "auth-token", "acme", "vault-1", &private_key)
            .await
            .expect("bound org payload should decrypt");

        assert_eq!(pulled.version, 8);
        assert_eq!(pulled.content_key_version, 3);
        assert_eq!(
            pulled.raw_json,
            r#"{"environments":{"default":{"TOKEN":"secret"}}}"#
        );
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn scoped_org_pull_uses_the_signed_authenticated_caller_key_slot() {
        let _guard = env_lock_guard();
        let _isolated = IsolatedVaultKeyEnv::new();
        let server = MockServer::start().await;
        let scope = SharingKeyScope::new(&server.uri(), "organization-test-caller")
            .expect("sharing key scope");
        let local = crate::sync::public_key::resolve_local_public_key_state(&scope)
            .expect("create scoped sharing key");
        let public_key =
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(local.private_key));
        let body = encrypted_org_pull_body(
            &local.private_key,
            r#"{"TOKEN":"secret"}"#,
            "acme",
            "vault-scoped",
            5,
            2,
            public_key_fingerprint(public_key.as_bytes()),
        );
        Mock::given(method("GET"))
            .and(path("/api/orgs/acme/vaults/vault-scoped"))
            .respond_with(signed_sync_ok_response(
                body,
                "auth-token",
                "vault-scoped",
                TestSyncScope::Organization("acme".into()),
            ))
            .expect(1)
            .mount(&server)
            .await;

        let pulled = pull_org_with_scoped_key_bound_to_principal(
            &server.uri(),
            "auth-token",
            "acme",
            "vault-scoped",
            Some(TEST_ORGANIZATION_ID),
        )
        .await
        .expect("signed caller identity must select its scoped sharing key");

        assert_eq!(pulled.raw_json, r#"{"TOKEN":"secret"}"#);
        assert_eq!(pulled.caller_user_id, "organization-test-caller");
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn scoped_org_pull_rejects_a_signed_caller_identity_substitution() {
        let _guard = env_lock_guard();
        let _isolated = IsolatedVaultKeyEnv::new();
        let server = MockServer::start().await;
        let scope = SharingKeyScope::new(&server.uri(), "organization-test-caller")
            .expect("sharing key scope");
        let local = crate::sync::public_key::resolve_local_public_key_state(&scope)
            .expect("create scoped sharing key");
        let public_key =
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(local.private_key));
        let body = encrypted_org_pull_body(
            &local.private_key,
            r#"{"TOKEN":"secret"}"#,
            "acme",
            "vault-caller-substitution",
            5,
            2,
            public_key_fingerprint(public_key.as_bytes()),
        );
        Mock::given(method("GET"))
            .and(path("/api/orgs/acme/vaults/vault-caller-substitution"))
            .respond_with(signed_sync_ok_response_with(
                body,
                "auth-token",
                "vault-caller-substitution",
                TestSyncScope::Organization("acme".into()),
                substitute_caller_user,
            ))
            .expect(1)
            .mount(&server)
            .await;

        let error = pull_org_with_scoped_key_bound_to_principal(
            &server.uri(),
            "auth-token",
            "acme",
            "vault-caller-substitution",
            Some(TEST_ORGANIZATION_ID),
        )
        .await
        .expect_err("a substituted signed caller must not reuse another caller's key slot");

        assert!(
            error
                .to_string()
                .contains("different local sharing-key fingerprint"),
            "{error}"
        );
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn scoped_org_pull_rejects_missing_or_malformed_signed_caller_identity() {
        for (vault_id, mutation) in [
            (
                "vault-missing-caller",
                remove_caller_user as fn(&mut serde_json::Value),
            ),
            (
                "vault-malformed-caller",
                invalidate_caller_user as fn(&mut serde_json::Value),
            ),
        ] {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path(format!("/api/orgs/acme/vaults/{vault_id}")))
                .respond_with(signed_sync_ok_response_with(
                    serde_json::json!({
                        "encryptedBlob": "ciphertext",
                        "wrappedKey": "wrapped-key",
                        "version": 1,
                        "cryptoVersion": crypto::CURRENT_CRYPTO_VERSION,
                        "contentKeyVersion": 1,
                        "recipientPublicKeyVersion": 1,
                        "recipientPublicKeyFingerprint": "a".repeat(64),
                    }),
                    "auth-token",
                    vault_id,
                    TestSyncScope::Organization("acme".into()),
                    mutation,
                ))
                .expect(1)
                .mount(&server)
                .await;

            let error = pull_org_with_scoped_key_bound_to_principal(
                &server.uri(),
                "auth-token",
                "acme",
                vault_id,
                Some(TEST_ORGANIZATION_ID),
            )
            .await
            .expect_err("an invalid signed caller identity must fail closed");

            let message = error.to_string();
            assert!(
                message.contains("callerUserId") || message.contains("caller user ID"),
                "{error}"
            );
        }
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn pull_org_preserves_the_exact_member_rewrap_error_code() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/orgs/acme/vaults/vault-rewrap"))
            .respond_with(signed_envelope_response(
                403,
                "vault.pull",
                "memberRewrapRequired",
                organization_binding("vault-rewrap", "11111111-1111-4111-8111-111111111111"),
                serde_json::json!({
                    "revision": 7,
                    "contentKeyVersion": 3,
                }),
            ))
            .expect(1)
            .mount(&server)
            .await;

        let error = pull_org(
            &server.uri(),
            "auth-token",
            "acme",
            "vault-rewrap",
            &[11u8; 32],
        )
        .await
        .expect_err("member rewrap response must remain distinguishable");

        assert!(error.has_http_code(403, "vault_member_needs_rewrap"));
        assert_eq!(
            error.org_member_rewrap_identity(),
            Some((
                "00000000-0000-4000-8000-000000000001",
                "11111111-1111-4111-8111-111111111111",
            )),
        );
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn pull_org_rejects_member_rewrap_fallback_without_bound_identities() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/orgs/acme/vaults/vault-rewrap"))
            .respond_with(signed_envelope_response_with(
                403,
                "vault.pull",
                "memberRewrapRequired",
                organization_binding("vault-rewrap", "user-caller"),
                serde_json::json!({
                    "revision": 7,
                    "contentKeyVersion": 3,
                }),
                remove_caller_user,
            ))
            .expect(1)
            .mount(&server)
            .await;

        let error = pull_org(
            &server.uri(),
            "auth-token",
            "acme",
            "vault-rewrap",
            &[11u8; 32],
        )
        .await
        .expect_err("unbound member rewrap response must fail closed");

        assert!(!error.has_http_code(403, "vault_member_needs_rewrap"));
        assert_eq!(error.org_member_rewrap_identity(), None);
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn pull_org_does_not_classify_other_forbidden_responses_as_member_rewrap() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/orgs/acme/vaults/vault-forbidden"))
            .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
                "error": "Forbidden",
                "code": "vault_access_denied",
            })))
            .expect(1)
            .mount(&server)
            .await;

        let error = pull_org(
            &server.uri(),
            "auth-token",
            "acme",
            "vault-forbidden",
            &[11u8; 32],
        )
        .await
        .expect_err("forbidden response must fail");

        assert!(!error.has_http_code(403, "vault_member_needs_rewrap"));
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn pull_org_rejects_a_signed_canonical_slug_substitution() {
        let private_key = [21u8; 32];
        let public_key =
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(private_key));
        let content_key = crypto::generate_aes_key();
        let encrypted_blob = crypto::encrypt_vault_payload(
            &content_key,
            br#"{"TOKEN":"secret"}"#,
            crypto::VaultScope::Organization("acme"),
            TEST_ORGANIZATION_ID,
            "vault-envelope",
            4,
        )
        .expect("encrypt organization envelope fixture");
        let wrapped_key = crypto::wrap_key_for_recipient(&content_key, public_key.as_bytes())
            .expect("wrap organization envelope fixture key");
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/orgs/acme/vaults/vault-envelope"))
            .respond_with(signed_sync_ok_response_with(
                serde_json::json!({
                    "encryptedBlob": encrypted_blob,
                    "wrappedKey": wrapped_key,
                    "version": 4,
                    "cryptoVersion": crypto::CURRENT_CRYPTO_VERSION,
                    "contentKeyVersion": 3,
                    "recipientPublicKeyVersion": 4,
                    "recipientPublicKeyFingerprint": public_key_fingerprint(public_key.as_bytes()),
                }),
                "auth-token",
                "vault-envelope",
                TestSyncScope::Organization("acme".into()),
                substitute_organization_slug,
            ))
            .expect(1)
            .mount(&server)
            .await;

        let result = pull_org(
            &server.uri(),
            "auth-token",
            "acme",
            "vault-envelope",
            &private_key,
        )
        .await;

        assert!(
            result.is_err(),
            "client accepted a signed envelope for another canonical organization slug"
        );
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn pull_org_rejects_wrap_for_different_recipient_fingerprint() {
        let private_key = [12u8; 32];
        let body = encrypted_org_pull_body(
            &private_key,
            r#"{"TOKEN":"secret"}"#,
            "acme",
            "vault-2",
            2,
            1,
            "a".repeat(64),
        );
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/orgs/acme/vaults/vault-2"))
            .respond_with(signed_sync_ok_response(
                body,
                "auth-token",
                "vault-2",
                TestSyncScope::Organization("acme".into()),
            ))
            .expect(1)
            .mount(&server)
            .await;

        let error = pull_org(&server.uri(), "auth-token", "acme", "vault-2", &private_key)
            .await
            .expect_err("stale recipient fingerprint must fail closed");

        assert!(
            error
                .to_string()
                .contains("different local sharing-key fingerprint")
        );
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn pull_org_rejects_non_positive_content_key_version() {
        let private_key = [13u8; 32];
        let public_key =
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(private_key));
        let body = encrypted_org_pull_body(
            &private_key,
            r#"{"TOKEN":"secret"}"#,
            "acme",
            "vault-3",
            2,
            0,
            public_key_fingerprint(public_key.as_bytes()),
        );
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/orgs/acme/vaults/vault-3"))
            .respond_with(signed_sync_ok_response(
                body,
                "auth-token",
                "vault-3",
                TestSyncScope::Organization("acme".into()),
            ))
            .expect(1)
            .mount(&server)
            .await;

        let error = pull_org(&server.uri(), "auth-token", "acme", "vault-3", &private_key)
            .await
            .expect_err("invalid content-key epoch must fail closed");

        assert_eq!(
            error.to_string(),
            "authenticated sync envelope requires a valid content key version"
        );
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn push_org_with_keys_rejects_an_unpinned_recipient_set_before_posting() {
        #[derive(Clone)]
        struct CapturePushResponder {
            body: Arc<StdMutex<Option<String>>>,
            response: SignedSyncResponse,
        }

        impl Respond for CapturePushResponder {
            fn respond(&self, request: &Request) -> ResponseTemplate {
                let body = String::from_utf8(request.body.clone())
                    .expect("push_org_with_keys request body should be valid utf-8 json");
                *self.body.lock().unwrap() = Some(body);
                self.response.respond(request)
            }
        }

        let _guard = env_lock_guard();
        let _isolated = IsolatedVaultKeyEnv::new();
        let server = MockServer::start().await;
        let captured_body = Arc::new(StdMutex::new(None));
        let (_, member_public_key) = crypto::generate_x25519_keypair();
        let member_fingerprint = format!("{:x}", Sha256::digest(member_public_key));

        Mock::given(method("GET"))
            .and(path("/api/orgs/acme/members/public-keys"))
            .and(header("authorization", "Bearer auth-token"))
            .respond_with(signed_member_inventory(
                "user-keyed",
                true,
                serde_json::json!([
                    {
                        "userId": "user-keyed",
                        "role": "admin",
                        "sharingKey": {
                            "algorithm": "X25519",
                            "publicKey": BASE64.encode(member_public_key),
                            "version": 7,
                            "fingerprint": member_fingerprint,
                        }
                    },
                    {
                        "userId": "user-missing",
                        "role": "developer",
                        "sharingKey": null,
                    }
                ]),
            ))
            .expect(1)
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/api/orgs/acme/vaults/vault-123"))
            .and(header("authorization", "Bearer auth-token"))
            .respond_with(CapturePushResponder {
                body: Arc::clone(&captured_body),
                response: signed_sync_ok_response(
                    serde_json::json!({
                        "version": 8,
                        "cryptoVersion": crypto::CURRENT_CRYPTO_VERSION,
                        "status": "synced",
                    }),
                    "auth-token",
                    "vault-123",
                    TestSyncScope::Organization("acme".into()),
                ),
            })
            .expect(0)
            .mount(&server)
            .await;

        let error = push_org_with_keys(
            &server.uri(),
            "auth-token",
            OrgPushRequest {
                org_slug: "acme",
                vault_id: "vault-123",
                secrets_json: r#"{"API_KEY":"secret-value"}"#,
                expected_version: Some(7),
                recreate_missing: false,
                metadata: None,
                recipient_set_acceptance: None,
            },
        )
        .await
        .expect_err("an unpinned recipient set must fail closed");

        assert!(error.to_string().contains("recipient set is not trusted"));
        assert!(captured_body.lock().unwrap().is_none());
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn maintainer_push_rejects_a_wrapped_key_from_another_ciphertext() {
        let server = MockServer::start().await;
        let private_key = [43_u8; 32];
        let public_key =
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(private_key));
        let ciphertext_key = [19_u8; 32];
        let substituted_key = [23_u8; 32];
        let encrypted_blob = crypto::encrypt_vault_payload(
            &ciphertext_key,
            br#"{"environments":{"default":{"OLD":"value"}}}"#,
            crypto::VaultScope::Organization("acme"),
            TEST_ORGANIZATION_ID,
            "vault-maintainer",
            7,
        )
        .expect("encrypt current payload");
        let current_body = serde_json::json!({
            "encryptedBlob": encrypted_blob,
            "wrappedKey": crypto::wrap_key_for_recipient(
                &substituted_key,
                public_key.as_bytes(),
            )
            .expect("wrap substituted content key"),
            "version": 7,
            "cryptoVersion": crypto::CURRENT_CRYPTO_VERSION,
            "contentKeyVersion": 3,
            "recipientPublicKeyVersion": 4,
            "recipientPublicKeyFingerprint": public_key_fingerprint(public_key.as_bytes()),
        });

        Mock::given(method("GET"))
            .and(path("/api/orgs/acme/members/public-keys"))
            .respond_with(signed_member_inventory(
                "user-maintainer",
                false,
                serde_json::json!([{
                    "userId": "user-maintainer",
                    "role": "maintainer",
                    "sharingKey": null,
                }]),
            ))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/orgs/acme/vaults/vault-maintainer"))
            .respond_with(signed_sync_ok_response_with(
                current_body,
                "auth-token",
                "vault-maintainer",
                TestSyncScope::Organization("acme".into()),
                set_maintainer_caller_user,
            ))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/orgs/acme/vaults/vault-maintainer"))
            .respond_with(signed_sync_ok_response(
                serde_json::json!({
                    "version": 8,
                    "contentKeyVersion": 3,
                    "cryptoVersion": crypto::CURRENT_CRYPTO_VERSION,
                    "status": "synced",
                }),
                "auth-token",
                "vault-maintainer",
                TestSyncScope::Organization("acme".into()),
            ))
            .expect(0)
            .mount(&server)
            .await;

        let error = push_org(
            &server.uri(),
            "auth-token",
            OrgPushRequest {
                org_slug: "acme",
                vault_id: "vault-maintainer",
                secrets_json: r#"{"environments":{"default":{"NEW":"value"}}}"#,
                expected_version: Some(7),
                recreate_missing: false,
                metadata: None,
                recipient_set_acceptance: None,
            },
            &private_key,
        )
        .await
        .expect_err("a substituted content key must fail before upload");

        assert!(error.to_string().contains("decryption failed"), "{error}");
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn recreated_org_vault_retries_from_the_retained_server_floor() {
        #[derive(Clone)]
        struct ConflictThenSuccess {
            attempts: Arc<std::sync::atomic::AtomicUsize>,
            bodies: Arc<StdMutex<Vec<serde_json::Value>>>,
            conflict: SignedEnvelopeResponse,
            success: SignedSyncResponse,
        }

        impl Respond for ConflictThenSuccess {
            fn respond(&self, request: &Request) -> ResponseTemplate {
                self.bodies.lock().unwrap().push(
                    serde_json::from_slice(&request.body).expect("org push body must be JSON"),
                );
                let attempt = self
                    .attempts
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if attempt == 0 {
                    return self.conflict.respond(request);
                }
                self.success.respond(request)
            }
        }

        let _guard = env_lock_guard();
        let _isolated = IsolatedVaultKeyEnv::new();
        let server = MockServer::start().await;
        let (_, member_public_key) = crypto::generate_x25519_keypair();
        let recipient = registered_member("user-admin", "admin", member_public_key, 1);
        let prepared = prepare_recipients(&[&recipient]).expect("prepare recipient");
        let acceptance = acceptance_digest(&server.uri(), TEST_ORGANIZATION_ID, "acme", &prepared)
            .expect("compute recipient acceptance");
        let bodies = Arc::new(StdMutex::new(Vec::new()));
        Mock::given(method("POST"))
            .and(path("/api/orgs/acme/vaults/vault-recreate"))
            .and(header("authorization", "Bearer auth-token"))
            .respond_with(ConflictThenSuccess {
                attempts: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                bodies: Arc::clone(&bodies),
                conflict: signed_envelope_response(
                    409,
                    "vault.write",
                    "revisionConflict",
                    organization_binding("vault-recreate", "user-admin"),
                    serde_json::json!({ "currentRevision": 7 }),
                ),
                success: signed_sync_ok_response(
                    serde_json::json!({
                        "version": 8,
                        "cryptoVersion": crypto::CURRENT_CRYPTO_VERSION,
                        "contentKeyVersion": 1,
                        "status": "synced",
                    }),
                    "auth-token",
                    "vault-recreate",
                    TestSyncScope::Organization("acme".into()),
                ),
            })
            .expect(2)
            .mount(&server)
            .await;
        let access = super::super::public_key::OrgMemberKeyAccess {
            organization_id: TEST_ORGANIZATION_ID.to_owned(),
            caller_user_id: "user-admin".to_owned(),
            members: vec![recipient],
            can_replace_wrapped_keys: true,
        };

        let result = push_org_with_access(
            &server.uri(),
            "auth-token",
            OrgPushRequest {
                org_slug: "acme",
                vault_id: "vault-recreate",
                secrets_json: r#"{"environments":{"default":{"TOKEN":"secret"}}}"#,
                expected_version: Some(5),
                recreate_missing: true,
                metadata: None,
                recipient_set_acceptance: Some(&acceptance),
            },
            &[41_u8; 32],
            &access,
        )
        .await
        .expect("recreation must retry from the retained server floor");

        assert_eq!(result.version, Some(8));
        let bodies = bodies.lock().unwrap();
        assert_eq!(bodies.len(), 2);
        assert_eq!(bodies[0]["expectedVersion"], 5);
        assert_eq!(bodies[0]["ciphertextRevision"], 6);
        assert_eq!(bodies[1]["expectedVersion"], 7);
        assert_eq!(bodies[1]["ciphertextRevision"], 8);
        assert_ne!(bodies[0]["encryptedBlob"], bodies[1]["encryptedBlob"]);
        assert_eq!(bodies[0]["wrappedKeys"], bodies[1]["wrappedKeys"]);
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn push_org_preserves_wrapped_keys_when_caller_cannot_replace_them() {
        #[derive(Clone)]
        struct CapturePushResponder {
            body: Arc<StdMutex<Option<String>>>,
            response: SignedSyncResponse,
        }

        impl Respond for CapturePushResponder {
            fn respond(&self, request: &Request) -> ResponseTemplate {
                let body = String::from_utf8(request.body.clone())
                    .expect("organization update body should be valid JSON");
                *self.body.lock().unwrap() = Some(body);
                self.response.respond(request)
            }
        }

        let server = MockServer::start().await;
        let captured_body = Arc::new(StdMutex::new(None));
        let private_key = [41u8; 32];
        let public_key =
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(private_key));
        let content_key = [17u8; 32];
        let encrypted_blob = crypto::encrypt_vault_payload(
            &content_key,
            br#"{"environments":{"default":{"OLD":"value"}}}"#,
            crypto::VaultScope::Organization("acme"),
            TEST_ORGANIZATION_ID,
            "vault-maintainer",
            7,
        )
        .expect("encrypt current payload");
        let current_body = serde_json::json!({
            "encryptedBlob": encrypted_blob,
            "wrappedKey": crypto::wrap_key_for_recipient(&content_key, public_key.as_bytes())
                .expect("wrap current content key"),
            "version": 7,
            "cryptoVersion": crypto::CURRENT_CRYPTO_VERSION,
            "contentKeyVersion": 3,
            "recipientPublicKeyVersion": 4,
            "recipientPublicKeyFingerprint": public_key_fingerprint(public_key.as_bytes()),
        });

        Mock::given(method("GET"))
            .and(path("/api/orgs/acme/members/public-keys"))
            .respond_with(signed_member_inventory(
                "user-maintainer",
                false,
                serde_json::json!([{
                    "userId": "user-maintainer",
                    "role": "maintainer",
                    "sharingKey": null,
                }]),
            ))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/orgs/acme/vaults/vault-maintainer"))
            .respond_with(signed_sync_ok_response_with(
                current_body,
                "auth-token",
                "vault-maintainer",
                TestSyncScope::Organization("acme".into()),
                set_maintainer_caller_user,
            ))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/orgs/acme/vaults/vault-maintainer"))
            .respond_with(CapturePushResponder {
                body: Arc::clone(&captured_body),
                response: signed_sync_ok_response(
                    serde_json::json!({
                        "version": 8,
                        "contentKeyVersion": 3,
                        "cryptoVersion": crypto::CURRENT_CRYPTO_VERSION,
                        "status": "synced",
                    }),
                    "auth-token",
                    "vault-maintainer",
                    TestSyncScope::Organization("acme".into()),
                ),
            })
            .expect(1)
            .mount(&server)
            .await;

        let result = push_org(
            &server.uri(),
            "auth-token",
            OrgPushRequest {
                org_slug: "acme",
                vault_id: "vault-maintainer",
                secrets_json: r#"{"environments":{"default":{"NEW":"value"}}}"#,
                expected_version: Some(7),
                recreate_missing: false,
                metadata: None,
                recipient_set_acceptance: None,
            },
            &private_key,
        )
        .await
        .expect("maintainer update should preserve the current content key");

        assert_eq!(result.version, Some(8));
        let raw = captured_body
            .lock()
            .unwrap()
            .clone()
            .expect("capture organization update");
        let parsed: serde_json::Value = serde_json::from_str(&raw).expect("parse update body");
        assert!(parsed.get("wrappedKeys").is_none());
        assert_eq!(
            parsed.get("expectedOrganizationId"),
            Some(&serde_json::json!(TEST_ORGANIZATION_ID))
        );
        assert_eq!(
            parsed.get("expectedCallerUserId"),
            Some(&serde_json::json!("user-maintainer"))
        );
        assert_eq!(parsed.get("expectedVersion"), Some(&serde_json::json!(7)));
        assert_eq!(
            parsed.get("ciphertextRevision"),
            Some(&serde_json::json!(8))
        );
        assert_eq!(
            parsed.get("cryptoVersion"),
            Some(&serde_json::json!(crypto::CURRENT_CRYPTO_VERSION))
        );
        let encrypted_blob = parsed["encryptedBlob"].as_str().expect("encrypted blob");
        let decrypted = crypto::decrypt_vault_payload(
            &content_key,
            encrypted_blob,
            crypto::VaultScope::Organization("acme"),
            TEST_ORGANIZATION_ID,
            "vault-maintainer",
            8,
            crypto::CURRENT_CRYPTO_VERSION,
        )
        .expect("decrypt update");
        assert_eq!(
            decrypted,
            br#"{"environments":{"default":{"NEW":"value"}}}"#
        );
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn maintainer_push_rejects_a_changed_organization_before_posting() {
        let server = MockServer::start().await;
        let private_key = [43u8; 32];
        let public_key =
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(private_key));
        let content_key = [19u8; 32];

        Mock::given(method("GET"))
            .and(path("/api/orgs/acme/vaults/vault-maintainer"))
            .respond_with(signed_sync_ok_response_with(
                serde_json::json!({
                    "encryptedBlob": crypto::encrypt_vault_payload(
                        &content_key,
                        br#"{"environments":{"default":{"OLD":"value"}}}"#,
                        crypto::VaultScope::Organization("acme"),
                        TEST_ORGANIZATION_ID,
                        "vault-maintainer",
                        7,
                    )
                    .expect("encrypt current payload"),
                    "wrappedKey": crypto::wrap_key_for_recipient(
                        &content_key,
                        public_key.as_bytes(),
                    )
                    .expect("wrap current content key"),
                    "version": 7,
                    "cryptoVersion": crypto::CURRENT_CRYPTO_VERSION,
                    "contentKeyVersion": 3,
                    "recipientPublicKeyVersion": 4,
                    "recipientPublicKeyFingerprint": public_key_fingerprint(public_key.as_bytes()),
                }),
                "auth-token",
                "vault-maintainer",
                TestSyncScope::Organization("acme".into()),
                substitute_organization_principal,
            ))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/orgs/acme/vaults/vault-maintainer"))
            .respond_with(signed_sync_ok_response(
                serde_json::json!({
                    "version": 8,
                    "contentKeyVersion": 3,
                    "cryptoVersion": crypto::CURRENT_CRYPTO_VERSION,
                    "status": "synced",
                }),
                "auth-token",
                "vault-maintainer",
                TestSyncScope::Organization("acme".into()),
            ))
            .expect(0)
            .mount(&server)
            .await;

        let access = super::super::public_key::OrgMemberKeyAccess {
            organization_id: TEST_ORGANIZATION_ID.to_owned(),
            caller_user_id: "user-maintainer".to_owned(),
            members: Vec::new(),
            can_replace_wrapped_keys: false,
        };
        let error = push_org_with_access(
            &server.uri(),
            "auth-token",
            OrgPushRequest {
                org_slug: "acme",
                vault_id: "vault-maintainer",
                secrets_json: r#"{"environments":{"default":{"NEW":"value"}}}"#,
                expected_version: Some(7),
                recreate_missing: false,
                metadata: None,
                recipient_set_acceptance: None,
            },
            &private_key,
            &access,
        )
        .await
        .expect_err("a reused slug must not redirect a maintainer write");

        assert!(error.to_string().contains("different organization"));
    }

    #[cfg(debug_assertions)]
    #[test]
    fn push_org_with_keys_round_trips_name_and_schema_metadata() {
        // Org pushes used to omit `name` + `schema` from the request body, so
        // the dashboard for an org vault froze whatever schema was set at
        // creation time and never reflected later CLI pushes. This test pins
        // the contract: when the caller passes `PushMetadata`, both fields
        // land on the wire alongside the encrypted blob and wrapped keys.
        let _guard = env_lock_guard();
        let temp = tempfile::tempdir().expect("tempdir for metadata round-trip test");
        let original_home = crate::test_env_lock::HomeEnvSnapshot::set(temp.path());
        let original_force_file_vault = std::env::var_os("LPM_FORCE_FILE_VAULT");

        unsafe {
            std::env::set_var("LPM_FORCE_FILE_VAULT", "1");
        }

        let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
        runtime.block_on(async {
            #[derive(Clone)]
            struct CapturePushResponder {
                body: Arc<StdMutex<Option<String>>>,
                response: SignedSyncResponse,
            }

            impl Respond for CapturePushResponder {
                fn respond(&self, request: &Request) -> ResponseTemplate {
                    let body = String::from_utf8(request.body.clone())
                        .expect("push request body must be valid utf-8");
                    *self.body.lock().unwrap() = Some(body);
                    self.response.respond(request)
                }
            }

            let server = MockServer::start().await;
            let captured_body = Arc::new(StdMutex::new(None));
            let (_, member_public_key) = crypto::generate_x25519_keypair();
            let recipient = registered_member("user-1", "admin", member_public_key, 1);
            let prepared = prepare_recipients(&[&recipient]).expect("prepare recipient");
            let acceptance =
                acceptance_digest(&server.uri(), TEST_ORGANIZATION_ID, "acme", &prepared)
                    .expect("compute recipient acceptance");

            Mock::given(method("GET"))
                .and(path("/api/orgs/acme/members/public-keys"))
                .respond_with(signed_member_inventory(
                    "user-1",
                    true,
                    serde_json::json!([{
                        "userId": "user-1",
                        "role": "admin",
                        "sharingKey": {
                            "algorithm": "X25519",
                            "publicKey": BASE64.encode(member_public_key),
                            "version": 1,
                            "fingerprint": public_key_fingerprint(&member_public_key),
                        }
                    }]),
                ))
                .expect(1)
                .mount(&server)
                .await;

            Mock::given(method("POST"))
                .and(path("/api/orgs/acme/vaults/vault-meta"))
                .respond_with(CapturePushResponder {
                    body: Arc::clone(&captured_body),
                    response: signed_sync_ok_response(
                        serde_json::json!({
                            "version": 4,
                            "cryptoVersion": crypto::CURRENT_CRYPTO_VERSION,
                            "contentKeyVersion": 1,
                            "status": "synced",
                        }),
                        "auth-token",
                        "vault-meta",
                        TestSyncScope::Organization("acme".into()),
                    ),
                })
                .expect(1)
                .mount(&server)
                .await;

            let schema = serde_json::json!({
                "version": 2,
                "envSchema": {
                    "DATABASE_URL": { "required": true, "format": "url" }
                }
            });
            let metadata = PushMetadata {
                name: Some("acme-api"),
                schema: Some(&schema),
            };

            let result = push_org_with_keys(
                &server.uri(),
                "auth-token",
                OrgPushRequest {
                    org_slug: "acme",
                    vault_id: "vault-meta",
                    secrets_json: r#"{"DATABASE_URL":"postgres://"}"#,
                    expected_version: Some(3),
                    recreate_missing: false,
                    metadata: Some(&metadata),
                    recipient_set_acceptance: Some(&acceptance),
                },
            )
            .await
            .expect("org push should succeed when metadata is supplied");

            assert_eq!(result.version, Some(4));

            let raw = captured_body
                .lock()
                .unwrap()
                .clone()
                .expect("captured push body");
            let parsed: serde_json::Value =
                serde_json::from_str(&raw).expect("push body must be valid JSON");

            assert_eq!(
                parsed.get("name"),
                Some(&serde_json::json!("acme-api")),
                "org push must round-trip the project name field"
            );
            assert_eq!(
                parsed
                    .get("schema")
                    .and_then(|s| s.get("envSchema"))
                    .and_then(|e| e.get("DATABASE_URL"))
                    .and_then(|d| d.get("required")),
                Some(&serde_json::json!(true)),
                "org push must round-trip the envSchema content alongside the encrypted blob"
            );
            assert!(
                parsed.get("encryptedBlob").is_some(),
                "encryptedBlob field must still be present alongside metadata"
            );
            assert!(
                parsed.get("wrappedKeys").is_some(),
                "wrappedKeys field must still be present alongside metadata"
            );
            assert_eq!(
                parsed.get("expectedVersion"),
                Some(&serde_json::json!(3)),
                "expectedVersion must still be present alongside metadata"
            );
            assert_eq!(
                parsed.get("ciphertextRevision"),
                Some(&serde_json::json!(4)),
                "ciphertextRevision must bind the next server version"
            );
        });

        original_home.restore();
        match original_force_file_vault {
            Some(value) => unsafe { std::env::set_var("LPM_FORCE_FILE_VAULT", value) },
            None => unsafe { std::env::remove_var("LPM_FORCE_FILE_VAULT") },
        }
    }

    #[cfg(debug_assertions)]
    #[test]
    fn push_org_with_keys_omits_metadata_fields_when_caller_passes_none() {
        // Symmetry with the round-trip test above: when no metadata is
        // supplied, the body must NOT contain `name` or `schema` fields.
        // This pins the "explicit None means don't touch dashboard
        // metadata" contract — server keeps last-known-good schema/name.
        let _guard = env_lock_guard();
        let temp = tempfile::tempdir().expect("tempdir for None-metadata test");
        let original_home = crate::test_env_lock::HomeEnvSnapshot::set(temp.path());
        let original_force_file_vault = std::env::var_os("LPM_FORCE_FILE_VAULT");

        unsafe {
            std::env::set_var("LPM_FORCE_FILE_VAULT", "1");
        }

        let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
        runtime.block_on(async {
            #[derive(Clone)]
            struct CapturePushResponder {
                body: Arc<StdMutex<Option<String>>>,
                response: SignedSyncResponse,
            }

            impl Respond for CapturePushResponder {
                fn respond(&self, request: &Request) -> ResponseTemplate {
                    let body = String::from_utf8(request.body.clone()).expect("push body utf-8");
                    *self.body.lock().unwrap() = Some(body);
                    self.response.respond(request)
                }
            }

            let server = MockServer::start().await;
            let captured_body = Arc::new(StdMutex::new(None));
            let (_, member_public_key) = crypto::generate_x25519_keypair();
            let recipient = registered_member("user-1", "admin", member_public_key, 1);
            let prepared = prepare_recipients(&[&recipient]).expect("prepare recipient");
            let acceptance =
                acceptance_digest(&server.uri(), TEST_ORGANIZATION_ID, "acme", &prepared)
                    .expect("compute recipient acceptance");

            Mock::given(method("GET"))
                .and(path("/api/orgs/acme/members/public-keys"))
                .respond_with(signed_member_inventory(
                    "user-1",
                    true,
                    serde_json::json!([{
                        "userId": "user-1",
                        "role": "admin",
                        "sharingKey": {
                            "algorithm": "X25519",
                            "publicKey": BASE64.encode(member_public_key),
                            "version": 1,
                            "fingerprint": public_key_fingerprint(&member_public_key),
                        }
                    }]),
                ))
                .mount(&server)
                .await;

            Mock::given(method("POST"))
                .and(path("/api/orgs/acme/vaults/vault-no-meta"))
                .respond_with(CapturePushResponder {
                    body: Arc::clone(&captured_body),
                    response: signed_sync_ok_response(
                        serde_json::json!({
                            "version": 1,
                            "cryptoVersion": crypto::CURRENT_CRYPTO_VERSION,
                            "contentKeyVersion": 1,
                            "status": "synced",
                        }),
                        "auth-token",
                        "vault-no-meta",
                        TestSyncScope::Organization("acme".into()),
                    ),
                })
                .expect(1)
                .mount(&server)
                .await;

            push_org_with_keys(
                &server.uri(),
                "auth-token",
                OrgPushRequest {
                    org_slug: "acme",
                    vault_id: "vault-no-meta",
                    secrets_json: r#"{"K":"V"}"#,
                    expected_version: None,
                    recreate_missing: false,
                    metadata: None,
                    recipient_set_acceptance: Some(&acceptance),
                },
            )
            .await
            .expect("org push should succeed without metadata");

            let raw = captured_body
                .lock()
                .unwrap()
                .clone()
                .expect("captured body");
            let parsed: serde_json::Value =
                serde_json::from_str(&raw).expect("body must parse as JSON");

            assert!(
                parsed.get("name").is_none(),
                "name must not be sent when metadata is None"
            );
            assert!(
                parsed.get("schema").is_none(),
                "schema must not be sent when metadata is None"
            );
            assert_eq!(
                parsed.get("ciphertextRevision"),
                Some(&serde_json::json!(1))
            );
        });

        original_home.restore();
        match original_force_file_vault {
            Some(value) => unsafe { std::env::set_var("LPM_FORCE_FILE_VAULT", value) },
            None => unsafe { std::env::remove_var("LPM_FORCE_FILE_VAULT") },
        }
    }

    #[test]
    fn wrap_keys_for_members_rejects_malformed_public_key_length() {
        let short_key = BASE64.encode([9u8; 31]);
        let result = super::super::public_key::ValidatedSharingKey::from_authenticated(
            short_key,
            1,
            "a".repeat(64),
        );

        assert!(matches!(
            result,
            Err(message) if message == "authenticated response has an invalid sharing public key"
        ));
    }

    #[test]
    fn recipient_selection_rejects_more_than_ten_thousand_members() {
        let members = (0..=10_000)
            .map(|index| MemberPublicKey::without_test_key(format!("member-{index}"), "member"))
            .collect::<Vec<_>>();

        let error = prepare_authenticated_recipients(&members).unwrap_err();

        assert!(error.contains("10,000-member limit"));
    }

    #[test]
    fn wrap_keys_for_members_wraps_each_valid_member_key() {
        let aes_key = crypto::generate_aes_key();
        let (_, public_a) = crypto::generate_x25519_keypair();
        let (_, public_b) = crypto::generate_x25519_keypair();
        let member_a = registered_member("user-a", "admin", public_a, 3);
        let member_b = registered_member("user-b", "developer", public_b, 5);

        let recipients = super::super::recipient_set::prepare_recipients(&[&member_a, &member_b])
            .expect("valid recipients should prepare successfully");
        let result = wrap_keys_for_members(&aes_key, &recipients)
            .expect("valid member keys should wrap successfully");

        assert_eq!(result.len(), 2);
        assert_eq!(result[0].user_id, "user-a");
        assert_eq!(
            result[0].user_id.as_ptr(),
            recipients[0].binding.user_id.as_ptr()
        );
        assert!(!result[0].wrapped_key.is_empty());
        assert_eq!(result[0].public_key_version, 3);
        assert_eq!(
            result[0].public_key_fingerprint,
            public_key_fingerprint(&public_a)
        );
        assert_eq!(
            result[0].public_key_fingerprint.as_ptr(),
            recipients[0].binding.public_key_fingerprint.as_ptr()
        );
        assert_eq!(result[1].user_id, "user-b");
        assert!(!result[1].wrapped_key.is_empty());
        assert_eq!(result[1].public_key_version, 5);
        assert_eq!(
            result[1].public_key_fingerprint,
            public_key_fingerprint(&public_b)
        );
    }

    #[cfg(debug_assertions)]
    #[test]
    fn authenticated_sharing_keys_are_validated_once_through_trust_and_wrapping() {
        let _guard = env_lock_guard();
        let _isolated = IsolatedVaultKeyEnv::new();
        super::super::public_key::reset_validated_sharing_key_count();
        let aes_key = crypto::generate_aes_key();
        let (_, public_a) = crypto::generate_x25519_keypair();
        let (_, public_b) = crypto::generate_x25519_keypair();
        let members = [
            registered_member("user-a", "admin", public_a, 3),
            registered_member("user-b", "developer", public_b, 5),
        ];

        let recipients =
            prepare_authenticated_recipients(&members).expect("prepare authenticated recipients");
        let registry_url = "https://registry.example";
        let acceptance = acceptance_digest(registry_url, TEST_ORGANIZATION_ID, "acme", &recipients)
            .expect("compute recipient acceptance");
        enforce_recipient_trust(
            registry_url,
            TEST_ORGANIZATION_ID,
            "acme",
            &recipients,
            Some(&acceptance),
        )
        .expect("persist authenticated recipient trust");
        wrap_keys_for_members(&aes_key, &recipients).expect("wrap for authenticated recipients");

        assert_eq!(
            super::super::public_key::validated_sharing_key_count(),
            members.len()
        );
    }

    #[test]
    fn authenticated_recipient_preparation_skips_members_without_registered_keys() {
        let aes_key = crypto::generate_aes_key();
        let (_, public_key) = crypto::generate_x25519_keypair();
        let member_with_key = registered_member("user-keyed", "admin", public_key, 1);
        let member_without_key = MemberPublicKey::without_test_key("user-missing", "developer");

        let members = [member_with_key, member_without_key];
        let recipients = prepare_authenticated_recipients(&members)
            .expect("authenticated inventory should prepare directly");
        let wrapped = wrap_keys_for_members(&aes_key, &recipients)
            .expect("only the keyed member should receive a wrapped AES key");

        assert_eq!(wrapped.len(), 1);
        assert_eq!(wrapped[0].user_id, "user-keyed");
        assert!(!wrapped[0].wrapped_key.is_empty());
    }

    #[test]
    fn authenticated_recipient_preparation_reserves_only_for_registered_keys() {
        let (_, public_key) = crypto::generate_x25519_keypair();
        let mut members = (0..9_999)
            .map(|index| {
                MemberPublicKey::without_test_key(format!("member-{index:05}"), "developer")
            })
            .collect::<Vec<_>>();
        members.push(registered_member("member-09999", "admin", public_key, 1));

        let recipients = prepare_authenticated_recipients(&members)
            .expect("sparse authenticated inventory should prepare");

        assert_eq!(recipients.len(), 1);
        assert_eq!(recipients.capacity(), 1);
    }

    #[test]
    fn validated_sharing_key_rejects_a_nonpositive_version() {
        let public_key = crate::crypto::x25519_public_from_private(&[7u8; 32]);
        let error = super::super::public_key::ValidatedSharingKey::from_authenticated(
            BASE64.encode(public_key),
            0,
            public_key_fingerprint(&public_key),
        )
        .expect_err("a nonpositive key version must fail closed");

        assert!(error.contains("positive integer"));
    }

    #[test]
    fn wrap_keys_for_members_drops_stale_recipients_when_member_set_changes_between_shares() {
        let aes_key = crypto::generate_aes_key();
        let (_, public_a) = crypto::generate_x25519_keypair();
        let (_, public_b) = crypto::generate_x25519_keypair();
        let (_, public_c) = crypto::generate_x25519_keypair();
        let member_a = registered_member("user-a", "admin", public_a, 1);
        let member_b = registered_member("user-b", "developer", public_b, 1);
        let member_c = registered_member("user-c", "developer", public_c, 1);

        let first_recipients = prepare_recipients(&[&member_a, &member_b])
            .expect("first recipient set should validate");
        let second_recipients = prepare_recipients(&[&member_b, &member_c])
            .expect("second recipient set should validate");
        let first_share = wrap_keys_for_members(&aes_key, &first_recipients)
            .expect("first share should wrap current member set");
        let second_share = wrap_keys_for_members(&aes_key, &second_recipients)
            .expect("second share should wrap updated member set");

        let first_ids: std::collections::BTreeSet<_> =
            first_share.iter().map(|wrapped| wrapped.user_id).collect();
        let second_ids: std::collections::BTreeSet<_> =
            second_share.iter().map(|wrapped| wrapped.user_id).collect();

        assert_eq!(
            first_ids,
            std::collections::BTreeSet::from(["user-a", "user-b"])
        );
        assert_eq!(
            second_ids,
            std::collections::BTreeSet::from(["user-b", "user-c"])
        );
        assert!(
            !second_ids.contains("user-a"),
            "stale recipients from prior shares must not remain in a new wrapped-key set"
        );
    }
}
