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
    public_key_fingerprint, resolve_local_public_key_state_for_fingerprint,
};
#[cfg(all(test, debug_assertions))]
use super::recipient_set::acceptance_digest;
use super::recipient_set::{PreparedRecipient, enforce_recipient_trust, prepare_recipients};
use crate::crypto;

const MAX_ORG_VAULT_SHARE_MEMBERS: usize = 10_000;

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

struct DecryptedOrgVault {
    pulled: PulledOrgVault,
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
        auth_token,
        vault_id,
        SyncScope::Organization(org_slug),
        SyncEnvelopePolicy::CurrentOnly,
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
        SyncHttpResponse::Error { status, body } => {
            let parsed = serde_json::from_slice::<OrgPullError>(&body).ok();
            if status == reqwest::StatusCode::NOT_FOUND
                && parsed.as_ref().and_then(|error| error.error.as_deref())
                    == Some("Vault not found")
            {
                return Ok(None);
            }
            let message = parsed
                .and_then(|error| error.error)
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
    Ok(pull_org_with_content_key(
        client,
        registry_url,
        auth_token,
        org_slug,
        vault_id,
        Some(private_key),
        expected_principal_id,
    )
    .await?
    .pulled)
}

pub async fn pull_org_with_scoped_key_bound_to_principal(
    registry_url: &str,
    auth_token: &str,
    org_slug: &str,
    vault_id: &str,
    expected_principal_id: Option<&str>,
) -> Result<PulledOrgVault, SyncError> {
    let client = sync_http_client()?;
    Ok(pull_org_with_content_key(
        client,
        registry_url,
        auth_token,
        org_slug,
        vault_id,
        None,
        expected_principal_id,
    )
    .await?
    .pulled)
}

async fn pull_org_with_content_key(
    client: &reqwest::Client,
    registry_url: &str,
    auth_token: &str,
    org_slug: &str,
    vault_id: &str,
    private_key: Option<&[u8; 32]>,
    expected_principal_id: Option<&str>,
) -> Result<DecryptedOrgVault, SyncError> {
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
        auth_token,
        vault_id,
        SyncScope::Organization(org_slug),
        SyncEnvelopePolicy::Pull,
    )
    .await?
    {
        SyncHttpResponse::Success(data) => data,
        SyncHttpResponse::Error { status, body } => {
            let message = std::str::from_utf8(&body).unwrap_or("");
            let parsed = serde_json::from_slice::<OrgPullError>(&body).ok();
            let code = parsed.as_ref().and_then(|error| error.code.clone());
            let rewrap_identity = parsed.as_ref().and_then(|error| {
                let organization_id = error.organization_id.as_deref()?;
                let caller_user_id = error.caller_user_id.as_deref()?;
                if error.code.as_deref() == Some("vault_member_needs_rewrap")
                    && super::public_key::is_canonical_organization_id(organization_id)
                    && !caller_user_id.is_empty()
                    && caller_user_id.len() <= 256
                    && !caller_user_id.chars().any(char::is_control)
                {
                    Some((organization_id.to_owned(), caller_user_id.to_owned()))
                } else {
                    None
                }
            });
            let (organization_id, caller_user_id) = rewrap_identity.unzip();
            return Err(SyncError::http_with_rewrap_identity(
                status,
                code,
                organization_id,
                caller_user_id,
                format!("server error: {message}"),
            ));
        }
    };

    let principal_id = data
        .principal_id
        .as_deref()
        .ok_or("organization env response omitted the principal ID")?;
    if expected_principal_id.is_some_and(|expected| expected != principal_id) {
        return Err(
			"this env checkout is bound to a different organization; use a separate checkout when switching organizations"
				.into(),
		);
    }
    let encrypted_blob = data
        .encrypted_blob
        .as_deref()
        .ok_or("organization env response omitted encrypted data")?;
    let wrapped_key = data
        .wrapped_key
        .as_deref()
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
        .as_deref()
        .ok_or("organization env response omitted the recipient key fingerprint")?;
    let caller_user_id = data
        .caller_user_id
        .as_deref()
        .ok_or("organization env response omitted the authenticated caller ID")?;
    let scoped_local_key = if private_key.is_none() {
        let scope = SharingKeyScope::new(registry_url, caller_user_id)?;
        Some(resolve_local_public_key_state_for_fingerprint(
            &scope,
            recipient_public_key_fingerprint,
        )?)
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
    let content_key = crypto::unwrap_key_from_sender(wrapped_key, private_key)?;
    let plaintext = crypto::decrypt_vault_payload(
        &content_key,
        encrypted_blob,
        crypto::VaultScope::Organization(org_slug),
        principal_id,
        vault_id,
        version,
        crypto_version,
    )?;
    let json = String::from_utf8(plaintext).map_err(|e| format!("utf8 error: {e}"))?;

    Ok(DecryptedOrgVault {
        pulled: PulledOrgVault {
            raw_json: json,
            version,
            content_key_version,
            principal_id: principal_id.to_owned(),
            caller_user_id: caller_user_id.to_owned(),
        },
        content_key,
    })
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct OrgPullError {
    error: Option<String>,
    code: Option<String>,
    organization_id: Option<String>,
    caller_user_id: Option<String>,
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
    let current = pull_org_with_content_key(
        client,
        registry_url,
        auth_token,
        request.org_slug,
        request.vault_id,
        Some(private_key),
        Some(&access.organization_id),
    )
    .await?;
    if current.pulled.principal_id != access.organization_id {
        return Err("organization principal changed during env update; fetch current organization access and retry".into());
    }
    if current.pulled.caller_user_id != access.caller_user_id {
        return Err("authenticated caller changed during env update; fetch current organization access and retry".into());
    }
    if current.pulled.version != expected_version {
        return Err(format!(
            "organization env version changed from {expected_version} to {}; pull and retry",
            current.pulled.version
        )
        .into());
    }
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
    let members_with_keys = select_members_with_keys(members)?;
    let recipients = prepare_recipients(&members_with_keys)?;
    enforce_recipient_trust(
        registry_url,
        organization_id,
        request.org_slug,
        &recipients,
        request.recipient_set_acceptance,
    )?;
    let target_revision = crypto::next_sync_revision(request.expected_version)?;

    let aes_key = crypto::generate_aes_key();
    let encrypted_blob = crypto::encrypt_vault_payload(
        &aes_key,
        request.secrets_json.as_bytes(),
        crypto::VaultScope::Organization(request.org_slug),
        organization_id,
        request.vault_id,
        target_revision,
    )?;

    let wrapped_keys = wrap_keys_for_members(&aes_key, &recipients)?;

    post_org_update(
        client,
        registry_url,
        auth_token,
        PreparedOrgUpdate {
            request,
            organization_id,
            caller_user_id,
            encrypted_blob,
            wrapped_keys: Some(wrapped_keys),
        },
    )
    .await
}

struct PreparedOrgUpdate<'request, 'identity, 'recipient> {
    request: OrgPushRequest<'request>,
    organization_id: &'identity str,
    caller_user_id: &'identity str,
    encrypted_blob: String,
    wrapped_keys: Option<Vec<WrappedMemberKey<'recipient>>>,
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
        wrapped_keys: wrapped_keys.as_deref(),
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
        auth_token,
        request.vault_id,
        SyncScope::Organization(request.org_slug),
        SyncEnvelopePolicy::CurrentOnly,
    )
    .await?
    {
        SyncHttpResponse::Success(result) => result,
        SyncHttpResponse::Error { status, body } => {
            let message = serde_json::from_slice::<PushResponse>(&body).map_or_else(
                |_| format!("server error: {status}"),
                |result| format_push_error(&result, status),
            );
            return Err(SyncError::http(status, message));
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

fn select_members_with_keys(members: &[MemberPublicKey]) -> Result<Vec<&MemberPublicKey>, String> {
    if members.len() > MAX_ORG_VAULT_SHARE_MEMBERS {
        return Err("organization vault sharing exceeds the 10,000-member limit".to_owned());
    }

    let mut members_with_keys = Vec::with_capacity(members.len());
    for member in members {
        if !member.has_public_key {
            if member.public_key.is_some()
                || member.public_key_version.is_some()
                || member.public_key_fingerprint.is_some()
            {
                return Err(format!(
                    "inconsistent public-key state for organization member {}",
                    member.user_id
                ));
            }
            continue;
        }
        if member.public_key.is_none()
            || member.public_key_version.is_none()
            || member.public_key_fingerprint.is_none()
        {
            return Err(format!(
                "organization member {} has an incomplete public-key binding",
                member.user_id
            ));
        }
        members_with_keys.push(member);
    }

    if members_with_keys.is_empty() {
        return Err("no org members have registered public keys. Each member needs to run `lpm env share --org <slug>` once to generate their keypair.".into());
    }

    Ok(members_with_keys)
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
        IsolatedVaultKeyEnv, SignedSyncResponse, TestSyncScope, env_lock_guard,
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
        body["organizationSlug"] = "other-org".into();
    }

    #[cfg(debug_assertions)]
    fn substitute_organization_principal(body: &mut serde_json::Value) {
        body["principalId"] = "00000000-0000-4000-8000-000000000002".into();
    }

    #[cfg(debug_assertions)]
    fn substitute_caller_user(body: &mut serde_json::Value) {
        body["callerUserId"] = "other-caller".into();
    }

    #[cfg(debug_assertions)]
    fn set_maintainer_caller_user(body: &mut serde_json::Value) {
        body["callerUserId"] = "user-maintainer".into();
    }

    #[cfg(debug_assertions)]
    fn remove_caller_user(body: &mut serde_json::Value) {
        body.as_object_mut()
            .expect("signed response must be an object")
            .remove("callerUserId");
    }

    #[cfg(debug_assertions)]
    fn invalidate_caller_user(body: &mut serde_json::Value) {
        body["callerUserId"] = "caller\nsubstitution".into();
    }

    fn registered_member(
        user_id: &str,
        role: &str,
        public_key: [u8; 32],
        public_key_version: i32,
    ) -> MemberPublicKey {
        MemberPublicKey {
            user_id: user_id.into(),
            role: role.into(),
            public_key: Some(BASE64.encode(public_key)),
            public_key_version: Some(public_key_version),
            public_key_fingerprint: Some(public_key_fingerprint(&public_key)),
            has_public_key: true,
        }
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
                    "recipientPublicKeyFingerprint": "not-the-local-key",
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
        let local = crate::sync::public_key::resolve_local_public_key_state(&scope, None)
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
        let local = crate::sync::public_key::resolve_local_public_key_state(&scope, None)
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

            assert!(error.to_string().contains("caller identity"), "{error}");
        }
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn pull_org_preserves_the_exact_member_rewrap_error_code() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/orgs/acme/vaults/vault-rewrap"))
            .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
                "error": "Member needs rewrap",
                "code": "vault_member_needs_rewrap",
                "organizationId": "00000000-0000-4000-8000-000000000001",
                "callerUserId": "11111111-1111-4111-8111-111111111111",
            })))
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
            .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
                "error": "Member needs rewrap",
                "code": "vault_member_needs_rewrap",
            })))
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

        assert!(error.has_http_code(403, "vault_member_needs_rewrap"));
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
            "organization env response contains an invalid key/version binding"
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

        let server = MockServer::start().await;
        let captured_body = Arc::new(StdMutex::new(None));
        let (_, member_public_key) = crypto::generate_x25519_keypair();
        let member_fingerprint = format!("{:x}", Sha256::digest(member_public_key));

        Mock::given(method("GET"))
            .and(path("/api/orgs/acme/members/public-keys"))
            .and(header("authorization", "Bearer auth-token"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("X-LPM-Organization-ID", TEST_ORGANIZATION_ID)
                    .insert_header("X-LPM-Caller-User-ID", "user-keyed")
                    .set_body_json(serde_json::json!([
                        {
                            "userId": "user-keyed",
                            "role": "admin",
                            "publicKey": BASE64.encode(member_public_key),
                            "publicKeyVersion": 7,
                            "publicKeyFingerprint": member_fingerprint,
                            "hasPublicKey": true
                        },
                        {
                            "userId": "user-missing",
                            "role": "developer",
                            "publicKey": null,
                            "hasPublicKey": false
                        }
                    ])),
            )
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
        let current_body = serde_json::json!({
            "encryptedBlob": crypto::encrypt_vault_payload(
                &content_key,
                br#"{"environments":{"default":{"OLD":"value"}}}"#,
                crypto::VaultScope::Organization("acme"),
                TEST_ORGANIZATION_ID,
                "vault-maintainer",
                7,
            )
                .expect("encrypt current payload"),
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
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("X-LPM-Organization-ID", TEST_ORGANIZATION_ID)
                    .insert_header("X-LPM-Caller-User-ID", "user-maintainer")
                    .insert_header("X-LPM-Org-Wrapped-Keys-Write", "forbidden")
                    .set_body_json(serde_json::json!([])),
            )
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
                .respond_with(
                    ResponseTemplate::new(200)
                        .insert_header("X-LPM-Organization-ID", TEST_ORGANIZATION_ID)
                        .insert_header("X-LPM-Caller-User-ID", "user-1")
                        .set_body_json(serde_json::json!([
                            {
                                "userId": "user-1",
                                "role": "admin",
                                "publicKey": BASE64.encode(member_public_key),
                                "publicKeyVersion": 1,
                                "publicKeyFingerprint": public_key_fingerprint(&member_public_key),
                                "hasPublicKey": true
                            }
                        ])),
                )
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
                .respond_with(
                    ResponseTemplate::new(200)
                        .insert_header("X-LPM-Organization-ID", TEST_ORGANIZATION_ID)
                        .insert_header("X-LPM-Caller-User-ID", "user-1")
                        .set_body_json(serde_json::json!([
                            {
                                "userId": "user-1",
                                "role": "admin",
                                "publicKey": BASE64.encode(member_public_key),
                                "publicKeyVersion": 1,
                                "publicKeyFingerprint": public_key_fingerprint(&member_public_key),
                                "hasPublicKey": true
                            }
                        ])),
                )
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
        let member = MemberPublicKey {
            user_id: "user-short".into(),
            role: "admin".into(),
            public_key: Some(short_key),
            public_key_version: Some(1),
            public_key_fingerprint: Some("a".repeat(64)),
            has_public_key: true,
        };

        let result = prepare_recipients(&[&member]);

        assert!(matches!(
            result,
            Err(message)
                if message == "invalid public key for user user-short: expected 32 bytes, got 31"
        ));
    }

    #[test]
    fn recipient_selection_rejects_more_than_ten_thousand_members() {
        let members = (0..=10_000)
            .map(|index| MemberPublicKey {
                user_id: format!("member-{index}"),
                role: "member".to_owned(),
                public_key: None,
                public_key_version: None,
                public_key_fingerprint: None,
                has_public_key: false,
            })
            .collect::<Vec<_>>();

        let error = select_members_with_keys(&members).unwrap_err();

        assert!(error.contains("10,000-member limit"));
    }

    #[test]
    fn wrap_keys_for_members_wraps_each_valid_member_key() {
        let aes_key = crypto::generate_aes_key();
        let (_, public_a) = crypto::generate_x25519_keypair();
        let (_, public_b) = crypto::generate_x25519_keypair();
        let member_a = registered_member("user-a", "admin", public_a, 3);
        let member_b = registered_member("user-b", "developer", public_b, 5);

        let recipients = prepare_recipients(&[&member_a, &member_b])
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

    #[test]
    fn select_members_with_keys_skips_members_without_registered_keys() {
        let aes_key = crypto::generate_aes_key();
        let (_, public_key) = crypto::generate_x25519_keypair();
        let member_with_key = registered_member("user-keyed", "admin", public_key, 1);
        let member_without_key = MemberPublicKey {
            user_id: "user-missing".into(),
            role: "developer".into(),
            public_key: None,
            public_key_version: None,
            public_key_fingerprint: None,
            has_public_key: false,
        };

        let members = [member_without_key, member_with_key];

        let selected = select_members_with_keys(&members)
            .expect("at least one keyed member should keep org sharing enabled");

        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].user_id, "user-keyed");

        let recipients =
            prepare_recipients(&selected).expect("selected recipients should validate");
        let wrapped = wrap_keys_for_members(&aes_key, &recipients)
            .expect("only the keyed member should receive a wrapped AES key");

        assert_eq!(wrapped.len(), 1);
        assert_eq!(wrapped[0].user_id, "user-keyed");
        assert!(!wrapped[0].wrapped_key.is_empty());
    }

    #[test]
    fn select_members_with_keys_rejects_incomplete_registered_member_binding() {
        let member = MemberPublicKey {
            user_id: "user-incomplete".into(),
            role: "developer".into(),
            public_key: Some(BASE64.encode([7u8; 32])),
            public_key_version: None,
            public_key_fingerprint: None,
            has_public_key: true,
        };

        let error =
            select_members_with_keys(&[member]).expect_err("incomplete bindings must fail closed");

        assert_eq!(
            error,
            "organization member user-incomplete has an incomplete public-key binding"
        );
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
