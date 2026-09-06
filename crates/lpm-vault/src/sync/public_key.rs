use super::SyncError;
use super::envelope::{
    REQUEST_NONCE_HEADER, generate_request_nonce, parse_member_inventory_response,
    parse_sharing_key_response,
};
use super::http::{read_verified_response, sync_http_client, url_path_segment};
use super::step_up::CLI_STEP_UP_HEADER_NAME;
use base64::Engine as _;
use sha2::Digest as _;

#[cfg(test)]
thread_local! {
    static VALIDATED_SHARING_KEY_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedSharingKey {
    encoded_public_key: String,
    raw_public_key: [u8; 32],
    version: i32,
    fingerprint: String,
}

impl ValidatedSharingKey {
    pub(super) fn from_authenticated(
        encoded_public_key: String,
        version: i32,
        fingerprint: String,
    ) -> Result<Self, String> {
        if version <= 0 {
            return Err("sharing key version must be a positive integer".to_owned());
        }
        if fingerprint.len() != 64
            || !fingerprint
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err("sharing key fingerprint is invalid".to_owned());
        }
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&encoded_public_key)
            .map_err(|_| "authenticated response has an invalid sharing public key")?;
        let raw_public_key: [u8; 32] = decoded
            .try_into()
            .map_err(|_| "authenticated response has an invalid sharing public key")?;
        if base64::engine::general_purpose::STANDARD.encode(raw_public_key) != encoded_public_key {
            return Err("authenticated response has an invalid sharing public key".to_owned());
        }
        if public_key_fingerprint(&raw_public_key) != fingerprint {
            return Err(
                "authenticated response sharing-key fingerprint does not match its public key"
                    .to_owned(),
            );
        }
        crate::crypto::validate_contributory_x25519_public_key(&raw_public_key)?;
        #[cfg(test)]
        VALIDATED_SHARING_KEY_COUNT.with(|count| count.set(count.get() + 1));
        Ok(Self {
            encoded_public_key,
            raw_public_key,
            version,
            fingerprint,
        })
    }

    pub fn encoded_public_key(&self) -> &str {
        &self.encoded_public_key
    }

    pub fn raw_public_key(&self) -> &[u8; 32] {
        &self.raw_public_key
    }

    pub fn version(&self) -> i32 {
        self.version
    }

    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
}

#[cfg(test)]
pub(super) fn reset_validated_sharing_key_count() {
    VALIDATED_SHARING_KEY_COUNT.with(|count| count.set(0));
}

#[cfg(test)]
pub(super) fn validated_sharing_key_count() -> usize {
    VALIDATED_SHARING_KEY_COUNT.with(std::cell::Cell::get)
}

/// Server response from `POST /api/users/me/public-key`.
#[derive(Debug, Default)]
pub struct UploadPublicKeyResponse {
    pub ok: Option<bool>,
    pub status: Option<String>,
    pub fingerprint_prefix: Option<String>,
    pub previous_fingerprint_prefix: Option<String>,
    pub invalidated_wrapped_keys: Option<u32>,
    pub affected_orgs: Option<u32>,
    pub public_key_version: Option<i32>,
    pub public_key_fingerprint: Option<String>,
}

/// Upload the user's X25519 public key to the server.
///
/// `step_up_proof` carries the CLI step-up JWT in the
/// `X-LPM-Step-Up-Proof` header. The server requires a proof minted
/// with audience `vault:public-key:set` for first-set, or
/// `vault:public-key:rotate` for rotation; an idempotent same-key
/// repost does not require a proof and is reported back as
/// `status: "unchanged"`.
///
/// Callers that pass `None` should expect the server to refuse any
/// mutating write with HTTP 403.
pub async fn upload_public_key(
    registry_url: &str,
    auth_token: &str,
    expected_principal_id: &str,
    public_key_b64: &str,
    step_up_proof: Option<&str>,
) -> Result<UploadPublicKeyResponse, SyncError> {
    let client = sync_http_client()?;
    let response = upload_public_key_with_client(
        client,
        registry_url,
        auth_token,
        expected_principal_id,
        public_key_b64,
        step_up_proof,
    )
    .await?;
    let authoritative =
        get_my_public_key_state_with_client(client, registry_url, auth_token).await?;
    if authoritative.principal_id != expected_principal_id
        || authoritative.public_key_b64.as_deref() != Some(public_key_b64)
    {
        return Err("server did not confirm the uploaded sharing key".into());
    }
    Ok(response)
}

pub async fn upload_public_key_for_org(
    registry_url: &str,
    auth_token: &str,
    org_slug: &str,
    expected_principal_id: &str,
    public_key_b64: &str,
    step_up_proof: &str,
) -> Result<OrgMemberKeyAccess, SyncError> {
    let client = sync_http_client()?;
    upload_public_key_with_client(
        client,
        registry_url,
        auth_token,
        expected_principal_id,
        public_key_b64,
        Some(step_up_proof),
    )
    .await?;
    let access =
        get_org_member_key_access_with_client(client, registry_url, auth_token, org_slug).await?;
    if access.caller_user_id != expected_principal_id {
        return Err("organization member inventory changed the authenticated caller".into());
    }
    if authenticated_caller_public_key(&access)? != Some(public_key_b64) {
        return Err(
            "organization member inventory did not confirm the uploaded sharing key".into(),
        );
    }
    Ok(access)
}

async fn upload_public_key_with_client(
    client: &reqwest::Client,
    registry_url: &str,
    auth_token: &str,
    expected_principal_id: &str,
    public_key_b64: &str,
    step_up_proof: Option<&str>,
) -> Result<UploadPublicKeyResponse, SyncError> {
    let url = format!("{registry_url}/api/users/me/public-key");
    let body = serde_json::json!({
        "publicKey": public_key_b64,
        "expectedPrincipalId": expected_principal_id,
    });

    let mut request = client
        .post(&url)
        .bearer_auth(auth_token)
        .json(&body)
        .timeout(std::time::Duration::from_secs(15));
    if let Some(proof) = step_up_proof {
        request = request.header(CLI_STEP_UP_HEADER_NAME, proof);
    }

    let request_nonce = generate_request_nonce()?;
    let response = request
        .header(REQUEST_NONCE_HEADER, &request_nonce)
        .send()
        .await
        .map_err(super::http::network_error)?;
    let (status, body) = read_verified_response(response).await?;
    if status == reqwest::StatusCode::UNAUTHORIZED && body.is_empty() {
        return Err(SyncError::http(
            status,
            "failed to upload public key: authentication failed".into(),
        ));
    }
    let envelope = parse_sharing_key_response(
        &body,
        status.as_u16(),
        &request_nonce,
        true,
        Some(expected_principal_id),
    )?;
    if !status.is_success() {
        return Err(SyncError::http(
            status,
            format!(
                "failed to upload public key: {status}: {}",
                envelope.message.unwrap_or_else(|| "request failed".into())
            ),
        ));
    }
    let sharing_key = envelope
        .sharing_key
        .ok_or("sharing-key write response omitted the committed key")?;
    Ok(UploadPublicKeyResponse {
        ok: Some(true),
        status: Some(envelope.outcome),
        fingerprint_prefix: Some(sharing_key.fingerprint[..16].to_owned()),
        previous_fingerprint_prefix: None,
        invalidated_wrapped_keys: None,
        affected_orgs: None,
        public_key_version: Some(sharing_key.version),
        public_key_fingerprint: Some(sharing_key.fingerprint),
    })
}

/// Check if the user's public key is already on the server.
///
/// The Registry response must be a verified `sharingKey.read` envelope bound
/// to the request nonce and authenticated principal. A signed `present`
/// outcome returns the canonical public key, while a signed `absent` outcome
/// returns `None`. Malformed, unsigned, mismatched, or non-success responses
/// return an error.
pub async fn get_my_public_key(
    registry_url: &str,
    auth_token: &str,
) -> Result<Option<String>, SyncError> {
    let client = sync_http_client()?;
    Ok(
        get_my_public_key_state_with_client(client, registry_url, auth_token)
            .await?
            .public_key_b64,
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MyPublicKeyState {
    pub principal_id: String,
    pub public_key_b64: Option<String>,
}

pub async fn get_my_public_key_state(
    registry_url: &str,
    auth_token: &str,
) -> Result<MyPublicKeyState, SyncError> {
    let client = sync_http_client()?;
    get_my_public_key_state_with_client(client, registry_url, auth_token).await
}

async fn get_my_public_key_state_with_client(
    client: &reqwest::Client,
    registry_url: &str,
    auth_token: &str,
) -> Result<MyPublicKeyState, SyncError> {
    let url = format!("{registry_url}/api/users/me/public-key");
    let request_nonce = generate_request_nonce()?;

    let response = client
        .get(&url)
        .bearer_auth(auth_token)
        .header(REQUEST_NONCE_HEADER, &request_nonce)
        .timeout(std::time::Duration::from_secs(15))
        .send()
        .await
        .map_err(super::http::network_error)?;

    let (status, body) = read_verified_response(response).await?;
    if status == reqwest::StatusCode::UNAUTHORIZED && body.is_empty() {
        return Err(SyncError::http(
            status,
            "get public key: authentication failed".into(),
        ));
    }
    let envelope = parse_sharing_key_response(&body, status.as_u16(), &request_nonce, false, None)?;
    if !status.is_success() {
        return Err(SyncError::http(
            status,
            format!(
                "get public key: {status}: {}",
                envelope.message.unwrap_or_else(|| "request failed".into())
            ),
        ));
    }
    let public_key_b64 = envelope
        .sharing_key
        .map(|key| key.encoded_public_key().to_owned());
    Ok(MyPublicKeyState {
        principal_id: envelope.principal_id,
        public_key_b64,
    })
}

/// Locally-resolved sharing keypair material. The private half stays
/// in memory and in protected storage (Keychain on macOS, an owner-only file
/// elsewhere);
/// the public half is the canonical Base64 form the server expects.
#[derive(Clone, PartialEq, Eq)]
pub struct LocalPublicKeyState {
    /// Raw 32-byte X25519 private key. Callers should not log or surface
    /// this material.
    pub private_key: [u8; 32],
    /// Standard Base64 encoding of the matching X25519 public key.
    pub public_key_b64: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharingKeyScope {
    registry_url: String,
    principal_id: String,
    storage_digest: String,
}

impl SharingKeyScope {
    pub fn new(registry_url: &str, principal_id: &str) -> Result<Self, String> {
        if principal_id.is_empty()
            || principal_id.len() > 256
            || principal_id.chars().any(char::is_control)
        {
            return Err("invalid authenticated caller identity".to_owned());
        }
        let registry_url = canonical_registry_url(registry_url)?;
        let mut digest = sha2::Sha256::new();
        for component in [registry_url.as_bytes(), principal_id.as_bytes()] {
            digest.update((component.len() as u64).to_be_bytes());
            digest.update(component);
        }
        Ok(Self {
            registry_url,
            principal_id: principal_id.to_owned(),
            storage_digest: hex::encode(digest.finalize()),
        })
    }

    pub fn principal_id(&self) -> &str {
        &self.principal_id
    }

    pub fn registry_url(&self) -> &str {
        &self.registry_url
    }

    fn live_file_name(&self) -> String {
        format!(".x25519-key-{}", self.storage_digest)
    }

    fn pending_file_name(&self) -> String {
        format!(".x25519-key-{}.pending", self.storage_digest)
    }

    fn rotation_lock_file_name(&self) -> String {
        format!(".x25519-key-{}.rotation.lock", self.storage_digest)
    }

    #[cfg(any(target_os = "macos", test))]
    fn live_keychain_account(&self) -> String {
        format!("__x25519_private_key__.{}", self.storage_digest)
    }

    #[cfg(any(target_os = "macos", test))]
    fn pending_keychain_account(&self) -> String {
        format!("__x25519_private_key__.{}.pending", self.storage_digest)
    }
}

pub(super) fn canonical_registry_url(registry_url: &str) -> Result<String, String> {
    let mut parsed = reqwest::Url::parse(registry_url)
        .map_err(|error| format!("invalid registry URL for sharing key: {error}"))?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err("invalid registry URL for sharing key".to_owned());
    }
    let normalized_path = parsed.path().trim_end_matches('/').to_owned();
    parsed.set_path(if normalized_path.is_empty() {
        "/"
    } else {
        &normalized_path
    });
    Ok(parsed.as_str().trim_end_matches('/').to_owned())
}

impl std::fmt::Debug for LocalPublicKeyState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LocalPublicKeyState")
            .field("private_key", &"<redacted>")
            .field("public_key_b64", &self.public_key_b64)
            .finish()
    }
}

/// Classification of the local-vs-server sharing-key state, produced by
/// [`classify_public_key_state`]. The CLI command layer branches on this
/// enum to decide whether to proceed silently, prompt for the step-up
/// proof and register, or refuse and direct the user to the explicit
/// `lpm env rotate-sharing-key` flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicKeyRegistrationState {
    /// Server-stored key matches the local key. No write needed; callers
    /// can proceed with the wrap/unwrap operation that prompted the
    /// check.
    Matches(LocalPublicKeyState),
    /// Server has no key for this user. Caller must acquire a CLI
    /// step-up proof (`vault:public-key:set` scope) and call
    /// `upload_public_key(..., Some(proof))` to register before
    /// proceeding.
    NeedsInitialSet(LocalPublicKeyState),
    /// Server has a key but it differs from the local one. The caller
    /// MUST NOT silently overwrite — this is the silent-rotation
    /// vector the server hardening exists to close. The CLI command layer
    /// surfaces this state by refusing the operation and instructing
    /// the user to run the explicit rotation flow (`lpm env
    /// rotate-sharing-key`), which acquires a `vault:public-key:rotate`
    /// proof.
    RotationRequired {
        local: LocalPublicKeyState,
        server_public_key_b64: String,
    },
}

/// Load (or create) the local sharing keypair and classify it against
/// the server's current state.
///
/// Pure classifier — does not mutate server state. Three outcomes:
///
///   - `Matches` — same key on both sides; caller can no-op.
///   - `NeedsInitialSet` — no key on server; caller can register the
///     local key with a `vault:public-key:set` proof.
///   - `RotationRequired` — different key on server; caller MUST refuse
///     to silently upload (the prior `ensure_public_key` path overwrote
///     here, which is the security bug this state prevents).
///
/// All server errors propagate as `Err(...)` — a 401, 403, or 5xx will
/// NOT be misclassified as "no key on server" the way the old
/// `get_my_public_key` `Ok(None)` collapse did.
pub async fn classify_public_key_state(
    registry_url: &str,
    auth_token: &str,
) -> Result<PublicKeyRegistrationState, SyncError> {
    let server = get_my_public_key_state(registry_url, auth_token).await?;
    let scope = SharingKeyScope::new(registry_url, &server.principal_id)?;
    let local = resolve_local_public_key_state(&scope)?;

    match server.public_key_b64 {
        None => Ok(PublicKeyRegistrationState::NeedsInitialSet(local)),
        Some(server) if server == local.public_key_b64 => {
            Ok(PublicKeyRegistrationState::Matches(local))
        }
        Some(server) => Ok(PublicKeyRegistrationState::RotationRequired {
            local,
            server_public_key_b64: server,
        }),
    }
}

/// Load or create the sharing keypair for one Registry and authenticated principal.
pub fn resolve_local_public_key_state(
    scope: &SharingKeyScope,
) -> Result<LocalPublicKeyState, String> {
    #[cfg(target_os = "macos")]
    if !force_file_x25519_keypair() {
        let (private_key, _) = crate::keychain::get_or_create_x25519_keypair_for_account(
            &scope.live_keychain_account(),
        )?;
        return Ok(local_public_key_state(private_key));
    }

    crate::storage_transaction::with_vault_transaction(|directory| {
        let scoped_file = scope.live_file_name();
        if let Some(private_key) = read_private_key_file(directory, &scoped_file, "X25519")? {
            return Ok(local_public_key_state(private_key));
        }
        let (private_key, _) = get_or_create_file_backed_x25519_keypair(directory, &scoped_file)?;
        Ok(local_public_key_state(private_key))
    })
}

fn local_public_key_state(private_key: [u8; 32]) -> LocalPublicKeyState {
    let public_key = crate::crypto::x25519_public_from_private(&private_key);
    LocalPublicKeyState {
        private_key,
        public_key_b64: base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            public_key,
        ),
    }
}

/// Pending sharing-keypair lifecycle helpers used by the
/// `rotate-sharing-key` flow.
///
/// Rotation is split across two writes: server-side upload of the new
/// public key, then local promotion of the matching private key into
/// the live slot. A crash, network drop, or process kill between those
/// two steps must NOT leave the live slot pointing at a key the server
/// no longer knows about (the user would silently lose access to every
/// org vault). The pending slot is the recovery primitive:
///
///   1. Generate a fresh keypair and persist it to the pending slot
///      WITHOUT touching the live slot.
///   2. Upload the pending public key with a `vault:public-key:rotate`
///      step-up proof.
///   3. On HTTP success, atomically promote the pending slot into the
///      live slot.
///   4. On restart (or any future invocation), if the pending slot
///      contains a key that matches the server's current public key,
///      the previous run was interrupted between steps 2 and 3 — finish
///      promotion. If the pending slot exists but doesn't match the
///      server, the upload failed before commit; discard the pending.
///
/// macOS stores live and pending keys under separate accounts in the shared
/// Data Protection Keychain. Other platforms use owner-only file slots.

#[derive(Clone)]
pub struct PendingPublicKey {
    pub private_key: [u8; 32],
    pub public_key_b64: String,
}

impl std::fmt::Debug for PendingPublicKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PendingPublicKey")
            .field("private_key", &"<redacted>")
            .field("public_key_b64", &self.public_key_b64)
            .finish()
    }
}

#[cfg(all(test, debug_assertions))]
fn pending_x25519_key_path(scope: &SharingKeyScope) -> Result<std::path::PathBuf, String> {
    Ok(crate::lpm_home_dir()
        .ok_or("no home directory")?
        .join(".lpm")
        .join(scope.pending_file_name()))
}

#[cfg(all(test, debug_assertions))]
fn live_x25519_key_path(scope: &SharingKeyScope) -> Result<std::path::PathBuf, String> {
    Ok(crate::lpm_home_dir()
        .ok_or("no home directory")?
        .join(".lpm")
        .join(scope.live_file_name()))
}

/// Process-wide and cross-process exclusion for one complete sharing-key
/// rotation, including the remote upload and local promotion phases.
pub struct SharingKeyRotationLock {
    _handle: lpm_common::SingleFileExclusiveLockHandle,
}

/// Try to reserve the complete sharing-key rotation lifecycle.
///
/// A second command fails immediately instead of waiting and accidentally
/// performing another rotation after the first command completes.
pub fn try_acquire_sharing_key_rotation_lock(
    scope: &SharingKeyScope,
) -> Result<Option<SharingKeyRotationLock>, String> {
    crate::storage_transaction::try_acquire_named_lock(
        &scope.rotation_lock_file_name(),
        "sharing-key rotation lock",
    )
    .map(|handle| handle.map(|_handle| SharingKeyRotationLock { _handle }))
}

/// Generate a fresh X25519 keypair and persist it to the pending slot.
/// Does NOT touch the live slot. Overwrites any existing pending slot —
/// the caller's `rotate-sharing-key` flow has already verified the
/// pending state via [`read_pending_x25519_keypair`] and confirmed it's
/// safe to overwrite (stale orphan from a failed prior attempt).
pub fn create_pending_x25519_keypair(scope: &SharingKeyScope) -> Result<PendingPublicKey, String> {
    let (private_key, public_key) = crate::crypto::generate_x25519_keypair();

    #[cfg(target_os = "macos")]
    if !force_file_x25519_keypair() {
        crate::keychain::write_x25519_private_key_for_account(
            &scope.pending_keychain_account(),
            &private_key,
        )?;
        return Ok(pending_public_key(private_key, public_key));
    }

    crate::storage_transaction::with_vault_transaction(|directory| {
        write_private_key_file(
            directory,
            &scope.pending_file_name(),
            &private_key,
            "pending",
        )
    })?;
    Ok(pending_public_key(private_key, public_key))
}

/// Read the pending slot without promoting. Returns `Ok(None)` when no
/// pending slot exists (the steady state). Used on every
/// `rotate-sharing-key` invocation to detect crash-interrupted prior
/// rotations.
pub fn read_pending_x25519_keypair(
    scope: &SharingKeyScope,
) -> Result<Option<PendingPublicKey>, String> {
    #[cfg(target_os = "macos")]
    if !force_file_x25519_keypair() {
        return crate::keychain::try_read_x25519_private_key_for_account(
            &scope.pending_keychain_account(),
        )
        .map(|key| key.map(pending_public_key_from_private));
    }

    crate::storage_transaction::with_vault_transaction(|directory| {
        read_private_key_file(directory, &scope.pending_file_name(), "pending")
            .map(|key| key.map(pending_public_key_from_private))
    })
}

/// Promote the pending slot into the live slot and then remove pending state.
///
/// A crash before the live write leaves pending state for recovery. A crash
/// after the live write leaves two identical copies, so repeating promotion is
/// safe. On macOS both accounts remain in the shared Data Protection Keychain.
pub fn promote_pending_x25519_keypair(scope: &SharingKeyScope) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    if !force_file_x25519_keypair() {
        return crate::keychain::promote_x25519_private_key_accounts(
            &scope.pending_keychain_account(),
            &scope.live_keychain_account(),
        );
    }

    crate::storage_transaction::with_vault_transaction(|directory| {
        let pending_file = scope.pending_file_name();
        let pending = read_private_key_file(directory, &pending_file, "pending")?
            .ok_or("no pending key to promote")?;
        write_private_key_file(directory, &scope.live_file_name(), &pending, "live")?;
        directory.remove_file(&pending_file, "pending X25519 key")?;
        Ok(())
    })
}

/// Delete the pending slot without promoting. Called when the prior
/// upload failed before commit (pending key doesn't match server's
/// current key), or after a successful promotion.
pub fn discard_pending_x25519_keypair(scope: &SharingKeyScope) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    if !force_file_x25519_keypair() {
        return crate::keychain::delete_x25519_private_key_for_account(
            &scope.pending_keychain_account(),
        );
    }

    crate::storage_transaction::with_vault_transaction(|directory| {
        directory.remove_file(&scope.pending_file_name(), "pending X25519 key")?;
        Ok(())
    })
}

/// Org member public key info.
#[derive(Debug)]
pub struct MemberPublicKey {
    pub user_id: String,
    pub role: String,
    sharing_key: Option<ValidatedSharingKey>,
}

impl MemberPublicKey {
    pub fn sharing_key(&self) -> Option<&ValidatedSharingKey> {
        self.sharing_key.as_ref()
    }

    #[cfg(test)]
    pub(super) fn with_test_key(
        user_id: impl Into<String>,
        role: impl Into<String>,
        raw_public_key: [u8; 32],
        version: i32,
    ) -> Self {
        let encoded_public_key = base64::engine::general_purpose::STANDARD.encode(raw_public_key);
        let fingerprint = public_key_fingerprint(&raw_public_key);
        let sharing_key =
            ValidatedSharingKey::from_authenticated(encoded_public_key, version, fingerprint)
                .expect("test sharing key should be valid");
        Self {
            user_id: user_id.into(),
            role: role.into(),
            sharing_key: Some(sharing_key),
        }
    }

    #[cfg(test)]
    pub(super) fn without_test_key(user_id: impl Into<String>, role: impl Into<String>) -> Self {
        Self {
            user_id: user_id.into(),
            role: role.into(),
            sharing_key: None,
        }
    }
}

/// Organization member keys together with the caller's key-management capability.
#[derive(Debug)]
pub struct OrgMemberKeyAccess {
    /// Immutable organization identity asserted by the registry.
    pub organization_id: String,
    /// Authenticated user identity asserted independently of the member payload.
    pub caller_user_id: String,
    /// Current organization members and their registered sharing keys.
    pub members: Vec<MemberPublicKey>,
    /// Whether the caller may replace the organization content-key wraps.
    pub can_replace_wrapped_keys: bool,
}

/// Returns the lowercase SHA-256 fingerprint for a canonical X25519 public key.
pub fn public_key_fingerprint(public_key: &[u8; 32]) -> String {
    use sha2::{Digest, Sha256};

    hex::encode(Sha256::digest(public_key))
}

/// Classify the local sharing key against the authenticated caller's inventory row.
pub fn classify_public_key_state_from_member_access(
    local: LocalPublicKeyState,
    access: &OrgMemberKeyAccess,
) -> Result<PublicKeyRegistrationState, SyncError> {
    match authenticated_caller_public_key(access)? {
        None => Ok(PublicKeyRegistrationState::NeedsInitialSet(local)),
        Some(caller_public_key_b64) if caller_public_key_b64 == local.public_key_b64 => {
            Ok(PublicKeyRegistrationState::Matches(local))
        }
        Some(server_public_key_b64) => Ok(PublicKeyRegistrationState::RotationRequired {
            local,
            server_public_key_b64: server_public_key_b64.to_owned(),
        }),
    }
}

pub fn resolve_public_key_state_from_member_access(
    registry_url: &str,
    access: &OrgMemberKeyAccess,
) -> Result<PublicKeyRegistrationState, SyncError> {
    authenticated_caller_public_key(access)?;
    let scope = SharingKeyScope::new(registry_url, &access.caller_user_id)?;
    let local = resolve_local_public_key_state(&scope)?;
    classify_public_key_state_from_member_access(local, access)
}

fn authenticated_caller_public_key(access: &OrgMemberKeyAccess) -> Result<Option<&str>, SyncError> {
    let mut caller_entries = access
        .members
        .iter()
        .filter(|member| member.user_id == access.caller_user_id);
    let caller = caller_entries
        .next()
        .ok_or("organization member inventory omitted the authenticated caller")?;
    if caller_entries.next().is_some() {
        return Err("organization member inventory duplicated the authenticated caller".into());
    }

    Ok(caller
        .sharing_key()
        .map(ValidatedSharingKey::encoded_public_key))
}

/// Fetch all org members' public keys.
pub async fn get_org_member_keys(
    registry_url: &str,
    auth_token: &str,
    org_slug: &str,
) -> Result<Vec<MemberPublicKey>, SyncError> {
    Ok(
        get_org_member_key_access(registry_url, auth_token, org_slug)
            .await?
            .members,
    )
}

/// Fetch member keys and the caller's wrapped-key write capability.
pub async fn get_org_member_key_access(
    registry_url: &str,
    auth_token: &str,
    org_slug: &str,
) -> Result<OrgMemberKeyAccess, SyncError> {
    let client = sync_http_client()?;
    get_org_member_key_access_with_client(client, registry_url, auth_token, org_slug).await
}

pub(super) async fn get_org_member_key_access_with_client(
    client: &reqwest::Client,
    registry_url: &str,
    auth_token: &str,
    org_slug: &str,
) -> Result<OrgMemberKeyAccess, SyncError> {
    let url = format!(
        "{registry_url}/api/orgs/{}/members/public-keys",
        url_path_segment(org_slug)
    );
    let request_nonce = generate_request_nonce()?;

    let response = client
        .get(&url)
        .bearer_auth(auth_token)
        .header(REQUEST_NONCE_HEADER, &request_nonce)
        .timeout(std::time::Duration::from_secs(15))
        .send()
        .await
        .map_err(super::http::network_error)?;

    let (status, body) = read_verified_response(response).await?;
    if status == reqwest::StatusCode::UNAUTHORIZED && body.is_empty() {
        return Err(SyncError::http(
            status,
            "failed to fetch member keys: authentication failed".into(),
        ));
    }
    let envelope =
        parse_member_inventory_response(&body, status.as_u16(), &request_nonce, org_slug).map_err(
            |error| {
                if status.is_success() {
                    SyncError::from(error)
                } else {
                    SyncError::http(
                        status,
                        format!("failed to fetch member keys: {status}: {error}"),
                    )
                }
            },
        )?;
    Ok(member_access_from_authenticated(envelope))
}

fn member_access_from_authenticated(
    envelope: super::envelope::AuthenticatedMemberInventory,
) -> OrgMemberKeyAccess {
    let members = envelope
        .members
        .into_iter()
        .map(|member| MemberPublicKey {
            user_id: member.user_id,
            role: member.role,
            sharing_key: member.sharing_key,
        })
        .collect();

    OrgMemberKeyAccess {
        organization_id: envelope.organization_id,
        caller_user_id: envelope.caller_user_id,
        members,
        can_replace_wrapped_keys: envelope.can_replace_wrapped_keys,
    }
}

pub(super) fn is_canonical_organization_id(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte),
        })
}

/// Honoured only on macOS — the keychain backend is the default there
/// and this env var is the test-only escape hatch that pins file-backed
/// storage. Linux and Windows already use the file backend
/// unconditionally, so the function is gated to avoid a `dead_code`
/// warning on those targets.
#[cfg(target_os = "macos")]
fn force_file_x25519_keypair() -> bool {
    if !cfg!(debug_assertions) && !crate::acceptance_file_storage_enabled() {
        return false;
    }
    matches!(
        std::env::var("LPM_FORCE_FILE_VAULT").as_deref(),
        Ok("1") | Ok("true") | Ok("TRUE") | Ok("yes") | Ok("YES")
    )
}

fn get_or_create_file_backed_x25519_keypair(
    directory: &crate::storage_transaction::VaultStorageDirectory,
    file_name: &str,
) -> Result<([u8; 32], [u8; 32]), String> {
    if let Some(private_key) = read_private_key_file(directory, file_name, "X25519")? {
        let public_key = crate::crypto::x25519_public_from_private(&private_key);
        return Ok((private_key, public_key));
    }

    let (candidate, public_key) = crate::crypto::generate_x25519_keypair();
    if directory.create_owner_only_file(file_name, &candidate, "X25519 key")? {
        return Ok((candidate, public_key));
    }
    let private_key = read_private_key_file(directory, file_name, "X25519")?
        .ok_or("X25519 key was created concurrently but could not be read")?;
    let public_key = crate::crypto::x25519_public_from_private(&private_key);
    Ok((private_key, public_key))
}

fn pending_public_key(private_key: [u8; 32], public_key: [u8; 32]) -> PendingPublicKey {
    PendingPublicKey {
        private_key,
        public_key_b64: base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            public_key,
        ),
    }
}

fn pending_public_key_from_private(private_key: [u8; 32]) -> PendingPublicKey {
    let public_key = crate::crypto::x25519_public_from_private(&private_key);
    pending_public_key(private_key, public_key)
}

fn read_private_key_file(
    directory: &crate::storage_transaction::VaultStorageDirectory,
    name: &str,
    label: &str,
) -> Result<Option<[u8; 32]>, String> {
    let Some(data) = directory.read_owner_only_file(name, &format!("{label} key"))? else {
        return Ok(None);
    };
    let private_key: [u8; 32] = data.try_into().map_err(|data: Vec<u8>| {
        format!(
            "{label} key file has invalid length {} (expected 32)",
            data.len()
        )
    })?;
    Ok(Some(private_key))
}

fn write_private_key_file(
    directory: &crate::storage_transaction::VaultStorageDirectory,
    name: &str,
    private_key: &[u8; 32],
    label: &str,
) -> Result<(), String> {
    directory.write_owner_only_file(name, private_key, &format!("{label} key"))
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
    use crate::sync::test_support::{env_lock_guard, signed_envelope_response};
    use base64::Engine;
    use wiremock::matchers::{body_json, method, path};
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

    fn test_public_key(byte: u8) -> String {
        let private_key = [byte.wrapping_add(1); 32];
        base64::engine::general_purpose::STANDARD
            .encode(crate::crypto::x25519_public_from_private(&private_key))
    }

    fn account_binding(principal_id: &str) -> serde_json::Value {
        serde_json::json!({
            "scope": "account",
            "principalId": principal_id,
        })
    }

    fn sharing_key_data(public_key: &str, version: i32) -> serde_json::Value {
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(public_key)
            .expect("test sharing key must be valid base64");
        serde_json::json!({
            "sharingKey": {
                "algorithm": "X25519",
                "publicKey": public_key,
                "version": version,
                "fingerprint": hex::encode(sha2::Sha256::digest(decoded)),
                "createdAt": "2026-09-05T12:00:00.000Z",
                "updatedAt": "2026-09-05T12:00:00.000Z",
            }
        })
    }

    fn member_inventory_binding(caller_user_id: &str) -> serde_json::Value {
        serde_json::json!({
            "scope": "organization",
            "principalId": "00000000-0000-4000-8000-000000000001",
            "callerUserId": caller_user_id,
            "organizationSlug": "acme",
        })
    }

    fn member_inventory_data(caller_user_id: &str, public_key: Option<&str>) -> serde_json::Value {
        let sharing_key = public_key.map(|public_key| {
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(public_key)
                .expect("test sharing key must be valid base64");
            serde_json::json!({
                "algorithm": "X25519",
                "publicKey": public_key,
                "version": 1,
                "fingerprint": hex::encode(sha2::Sha256::digest(decoded)),
            })
        });
        serde_json::json!({
            "capability": "replaceWrappedKeysAllowed",
            "members": [{
                "userId": caller_user_id,
                "role": "member",
                "sharingKey": sharing_key,
            }]
        })
    }

    #[cfg(all(target_os = "macos", not(debug_assertions)))]
    #[test]
    fn force_file_x25519_keypair_ignores_env_in_release_builds() {
        let _guard = env_lock_guard();
        let prior = std::env::var_os("LPM_FORCE_FILE_VAULT");
        unsafe {
            std::env::set_var("LPM_FORCE_FILE_VAULT", "1");
        }
        let forced = force_file_x25519_keypair();
        unsafe {
            match prior {
                Some(value) => std::env::set_var("LPM_FORCE_FILE_VAULT", value),
                None => std::env::remove_var("LPM_FORCE_FILE_VAULT"),
            }
        }

        assert!(!forced);
    }

    #[tokio::test]
    async fn get_my_public_key_returns_err_on_non_2xx() {
        // The previous implementation collapsed every non-2xx to
        // `Ok(None)`, which silently turned a 401 / 403 / 500 into "no
        // key on server" and routed the caller into the silent-overwrite
        // path. Pin the new semantics: any non-2xx is an error.
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/users/me/public-key"))
            .respond_with(ResponseTemplate::new(401).set_body_string("unauthorized"))
            .expect(1)
            .mount(&server)
            .await;
        let err = get_my_public_key(&server.uri(), "bad-token")
            .await
            .expect_err("401 must propagate as Err, not Ok(None)");
        assert!(err.is_unauthorized());
    }

    #[tokio::test]
    async fn get_my_public_key_returns_some_on_2xx_with_key() {
        let server = MockServer::start().await;
        let public_key = test_public_key(1);

        Mock::given(method("GET"))
            .and(path("/api/users/me/public-key"))
            .respond_with(signed_envelope_response(
                200,
                "sharingKey.read",
                "present",
                account_binding("caller"),
                sharing_key_data(&public_key, 1),
            ))
            .expect(1)
            .mount(&server)
            .await;

        let key = get_my_public_key(&server.uri(), "token")
            .await
            .expect("happy path must succeed");
        assert_eq!(key.as_deref(), Some(public_key.as_str()));
    }

    #[tokio::test]
    async fn get_my_public_key_returns_none_on_2xx_with_null_field() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/users/me/public-key"))
            .respond_with(signed_envelope_response(
                200,
                "sharingKey.read",
                "absent",
                account_binding("caller"),
                serde_json::json!({}),
            ))
            .expect(1)
            .mount(&server)
            .await;

        let key = get_my_public_key(&server.uri(), "token")
            .await
            .expect("null publicKey is the explicit 'no key' signal");
        assert!(key.is_none());
    }

    #[tokio::test]
    async fn get_org_member_keys_requires_an_immutable_organization_identity() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/orgs/acme/members/public-keys"))
            .respond_with(signed_envelope_response(
                200,
                "organization.memberKeys.read",
                "current",
                serde_json::json!({
                    "scope": "organization",
                    "principalId": "not-an-organization-id",
                    "callerUserId": "caller",
                    "organizationSlug": "acme",
                }),
                member_inventory_data("caller", None),
            ))
            .expect(1)
            .mount(&server)
            .await;

        let error = get_org_member_key_access(&server.uri(), "token", "acme")
            .await
            .expect_err("an unscoped organization member response must fail closed");

        assert!(error.to_string().contains("organization ID"));
    }

    #[tokio::test]
    async fn get_org_member_keys_requires_an_authenticated_caller_identity() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/orgs/acme/members/public-keys"))
            .respond_with(signed_envelope_response(
                200,
                "organization.memberKeys.read",
                "current",
                serde_json::json!({
                    "scope": "organization",
                    "principalId": "00000000-0000-4000-8000-000000000001",
                    "organizationSlug": "acme",
                }),
                member_inventory_data("caller", None),
            ))
            .expect(1)
            .mount(&server)
            .await;

        let error = get_org_member_key_access(&server.uri(), "token", "acme")
            .await
            .expect_err("an organization member response without its caller must fail closed");

        assert!(error.to_string().contains("callerUserId"));
    }

    #[tokio::test]
    async fn get_org_member_keys_requires_an_explicit_wrapped_key_capability() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/orgs/acme/members/public-keys"))
            .respond_with(signed_envelope_response(
                200,
                "organization.memberKeys.read",
                "current",
                member_inventory_binding("caller"),
                serde_json::json!({
                    "capability": "allowed",
                    "members": [{
                        "userId": "caller",
                        "role": "member",
                        "sharingKey": null,
                    }]
                }),
            ))
            .expect(1)
            .mount(&server)
            .await;

        let error = get_org_member_key_access(&server.uri(), "token", "acme")
            .await
            .expect_err("a missing capability header must fail closed");

        assert!(error.to_string().contains("invalid capability"));
    }

    fn member_with_key(user_id: &str, public_key: [u8; 32]) -> MemberPublicKey {
        MemberPublicKey::with_test_key(user_id, "member", public_key, 1)
    }

    fn member_without_key(user_id: &str) -> MemberPublicKey {
        MemberPublicKey::without_test_key(user_id, "member")
    }

    #[test]
    fn authenticated_member_keys_are_validated_once_before_recipient_preparation() {
        reset_validated_sharing_key_count();
        let caller_private_key = [7u8; 32];
        let caller_public_key = crate::crypto::x25519_public_from_private(&caller_private_key);
        let member_public_key = crate::crypto::x25519_public_from_private(&[9u8; 32]);
        let request_nonce = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([3u8; 32]);
        let sharing_key = |public_key: [u8; 32]| {
            serde_json::json!({
                "algorithm": "X25519",
                "publicKey": base64::engine::general_purpose::STANDARD.encode(public_key),
                "version": 1,
                "fingerprint": public_key_fingerprint(&public_key),
            })
        };
        let body = serde_json::to_vec(&serde_json::json!({
            "envelopeVersion": 3,
            "operation": "organization.memberKeys.read",
            "outcome": "current",
            "requestNonce": request_nonce,
            "binding": {
                "scope": "organization",
                "principalId": "00000000-0000-4000-8000-000000000001",
                "callerUserId": "caller",
                "organizationSlug": "acme",
            },
            "data": {
                "capability": "replaceWrappedKeysAllowed",
                "members": [
                    {
                        "userId": "caller",
                        "role": "admin",
                        "sharingKey": sharing_key(caller_public_key),
                    },
                    {
                        "userId": "member-b",
                        "role": "member",
                        "sharingKey": sharing_key(member_public_key),
                    },
                    {
                        "userId": "member-c",
                        "role": "member",
                        "sharingKey": null,
                    },
                ],
            },
        }))
        .expect("member inventory should encode");

        let envelope = parse_member_inventory_response(&body, 200, &request_nonce, "acme")
            .expect("member inventory should authenticate");
        let access = member_access_from_authenticated(envelope);
        assert_eq!(validated_sharing_key_count(), 2);

        let state = classify_public_key_state_from_member_access(
            local_public_key_state(caller_private_key),
            &access,
        )
        .expect("caller key should classify");
        assert!(matches!(state, PublicKeyRegistrationState::Matches(_)));
        let keyed_members: Vec<_> = access
            .members
            .iter()
            .filter(|member| member.sharing_key().is_some())
            .collect();
        let prepared = crate::sync::recipient_set::prepare_recipients(&keyed_members)
            .expect("authenticated keys should prepare");

        assert_eq!(validated_sharing_key_count(), 2);
        assert_eq!(prepared[0].public_key, caller_public_key);
        assert_eq!(prepared[1].public_key, member_public_key);
    }

    fn member_access(caller_user_id: &str, members: Vec<MemberPublicKey>) -> OrgMemberKeyAccess {
        OrgMemberKeyAccess {
            organization_id: "00000000-0000-4000-8000-000000000001".to_owned(),
            caller_user_id: caller_user_id.to_owned(),
            members,
            can_replace_wrapped_keys: true,
        }
    }

    fn local_state(private_key: [u8; 32]) -> LocalPublicKeyState {
        let public_key = crate::crypto::x25519_public_from_private(&private_key);
        LocalPublicKeyState {
            private_key,
            public_key_b64: base64::engine::general_purpose::STANDARD.encode(public_key),
        }
    }

    #[test]
    fn member_access_classifier_matches_the_authenticated_caller_key() {
        let local = local_state([7; 32]);
        let public_key = crate::crypto::x25519_public_from_private(&local.private_key);
        let access = member_access("caller", vec![member_with_key("caller", public_key)]);

        let state = classify_public_key_state_from_member_access(local.clone(), &access)
            .expect("valid caller binding must classify");

        assert_eq!(state, PublicKeyRegistrationState::Matches(local));
    }

    #[test]
    fn member_access_classifier_requires_an_initial_set_for_an_empty_caller_binding() {
        let local = local_state([7; 32]);
        let access = member_access("caller", vec![member_without_key("caller")]);

        let state = classify_public_key_state_from_member_access(local.clone(), &access)
            .expect("empty caller binding must classify");

        assert_eq!(state, PublicKeyRegistrationState::NeedsInitialSet(local));
    }

    #[test]
    fn member_access_classifier_requires_rotation_for_a_changed_caller_key() {
        let local = local_state([7; 32]);
        let server_public_key = crate::crypto::x25519_public_from_private(&[9; 32]);
        let access = member_access("caller", vec![member_with_key("caller", server_public_key)]);

        let state = classify_public_key_state_from_member_access(local.clone(), &access)
            .expect("changed caller binding must classify");

        assert_eq!(
            state,
            PublicKeyRegistrationState::RotationRequired {
                local,
                server_public_key_b64: base64::engine::general_purpose::STANDARD
                    .encode(server_public_key),
            }
        );
    }

    #[test]
    fn member_access_classifier_rejects_a_missing_caller_row() {
        let error = classify_public_key_state_from_member_access(
            local_state([7; 32]),
            &member_access("caller", vec![member_without_key("other")]),
        )
        .expect_err("the authenticated caller must be present");

        assert!(
            error
                .to_string()
                .contains("omitted the authenticated caller")
        );
    }

    #[test]
    fn member_access_classifier_rejects_duplicate_caller_rows() {
        let error = classify_public_key_state_from_member_access(
            local_state([7; 32]),
            &member_access(
                "caller",
                vec![member_without_key("caller"), member_without_key("caller")],
            ),
        )
        .expect_err("the authenticated caller must be unique");

        assert!(
            error
                .to_string()
                .contains("duplicated the authenticated caller")
        );
    }

    #[test]
    fn member_access_classifier_does_not_identify_the_caller_by_key_bytes() {
        let local = local_state([7; 32]);
        let local_public_key = crate::crypto::x25519_public_from_private(&local.private_key);
        let caller_public_key = crate::crypto::x25519_public_from_private(&[9; 32]);
        let access = member_access(
            "caller",
            vec![
                member_with_key("other", local_public_key),
                member_with_key("caller", caller_public_key),
            ],
        );

        let state = classify_public_key_state_from_member_access(local.clone(), &access)
            .expect("caller identity must control selection");

        assert_eq!(
            state,
            PublicKeyRegistrationState::RotationRequired {
                local,
                server_public_key_b64: base64::engine::general_purpose::STANDARD
                    .encode(caller_public_key),
            }
        );
    }

    #[test]
    fn validated_sharing_key_rejects_a_mismatched_fingerprint() {
        let public_key = crate::crypto::x25519_public_from_private(&[7; 32]);
        let error = ValidatedSharingKey::from_authenticated(
            base64::engine::general_purpose::STANDARD.encode(public_key),
            1,
            "0".repeat(64),
        )
        .expect_err("a mismatched fingerprint must fail closed");

        assert!(error.contains("fingerprint does not match"));
    }

    #[tokio::test]
    async fn upload_public_key_sends_step_up_proof_header_when_provided() {
        // The hardened server route refuses any mutating write without a
        // valid `X-LPM-Step-Up-Proof` header. Pin that the helper
        // emits the header when a proof is supplied, AND that it omits
        // the header when None is passed (so old servers don't reject
        // a spurious empty header).
        use std::sync::Arc;
        use std::sync::Mutex as StdMutex;

        let server = MockServer::start().await;
        let captured_proof = Arc::new(StdMutex::new(Vec::<Option<String>>::new()));
        let public_key = test_public_key(2);

        let captured_for_responder = Arc::clone(&captured_proof);
        #[derive(Clone)]
        struct CaptureResponder {
            captured: Arc<StdMutex<Vec<Option<String>>>>,
            public_key: String,
        }
        impl Respond for CaptureResponder {
            fn respond(&self, request: &Request) -> ResponseTemplate {
                let proof = request
                    .headers
                    .get(CLI_STEP_UP_HEADER_NAME)
                    .map(|v| v.to_str().unwrap_or("").to_string());
                self.captured.lock().unwrap().push(proof);
                signed_envelope_response(
                    200,
                    "sharingKey.write",
                    "set",
                    account_binding("caller"),
                    sharing_key_data(&self.public_key, 1),
                )
                .respond(request)
            }
        }

        Mock::given(method("POST"))
            .and(path("/api/users/me/public-key"))
            .and(body_json(serde_json::json!({
                "expectedPrincipalId": "caller",
                "publicKey": public_key,
            })))
            .respond_with(CaptureResponder {
                captured: captured_for_responder,
                public_key: public_key.clone(),
            })
            .expect(2)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/users/me/public-key"))
            .respond_with(signed_envelope_response(
                200,
                "sharingKey.read",
                "present",
                account_binding("caller"),
                sharing_key_data(&public_key, 1),
            ))
            .expect(2)
            .mount(&server)
            .await;

        // With a proof — header must be present and match.
        let result_with = upload_public_key(
            &server.uri(),
            "auth-token",
            "caller",
            &public_key,
            Some("proof-jwt-here"),
        )
        .await
        .expect("happy path with proof");
        assert_eq!(result_with.status.as_deref(), Some("set"));
        assert_eq!(result_with.ok, Some(true));
        assert!(result_with.fingerprint_prefix.is_some());

        // Without a proof — header must be absent.
        upload_public_key(&server.uri(), "auth-token", "caller", &public_key, None)
            .await
            .expect("no-proof call still completes against this mock");

        let captured = captured_proof.lock().unwrap();
        assert_eq!(captured.len(), 2);
        assert_eq!(captured[0].as_deref(), Some("proof-jwt-here"));
        assert!(
            captured[1].is_none(),
            "passing None must NOT send the header at all"
        );
    }

    #[tokio::test]
    async fn upload_public_key_propagates_server_error_envelope_on_non_2xx() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/api/users/me/public-key"))
            .respond_with(signed_envelope_response(
                403,
                "sharingKey.write",
                "stepUpRequired",
                account_binding("caller"),
                serde_json::json!({ "requiredScope": "vault:public-key:set" }),
            ))
            .expect(1)
            .mount(&server)
            .await;

        let err = upload_public_key(&server.uri(), "token", "caller", &test_public_key(3), None)
            .await
            .expect_err("403 must propagate as Err");
        assert!(
            err.to_string().contains("step-up"),
            "error must surface the server envelope so the CLI can render the actionable hint: {err}"
        );
    }

    #[tokio::test]
    async fn upload_public_key_rejects_ambiguous_success_when_authoritative_key_differs() {
        let server = MockServer::start().await;
        let new_key = test_public_key(4);
        let old_key = test_public_key(5);

        Mock::given(method("POST"))
            .and(path("/api/users/me/public-key"))
            .respond_with(signed_envelope_response(
                200,
                "sharingKey.write",
                "set",
                account_binding("caller"),
                sharing_key_data(&new_key, 2),
            ))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/users/me/public-key"))
            .respond_with(signed_envelope_response(
                200,
                "sharingKey.read",
                "present",
                account_binding("caller"),
                sharing_key_data(&old_key, 1),
            ))
            .expect(1)
            .mount(&server)
            .await;

        let result =
            upload_public_key(&server.uri(), "token", "caller", &new_key, Some("proof")).await;

        assert!(
            matches!(result, Err(error) if error.to_string().contains("did not confirm")),
            "a mismatched authoritative key must keep pending local key material"
        );
    }

    #[tokio::test]
    async fn upload_public_key_rejects_a_principal_change_after_the_write() {
        let server = MockServer::start().await;
        let new_key = test_public_key(6);

        Mock::given(method("POST"))
            .and(path("/api/users/me/public-key"))
            .and(body_json(serde_json::json!({
                "expectedPrincipalId": "caller",
                "publicKey": new_key.clone(),
            })))
            .respond_with(signed_envelope_response(
                200,
                "sharingKey.write",
                "set",
                account_binding("caller"),
                sharing_key_data(&new_key, 1),
            ))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/users/me/public-key"))
            .respond_with(signed_envelope_response(
                200,
                "sharingKey.read",
                "present",
                account_binding("other-caller"),
                sharing_key_data(&new_key, 1),
            ))
            .expect(1)
            .mount(&server)
            .await;

        let error = upload_public_key(&server.uri(), "token", "caller", &new_key, Some("proof"))
            .await
            .expect_err("a response for another principal must not confirm the upload");

        assert!(error.to_string().contains("did not confirm"), "{error}");
    }

    #[tokio::test]
    async fn upload_public_key_rejects_the_retired_flat_success_shape() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/api/users/me/public-key"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "status": "saved" })),
            )
            .expect(1)
            .mount(&server)
            .await;
        let result = upload_public_key(
            &server.uri(),
            "token",
            "caller",
            &test_public_key(7),
            Some("proof"),
        )
        .await
        .expect_err("retired flat success responses must fail closed");

        assert!(result.to_string().contains(signature::SIGNATURE_HEADER));
    }

    #[tokio::test]
    async fn org_registration_confirms_the_uploaded_key_from_one_refetched_member_inventory() {
        let local = local_state([7; 32]);
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/api/users/me/public-key"))
            .respond_with(signed_envelope_response(
                200,
                "sharingKey.write",
                "set",
                account_binding("caller"),
                sharing_key_data(&local.public_key_b64, 1),
            ))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/orgs/acme/members/public-keys"))
            .respond_with(signed_envelope_response(
                200,
                "organization.memberKeys.read",
                "current",
                member_inventory_binding("caller"),
                member_inventory_data("caller", Some(&local.public_key_b64)),
            ))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/users/me/public-key"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;

        let access = upload_public_key_for_org(
            &server.uri(),
            "token",
            "acme",
            "caller",
            &local.public_key_b64,
            "proof",
        )
        .await
        .expect("the member inventory must confirm the uploaded key");

        assert_eq!(
            classify_public_key_state_from_member_access(local.clone(), &access)
                .expect("refetched caller binding must classify"),
            PublicKeyRegistrationState::Matches(local),
        );
    }

    #[tokio::test]
    async fn org_registration_rejects_a_changed_authenticated_caller() {
        let local = local_state([7; 32]);
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/api/users/me/public-key"))
            .respond_with(signed_envelope_response(
                200,
                "sharingKey.write",
                "set",
                account_binding("caller"),
                sharing_key_data(&local.public_key_b64, 1),
            ))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/orgs/acme/members/public-keys"))
            .respond_with(signed_envelope_response(
                200,
                "organization.memberKeys.read",
                "current",
                member_inventory_binding("other-caller"),
                member_inventory_data("other-caller", Some(&local.public_key_b64)),
            ))
            .expect(1)
            .mount(&server)
            .await;

        let error = upload_public_key_for_org(
            &server.uri(),
            "token",
            "acme",
            "caller",
            &local.public_key_b64,
            "proof",
        )
        .await
        .expect_err("a caller change after upload must fail closed");

        assert!(
            error.to_string().contains("authenticated caller"),
            "{error}"
        );
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn classify_public_key_state_matches_when_server_key_equals_local() {
        let _guard = env_lock_guard();
        let _isolated = IsolatedVaultKeyEnv::new();
        let server = MockServer::start().await;

        // Pre-warm the local keypair so we know its public form.
        let scope = SharingKeyScope::new(&server.uri(), "caller").expect("sharing key scope");
        let local = resolve_local_public_key_state(&scope).expect("load local keypair");

        Mock::given(method("GET"))
            .and(path("/api/users/me/public-key"))
            .respond_with(signed_envelope_response(
                200,
                "sharingKey.read",
                "present",
                account_binding("caller"),
                sharing_key_data(&local.public_key_b64, 1),
            ))
            .expect(1)
            .mount(&server)
            .await;

        let state = classify_public_key_state(&server.uri(), "token")
            .await
            .expect("classification succeeds against happy server");
        match state {
            PublicKeyRegistrationState::Matches(l) => {
                assert_eq!(l.public_key_b64, local.public_key_b64);
            }
            other => panic!("expected Matches, got {other:?}"),
        }
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn classify_public_key_state_needs_initial_set_when_server_returns_null() {
        let _guard = env_lock_guard();
        let _isolated = IsolatedVaultKeyEnv::new();

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/users/me/public-key"))
            .respond_with(signed_envelope_response(
                200,
                "sharingKey.read",
                "absent",
                account_binding("caller"),
                serde_json::json!({}),
            ))
            .expect(1)
            .mount(&server)
            .await;

        let state = classify_public_key_state(&server.uri(), "token")
            .await
            .expect("classification succeeds for empty server state");
        assert!(matches!(
            state,
            PublicKeyRegistrationState::NeedsInitialSet(_)
        ));
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn classify_public_key_state_rotation_required_when_server_key_differs() {
        // Critical regression guard: the previous `ensure_public_key`
        // path would silently upload here, overwriting whatever key
        // was on the server. The new classifier must surface this
        // state so the CLI command layer can refuse and direct the
        // user to the explicit rotation flow.
        let _guard = env_lock_guard();
        let _isolated = IsolatedVaultKeyEnv::new();

        let server = MockServer::start().await;
        let server_key = test_public_key(0);
        Mock::given(method("GET"))
            .and(path("/api/users/me/public-key"))
            .respond_with(signed_envelope_response(
                200,
                "sharingKey.read",
                "present",
                account_binding("caller"),
                sharing_key_data(&server_key, 1),
            ))
            .expect(1)
            .mount(&server)
            .await;

        let state = classify_public_key_state(&server.uri(), "token")
            .await
            .expect("classification succeeds against mismatch");
        match state {
            PublicKeyRegistrationState::RotationRequired {
                local: _,
                server_public_key_b64,
            } => {
                assert_eq!(server_public_key_b64, server_key);
            }
            other => panic!("expected RotationRequired, got {other:?}"),
        }
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn classify_public_key_state_propagates_server_errors_instead_of_collapsing() {
        // The prior `get_my_public_key` mapped 401/500 to `Ok(None)`,
        // which would have made the classifier return
        // `NeedsInitialSet` for a token that was actually expired or a
        // server that was simply broken. Pin that errors propagate.
        let _guard = env_lock_guard();
        let _isolated = IsolatedVaultKeyEnv::new();

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/users/me/public-key"))
            .respond_with(signed_envelope_response(
                500,
                "sharingKey.read",
                "rejected",
                account_binding("caller"),
                serde_json::json!({
                    "code": "sharing_key_internal_error",
                    "message": "boom",
                }),
            ))
            .expect(1)
            .mount(&server)
            .await;

        let err = classify_public_key_state(&server.uri(), "token")
            .await
            .expect_err("server 500 must propagate, not be misclassified");
        assert!(err.to_string().contains("500"), "got: {err}");
    }

    #[cfg(debug_assertions)]
    #[test]
    fn pending_key_lifecycle_round_trips_through_create_read_promote() {
        // Create → read → promote, verifying that promote leaves the
        // live slot with the pending bytes and clears the pending file.
        let _guard = env_lock_guard();
        let _isolated = IsolatedVaultKeyEnv::new();
        let scope =
            SharingKeyScope::new("https://registry.example", "caller").expect("sharing key scope");

        // No pending at first.
        assert!(
            read_pending_x25519_keypair(&scope)
                .expect("read pending")
                .is_none(),
            "fresh HOME should have no pending key"
        );

        // Create — pending file now exists, live slot still untouched.
        let pending = create_pending_x25519_keypair(&scope).expect("create pending");
        let pending_path = pending_x25519_key_path(&scope).expect("path");
        let live_path = live_x25519_key_path(&scope).expect("path");
        assert!(pending_path.exists(), "create must persist the pending key");
        assert!(
            !live_path.exists(),
            "create must NOT touch the live slot until promotion"
        );

        // Read returns the same key bytes.
        let read_back = read_pending_x25519_keypair(&scope)
            .expect("read pending")
            .expect("pending should be present");
        assert_eq!(read_back.public_key_b64, pending.public_key_b64);

        // Promote — live slot now holds the pending bytes; pending is gone.
        promote_pending_x25519_keypair(&scope).expect("promote");
        assert!(live_path.exists(), "live slot must be present post-promote");
        assert!(
            !pending_path.exists(),
            "pending must be deleted after promote"
        );
        let live_bytes = std::fs::read(&live_path).expect("read live");
        assert_eq!(live_bytes, &pending.private_key);

        let live = resolve_local_public_key_state(&scope).expect("load live");
        assert_eq!(live.public_key_b64, pending.public_key_b64);
    }

    #[cfg(debug_assertions)]
    #[test]
    fn pending_key_discard_removes_orphan_without_touching_live() {
        let _guard = env_lock_guard();
        let _isolated = IsolatedVaultKeyEnv::new();
        let scope =
            SharingKeyScope::new("https://registry.example", "caller").expect("sharing key scope");

        // Pre-seed a live key.
        let live = resolve_local_public_key_state(&scope).expect("seed live");
        let live_path = live_x25519_key_path(&scope).expect("path");
        assert!(live_path.exists());

        // Create + discard pending.
        let _ = create_pending_x25519_keypair(&scope).expect("create pending");
        let pending_path = pending_x25519_key_path(&scope).expect("path");
        assert!(pending_path.exists());

        discard_pending_x25519_keypair(&scope).expect("discard");
        assert!(!pending_path.exists());
        assert!(live_path.exists(), "discard must NOT touch live");
        // Live key bytes unchanged.
        let live_after = resolve_local_public_key_state(&scope).expect("load live");
        assert_eq!(live_after.public_key_b64, live.public_key_b64);
    }

    #[cfg(debug_assertions)]
    #[test]
    fn pending_key_promote_when_no_pending_is_explicit_error() {
        let _guard = env_lock_guard();
        let _isolated = IsolatedVaultKeyEnv::new();
        let scope =
            SharingKeyScope::new("https://registry.example", "caller").expect("sharing key scope");

        let err = promote_pending_x25519_keypair(&scope)
            .expect_err("promote with no pending must Err, not silently succeed");
        assert!(err.contains("no pending"), "got: {err}");
    }

    #[cfg(debug_assertions)]
    #[test]
    fn sharing_key_rotation_lock_rejects_a_concurrent_command() {
        let _guard = env_lock_guard();
        let _env = IsolatedVaultKeyEnv::new();
        let scope =
            SharingKeyScope::new("https://registry.example", "caller").expect("sharing key scope");
        let other_scope = SharingKeyScope::new("https://registry.example", "other-caller")
            .expect("other sharing key scope");
        let first = try_acquire_sharing_key_rotation_lock(&scope)
            .expect("acquire first rotation lock")
            .expect("first rotation lock should be available");

        let second =
            try_acquire_sharing_key_rotation_lock(&scope).expect("probe second rotation lock");
        let independent = try_acquire_sharing_key_rotation_lock(&other_scope)
            .expect("probe independent rotation lock");

        assert!(second.is_none());
        assert!(independent.is_some());
        drop(first);
    }

    #[cfg(debug_assertions)]
    #[test]
    fn unscoped_live_key_is_never_adopted_into_an_authenticated_scope() {
        let _guard = env_lock_guard();
        let _env = IsolatedVaultKeyEnv::new();
        let unscoped_private_key = [7; 32];
        crate::storage_transaction::with_vault_transaction(|directory| {
            write_private_key_file(
                directory,
                ".x25519_key",
                &unscoped_private_key,
                "unscoped X25519",
            )
        })
        .expect("seed unscoped sharing key");
        let scope =
            SharingKeyScope::new("https://registry.example", "caller").expect("sharing key scope");

        let resolved = resolve_local_public_key_state(&scope).expect("create scoped key");

        assert_ne!(resolved.private_key, unscoped_private_key);
    }

    #[cfg(debug_assertions)]
    #[test]
    fn unscoped_pending_key_is_never_adopted_into_an_authenticated_scope() {
        let _guard = env_lock_guard();
        let _env = IsolatedVaultKeyEnv::new();
        let unscoped_private_key = [7; 32];
        crate::storage_transaction::with_vault_transaction(|directory| {
            write_private_key_file(
                directory,
                ".x25519_key.pending",
                &unscoped_private_key,
                "unscoped pending",
            )
        })
        .expect("seed unscoped pending key");
        let scope =
            SharingKeyScope::new("https://registry.example", "caller").expect("sharing key scope");

        let resolved = read_pending_x25519_keypair(&scope).expect("probe scoped pending key");

        assert!(resolved.is_none());
    }

    #[cfg(debug_assertions)]
    #[test]
    fn sharing_keys_are_isolated_by_registry_and_authenticated_principal() {
        let _guard = env_lock_guard();
        let _env = IsolatedVaultKeyEnv::new();
        let first_scope =
            SharingKeyScope::new("https://registry-a.example", "user-1").expect("first scope");
        let other_registry = SharingKeyScope::new("https://registry-b.example", "user-1")
            .expect("other Registry scope");
        let other_principal = SharingKeyScope::new("https://registry-a.example", "user-2")
            .expect("other principal scope");

        let first = resolve_local_public_key_state(&first_scope).expect("first key");
        let second = resolve_local_public_key_state(&other_registry).expect("other Registry key");
        let third = resolve_local_public_key_state(&other_principal).expect("other principal key");

        assert_ne!(first.public_key_b64, second.public_key_b64);
        assert_ne!(first.public_key_b64, third.public_key_b64);
    }

    #[test]
    fn sharing_key_rotation_account_matches_the_swift_client() {
        let scope =
            SharingKeyScope::new("https://registry.example/", "user-1").expect("sharing key scope");

        assert_eq!(
            scope.live_keychain_account(),
            "__x25519_private_key__.5a12911fb761923d976c0aa9f51355a7a8b1c31b06d152393eec5ab45357e666"
        );
        assert_eq!(
            scope.pending_keychain_account(),
            "__x25519_private_key__.5a12911fb761923d976c0aa9f51355a7a8b1c31b06d152393eec5ab45357e666.pending"
        );
    }

    #[test]
    fn private_key_debug_output_is_redacted() {
        let state = LocalPublicKeyState {
            private_key: [7; 32],
            public_key_b64: "public".to_owned(),
        };

        let debug = format!("{state:?}");

        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("7, 7"));
    }
}
