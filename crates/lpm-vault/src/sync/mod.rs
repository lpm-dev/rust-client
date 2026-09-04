//! Cloud sync for vault secrets.
//!
//! Handles push/pull of encrypted vault data to/from the LPM API.
//!
//! Successful responses from signed vault endpoints carry an
//! `X-LPM-Signature` header (HMAC-SHA256 over the body keyed by
//! SHA-256 of the auth token). Every signed surface routes through
//! the shared verified-response helper, which reads the body once,
//! snapshots the signature header, and verifies before any caller-side
//! parsing or decryption. Error responses (non-2xx) are not signed and
//! are returned unverified for the caller to format.
//!
//! Personal and organization sync requests also carry a fresh 32-byte
//! request nonce. Successful protocol-v2 envelopes must bind that nonce,
//! the vault identity, scope, crypto version, server version, and any
//! encrypted payload before the response reaches decryption or a caller.

mod audit;
mod ci;
mod envelope;
mod http;
mod org;
mod pairing;
mod personal;
mod public_key;
mod recipient_set;
mod step_up;

/// Error returned by authenticated env API operations.
#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    /// The server returned a non-success HTTP response.
    #[error("{message}")]
    Http {
        status: u16,
        code: Option<String>,
        organization_id: Option<String>,
        caller_user_id: Option<String>,
        message: String,
    },
    /// The server accepted the bearer but rejected a credential submitted by
    /// the operation itself.
    #[error("{message}")]
    CredentialRejected { status: u16, message: String },
    /// Request construction, transport, parsing, or local processing failed.
    #[error("{0}")]
    Other(String),
}

impl SyncError {
    /// Return whether the server rejected the bearer credential.
    pub fn is_unauthorized(&self) -> bool {
        matches!(self, Self::Http { status: 401, .. })
    }

    /// Return whether the server supplied an exact structured HTTP error code.
    pub fn has_http_code(&self, status: u16, code: &str) -> bool {
        matches!(
            self,
            Self::Http {
                status: actual_status,
                code: Some(actual_code),
                ..
            } if *actual_status == status && actual_code == code
        )
    }

    pub fn org_member_rewrap_identity(&self) -> Option<(&str, &str)> {
        match self {
            Self::Http {
                status: 403,
                code: Some(code),
                organization_id: Some(organization_id),
                caller_user_id: Some(caller_user_id),
                ..
            } if code == "vault_member_needs_rewrap" => Some((organization_id, caller_user_id)),
            _ => None,
        }
    }

    pub(crate) fn http(status: reqwest::StatusCode, message: String) -> Self {
        Self::Http {
            status: status.as_u16(),
            code: None,
            organization_id: None,
            caller_user_id: None,
            message,
        }
    }

    pub(crate) fn http_with_rewrap_identity(
        status: reqwest::StatusCode,
        code: Option<String>,
        organization_id: Option<String>,
        caller_user_id: Option<String>,
        message: String,
    ) -> Self {
        Self::Http {
            status: status.as_u16(),
            code,
            organization_id,
            caller_user_id,
            message,
        }
    }

    pub(crate) fn credential_rejected(status: reqwest::StatusCode, message: String) -> Self {
        Self::CredentialRejected {
            status: status.as_u16(),
            message,
        }
    }
}

impl From<String> for SyncError {
    fn from(error: String) -> Self {
        Self::Other(error)
    }
}

impl From<&str> for SyncError {
    fn from(error: &str) -> Self {
        Self::Other(error.to_owned())
    }
}

pub use audit::{AuditEntry, AuditResponse, get_audit_log};
pub use ci::{CiPullResponse, ci_pull, upload_escrow_key};
pub use org::{
    OrgPushRequest, PulledOrgVault, list_org_vaults, org_version_preflight_bound_to_principal,
    pull_org, pull_org_bound_to_principal, pull_org_with_scoped_key_bound_to_principal, push_org,
    push_org_with_access, push_org_with_keys, push_org_with_keys_and_access,
};
pub use pairing::{
    PairingSession, approve_pairing, approve_pairing_legacy, get_pairing_session, stage_pairing,
    unpair_all,
};
pub use personal::{
    ListVaultsResponse, PersonalPushOptions, PullResponse, PulledPersonalVault, PushMetadata,
    PushResponse, RemoteVault, RemoteVaultRevision, list_remote, personal_version_preflight, pull,
    pull_bound_to_principal, pull_env, pull_env_bound_to_principal, pull_raw, pull_raw_bound,
    pull_raw_bound_to_principal, pull_raw_for_rotation, pull_raw_for_rotation_bound,
    pull_raw_for_rotation_bound_to_principal, push, push_raw, push_raw_with_options,
};
pub use public_key::{
    LocalPublicKeyState, MemberPublicKey, MyPublicKeyState, OrgMemberKeyAccess, PendingPublicKey,
    PublicKeyRegistrationState, SharingKeyRotationLock, SharingKeyScope, UploadPublicKeyResponse,
    classify_public_key_state, classify_public_key_state_from_member_access,
    create_pending_x25519_keypair, discard_pending_x25519_keypair, get_my_public_key,
    get_my_public_key_state, get_org_member_key_access, get_org_member_keys,
    promote_pending_x25519_keypair, read_pending_x25519_keypair, resolve_local_public_key_state,
    resolve_public_key_state_from_member_access, try_acquire_sharing_key_rotation_lock,
    upload_public_key, upload_public_key_for_org,
};
pub use step_up::{
    CLI_STEP_UP_HEADER_NAME, CliStepUpCredential, CliStepUpPolicy, discover_cli_step_up_policy,
    mint_cli_step_up_proof,
};

#[cfg(test)]
pub(crate) mod test_support {
    #[cfg(debug_assertions)]
    use crate::signature;
    #[cfg(debug_assertions)]
    use sha2::{Digest, Sha256};
    #[cfg(debug_assertions)]
    use wiremock::{Request, Respond, ResponseTemplate};

    #[cfg(debug_assertions)]
    const TEST_REQUEST_NONCE_HEADER: &str = "x-lpm-vault-request-nonce";

    #[cfg(debug_assertions)]
    #[derive(Clone)]
    pub(crate) enum TestSyncScope {
        Personal,
        Organization(String),
    }

    #[cfg(debug_assertions)]
    #[derive(Clone)]
    pub(crate) struct SignedSyncResponse {
        body: serde_json::Value,
        auth_token: String,
        vault_id: String,
        scope: TestSyncScope,
        mutate: Option<fn(&mut serde_json::Value)>,
    }

    #[cfg(debug_assertions)]
    impl Respond for SignedSyncResponse {
        fn respond(&self, request: &Request) -> ResponseTemplate {
            let nonce = request
                .headers
                .get(TEST_REQUEST_NONCE_HEADER)
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default();
            let mut body = self.body.clone();
            let object = body
                .as_object_mut()
                .expect("test sync response body must be a JSON object");
            let version = object
                .get("version")
                .and_then(serde_json::Value::as_i64)
                .expect("test sync response must include an integer version");
            object.insert("vaultId".into(), self.vault_id.clone().into());
            object.insert("envelopeVersion".into(), 2.into());
            object.insert("serverVersion".into(), version.into());
            object.insert("requestNonce".into(), nonce.into());
            object
                .entry("cryptoVersion")
                .or_insert_with(|| serde_json::Value::from(crate::crypto::CURRENT_CRYPTO_VERSION));
            match &self.scope {
                TestSyncScope::Personal => {
                    object.insert("scope".into(), "personal".into());
                    object.insert("principalId".into(), "personal-test-principal".into());
                }
                TestSyncScope::Organization(slug) => {
                    object.insert("scope".into(), "organization".into());
                    object.insert("callerUserId".into(), "organization-test-caller".into());
                    object.insert(
                        "principalId".into(),
                        "00000000-0000-4000-8000-000000000001".into(),
                    );
                    object.insert("organizationSlug".into(), slug.clone().into());
                }
            }
            if let (Some(encrypted_blob), Some(wrapped_key)) = (
                object
                    .get("encryptedBlob")
                    .and_then(serde_json::Value::as_str),
                object.get("wrappedKey").and_then(serde_json::Value::as_str),
            ) {
                let digest = test_sync_payload_digest(encrypted_blob, wrapped_key);
                object.insert("payloadDigest".into(), digest.into());
            }
            if let Some(mutate) = self.mutate {
                mutate(&mut body);
            }

            let body_string =
                serde_json::to_string(&body).expect("test sync response should serialize");
            let signature = signature::sign_body(body_string.as_bytes(), &self.auth_token);
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "application/json")
                .insert_header(signature::SIGNATURE_HEADER, signature.as_str())
                .set_body_string(body_string)
        }
    }

    #[cfg(debug_assertions)]
    fn test_sync_payload_digest(encrypted_blob: &str, wrapped_key: &str) -> String {
        let mut hash = Sha256::new();
        hash.update(b"lpm-vault-payload\0");
        for value in [encrypted_blob, wrapped_key] {
            let bytes = value.as_bytes();
            let length = u32::try_from(bytes.len()).expect("test payload field should fit in u32");
            hash.update(length.to_be_bytes());
            hash.update(bytes);
        }
        hex::encode(hash.finalize())
    }

    #[cfg(debug_assertions)]
    pub(crate) fn signed_sync_ok_response(
        body: serde_json::Value,
        auth_token: &str,
        vault_id: &str,
        scope: TestSyncScope,
    ) -> SignedSyncResponse {
        SignedSyncResponse {
            body,
            auth_token: auth_token.to_owned(),
            vault_id: vault_id.to_owned(),
            scope,
            mutate: None,
        }
    }

    #[cfg(debug_assertions)]
    pub(crate) fn signed_sync_ok_response_with(
        body: serde_json::Value,
        auth_token: &str,
        vault_id: &str,
        scope: TestSyncScope,
        mutate: fn(&mut serde_json::Value),
    ) -> SignedSyncResponse {
        SignedSyncResponse {
            mutate: Some(mutate),
            ..signed_sync_ok_response(body, auth_token, vault_id, scope)
        }
    }

    /// Acquire the crate-wide env-mutation lock so this module's
    /// tests serialise with `crypto::tests` and the top-level
    /// `lib.rs::tests`. The lock must cover the full window from
    /// env-mutation through any code that reads the same env vars,
    /// so one module's test cannot read another's in-flight env
    /// state. Blocking briefly inside `#[tokio::test]` is safe —
    /// each tokio test runs in its own runtime, so blocking on a
    /// `std::sync::Mutex` doesn't starve any other task.
    pub(crate) fn env_lock_guard() -> std::sync::MutexGuard<'static, ()> {
        crate::test_env_lock::acquire_env_lock()
    }

    /// Build a 200 response that mirrors what the LPM origin actually sends
    /// for signed vault endpoints — body bytes plus matching X-LPM-Signature
    /// header. Tests that drive `pull*`/`push*` for `auth_token` must use
    /// this helper or the response fails verification.
    #[cfg(debug_assertions)]
    pub(crate) fn signed_ok_response(
        body: serde_json::Value,
        auth_token: &str,
    ) -> ResponseTemplate {
        let body_str = serde_json::to_string(&body).expect("test body should serialize");
        let sig = signature::sign_body(body_str.as_bytes(), auth_token);
        ResponseTemplate::new(200)
            .insert_header("Content-Type", "application/json")
            .insert_header(signature::SIGNATURE_HEADER, sig.as_str())
            .set_body_string(body_str)
    }

    /// Hermetic env for tests that touch `crypto::encrypt_vault_for_sync`
    /// or `crypto::decrypt_vault_from_sync` in-process. Snapshots `HOME`
    /// and `LPM_FORCE_FILE_VAULT`, points HOME at a fresh tempdir and
    /// pins file-only mode. Drop restores both.
    ///
    /// Caller must already hold `env_lock_guard()` — this struct does not
    /// acquire it. The async tests in this module take `env_lock`
    /// immediately and the lock guard outlives this struct.
    #[cfg(debug_assertions)]
    pub(crate) struct IsolatedVaultKeyEnv {
        _tmp: tempfile::TempDir,
        prior_home: Option<crate::test_env_lock::HomeEnvSnapshot>,
        prior_force_file: Option<std::ffi::OsString>,
    }

    #[cfg(debug_assertions)]
    impl IsolatedVaultKeyEnv {
        pub(crate) fn new() -> Self {
            let tmp = tempfile::tempdir().expect("tempdir for vault key isolation");
            let prior_home = Some(crate::test_env_lock::HomeEnvSnapshot::set(tmp.path()));
            let prior_force_file = std::env::var_os("LPM_FORCE_FILE_VAULT");
            // SAFETY: caller holds env_lock_guard(), serialising env mutation
            // across all of this crate's tests (shared lock).
            unsafe {
                std::env::set_var("LPM_FORCE_FILE_VAULT", "1");
            }
            IsolatedVaultKeyEnv {
                _tmp: tmp,
                prior_home,
                prior_force_file,
            }
        }
    }

    #[cfg(debug_assertions)]
    impl Drop for IsolatedVaultKeyEnv {
        fn drop(&mut self) {
            // SAFETY: still inside the env_lock-protected section.
            unsafe {
                match &self.prior_force_file {
                    Some(v) => std::env::set_var("LPM_FORCE_FILE_VAULT", v),
                    None => std::env::remove_var("LPM_FORCE_FILE_VAULT"),
                }
            }
            if let Some(prior_home) = self.prior_home.take() {
                prior_home.restore();
            }
        }
    }
}
