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

mod audit;
mod ci;
mod http;
mod org;
mod pairing;
mod personal;
mod public_key;
mod step_up;

/// Error returned by authenticated env API operations.
#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    /// The server returned a non-success HTTP response.
    #[error("{message}")]
    Http { status: u16, message: String },
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

    pub(crate) fn http(status: reqwest::StatusCode, message: String) -> Self {
        Self::Http {
            status: status.as_u16(),
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
    OrgPushRequest, PulledOrgVault, list_org_vaults, pull_org, push_org, push_org_with_keys,
};
pub use pairing::{
    PairingSession, approve_pairing, approve_pairing_legacy, get_pairing_session, stage_pairing,
    unpair_all,
};
pub use personal::{
    ListVaultsResponse, PullResponse, PushMetadata, PushResponse, RemoteVault, list_remote, pull,
    pull_env, pull_raw, pull_raw_for_rotation, push, push_raw,
};
pub use public_key::{
    LocalPublicKeyState, MemberPublicKey, OrgMemberKeyAccess, PendingPublicKey,
    PublicKeyRegistrationState, SharingKeyRotationLock, UploadPublicKeyResponse,
    classify_public_key_state, create_pending_x25519_keypair, discard_pending_x25519_keypair,
    get_my_public_key, get_org_member_key_access, get_org_member_keys,
    promote_pending_x25519_keypair, read_pending_x25519_keypair,
    try_acquire_sharing_key_rotation_lock, upload_public_key,
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
    use wiremock::ResponseTemplate;

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
