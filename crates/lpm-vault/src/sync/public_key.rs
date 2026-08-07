use super::http::{read_capped_error_text, sync_http_client_builder, url_path_segment};
use super::step_up::CLI_STEP_UP_HEADER_NAME;

/// Server response from `POST /api/users/me/public-key`.
///
/// The server returns a structured envelope for public-key registration
/// state. Older servers returned `{ status: "saved" }`; we
/// forward-compat-parse that shape too — every field below is optional,
/// so a missing key is just `None` rather than a deserialization failure.
#[derive(Debug, Default, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UploadPublicKeyResponse {
    /// `true` on 2xx success. Old servers omit this field — treat absent
    /// as success (the route returned 2xx).
    pub ok: Option<bool>,
    /// `"set" | "unchanged" | "rotated"` from the hardened route. Old servers
    /// return `"saved"`.
    pub status: Option<String>,
    /// SHA-256 prefix of the new key (only on `set` and `rotated`).
    pub fingerprint_prefix: Option<String>,
    /// SHA-256 prefix of the previous key (only on `rotated`).
    pub previous_fingerprint_prefix: Option<String>,
    /// Count of `vault_org_keys` rows the rotation invalidated.
    pub invalidated_wrapped_keys: Option<u32>,
    /// Count of distinct orgs whose wrapped-key rows were invalidated.
    pub affected_orgs: Option<u32>,
    /// Monotonic revision of the registered sharing key.
    pub public_key_version: Option<i32>,
    /// Full SHA-256 fingerprint used by organization wrapped-key bindings.
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
/// mutating write with HTTP 403 and the structured `code:
/// "step_up_required"` envelope — that's the correct failure mode
/// against hardened servers. Against older servers, the header is
/// silently ignored and the legacy write path runs.
pub async fn upload_public_key(
    registry_url: &str,
    auth_token: &str,
    public_key_b64: &str,
    step_up_proof: Option<&str>,
) -> Result<UploadPublicKeyResponse, String> {
    let client = sync_http_client_builder()
        .build()
        .map_err(|e| format!("failed to build http client: {e}"))?;
    let url = format!("{registry_url}/api/users/me/public-key");
    let body = serde_json::json!({"publicKey": public_key_b64});

    let mut request = client
        .post(&url)
        .bearer_auth(auth_token)
        .json(&body)
        .timeout(std::time::Duration::from_secs(15));
    if let Some(proof) = step_up_proof {
        request = request.header(CLI_STEP_UP_HEADER_NAME, proof);
    }

    let response = request.send().await.map_err(super::http::network_error)?;

    if !response.status().is_success() {
        let body = read_capped_error_text(response).await;
        return Err(format!("failed to upload public key: {body}"));
    }

    // `response.json()` would happily Err if the body isn't JSON. Old
    // servers reliably return JSON; the explicit error keeps the
    // message tight for any future server that 2xxes with HTML.
    response
        .json::<UploadPublicKeyResponse>()
        .await
        .map_err(|e| format!("parse error: {e}"))
}

/// Check if the user's public key is already on the server.
///
/// Wire contract — distinguishes "no key on server" from "server is
/// failing" so callers can branch correctly:
///
///   - 2xx with `{ publicKey: "<b64>" }` → `Ok(Some(...))`
///   - 2xx with `{ publicKey: null }` or `publicKey` field absent → `Ok(None)`
///   - 2xx whose body is malformed JSON → `Err(...)`
///   - any non-2xx (401, 403, 5xx, redirect) → `Err(...)` with the
///     response status + body summary
///
/// The previous implementation collapsed every non-2xx response to
/// `Ok(None)`, which meant a transient 500 or a 401 (expired token)
/// would be misclassified as "no key on server" and the silent
/// `ensure_public_key` retry path would try to overwrite — exactly the
/// silent-overwrite vector the server hardening was built to close.
/// This implementation fails fast so the caller's classification
/// path can render an honest error.
pub async fn get_my_public_key(
    registry_url: &str,
    auth_token: &str,
) -> Result<Option<String>, String> {
    let client = sync_http_client_builder()
        .build()
        .map_err(|e| format!("failed to build http client: {e}"))?;
    let url = format!("{registry_url}/api/users/me/public-key");

    let response = client
        .get(&url)
        .bearer_auth(auth_token)
        .timeout(std::time::Duration::from_secs(15))
        .send()
        .await
        .map_err(super::http::network_error)?;

    let status = response.status();
    if !status.is_success() {
        let body = read_capped_error_text(response).await;
        return Err(format!("get public key: {status}: {body}"));
    }

    let data: serde_json::Value = response
        .json()
        .await
        .map_err(|e| format!("parse error: {e}"))?;

    Ok(data
        .get("publicKey")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string()))
}

/// Locally-resolved sharing keypair material. The private half stays
/// in memory and on disk (keychain on macOS, file fallback otherwise);
/// the public half is the canonical Base64 form the server expects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalPublicKeyState {
    /// Raw 32-byte X25519 private key. Callers should not log or surface
    /// this material.
    pub private_key: [u8; 32],
    /// Standard Base64 encoding of the matching X25519 public key.
    pub public_key_b64: String,
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
) -> Result<PublicKeyRegistrationState, String> {
    let local = load_local_public_key_state()?;
    let server_key = get_my_public_key(registry_url, auth_token).await?;

    match server_key {
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

/// Load the local X25519 keypair, creating one if absent.
fn load_local_public_key_state() -> Result<LocalPublicKeyState, String> {
    #[cfg(target_os = "macos")]
    let (private_key, public) = if should_use_file_backed_x25519_keypair(
        force_file_x25519_keypair(),
        live_x25519_key_path()?.exists(),
    ) {
        get_or_create_file_backed_x25519_keypair()?
    } else {
        crate::keychain::get_or_create_x25519_keypair()?
    };
    #[cfg(not(target_os = "macos"))]
    let (private_key, public) = get_or_create_file_backed_x25519_keypair()?;

    let public_key_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, public);
    Ok(LocalPublicKeyState {
        private_key,
        public_key_b64,
    })
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
/// Storage backend: ALWAYS the file-backed slots (`.x25519_key.pending`
/// in the user's `~/.lpm` directory). The macOS keychain backend only
/// supports a single named entry per service/account pair; juggling a
/// transient pending entry there adds complexity (and a multi-keychain-
/// item ACL surface) that the file slot avoids cleanly. Promotion
/// writes the new private key to the live slot via the same code path
/// `get_or_create_file_backed_x25519_keypair` uses for first-set, so
/// permissions stay consistent (`0o600` on Unix).

#[derive(Debug, Clone)]
pub struct PendingPublicKey {
    pub private_key: [u8; 32],
    pub public_key_b64: String,
}

fn pending_x25519_key_path() -> Result<std::path::PathBuf, String> {
    Ok(crate::lpm_home_dir()
        .ok_or("no home directory")?
        .join(".lpm")
        .join(".x25519_key.pending"))
}

fn live_x25519_key_path() -> Result<std::path::PathBuf, String> {
    Ok(crate::lpm_home_dir()
        .ok_or("no home directory")?
        .join(".lpm")
        .join(".x25519_key"))
}

/// Generate a fresh X25519 keypair and persist it to the pending slot.
/// Does NOT touch the live slot. Overwrites any existing pending slot —
/// the caller's `rotate-sharing-key` flow has already verified the
/// pending state via [`read_pending_x25519_keypair`] and confirmed it's
/// safe to overwrite (stale orphan from a failed prior attempt).
pub fn create_pending_x25519_keypair() -> Result<PendingPublicKey, String> {
    let (private_key, public_key) = crate::crypto::generate_x25519_keypair();
    let path = pending_x25519_key_path()?;
    let parent = path.parent().ok_or("invalid pending key path")?;
    std::fs::create_dir_all(parent)
        .map_err(|e| format!("failed to create pending key dir: {e}"))?;
    std::fs::write(&path, private_key).map_err(|e| format!("failed to write pending key: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("failed to set pending key permissions: {e}"))?;
    }
    Ok(PendingPublicKey {
        private_key,
        public_key_b64: base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            public_key,
        ),
    })
}

/// Read the pending slot without promoting. Returns `Ok(None)` when no
/// pending slot exists (the steady state). Used on every
/// `rotate-sharing-key` invocation to detect crash-interrupted prior
/// rotations.
pub fn read_pending_x25519_keypair() -> Result<Option<PendingPublicKey>, String> {
    let path = pending_x25519_key_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let data = lpm_common::read_file_capped(&path, lpm_common::STATE_FILE_SIZE_CAP_BYTES)
        .map_err(|e| format!("failed to read pending key: {e}"))?;
    if data.len() != 32 {
        return Err(format!(
            "pending key file has invalid length {} (expected 32)",
            data.len()
        ));
    }
    let mut private_key = [0u8; 32];
    private_key.copy_from_slice(&data);
    let secret = x25519_dalek::StaticSecret::from(private_key);
    let public_key = x25519_dalek::PublicKey::from(&secret);
    let public_key_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        public_key.as_bytes(),
    );
    Ok(Some(PendingPublicKey {
        private_key,
        public_key_b64,
    }))
}

/// Atomically promote the pending slot into the live slot.
///
/// Writes the pending private key to the live file with `0o600` perms,
/// then deletes the pending file. The write-then-delete order means a
/// crash between the two steps leaves BOTH files with the same key
/// (next promotion is a no-op); a crash before the write leaves only
/// pending (next rotation discovers it). Both orderings are safe; the
/// only unsafe state would be "live updated, pending still present
/// with a stale key" — which cannot happen because pending always
/// holds the key we just wrote to live.
///
/// Also clears any prior keychain entry on macOS so subsequent
/// `load_local_public_key_state` calls observe the new file-backed key
/// instead of the stale keychain entry. (The keychain entry survives
/// across rotations otherwise.)
pub fn promote_pending_x25519_keypair() -> Result<(), String> {
    let pending = read_pending_x25519_keypair()?.ok_or("no pending key to promote")?;
    let live_path = live_x25519_key_path()?;
    let parent = live_path.parent().ok_or("invalid live key path")?;
    std::fs::create_dir_all(parent).map_err(|e| format!("failed to create live key dir: {e}"))?;
    std::fs::write(&live_path, pending.private_key)
        .map_err(|e| format!("failed to write live key: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&live_path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("failed to set live key permissions: {e}"))?;
    }

    // Clear macOS keychain entry if present so subsequent reads see
    // the file-backed key. Best-effort: a "not found" error here is
    // expected when the user was already on the file fallback, so we
    // intentionally swallow keychain errors.
    #[cfg(target_os = "macos")]
    {
        let _ = crate::keychain::delete_x25519_keypair();
    }

    discard_pending_x25519_keypair()
}

/// Delete the pending slot without promoting. Called when the prior
/// upload failed before commit (pending key doesn't match server's
/// current key), or after a successful promotion.
pub fn discard_pending_x25519_keypair() -> Result<(), String> {
    let path = pending_x25519_key_path()?;
    if path.exists() {
        std::fs::remove_file(&path).map_err(|e| format!("failed to delete pending key: {e}"))?;
    }
    Ok(())
}

/// Org member public key info.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemberPublicKey {
    pub user_id: String,
    pub role: String,
    pub public_key: Option<String>,
    pub public_key_version: Option<i32>,
    pub public_key_fingerprint: Option<String>,
    pub has_public_key: bool,
}

/// Returns the lowercase SHA-256 fingerprint for a canonical X25519 public key.
pub fn public_key_fingerprint(public_key: &[u8; 32]) -> String {
    use sha2::{Digest, Sha256};

    hex::encode(Sha256::digest(public_key))
}

/// Fetch all org members' public keys.
pub async fn get_org_member_keys(
    registry_url: &str,
    auth_token: &str,
    org_slug: &str,
) -> Result<Vec<MemberPublicKey>, String> {
    let client = sync_http_client_builder()
        .build()
        .map_err(|e| format!("failed to build http client: {e}"))?;
    let url = format!(
        "{registry_url}/api/orgs/{}/members/public-keys",
        url_path_segment(org_slug)
    );

    let response = client
        .get(&url)
        .bearer_auth(auth_token)
        .timeout(std::time::Duration::from_secs(15))
        .send()
        .await
        .map_err(super::http::network_error)?;

    if !response.status().is_success() {
        let body = read_capped_error_text(response).await;
        return Err(format!("failed to fetch member keys: {body}"));
    }

    response
        .json()
        .await
        .map_err(|e| format!("parse error: {e}"))
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

#[cfg(target_os = "macos")]
fn should_use_file_backed_x25519_keypair(force_file: bool, live_key_exists: bool) -> bool {
    force_file || live_key_exists
}

fn get_or_create_file_backed_x25519_keypair() -> Result<([u8; 32], [u8; 32]), String> {
    let key_path = crate::lpm_home_dir()
        .ok_or("no home directory")?
        .join(".lpm")
        .join(".x25519_key");

    if key_path.exists() {
        let data = lpm_common::read_file_capped(&key_path, lpm_common::STATE_FILE_SIZE_CAP_BYTES)
            .map_err(|e| format!("failed to read X25519 key: {e}"))?;
        if data.len() == 32 {
            let mut private_key = [0u8; 32];
            private_key.copy_from_slice(&data);
            let secret = x25519_dalek::StaticSecret::from(private_key);
            let public_key = x25519_dalek::PublicKey::from(&secret);
            return Ok((private_key, *public_key.as_bytes()));
        }
    }

    let (private_key, public_key) = crate::crypto::generate_x25519_keypair();
    let parent = key_path.parent().ok_or("invalid X25519 key path")?;
    std::fs::create_dir_all(parent).map_err(|e| format!("failed to create X25519 key dir: {e}"))?;
    std::fs::write(&key_path, private_key)
        .map_err(|e| format!("failed to write X25519 key: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("failed to set X25519 key permissions: {e}"))?;
    }

    Ok((private_key, public_key))
}

#[cfg(test)]
// These tests hold the crate-wide env lock across mocked HTTP awaits so env
// mutation stays isolated for the whole request/response round-trip.
#[allow(clippy::await_holding_lock)]
mod tests {
    use super::*;
    #[cfg(debug_assertions)]
    use crate::sync::test_support::IsolatedVaultKeyEnv;
    use crate::sync::test_support::env_lock_guard;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

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
        assert!(
            err.contains("401"),
            "error must include the HTTP status so the caller can branch: {err}"
        );
    }

    #[tokio::test]
    async fn get_my_public_key_returns_some_on_2xx_with_key() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/users/me/public-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "publicKey": "abc=",
                "createdAt": null,
                "updatedAt": null,
            })))
            .expect(1)
            .mount(&server)
            .await;

        let key = get_my_public_key(&server.uri(), "token")
            .await
            .expect("happy path must succeed");
        assert_eq!(key.as_deref(), Some("abc="));
    }

    #[tokio::test]
    async fn get_my_public_key_returns_none_on_2xx_with_null_field() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/users/me/public-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "publicKey": null,
                "createdAt": null,
                "updatedAt": null,
            })))
            .expect(1)
            .mount(&server)
            .await;

        let key = get_my_public_key(&server.uri(), "token")
            .await
            .expect("null publicKey is the explicit 'no key' signal");
        assert!(key.is_none());
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

        let captured_for_responder = Arc::clone(&captured_proof);
        #[derive(Clone)]
        struct CaptureResponder {
            captured: Arc<StdMutex<Vec<Option<String>>>>,
        }
        impl Respond for CaptureResponder {
            fn respond(&self, request: &Request) -> ResponseTemplate {
                let proof = request
                    .headers
                    .get(CLI_STEP_UP_HEADER_NAME)
                    .map(|v| v.to_str().unwrap_or("").to_string());
                self.captured.lock().unwrap().push(proof);
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "ok": true,
                    "status": "set",
                    "fingerprintPrefix": "deadbeef0bad1dea",
                }))
            }
        }

        Mock::given(method("POST"))
            .and(path("/api/users/me/public-key"))
            .respond_with(CaptureResponder {
                captured: captured_for_responder,
            })
            .expect(2)
            .mount(&server)
            .await;

        // With a proof — header must be present and match.
        let result_with =
            upload_public_key(&server.uri(), "auth-token", "abc=", Some("proof-jwt-here"))
                .await
                .expect("happy path with proof");
        assert_eq!(result_with.status.as_deref(), Some("set"));
        assert_eq!(result_with.ok, Some(true));
        assert_eq!(
            result_with.fingerprint_prefix.as_deref(),
            Some("deadbeef0bad1dea")
        );

        // Without a proof — header must be absent.
        upload_public_key(&server.uri(), "auth-token", "abc=", None)
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
            .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
                "ok": false,
                "code": "step_up_required",
                "error": "Fresh step-up verification required.",
                "expectedScope": "vault:public-key:set",
                "header": CLI_STEP_UP_HEADER_NAME,
            })))
            .expect(1)
            .mount(&server)
            .await;

        let err = upload_public_key(&server.uri(), "token", "abc=", None)
            .await
            .expect_err("403 must propagate as Err");
        assert!(
            err.contains("step_up_required") || err.contains("Fresh step-up"),
            "error must surface the server envelope so the CLI can render the actionable hint: {err}"
        );
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn classify_public_key_state_matches_when_server_key_equals_local() {
        let _guard = env_lock_guard();
        let _isolated = IsolatedVaultKeyEnv::new();

        // Pre-warm the local keypair so we know its public form.
        let local = load_local_public_key_state().expect("load local keypair");

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/users/me/public-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "publicKey": local.public_key_b64.clone(),
            })))
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
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "publicKey": null,
            })))
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
        Mock::given(method("GET"))
            .and(path("/api/users/me/public-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "publicKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            })))
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
                assert_eq!(
                    server_public_key_b64,
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
                );
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
            .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
            .expect(1)
            .mount(&server)
            .await;

        let err = classify_public_key_state(&server.uri(), "token")
            .await
            .expect_err("server 500 must propagate, not be misclassified");
        assert!(err.contains("500"), "got: {err}");
    }

    #[cfg(debug_assertions)]
    #[test]
    fn pending_key_lifecycle_round_trips_through_create_read_promote() {
        // Create → read → promote, verifying that promote leaves the
        // live slot with the pending bytes and clears the pending file.
        let _guard = env_lock_guard();
        let _isolated = IsolatedVaultKeyEnv::new();

        // No pending at first.
        assert!(
            read_pending_x25519_keypair()
                .expect("read pending")
                .is_none(),
            "fresh HOME should have no pending key"
        );

        // Create — pending file now exists, live slot still untouched.
        let pending = create_pending_x25519_keypair().expect("create pending");
        let pending_path = pending_x25519_key_path().expect("path");
        let live_path = live_x25519_key_path().expect("path");
        assert!(pending_path.exists(), "create must persist the pending key");
        assert!(
            !live_path.exists(),
            "create must NOT touch the live slot until promotion"
        );

        // Read returns the same key bytes.
        let read_back = read_pending_x25519_keypair()
            .expect("read pending")
            .expect("pending should be present");
        assert_eq!(read_back.public_key_b64, pending.public_key_b64);

        // Promote — live slot now holds the pending bytes; pending is gone.
        promote_pending_x25519_keypair().expect("promote");
        assert!(live_path.exists(), "live slot must be present post-promote");
        assert!(
            !pending_path.exists(),
            "pending must be deleted after promote"
        );
        let live_bytes = std::fs::read(&live_path).expect("read live");
        assert_eq!(live_bytes, &pending.private_key);

        // Subsequent classify-equivalent: load_local_public_key_state
        // should see the new live key.
        let live = load_local_public_key_state().expect("load live");
        assert_eq!(live.public_key_b64, pending.public_key_b64);
    }

    #[cfg(debug_assertions)]
    #[test]
    fn pending_key_discard_removes_orphan_without_touching_live() {
        let _guard = env_lock_guard();
        let _isolated = IsolatedVaultKeyEnv::new();

        // Pre-seed a live key.
        let live = load_local_public_key_state().expect("seed live");
        let live_path = live_x25519_key_path().expect("path");
        assert!(live_path.exists());

        // Create + discard pending.
        let _ = create_pending_x25519_keypair().expect("create pending");
        let pending_path = pending_x25519_key_path().expect("path");
        assert!(pending_path.exists());

        discard_pending_x25519_keypair().expect("discard");
        assert!(!pending_path.exists());
        assert!(live_path.exists(), "discard must NOT touch live");
        // Live key bytes unchanged.
        let live_after = load_local_public_key_state().expect("load live");
        assert_eq!(live_after.public_key_b64, live.public_key_b64);
    }

    #[cfg(debug_assertions)]
    #[test]
    fn pending_key_promote_when_no_pending_is_explicit_error() {
        let _guard = env_lock_guard();
        let _isolated = IsolatedVaultKeyEnv::new();

        let err = promote_pending_x25519_keypair()
            .expect_err("promote with no pending must Err, not silently succeed");
        assert!(err.contains("no pending"), "got: {err}");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn x25519_backend_selection_uses_live_file_after_rotation_without_force_env() {
        assert!(
            should_use_file_backed_x25519_keypair(false, true),
            "a promoted live file must win over the default keychain path so post-rotation reads keep using the rotated key"
        );
        assert!(!should_use_file_backed_x25519_keypair(false, false));
        assert!(should_use_file_backed_x25519_keypair(true, false));
    }
}
