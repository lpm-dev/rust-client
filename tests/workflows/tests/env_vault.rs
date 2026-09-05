#![cfg(debug_assertions)]

mod support;

use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{AeadInPlace, generic_array::GenericArray},
};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use p256::SecretKey as P256SecretKey;
use sha2::{Digest, Sha256};
use support::assertions::parse_json_output;
use support::auth_state::{
    SessionSeed, credentials_path, read_credentials, read_expiry_metadata, seed_sessions,
    token_expiry_path, write_credentials_store,
};
use support::mock_registry::{
    MockRegistry, PersonalPullFailureFixture, SignedSyncResponse, TEST_OIDC_POLICY_ID,
    TestSyncScope, signed_personal_missing_response, signed_sync_response,
};
use support::{TempProject, lpm, write_private_file};
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, Request, Respond, ResponseTemplate};

const TEST_OIDC_POLICY_ID_2: &str = "22222222-2222-4222-8222-222222222222";

fn write_personal_bound_manifest(project: &TempProject, registry_url: &str, vault_id: &str) {
    project.write_file(
        "lpm.json",
        &personal_bound_manifest(registry_url, vault_id).to_string(),
    );
}

fn personal_bound_manifest(registry_url: &str, vault_id: &str) -> serde_json::Value {
    serde_json::json!({
        "vault": vault_id,
        "vaultSync": {
            "authorityCheckpoints": {
                "personal": {
                    registry_url: {
                        "account-1": {
                            "version": 1,
                            "syncedAt": "2026-09-05T00:00:00Z",
                        },
                    },
                },
            },
        },
    })
}

#[test]
fn env_oidc_allow_without_a_personal_binding_does_not_create_a_vault_manifest() {
    let project = TempProject::empty(r#"{"name":"vault-oidc-unbound","version":"1.0.0"}"#);
    let manifest_path = project.path().join("lpm.json");

    let output = lpm(&project)
        .args([
            "env",
            "oidc",
            "allow",
            "--provider=github",
            "--repo=acme/repo",
            "--repository-id=987654321",
            "--env=production",
            "--workflow=.github/workflows/deploy.yml",
        ])
        .output()
        .expect("run OIDC policy creation without a personal binding");

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("no authenticated personal binding"));
    assert!(
        !manifest_path.exists(),
        "a rejected OIDC policy command must not create lpm.json"
    );
}

struct ManifestReplacingSignedResponse {
    manifest_path: std::path::PathBuf,
    replacement: String,
    response: SignedSyncResponse,
}

impl Respond for ManifestReplacingSignedResponse {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        std::fs::write(&self.manifest_path, &self.replacement)
            .expect("replace lpm.json before returning the remote response");
        self.response.respond(request)
    }
}

struct ManifestReplacingResponse {
    manifest_path: std::path::PathBuf,
    replacement: String,
    response: SignedMemberInventoryResponse,
}

impl Respond for ManifestReplacingResponse {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        std::fs::write(&self.manifest_path, &self.replacement)
            .expect("replace lpm.json before returning the remote response");
        self.response.respond(request)
    }
}

struct CredentialsReplacingResponse {
    home: std::path::PathBuf,
    registry_url: String,
    replacement_token: String,
    response: SignedMemberInventoryResponse,
}

impl Respond for CredentialsReplacingResponse {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        write_credentials_store(
            &self.home,
            &serde_json::json!({
                (&self.registry_url): &self.replacement_token,
                (format!("refresh:{}", self.registry_url)): "org-share-refresh-token",
            }),
        );
        self.response.respond(request)
    }
}

#[derive(Clone)]
struct SignedMemberInventoryResponse {
    org_slug: String,
    organization_id: String,
    public_key_base64: String,
    fingerprint: String,
}

impl Respond for SignedMemberInventoryResponse {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let request_nonce = request
            .headers
            .get("x-lpm-vault-request-nonce")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        let body = serde_json::to_string(&serde_json::json!({
            "envelopeVersion": 3,
            "operation": "organization.memberKeys.read",
            "outcome": "current",
            "requestNonce": request_nonce,
            "binding": {
                "scope": "organization",
                "principalId": self.organization_id,
                "callerUserId": "11111111-1111-4111-8111-111111111111",
                "organizationSlug": self.org_slug,
            },
            "data": {
                "capability": "replaceWrappedKeysAllowed",
                "members": [{
                    "userId": "11111111-1111-4111-8111-111111111111",
                    "role": "owner",
                    "sharingKey": {
                        "algorithm": "X25519",
                        "publicKey": self.public_key_base64,
                        "version": 4,
                        "fingerprint": self.fingerprint,
                    },
                }],
            },
        }))
        .expect("member inventory response must serialize");
        let (key_id, signature) =
            lpm_vault::signature::sign_response_for_test(200, body.as_bytes());
        ResponseTemplate::new(200)
            .insert_header("Content-Type", "application/json")
            .insert_header(lpm_vault::signature::KEY_ID_HEADER, key_id.as_str())
            .insert_header(lpm_vault::signature::SIGNATURE_HEADER, signature.as_str())
            .set_body_string(body)
    }
}

fn signed_member_inventory_response(
    org_slug: &str,
    public_key_base64: &str,
    fingerprint: &str,
) -> SignedMemberInventoryResponse {
    SignedMemberInventoryResponse {
        org_slug: org_slug.to_owned(),
        organization_id: "00000000-0000-4000-8000-000000000001".to_owned(),
        public_key_base64: public_key_base64.to_owned(),
        fingerprint: fingerprint.to_owned(),
    }
}

fn signed_member_inventory_response_for_organization(
    org_slug: &str,
    organization_id: &str,
    public_key_base64: &str,
    fingerprint: &str,
) -> SignedMemberInventoryResponse {
    SignedMemberInventoryResponse {
        org_slug: org_slug.to_owned(),
        organization_id: organization_id.to_owned(),
        public_key_base64: public_key_base64.to_owned(),
        fingerprint: fingerprint.to_owned(),
    }
}

#[derive(Clone)]
struct SignedRejectedMemberInventoryResponse {
    org_slug: String,
    status: u16,
    code: String,
    message: String,
}

#[derive(Clone)]
struct SignedMissingOrgVaultResponse {
    org_slug: String,
    vault_id: String,
    retained_revision: i32,
}

#[derive(Clone)]
struct SignedOrgRevisionConflictResponse {
    org_slug: String,
    vault_id: String,
    current_revision: i32,
}

#[derive(Clone)]
struct SignedOrgMemberRewrapResponse {
    org_slug: String,
    vault_id: String,
}

impl Respond for SignedOrgMemberRewrapResponse {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let request_nonce = request
            .headers
            .get("x-lpm-vault-request-nonce")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        let body = serde_json::to_string(&serde_json::json!({
            "envelopeVersion": 3,
            "operation": "vault.pull",
            "outcome": "memberRewrapRequired",
            "requestNonce": request_nonce,
            "binding": {
                "scope": "organization",
                "principalId": "00000000-0000-4000-8000-000000000001",
                "callerUserId": "11111111-1111-4111-8111-111111111111",
                "organizationSlug": self.org_slug,
                "vaultId": self.vault_id,
            },
            "data": {
                "revision": 8,
                "contentKeyVersion": 3,
            },
        }))
        .expect("organization rewrap response must serialize");
        let (key_id, signature) =
            lpm_vault::signature::sign_response_for_test(403, body.as_bytes());
        ResponseTemplate::new(403)
            .insert_header("Content-Type", "application/json")
            .insert_header(lpm_vault::signature::KEY_ID_HEADER, key_id.as_str())
            .insert_header(lpm_vault::signature::SIGNATURE_HEADER, signature.as_str())
            .set_body_string(body)
    }
}

impl Respond for SignedOrgRevisionConflictResponse {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let request_nonce = request
            .headers
            .get("x-lpm-vault-request-nonce")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        let body = serde_json::to_string(&serde_json::json!({
            "envelopeVersion": 3,
            "operation": "vault.write",
            "outcome": "revisionConflict",
            "requestNonce": request_nonce,
            "binding": {
                "scope": "organization",
                "principalId": "00000000-0000-4000-8000-000000000001",
                "callerUserId": "11111111-1111-4111-8111-111111111111",
                "organizationSlug": self.org_slug,
                "vaultId": self.vault_id,
            },
            "data": {
                "currentRevision": self.current_revision,
            },
        }))
        .expect("organization revision conflict must serialize");
        let (key_id, signature) =
            lpm_vault::signature::sign_response_for_test(409, body.as_bytes());
        ResponseTemplate::new(409)
            .insert_header("Content-Type", "application/json")
            .insert_header(lpm_vault::signature::KEY_ID_HEADER, key_id.as_str())
            .insert_header(lpm_vault::signature::SIGNATURE_HEADER, signature.as_str())
            .set_body_string(body)
    }
}

impl Respond for SignedMissingOrgVaultResponse {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let request_nonce = request
            .headers
            .get("x-lpm-vault-request-nonce")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        let operation = if request
            .url
            .query_pairs()
            .any(|(key, value)| key == "versionOnly" && value == "true")
        {
            "vault.inspect"
        } else {
            "vault.pull"
        };
        let body = serde_json::to_string(&serde_json::json!({
            "envelopeVersion": 3,
            "operation": operation,
            "outcome": "missing",
            "requestNonce": request_nonce,
            "binding": {
                "scope": "organization",
                "principalId": "00000000-0000-4000-8000-000000000001",
                "callerUserId": "11111111-1111-4111-8111-111111111111",
                "organizationSlug": self.org_slug,
                "vaultId": self.vault_id,
            },
            "data": {
                "retainedRevision": self.retained_revision,
            },
        }))
        .expect("missing organization vault response must serialize");
        let (key_id, signature) =
            lpm_vault::signature::sign_response_for_test(404, body.as_bytes());
        ResponseTemplate::new(404)
            .insert_header("Content-Type", "application/json")
            .insert_header(lpm_vault::signature::KEY_ID_HEADER, key_id.as_str())
            .insert_header(lpm_vault::signature::SIGNATURE_HEADER, signature.as_str())
            .set_body_string(body)
    }
}

impl Respond for SignedRejectedMemberInventoryResponse {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let request_nonce = request
            .headers
            .get("x-lpm-vault-request-nonce")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        let body = serde_json::to_string(&serde_json::json!({
            "envelopeVersion": 3,
            "operation": "organization.memberKeys.read",
            "outcome": "rejected",
            "requestNonce": request_nonce,
            "binding": {
                "scope": "account",
                "principalId": "11111111-1111-4111-8111-111111111111",
                "organizationSlug": self.org_slug,
            },
            "data": {
                "code": self.code,
                "message": self.message,
            },
        }))
        .expect("member inventory rejection must serialize");
        let (key_id, signature) =
            lpm_vault::signature::sign_response_for_test(self.status, body.as_bytes());
        ResponseTemplate::new(self.status)
            .insert_header("Content-Type", "application/json")
            .insert_header(lpm_vault::signature::KEY_ID_HEADER, key_id.as_str())
            .insert_header(lpm_vault::signature::SIGNATURE_HEADER, signature.as_str())
            .set_body_string(body)
    }
}

fn doctor_check<'a>(json: &'a serde_json::Value, code: &str) -> &'a serde_json::Value {
    json["checks"]
        .as_array()
        .expect("doctor checks must be an array")
        .iter()
        .find(|check| check["code"].as_str() == Some(code))
        .unwrap_or_else(|| panic!("doctor output must include `{code}`: {json}"))
}

fn write_file_backed_vault(home: &std::path::Path, vault_id: &str, payload: serde_json::Value) {
    let lpm_dir = home.join(".lpm");
    let vaults_dir = lpm_dir.join("vaults");
    std::fs::create_dir_all(&vaults_dir).expect("failed to create test vault directory");

    let data_key = [0x42u8; 32];
    write_private_file(
        &lpm_dir.join(".vault-fallback-key"),
        format!("raw:{}", hex::encode(data_key)),
    );

    let plaintext =
        serde_json::to_string(&payload).expect("failed to serialize local vault payload");
    let cipher = Aes256Gcm::new_from_slice(&data_key).expect("failed to create vault cipher");
    let iv = [0x11u8; 12];
    let nonce = GenericArray::from_slice(&iv);
    let vault_id_bytes = vault_id.as_bytes();
    let vault_id_length = u32::try_from(vault_id_bytes.len()).expect("test vault ID length");
    let mut associated_data = Vec::with_capacity(20 + vault_id_bytes.len());
    associated_data.extend_from_slice(b"lpm-vault-local\x01");
    associated_data.extend_from_slice(&vault_id_length.to_be_bytes());
    associated_data.extend_from_slice(vault_id_bytes);
    let mut encrypted = plaintext.into_bytes();
    let auth_tag = cipher
        .encrypt_in_place_detached(nonce, &associated_data, &mut encrypted)
        .expect("failed to encrypt local vault payload");
    let encoded = format!(
        "{}:{}:{}",
        BASE64.encode(iv),
        BASE64.encode(auth_tag),
        BASE64.encode(encrypted)
    );

    write_private_file(&vaults_dir.join(format!("{vault_id}.enc")), encoded);
}

fn parse_clean_json_stdout(output: &std::process::Output) -> serde_json::Value {
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.trim_start().starts_with('{'),
        "JSON mode must not prefix stdout with human text:\nstdout:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stderr),
    );
    parse_json_output(&output.stdout)
}

fn seed_org_sharing_key(
    project: &TempProject,
    registry_url: &str,
) -> ([u8; 32], [u8; 32], String, String) {
    let (private_key, public_key) = lpm_vault::crypto::generate_x25519_keypair();
    let lpm_dir = project.home().join(".lpm");
    std::fs::create_dir_all(&lpm_dir).expect("create LPM home for sharing key");
    let mut scope_digest = Sha256::new();
    for component in [
        registry_url.trim_end_matches('/').as_bytes(),
        b"11111111-1111-4111-8111-111111111111".as_slice(),
    ] {
        scope_digest.update((component.len() as u64).to_be_bytes());
        scope_digest.update(component);
    }
    write_private_file(
        &lpm_dir.join(format!(
            ".x25519-key-{}",
            hex::encode(scope_digest.finalize())
        )),
        private_key,
    );
    let public_key_base64 = BASE64.encode(public_key);
    let fingerprint = hex::encode(Sha256::digest(public_key));
    (private_key, public_key, public_key_base64, fingerprint)
}

struct OrgRotationPullFixture<'a> {
    auth_token: &'a str,
    org_slug: &'a str,
    vault_id: &'a str,
    payload: &'a serde_json::Value,
    public_key: &'a [u8; 32],
    version: i32,
    content_key_version: i32,
    recipient_fingerprint: &'a str,
}

async fn mount_org_rotation_pull(
    mock: &MockRegistry,
    fixture: OrgRotationPullFixture<'_>,
) -> [u8; 32] {
    let plaintext = serde_json::to_vec(fixture.payload).expect("serialize org env payload");
    let content_key = lpm_vault::crypto::generate_aes_key();
    let encrypted_blob = lpm_vault::crypto::encrypt_vault_payload(
        &content_key,
        &plaintext,
        lpm_vault::crypto::VaultScope::Organization(fixture.org_slug),
        "00000000-0000-4000-8000-000000000001",
        fixture.vault_id,
        fixture.version,
    )
    .expect("encrypt org env payload");
    let wrapped_key = lpm_vault::crypto::wrap_key_for_recipient(&content_key, fixture.public_key)
        .expect("wrap org content key");
    let body = serde_json::json!({
        "vaultId": fixture.vault_id,
        "encryptedBlob": encrypted_blob,
        "wrappedKey": wrapped_key,
        "version": fixture.version,
        "cryptoVersion": lpm_vault::crypto::CURRENT_CRYPTO_VERSION,
        "contentKeyVersion": fixture.content_key_version,
        "recipientPublicKeyVersion": 4,
        "recipientPublicKeyFingerprint": fixture.recipient_fingerprint,
    });

    Mock::given(method("GET"))
        .and(path(format!(
            "/api/orgs/{}/vaults/{}",
            fixture.org_slug, fixture.vault_id
        )))
        .and(header(
            "authorization",
            format!("Bearer {}", fixture.auth_token),
        ))
        .respond_with(signed_sync_response(
            body,
            fixture.auth_token,
            fixture.vault_id,
            TestSyncScope::Organization(fixture.org_slug.to_owned()),
        ))
        .expect(1)
        .mount(mock.server())
        .await;

    content_key
}

async fn mount_org_member_keys(
    mock: &MockRegistry,
    auth_token: &str,
    org_slug: &str,
    public_key_base64: &str,
    fingerprint: &str,
) {
    Mock::given(method("GET"))
        .and(path(format!("/api/orgs/{org_slug}/members/public-keys")))
        .and(header("authorization", format!("Bearer {auth_token}")))
        .respond_with(signed_member_inventory_response(
            org_slug,
            public_key_base64,
            fingerprint,
        ))
        .expect(1)
        .mount(mock.server())
        .await;
}

async fn mount_org_rotation_push(
    mock: &MockRegistry,
    auth_token: &str,
    org_slug: &str,
    vault_id: &str,
    response: serde_json::Value,
) {
    Mock::given(method("POST"))
        .and(path(format!("/api/orgs/{org_slug}/vaults/{vault_id}")))
        .and(header("authorization", format!("Bearer {auth_token}")))
        .respond_with(signed_sync_response(
            response,
            auth_token,
            vault_id,
            TestSyncScope::Organization(org_slug.to_owned()),
        ))
        .expect(1)
        .mount(mock.server())
        .await;
}

const ORG_ROTATION_TOKEN: &str = "org-rotation-session-token";
const ORG_ROTATION_SLUG: &str = "acme";
const ORG_ROTATION_VAULT_ID: &str = "vault-org-rotate-123";

struct PreparedOrgRotation {
    private_key: [u8; 32],
    public_key_base64: String,
    fingerprint: String,
    previous_content_key: [u8; 32],
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct AcceptedRecipientSet<'a> {
    scope: AcceptedRecipientScope<'a>,
    recipients: [AcceptedRecipient<'a>; 1],
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct AcceptedRecipientScope<'a> {
    registry_url: &'a str,
    organization_id: &'static str,
    organization_slug: &'static str,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct AcceptedRecipient<'a> {
    user_id: &'static str,
    public_key_version: i32,
    public_key_fingerprint: &'a str,
}

fn org_rotation_recipient_acceptance(mock: &MockRegistry, fingerprint: &str) -> String {
    let registry_url = mock.url();
    let recipient_set = AcceptedRecipientSet {
        scope: AcceptedRecipientScope {
            registry_url: &registry_url,
            organization_id: "00000000-0000-4000-8000-000000000001",
            organization_slug: ORG_ROTATION_SLUG,
        },
        recipients: [AcceptedRecipient {
            user_id: "11111111-1111-4111-8111-111111111111",
            public_key_version: 4,
            public_key_fingerprint: fingerprint,
        }],
    };
    hex::encode(Sha256::digest(
        serde_json::to_vec(&recipient_set).expect("serialize accepted recipient set"),
    ))
}

async fn prepare_org_rotation(
    project: &TempProject,
    mock: &MockRegistry,
    payload: &serde_json::Value,
    stale_recipient_fingerprint: bool,
    mount_members: bool,
) -> PreparedOrgRotation {
    project.write_file(
        "lpm.json",
        &format!(r#"{{"vault":"{ORG_ROTATION_VAULT_ID}"}}"#),
    );
    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some(ORG_ROTATION_TOKEN),
            refresh_token: Some("org-rotation-refresh-token"),
            session_access_expires_at: Some("2030-01-01T00:00:00Z"),
        }],
    );
    let (private_key, public_key, public_key_base64, fingerprint) =
        seed_org_sharing_key(project, &mock.url());
    let recipient_fingerprint = if stale_recipient_fingerprint {
        "a".repeat(64)
    } else {
        fingerprint.clone()
    };
    let previous_content_key = mount_org_rotation_pull(
        mock,
        OrgRotationPullFixture {
            auth_token: ORG_ROTATION_TOKEN,
            org_slug: ORG_ROTATION_SLUG,
            vault_id: ORG_ROTATION_VAULT_ID,
            payload,
            public_key: &public_key,
            version: 8,
            content_key_version: 3,
            recipient_fingerprint: &recipient_fingerprint,
        },
    )
    .await;
    if mount_members {
        mount_org_member_keys(
            mock,
            ORG_ROTATION_TOKEN,
            ORG_ROTATION_SLUG,
            &public_key_base64,
            &fingerprint,
        )
        .await;
    }

    PreparedOrgRotation {
        private_key,
        public_key_base64,
        fingerprint,
        previous_content_key,
    }
}

#[test]
fn workflow_harness_removes_inherited_lpm_vault_id() {
    let project = TempProject::empty(r#"{"name":"vault-env-isolation-test","version":"1.0.0"}"#);
    let command = lpm(&project);

    let configured_value = command
        .get_envs()
        .find_map(|(name, value)| (name == std::ffi::OsStr::new("LPM_VAULT_ID")).then_some(value));

    assert_eq!(
        configured_value,
        Some(None),
        "workflow commands must not inherit LPM_VAULT_ID from the host",
    );
}

#[test]
fn env_set_with_a_named_environment_rejects_malformed_lpm_json_before_writing() {
    let project = TempProject::empty(r#"{"name":"env-config","version":"1.0.0"}"#);
    project.write_file("lpm.json", r#"{"env":{"prod":"production"}"#);

    let output = lpm(&project)
        .args(["env", "set", "--env=prod", "API_TOKEN=secret"])
        .output()
        .expect("run env set with malformed lpm.json");

    assert!(
        !output.status.success(),
        "a named env operation must not ignore malformed alias configuration"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("failed to parse lpm.json"),
        "the failure must identify malformed lpm.json:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn env_oidc_allow_help_is_a_successful_non_mutating_help_surface() {
    let project = TempProject::empty(r#"{"name":"oidc-help","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["env", "oidc", "allow", "--help"])
        .output()
        .expect("run env oidc allow --help");

    assert!(
        output.status.success(),
        "OIDC allow help must not be parsed as a policy mutation"
    );
    let rendered = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(rendered.contains("--provider=github"));
    assert!(rendered.contains("--provider=gitlab"));
    assert!(rendered.contains("--project-id"));
}

#[test]
fn doctor_json_reports_file_vault_fallback_when_forced_file_backend_is_active() {
    let project = TempProject::empty(r#"{"name":"vault-doctor","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["doctor", "--json"])
        .output()
        .expect("failed to run lpm doctor --json");
    let json = parse_json_output(&output.stdout);
    let check = doctor_check(&json, "vault_storage_fallback");

    assert_eq!(check["severity"].as_str(), Some("warn"));
    assert_eq!(check["passed"].as_bool(), Some(true));
}

#[cfg(not(target_os = "macos"))]
#[test]
fn doctor_json_reports_native_vault_storage_when_native_key_is_active() {
    let project = TempProject::empty(r#"{"name":"vault-doctor","version":"1.0.0"}"#);
    let native_key_hex = hex::encode([0x5au8; 32]);

    let output = lpm(&project)
        .env_remove("LPM_FORCE_FILE_VAULT")
        .env("LPM_TEST_VAULT_NATIVE_KEY_HEX", native_key_hex)
        .args(["doctor", "--json"])
        .output()
        .expect("failed to run lpm doctor --json");
    let json = parse_json_output(&output.stdout);
    let check = doctor_check(&json, "vault_storage_native");

    assert_eq!(check["severity"].as_str(), Some("pass"));
    assert_eq!(check["passed"].as_bool(), Some(true));
}

#[cfg(not(target_os = "macos"))]
#[test]
fn doctor_json_reports_unavailable_vault_storage_when_blob_has_no_key_source() {
    let project = TempProject::empty(r#"{"name":"vault-doctor","version":"1.0.0"}"#);
    let vaults_dir = project.home().join(".lpm").join("vaults");
    std::fs::create_dir_all(&vaults_dir).expect("failed to create vaults dir");
    std::fs::write(
        vaults_dir.join("missing-key.enc"),
        "not decrypted during status",
    )
    .expect("failed to seed vault blob");

    let output = lpm(&project)
        .env_remove("LPM_FORCE_FILE_VAULT")
        .env(
            "LPM_TEST_VAULT_NATIVE_KEY_READ_ERROR",
            "native store locked",
        )
        .args(["doctor", "--json"])
        .output()
        .expect("failed to run lpm doctor --json");
    let json = parse_json_output(&output.stdout);
    let check = doctor_check(&json, "vault_storage_unavailable");

    assert_eq!(check["severity"].as_str(), Some("fail"));
    assert_eq!(check["passed"].as_bool(), Some(false));
    assert!(
        check["detail"]
            .as_str()
            .is_some_and(|detail| detail.contains("native store locked")),
        "unavailable detail should include native backend error: {check}"
    );
}

#[tokio::test]
async fn env_log_refreshes_a_rejected_stored_access_token_before_reading_audit_events() {
    let project = TempProject::empty(r#"{"name":"env-log-refresh","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    project.write_file("lpm.json", r#"{"vault":"vault-log-refresh"}"#);

    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some("rejected-access-token"),
            refresh_token: Some("refresh-token"),
            session_access_expires_at: Some("2099-01-01T00:00:00Z"),
        }],
    );
    Mock::given(method("GET"))
        .and(path("/api/vaults/vault-log-refresh/audit"))
        .and(header("authorization", "Bearer rejected-access-token"))
        .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
            "error": "Unauthorized",
        })))
        .expect(1)
        .mount(mock.server())
        .await;
    mock.with_refresh_expected(
        "refresh-token",
        "refreshed-access-token",
        "rotated-refresh-token",
        "2030-01-02T00:00:00Z",
        1,
    )
    .await;
    Mock::given(method("GET"))
        .and(path("/api/vaults/vault-log-refresh/audit"))
        .and(header("authorization", "Bearer refreshed-access-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "entries": [],
            "nextCursor": null,
        })))
        .expect(1)
        .mount(mock.server())
        .await;

    let manifest_read_log = project.path().join("env-log-manifest-reads.log");
    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .env("LPM_TEST_MANIFEST_READ_LOG", &manifest_read_log)
        .args(["--json", "env", "log"])
        .output()
        .expect("run env log with a refreshable session");

    assert!(
        output.status.success(),
        "env log did not recover the rejected access token:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert_eq!(
        std::fs::read_to_string(manifest_read_log)
            .expect("read env-log manifest access log")
            .lines()
            .count(),
        1,
        "env log needs one validated command snapshot",
    );
}

#[tokio::test]
async fn env_log_does_not_require_whoami_when_the_env_api_accepts_the_session() {
    let project = TempProject::empty(r#"{"name":"env-log-no-whoami","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    project.write_file("lpm.json", r#"{"vault":"vault-log-no-whoami"}"#);

    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some("accepted-access-token"),
            refresh_token: Some("refresh-token"),
            session_access_expires_at: Some("2099-01-01T00:00:00Z"),
        }],
    );
    Mock::given(method("GET"))
        .and(path("/api/registry/-/whoami"))
        .respond_with(ResponseTemplate::new(503))
        .expect(0)
        .mount(mock.server())
        .await;
    Mock::given(method("GET"))
        .and(path("/api/vaults/vault-log-no-whoami/audit"))
        .and(header("authorization", "Bearer accepted-access-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "entries": [],
            "nextCursor": null,
        })))
        .expect(1)
        .mount(mock.server())
        .await;

    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["--json", "env", "log"])
        .output()
        .expect("run env log without a whoami route");

    assert!(
        output.status.success(),
        "env log incorrectly depended on whoami:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[tokio::test]
async fn env_log_binds_the_bearer_to_the_explicit_registry_origin() {
    let project = TempProject::empty(r#"{"name":"env-log-origin","version":"1.0.0"}"#);
    let selected = MockRegistry::start().await;
    let conflicting = MockRegistry::start().await;
    let selected_url = selected.url();
    let conflicting_url = conflicting.url();
    project.write_file("lpm.json", r#"{"vault":"vault-log-origin"}"#);

    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &selected_url,
            access_token: Some("selected-origin-token"),
            refresh_token: Some("selected-origin-refresh-token"),
            session_access_expires_at: Some("2030-01-01T00:00:00Z"),
        }],
    );
    Mock::given(method("GET"))
        .and(path("/api/vaults/vault-log-origin/audit"))
        .and(header("authorization", "Bearer selected-origin-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "entries": [],
            "nextCursor": null,
        })))
        .expect(1)
        .mount(selected.server())
        .await;
    Mock::given(method("GET"))
        .and(path("/api/vaults/vault-log-origin/audit"))
        .and(header("authorization", "Bearer selected-origin-token"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(conflicting.server())
        .await;

    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", &conflicting_url)
        .args(["--registry", selected_url.as_str(), "--json", "env", "log"])
        .output()
        .expect("run env log with an explicit registry");

    assert!(
        output.status.success(),
        "env log did not stay bound to the explicit registry:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[tokio::test]
async fn env_unpair_refreshes_after_an_authoritative_unauthorized_response() {
    let project = TempProject::empty(r#"{"name":"env-unpair-refresh","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;

    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some("rejected-access-token"),
            refresh_token: Some("refresh-token"),
            session_access_expires_at: Some("2099-01-01T00:00:00Z"),
        }],
    );
    mock.with_current_principal("rejected-access-token", "account-1", 1)
        .await;
    mock.with_revoke_all_pairings_for_principal_status(
        "rejected-access-token",
        "account-1",
        401,
        1,
    )
    .await;
    mock.with_refresh_expected(
        "refresh-token",
        "refreshed-access-token",
        "rotated-refresh-token",
        "2030-01-02T00:00:00Z",
        1,
    )
    .await;
    mock.with_revoke_all_pairings_for_principal_status(
        "refreshed-access-token",
        "account-1",
        200,
        1,
    )
    .await;

    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["--json", "env", "unpair"])
        .output()
        .expect("run env unpair with a rejected access token");

    assert!(
        output.status.success(),
        "env unpair did not recover after 401:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[tokio::test]
async fn env_unpair_retry_remains_bound_to_the_principal_captured_before_refresh() {
    let project = TempProject::empty(r#"{"name":"env-unpair-account-switch","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;

    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some("account-a-access"),
            refresh_token: Some("account-switch-refresh"),
            session_access_expires_at: Some("2099-01-01T00:00:00Z"),
        }],
    );
    mock.with_current_principal("account-a-access", "account-a", 1)
        .await;
    mock.with_current_principal("account-b-access", "account-b", 0)
        .await;
    mock.with_revoke_all_pairings_for_principal_status("account-a-access", "account-a", 401, 1)
        .await;
    mock.with_refresh_expected(
        "account-switch-refresh",
        "account-b-access",
        "account-b-refresh",
        "2030-01-02T00:00:00Z",
        1,
    )
    .await;
    mock.with_revoke_all_pairings_for_principal_status("account-b-access", "account-a", 409, 1)
        .await;

    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["--json", "env", "unpair"])
        .output()
        .expect("run env unpair across an account-switching refresh");

    assert!(
        !output.status.success(),
        "unpair must not retarget a retry to the refreshed account"
    );
}

#[tokio::test]
async fn env_unpair_does_not_replay_or_refresh_after_a_server_error() {
    let project = TempProject::empty(r#"{"name":"env-unpair-503","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let registry_url = mock.url();

    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &registry_url,
            access_token: Some("accepted-access-token"),
            refresh_token: Some("refresh-token"),
            session_access_expires_at: Some("2099-01-01T00:00:00Z"),
        }],
    );
    let credentials_before = read_credentials(project.home());
    mock.with_current_principal("accepted-access-token", "account-1", 1)
        .await;
    mock.with_revoke_all_pairings_for_principal_status(
        "accepted-access-token",
        "account-1",
        503,
        1,
    )
    .await;
    mock.with_refresh_expected(
        "refresh-token",
        "unused-access-token",
        "unused-refresh-token",
        "2030-01-02T00:00:00Z",
        0,
    )
    .await;

    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", &registry_url)
        .args(["--json", "env", "unpair"])
        .output()
        .expect("run env unpair while the server is unavailable");

    assert!(
        !output.status.success() && read_credentials(project.home()) == credentials_before,
        "env unpair retried an ambiguous mutation or changed credentials:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[tokio::test]
async fn env_pair_uppercases_code_and_approves_browser_pairing() {
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    let project = TempProject::empty(r#"{"name":"vault-pair-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;

    let browser_secret = P256SecretKey::random(&mut rand::thread_rng());
    let browser_public_key = BASE64.encode(
        browser_secret
            .public_key()
            .to_encoded_point(false)
            .as_bytes(),
    );
    mock.with_current_principal("session-access-token", "account-1", 1)
        .await;
    mock.with_pairing_session("ABC123", "session-access-token", &browser_public_key)
        .await;
    mock.with_pairing_approval("ABC123", "session-access-token")
        .await;

    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some("session-access-token"),
            refresh_token: Some("refresh-token"),
            session_access_expires_at: Some("2030-01-01T00:00:00Z"),
        }],
    );

    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["env", "pair", "abc123", "--yes"])
        .output()
        .expect("failed to run lpm env pair");

    assert!(
        output.status.success(),
        "pair command failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined_output = format!("{stdout}\n{stderr}");
    assert!(
        combined_output.contains("browser paired successfully")
            || combined_output.contains("dashboard can now decrypt your vault secrets"),
        "expected pairing success output, got combined output: {combined_output}"
    );
    assert!(
        project.home().join(".lpm").join(".vault-key").exists(),
        "workflow vault pairing should use the file-backed wrapping key in isolated HOME"
    );
}

#[tokio::test]
async fn env_pair_stage_retry_remains_bound_to_the_principal_captured_before_refresh() {
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    let project =
        TempProject::empty(r#"{"name":"env-pair-stage-account-switch","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let browser_secret = P256SecretKey::random(&mut rand::thread_rng());
    let browser_public_key = BASE64.encode(
        browser_secret
            .public_key()
            .to_encoded_point(false)
            .as_bytes(),
    );

    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some("account-a-access"),
            refresh_token: Some("account-switch-refresh"),
            session_access_expires_at: Some("2099-01-01T00:00:00Z"),
        }],
    );
    mock.with_current_principal("account-a-access", "account-a", 1)
        .await;
    mock.with_current_principal("account-b-access", "account-b", 0)
        .await;
    mock.with_pairing_session("STG123", "account-a-access", &browser_public_key)
        .await;
    mock.with_pairing_stage_for_principal_status("STG123", "account-a-access", "account-a", 401, 1)
        .await;
    mock.with_refresh_expected(
        "account-switch-refresh",
        "account-b-access",
        "account-b-refresh",
        "2030-01-02T00:00:00Z",
        1,
    )
    .await;
    mock.with_pairing_stage_for_principal_status("STG123", "account-b-access", "account-a", 409, 1)
        .await;
    mock.with_pairing_final_approval_for_principal_status(
        "STG123",
        "account-b-access",
        "account-a",
        200,
        0,
    )
    .await;

    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["--json", "env", "pair", "stg123", "--yes"])
        .output()
        .expect("run env pair stage across an account-switching refresh");

    assert!(
        !output.status.success(),
        "pair stage must not retarget a retry to the refreshed account"
    );
    assert!(!project.home().join(".lpm").join(".vault-key").exists());
}

#[tokio::test]
async fn env_pair_approval_retry_remains_bound_to_the_principal_captured_before_refresh() {
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    let project =
        TempProject::empty(r#"{"name":"env-pair-approval-account-switch","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let browser_secret = P256SecretKey::random(&mut rand::thread_rng());
    let browser_public_key = BASE64.encode(
        browser_secret
            .public_key()
            .to_encoded_point(false)
            .as_bytes(),
    );

    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some("account-a-access"),
            refresh_token: Some("account-switch-refresh"),
            session_access_expires_at: Some("2099-01-01T00:00:00Z"),
        }],
    );
    mock.with_current_principal("account-a-access", "account-a", 1)
        .await;
    mock.with_current_principal("account-b-access", "account-b", 0)
        .await;
    mock.with_pairing_session("APR123", "account-a-access", &browser_public_key)
        .await;
    mock.with_pairing_stage_for_principal_status("APR123", "account-a-access", "account-a", 200, 1)
        .await;
    mock.with_pairing_final_approval_for_principal_status(
        "APR123",
        "account-a-access",
        "account-a",
        401,
        1,
    )
    .await;
    mock.with_refresh_expected(
        "account-switch-refresh",
        "account-b-access",
        "account-b-refresh",
        "2030-01-02T00:00:00Z",
        1,
    )
    .await;
    mock.with_pairing_final_approval_for_principal_status(
        "APR123",
        "account-b-access",
        "account-a",
        409,
        1,
    )
    .await;

    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["--json", "env", "pair", "apr123", "--yes"])
        .output()
        .expect("run env pair approval across an account-switching refresh");

    assert!(
        !output.status.success(),
        "pair approval must not retarget a retry to the refreshed account"
    );
}

#[tokio::test]
async fn env_pair_refuses_when_stdin_is_not_a_tty_and_yes_flag_absent() {
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    // The headline H1 phishing payload — "run this command from a tutorial /
    // pipe / heredoc" — relies on the CLI completing the wrap with no human
    // pause. Defense: refuse outright unless either (a) the user is sitting at
    // a real terminal where the confirmation prompt can render, or (b) the
    // user explicitly passed --yes after reading the help. The mock pair
    // routes are mounted with `.expect(0)` so the regression check fails if
    // the CLI ever reaches the GET (let alone the approve POST).
    let project = TempProject::empty(r#"{"name":"vault-pair-non-tty-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;

    let browser_secret = P256SecretKey::random(&mut rand::thread_rng());
    let browser_public_key = BASE64.encode(
        browser_secret
            .public_key()
            .to_encoded_point(false)
            .as_bytes(),
    );
    mock.with_current_principal("session-access-token", "account-1", 0)
        .await;
    mock.with_pairing_session_call_count("NOTTY1", "session-access-token", &browser_public_key, 0)
        .await;
    mock.with_pairing_approval_call_count("NOTTY1", "session-access-token", 0)
        .await;

    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some("session-access-token"),
            refresh_token: Some("refresh-token"),
            session_access_expires_at: Some("2030-01-01T00:00:00Z"),
        }],
    );

    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["env", "pair", "notty1"])
        .output()
        .expect("failed to spawn lpm env pair without --yes");

    assert!(
        !output.status.success(),
        "pair without --yes on non-TTY stdin must FAIL — refusing the wrap is the H1 fix.\n\
         stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("interactive terminal") || stderr.contains("--yes"),
        "stderr must explain why the pair refused and how to bypass: {stderr}"
    );
}

#[tokio::test]
async fn env_pair_with_yes_prints_browser_key_fingerprint_and_match_number_before_approving() {
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    let project = TempProject::empty(r#"{"name":"vault-pair-meta-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;

    let browser_secret = P256SecretKey::random(&mut rand::thread_rng());
    let browser_public_key = BASE64.encode(
        browser_secret
            .public_key()
            .to_encoded_point(false)
            .as_bytes(),
    );

    mock.with_current_principal("session-access-token", "account-1", 1)
        .await;
    mock.with_pairing_session_with_metadata(
        "META01",
        "session-access-token",
        &browser_public_key,
        Some("Safari on iOS"),
        Some("2026-05-20T12:34:56Z"),
        Some("203.0.113.0/24"),
    )
    .await;
    mock.with_pairing_approval("META01", "session-access-token")
        .await;

    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some("session-access-token"),
            refresh_token: Some("refresh-token"),
            session_access_expires_at: Some("2030-01-01T00:00:00Z"),
        }],
    );

    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["env", "pair", "meta01", "--yes"])
        .output()
        .expect("failed to run lpm env pair --yes");

    assert!(
        output.status.success(),
        "pair --yes with metadata-rich session failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    // Audit trail: even with --yes, the binding info must be in the
    // terminal scrollback so the user has post-hoc evidence of what they
    // approved sight-unseen.
    assert!(
        combined.contains("Browser key fingerprint"),
        "binding info missing — expected fingerprint label: {combined}"
    );
    assert!(
        combined.contains("Safari on iOS"),
        "binding info missing — expected sanitized device label: {combined}"
    );
    assert!(
        combined.contains("203.0.113.0/24"),
        "binding info missing — expected createdFromIp: {combined}"
    );
    assert!(
        combined.contains("Verify the dashboard shows the same number"),
        "binding info missing — expected match-number caption: {combined}"
    );
    assert!(
        combined.contains("skipped browser-identity verification"),
        "--yes audit warning missing: {combined}"
    );
}

#[tokio::test]
async fn env_unpair_rejects_incomplete_session_credentials() {
    let project =
        TempProject::empty(r#"{"name":"vault-unpair-incomplete-session-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;

    mock.with_current_principal("incomplete-session-token", "account-1", 0)
        .await;
    mock.with_revoke_all_pairings_for_principal_status(
        "incomplete-session-token",
        "account-1",
        200,
        0,
    )
    .await;

    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some("incomplete-session-token"),
            refresh_token: None,
            session_access_expires_at: None,
        }],
    );

    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["env", "unpair"])
        .output()
        .expect("failed to run lpm env unpair");

    assert!(
        !output.status.success(),
        "unpair unexpectedly succeeded for incomplete session credentials:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not logged in"),
        "expected incomplete-session rejection, got stderr: {stderr}"
    );
}

#[tokio::test]
async fn env_pull_overwrites_local_state_with_remote_environments() {
    let project = TempProject::empty(r#"{"name":"vault-pull-overwrite-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let vault_id = "vault-pull-overwrite";

    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some("session-access-token"),
            refresh_token: Some("refresh-token"),
            session_access_expires_at: Some("2030-01-01T00:00:00Z"),
        }],
    );

    project.write_file(
        "lpm.json",
        &serde_json::json!({
            "vault": vault_id,
        })
        .to_string(),
    );
    write_file_backed_vault(
        project.home(),
        vault_id,
        serde_json::json!({
            "environments": {
                "default": {
                    "STALE_DEFAULT": "old-default",
                    "REMOVE_ME": "local-only"
                },
                "preview": {
                    "PREVIEW_ONLY": "stale-preview",
                    "SHARED_ENV": "stale-preview"
                }
            }
        }),
    );

    let wrapping_key = [0x52; 32];
    let data_key = [0x53; 32];
    write_private_file(
        &project.home().join(".lpm").join(".vault-key"),
        hex::encode(wrapping_key),
    );
    mock.with_personal_pull_keys(
        vault_id,
        "session-access-token",
        serde_json::json!({
            "environments": {
                "default": {
                    "API_URL": "https://api.example.com",
                    "SHARED_ENV": "remote-default"
                },
                "live": {
                    "LIVE_ONLY": "remote-live"
                }
            }
        }),
        &wrapping_key,
        &data_key,
        7,
    )
    .await;

    let pull = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["env", "pull", "--yes"])
        .output()
        .expect("failed to run personal vars pull");

    assert!(
        pull.status.success(),
        "personal vars pull failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&pull.stdout),
        String::from_utf8_lossy(&pull.stderr),
    );

    let default_list = lpm(&project)
        .args(["--json", "env", "list", "--reveal"])
        .output()
        .expect("failed to list default vault secrets after pull");
    assert!(
        default_list.status.success(),
        "default list after pull failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&default_list.stdout),
        String::from_utf8_lossy(&default_list.stderr),
    );
    assert_eq!(
        parse_json_output(&default_list.stdout),
        serde_json::json!({
            "API_URL": "https://api.example.com",
            "SHARED_ENV": "remote-default"
        })
    );

    let live_list = lpm(&project)
        .args(["--json", "env", "list", "--env=live", "--reveal"])
        .output()
        .expect("failed to list live vault secrets after pull");
    assert!(
        live_list.status.success(),
        "live list after pull failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&live_list.stdout),
        String::from_utf8_lossy(&live_list.stderr),
    );
    assert_eq!(
        parse_json_output(&live_list.stdout),
        serde_json::json!({
            "LIVE_ONLY": "remote-live"
        })
    );

    let preview_list = lpm(&project)
        .args(["--json", "env", "list", "--env=preview", "--reveal"])
        .output()
        .expect("failed to list preview vault secrets after pull");
    assert!(
        preview_list.status.success(),
        "preview list after pull failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&preview_list.stdout),
        String::from_utf8_lossy(&preview_list.stderr),
    );
    assert_eq!(
        parse_json_output(&preview_list.stdout),
        serde_json::json!({})
    );

    let synced_config: serde_json::Value =
        serde_json::from_str(&project.read_file("lpm.json")).expect("failed to re-read lpm.json");
    assert_eq!(synced_config["vault"].as_str(), Some(vault_id));
    assert_eq!(
        synced_config["vaultSync"]["personalVersion"].as_i64(),
        Some(7)
    );
}

#[tokio::test]
async fn env_pull_joined_org_selector_never_falls_back_to_personal_scope() {
    let project = TempProject::empty(r#"{"name":"vault-pull-org-scope-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let vault_id = "vault-pull-org-scope";

    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some("session-access-token"),
            refresh_token: Some("refresh-token"),
            session_access_expires_at: Some("2030-01-01T00:00:00Z"),
        }],
    );
    project.write_file(
        "lpm.json",
        &serde_json::json!({ "vault": vault_id }).to_string(),
    );
    write_file_backed_vault(
        project.home(),
        vault_id,
        serde_json::json!({
            "environments": {
                "default": { "KEEP": "local" }
            }
        }),
    );

    let wrapping_key = [0x62; 32];
    write_private_file(
        &project.home().join(".lpm").join(".vault-key"),
        hex::encode(wrapping_key),
    );

    let pull = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["env", "pull", "--org=acme", "--yes"])
        .output()
        .expect("failed to run organization-scoped env pull");

    assert!(
        !pull.status.success(),
        "an organization-scoped pull unexpectedly used personal data:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&pull.stdout),
        String::from_utf8_lossy(&pull.stderr),
    );
    let requests = mock.server().received_requests().await.unwrap();
    assert!(
        requests
            .iter()
            .all(|request| request.url.path() != format!("/api/vaults/{vault_id}/sync")),
        "organization selector reached the personal sync endpoint: {requests:?}"
    );

    let local = lpm(&project)
        .args(["--json", "env", "list", "--reveal"])
        .output()
        .expect("failed to read local env after rejected organization pull");
    assert_eq!(
        parse_json_output(&local.stdout),
        serde_json::json!({ "KEEP": "local" })
    );
}

#[tokio::test]
async fn env_pull_rejects_a_different_bound_account_before_local_overwrite() {
    let project = TempProject::empty(r#"{"name":"pull-account-binding","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let vault_id = "vault-account-binding";
    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some("session-access-token"),
            refresh_token: Some("refresh-token"),
            session_access_expires_at: Some("2030-01-01T00:00:00Z"),
        }],
    );
    project.write_file(
        "lpm.json",
        &serde_json::json!({
            "vault": vault_id,
            "vaultSync": {
                "authorityCheckpoints": {
                    "personal": {
                        (mock.url()): {
                            "account-a": {
                                "version": 7,
                                "syncedAt": "2026-09-05T00:00:00Z",
                            },
                        },
                    },
                }
            }
        })
        .to_string(),
    );
    write_file_backed_vault(
        project.home(),
        vault_id,
        serde_json::json!({
            "environments": {
                "default": {"ORIGINAL": "local"}
            }
        }),
    );
    let vault_path = project
        .home()
        .join(".lpm")
        .join("vaults")
        .join(format!("{vault_id}.enc"));
    let before_vault = std::fs::read(&vault_path).expect("read local vault before pull");
    let before_manifest = project.read_file("lpm.json");

    Mock::given(method("GET"))
        .and(path(format!("/api/vaults/{vault_id}/sync")))
        .and(header("authorization", "Bearer session-access-token"))
        .respond_with(signed_sync_response(
            serde_json::json!({
                "encryptedBlob": "invalid-ciphertext",
                "wrappedKey": "invalid-wrapped-key",
                "version": 8,
                "cryptoVersion": lpm_vault::crypto::CURRENT_CRYPTO_VERSION,
                "principalId": "account-b"
            }),
            "session-access-token",
            vault_id,
            TestSyncScope::Personal,
        ))
        .expect(1)
        .mount(mock.server())
        .await;

    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["--json", "env", "pull", "--yes"])
        .output()
        .expect("run pull under a different account");

    assert!(!output.status.success());
    let error = parse_json_output(&output.stdout);
    assert!(
        error["error"]
            .as_str()
            .is_some_and(|message| message.contains("different account")),
        "unexpected error: {error}"
    );
    assert_eq!(
        std::fs::read(&vault_path).expect("read local vault after rejected pull"),
        before_vault,
    );
    assert_eq!(project.read_file("lpm.json"), before_manifest);
}

#[tokio::test]
async fn env_pull_rejects_semantically_invalid_lpm_json_before_network_or_local_overwrite() {
    let project = TempProject::empty(r#"{"name":"pull-invalid-config","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    project.write_file(
        "lpm.json",
        r#"{"vault":"vault-invalid-pull","env":{"prod":123}}"#,
    );
    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some("session-access-token"),
            refresh_token: Some("refresh-token"),
            session_access_expires_at: Some("2030-01-01T00:00:00Z"),
        }],
    );
    write_file_backed_vault(
        project.home(),
        "vault-invalid-pull",
        serde_json::json!({
            "environments": {
                "default": {"KEEP": "local"}
            }
        }),
    );
    let vault_path = project.home().join(".lpm/vaults/vault-invalid-pull.enc");
    let original_vault = std::fs::read(&vault_path).expect("read original local vault");

    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["env", "pull", "--yes"])
        .output()
        .expect("run env pull with semantically invalid lpm.json");

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("lpm.json"),
        "the failure must identify the invalid project configuration"
    );
    assert!(
        mock.server().received_requests().await.unwrap().is_empty(),
        "canonical validation must happen before authentication or pull requests"
    );
    assert_eq!(
        std::fs::read(vault_path).expect("read local vault after rejected pull"),
        original_vault
    );
}

#[tokio::test]
async fn env_pair_refresh_only_session_then_unpair_reuses_normalized_session() {
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    let project =
        TempProject::empty(r#"{"name":"vault-pair-refresh-chain-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;

    let browser_secret = P256SecretKey::random(&mut rand::thread_rng());
    let browser_public_key = BASE64.encode(
        browser_secret
            .public_key()
            .to_encoded_point(false)
            .as_bytes(),
    );

    mock.with_refresh_expected(
        "refresh-seed-token",
        "access-from-refresh",
        "refresh-rotated-token",
        "2030-01-01T00:00:00Z",
        1,
    )
    .await;
    mock.with_current_principal("access-from-refresh", "account-1", 2)
        .await;
    mock.with_pairing_session("RFH123", "access-from-refresh", &browser_public_key)
        .await;
    mock.with_pairing_approval("RFH123", "access-from-refresh")
        .await;
    mock.with_revoke_all_pairings_for_principal_status("access-from-refresh", "account-1", 200, 1)
        .await;

    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: None,
            refresh_token: Some("refresh-seed-token"),
            session_access_expires_at: None,
        }],
    );

    let pair = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["env", "pair", "rfh123", "--yes"])
        .output()
        .expect("failed to run lpm env pair with refresh-only session");

    assert!(
        pair.status.success(),
        "pair with refresh-only session failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&pair.stdout),
        String::from_utf8_lossy(&pair.stderr),
    );

    let credentials = read_credentials(project.home());
    assert_eq!(credentials[&mock.url()], "access-from-refresh");
    assert_eq!(
        credentials[&format!("refresh:{}", mock.url())],
        "refresh-rotated-token"
    );

    let expiry = read_expiry_metadata(project.home());
    assert_eq!(
        expiry[&mock.url()]["session_access_expires_at"],
        "2030-01-01T00:00:00Z"
    );

    let unpair = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["env", "unpair"])
        .output()
        .expect("failed to run lpm env unpair after refresh-only pairing");

    assert!(
        unpair.status.success(),
        "unpair after refresh-only pairing failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&unpair.stdout),
        String::from_utf8_lossy(&unpair.stderr),
    );
}

#[tokio::test]
async fn env_pair_then_logout_revoke_revokes_pairings_and_blocks_future_pairing_commands() {
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    let project = TempProject::empty(r#"{"name":"vault-pair-logout-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;

    let browser_secret = P256SecretKey::random(&mut rand::thread_rng());
    let browser_public_key = BASE64.encode(
        browser_secret
            .public_key()
            .to_encoded_point(false)
            .as_bytes(),
    );
    mock.with_current_principal("session-access-token", "account-1", 2)
        .await;
    mock.with_pairing_session("PAIR01", "session-access-token", &browser_public_key)
        .await;
    mock.with_pairing_approval("PAIR01", "session-access-token")
        .await;
    mock.with_revoke_all_pairings_for_principal_status("session-access-token", "account-1", 200, 1)
        .await;
    mock.with_revoke_token("session-access-token").await;

    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some("session-access-token"),
            refresh_token: Some("refresh-token"),
            session_access_expires_at: Some("2030-01-01T00:00:00Z"),
        }],
    );

    let pair = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["env", "pair", "pair01", "--yes"])
        .output()
        .expect("failed to run pair before logout");

    assert!(
        pair.status.success(),
        "pair before logout failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&pair.stdout),
        String::from_utf8_lossy(&pair.stderr),
    );
    assert!(
        project.home().join(".lpm").join(".vault-key").exists(),
        "pair should materialize the local wrapping key file in isolated HOME"
    );

    let logout = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["logout", "--revoke"])
        .output()
        .expect("failed to run logout after pairing");

    assert!(
        logout.status.success(),
        "logout after pairing failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&logout.stdout),
        String::from_utf8_lossy(&logout.stderr),
    );

    assert!(
        !credentials_path(project.home()).exists(),
        "logout should remove credentials after revoking pairings"
    );

    if token_expiry_path(project.home()).exists() {
        let expiry = read_expiry_metadata(project.home());
        assert!(
            expiry.get(mock.url()).is_none(),
            "logout should remove session expiry metadata after revoking pairings"
        );
    }

    let pair_after_logout = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["env", "pair", "new123"])
        .output()
        .expect("failed to run pair after logout");

    assert!(
        !pair_after_logout.status.success(),
        "pair unexpectedly succeeded after logout:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&pair_after_logout.stdout),
        String::from_utf8_lossy(&pair_after_logout.stderr),
    );
    let pair_after_logout_stderr = String::from_utf8_lossy(&pair_after_logout.stderr);
    assert!(
        pair_after_logout_stderr.contains("not logged in. Run `lpm login` first"),
        "expected post-logout pair auth error, got stderr: {pair_after_logout_stderr}"
    );

    let unpair_after_logout = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["env", "unpair"])
        .output()
        .expect("failed to run unpair after logout");

    assert!(
        !unpair_after_logout.status.success(),
        "unpair unexpectedly succeeded after logout:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&unpair_after_logout.stdout),
        String::from_utf8_lossy(&unpair_after_logout.stderr),
    );
    let unpair_after_logout_stderr = String::from_utf8_lossy(&unpair_after_logout.stderr);
    assert!(
        unpair_after_logout_stderr.contains("not logged in. Run `lpm login` first"),
        "expected post-logout unpair auth error, got stderr: {unpair_after_logout_stderr}"
    );
}

#[tokio::test]
async fn env_pair_refresh_only_session_then_logout_revoke_revokes_pairings_and_blocks_future_pairing_commands()
 {
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    let project =
        TempProject::empty(r#"{"name":"vault-pair-refresh-logout-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;

    let browser_secret = P256SecretKey::random(&mut rand::thread_rng());
    let browser_public_key = BASE64.encode(
        browser_secret
            .public_key()
            .to_encoded_point(false)
            .as_bytes(),
    );

    mock.with_refresh_expected(
        "refresh-seed-token",
        "access-from-refresh",
        "refresh-rotated-token",
        "2030-01-01T00:00:00Z",
        1,
    )
    .await;
    mock.with_current_principal("access-from-refresh", "account-1", 2)
        .await;
    mock.with_pairing_session("RLG123", "access-from-refresh", &browser_public_key)
        .await;
    mock.with_pairing_approval("RLG123", "access-from-refresh")
        .await;
    mock.with_revoke_all_pairings_for_principal_status("access-from-refresh", "account-1", 200, 1)
        .await;
    mock.with_revoke_token("access-from-refresh").await;

    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: None,
            refresh_token: Some("refresh-seed-token"),
            session_access_expires_at: None,
        }],
    );

    let pair = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["env", "pair", "rlg123", "--yes"])
        .output()
        .expect("failed to run pair before logout for refresh-only session");

    assert!(
        pair.status.success(),
        "pair before logout failed for refresh-only session:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&pair.stdout),
        String::from_utf8_lossy(&pair.stderr),
    );

    let credentials_after_refresh = read_credentials(project.home());
    assert_eq!(
        credentials_after_refresh[&mock.url()],
        "access-from-refresh"
    );
    assert_eq!(
        credentials_after_refresh[&format!("refresh:{}", mock.url())],
        "refresh-rotated-token"
    );

    let logout = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["logout", "--revoke"])
        .output()
        .expect("failed to run logout after refresh-only pairing");

    assert!(
        logout.status.success(),
        "logout after refresh-only pairing failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&logout.stdout),
        String::from_utf8_lossy(&logout.stderr),
    );

    assert!(
        !credentials_path(project.home()).exists(),
        "logout should remove credentials after refresh-only pairing"
    );

    if token_expiry_path(project.home()).exists() {
        let expiry = read_expiry_metadata(project.home());
        assert!(
            expiry.get(mock.url()).is_none(),
            "logout should remove session expiry metadata after refresh-only pairing"
        );
    }

    let pair_after_logout = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["env", "pair", "ABC123"])
        .output()
        .expect("failed to run pair after logout for refresh-only session");

    assert!(
        !pair_after_logout.status.success(),
        "pair unexpectedly succeeded after refresh-only logout:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&pair_after_logout.stdout),
        String::from_utf8_lossy(&pair_after_logout.stderr),
    );
    let pair_after_logout_stderr = String::from_utf8_lossy(&pair_after_logout.stderr);
    assert!(
        pair_after_logout_stderr.contains("not logged in. Run `lpm login` first"),
        "expected post-logout pair auth error, got stderr: {pair_after_logout_stderr}"
    );
}

#[tokio::test]
async fn env_pair_unpair_then_logout_revoke_on_refresh_backed_session_keeps_normalized_state_and_blocks_future_vault_commands()
 {
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    let project = TempProject::empty(
        r#"{"name":"vault-pair-unpair-logout-refresh-chain-test","version":"1.0.0"}"#,
    );
    let mock = MockRegistry::start().await;

    let browser_secret = P256SecretKey::random(&mut rand::thread_rng());
    let browser_public_key = BASE64.encode(
        browser_secret
            .public_key()
            .to_encoded_point(false)
            .as_bytes(),
    );

    mock.with_refresh_expected(
        "refresh-seed-token",
        "access-from-refresh",
        "refresh-rotated-token",
        "2030-01-01T00:00:00Z",
        1,
    )
    .await;
    mock.with_current_principal("access-from-refresh", "account-1", 3)
        .await;
    mock.with_pairing_session("UPL123", "access-from-refresh", &browser_public_key)
        .await;
    mock.with_pairing_approval("UPL123", "access-from-refresh")
        .await;
    mock.with_revoke_all_pairings_for_principal_status("access-from-refresh", "account-1", 200, 2)
        .await;
    mock.with_revoke_token("access-from-refresh").await;

    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: None,
            refresh_token: Some("refresh-seed-token"),
            session_access_expires_at: None,
        }],
    );

    let pair = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["env", "pair", "upl123", "--yes"])
        .output()
        .expect("failed to run pair before unpair/logout refresh chain");

    assert!(
        pair.status.success(),
        "pair failed in refresh-backed pair/unpair/logout chain:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&pair.stdout),
        String::from_utf8_lossy(&pair.stderr),
    );

    let credentials_after_pair = read_credentials(project.home());
    assert_eq!(credentials_after_pair[&mock.url()], "access-from-refresh");
    assert_eq!(
        credentials_after_pair[&format!("refresh:{}", mock.url())],
        "refresh-rotated-token"
    );

    let unpair = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["env", "unpair"])
        .output()
        .expect("failed to run unpair in refresh-backed chain");

    assert!(
        unpair.status.success(),
        "unpair failed in refresh-backed pair/unpair/logout chain:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&unpair.stdout),
        String::from_utf8_lossy(&unpair.stderr),
    );

    let credentials_after_unpair = read_credentials(project.home());
    assert_eq!(credentials_after_unpair, credentials_after_pair);

    let expiry_after_unpair = read_expiry_metadata(project.home());
    assert_eq!(
        expiry_after_unpair[&mock.url()]["session_access_expires_at"],
        "2030-01-01T00:00:00Z"
    );

    let logout = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["logout", "--revoke"])
        .output()
        .expect("failed to run logout in refresh-backed chain");

    assert!(
        logout.status.success(),
        "logout failed in refresh-backed pair/unpair/logout chain:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&logout.stdout),
        String::from_utf8_lossy(&logout.stderr),
    );

    assert!(
        !credentials_path(project.home()).exists(),
        "logout should remove credentials after a refresh-backed pair/unpair chain"
    );

    if token_expiry_path(project.home()).exists() {
        let expiry_after_logout = read_expiry_metadata(project.home());
        assert!(
            expiry_after_logout.get(mock.url()).is_none(),
            "logout should remove session expiry metadata after a refresh-backed pair/unpair chain"
        );
    }

    let pair_after_logout = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["env", "pair", "NEW123"])
        .output()
        .expect("failed to run pair after refresh-backed logout chain");

    assert!(
        !pair_after_logout.status.success(),
        "pair unexpectedly succeeded after refresh-backed pair/unpair/logout chain:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&pair_after_logout.stdout),
        String::from_utf8_lossy(&pair_after_logout.stderr),
    );

    let unpair_after_logout = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["env", "unpair"])
        .output()
        .expect("failed to run unpair after refresh-backed logout chain");

    assert!(
        !unpair_after_logout.status.success(),
        "unpair unexpectedly succeeded after refresh-backed pair/unpair/logout chain:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&unpair_after_logout.stdout),
        String::from_utf8_lossy(&unpair_after_logout.stderr),
    );
    let unpair_after_logout_stderr = String::from_utf8_lossy(&unpair_after_logout.stderr);
    assert!(
        unpair_after_logout_stderr.contains("not logged in. Run `lpm login` first"),
        "expected post-logout unpair auth error, got stderr: {unpair_after_logout_stderr}"
    );
}

#[tokio::test]
async fn env_pair_unpair_then_logout_all_revoke_on_refresh_backed_session_clears_auth_state_and_blocks_future_vault_commands()
 {
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    let project = TempProject::empty(
        r#"{"name":"vault-pair-unpair-logout-all-refresh-chain-test","version":"1.0.0"}"#,
    );
    let mock = MockRegistry::start().await;

    let browser_secret = P256SecretKey::random(&mut rand::thread_rng());
    let browser_public_key = BASE64.encode(
        browser_secret
            .public_key()
            .to_encoded_point(false)
            .as_bytes(),
    );

    mock.with_refresh_expected(
        "refresh-seed-token",
        "access-from-refresh",
        "refresh-rotated-token",
        "2030-01-01T00:00:00Z",
        1,
    )
    .await;
    mock.with_current_principal("access-from-refresh", "account-1", 3)
        .await;
    mock.with_pairing_session("UAL123", "access-from-refresh", &browser_public_key)
        .await;
    mock.with_pairing_approval("UAL123", "access-from-refresh")
        .await;
    mock.with_revoke_all_pairings_for_principal_status("access-from-refresh", "account-1", 200, 2)
        .await;
    mock.with_revoke_token("access-from-refresh").await;

    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: None,
            refresh_token: Some("refresh-seed-token"),
            session_access_expires_at: None,
        }],
    );

    let pair = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["env", "pair", "ual123", "--yes"])
        .output()
        .expect("failed to run pair before refresh-backed logout-all chain");

    assert!(
        pair.status.success(),
        "pair failed in refresh-backed pair/unpair/logout-all chain:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&pair.stdout),
        String::from_utf8_lossy(&pair.stderr),
    );

    let unpair = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["env", "unpair"])
        .output()
        .expect("failed to run unpair before refresh-backed logout-all chain");

    assert!(
        unpair.status.success(),
        "unpair failed in refresh-backed pair/unpair/logout-all chain:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&unpair.stdout),
        String::from_utf8_lossy(&unpair.stderr),
    );

    let credentials_after_unpair = read_credentials(project.home());
    assert_eq!(credentials_after_unpair[&mock.url()], "access-from-refresh");
    assert_eq!(
        credentials_after_unpair[&format!("refresh:{}", mock.url())],
        "refresh-rotated-token"
    );

    let logout_all = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["logout", "--all", "--revoke"])
        .output()
        .expect("failed to run logout --all in refresh-backed vault chain");

    assert!(
        logout_all.status.success(),
        "logout --all failed in refresh-backed pair/unpair chain:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&logout_all.stdout),
        String::from_utf8_lossy(&logout_all.stderr),
    );

    assert!(
        !credentials_path(project.home()).exists(),
        "logout --all should remove credentials after a refresh-backed pair/unpair chain"
    );

    if token_expiry_path(project.home()).exists() {
        let expiry_after_logout = read_expiry_metadata(project.home());
        assert!(
            expiry_after_logout.get(mock.url()).is_none(),
            "logout --all should remove session expiry metadata after a refresh-backed pair/unpair chain"
        );
    }

    let pair_after_logout_all = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["env", "pair", "NEW123"])
        .output()
        .expect("failed to run pair after refresh-backed logout-all chain");

    assert!(
        !pair_after_logout_all.status.success(),
        "pair unexpectedly succeeded after refresh-backed pair/unpair/logout-all chain:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&pair_after_logout_all.stdout),
        String::from_utf8_lossy(&pair_after_logout_all.stderr),
    );

    let unpair_after_logout_all = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["env", "unpair"])
        .output()
        .expect("failed to run unpair after refresh-backed logout-all chain");

    assert!(
        !unpair_after_logout_all.status.success(),
        "unpair unexpectedly succeeded after refresh-backed pair/unpair/logout-all chain:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&unpair_after_logout_all.stdout),
        String::from_utf8_lossy(&unpair_after_logout_all.stderr),
    );
}

#[tokio::test]
async fn env_pull_oidc_writes_env_file_with_sorted_and_quoted_values() {
    let project = TempProject::empty(r#"{"name":"vault-oidc-pull-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let output_file = project.path().join(".env.ci");

    std::fs::write(
        project.path().join("lpm.json"),
        r#"{"vault":"vault-ci-123"}"#,
    )
    .expect("failed to write lpm.json");

    mock.with_oidc_exchange(
        "ci-oidc-token",
        "vault-ci-123",
        Some("preview"),
        "lpm-ci-token",
    )
    .await;
    mock.with_ci_pull(
        "vault-ci-123",
        "lpm-ci-token",
        Some("preview"),
        serde_json::json!({
            "Z_LAST": "plain",
            "API_KEY": "secret value",
            "MULTILINE": "line1\nline2",
            "CONTROL_WHITESPACE": "\tleft\rright\t",
            "QUOTED": "say \"hello\" from `LPM` with $TOKEN and C:\\vault",
        }),
    )
    .await;

    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .env("LPM_VAULT_ID", "vault-ci-123")
        .env("LPM_OIDC_TOKEN", "ci-oidc-token")
        .env("LPM_OIDC_POLICY_ID", TEST_OIDC_POLICY_ID)
        .args([
            "env",
            "pull",
            "--oidc",
            "--env=preview",
            &format!("--output={}", output_file.display()),
        ])
        .output()
        .expect("failed to run lpm env pull --oidc");

    assert!(
        output.status.success(),
        "oidc pull failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let written = std::fs::read_to_string(&output_file)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", output_file.display()));

    assert!(written.contains("# LPM vault secrets (env: preview)"));
    assert!(written.contains("API_KEY=\"secret value\""));
    assert!(written.contains("MULTILINE=\"line1\\nline2\""));
    let parsed = lpm_runner::dotenv::parse_env_str(&written);
    assert_eq!(parsed["API_KEY"], "secret value");
    assert_eq!(parsed["MULTILINE"], "line1\nline2");
    assert_eq!(parsed["CONTROL_WHITESPACE"], "\tleft\rright\t");
    assert_eq!(
        parsed["QUOTED"],
        "say \"hello\" from `LPM` with $TOKEN and C:\\vault"
    );

    let api_key_index = written
        .find("API_KEY=")
        .expect("API_KEY missing from output");
    let multiline_index = written
        .find("MULTILINE=")
        .expect("MULTILINE missing from output");
    let z_last_index = written.find("Z_LAST=").expect("Z_LAST missing from output");
    assert!(api_key_index < multiline_index && multiline_index < z_last_index);
}

#[tokio::test]
async fn env_pull_oidc_uses_lpm_vault_id_without_local_vault() {
    let project =
        TempProject::empty(r#"{"name":"vault-oidc-env-bootstrap-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;

    mock.with_oidc_exchange(
        "ci-oidc-token",
        "vault-from-environment",
        Some("preview"),
        "lpm-ci-token",
    )
    .await;
    mock.with_ci_pull(
        "vault-from-environment",
        "lpm-ci-token",
        Some("preview"),
        serde_json::json!({"BOOTSTRAPPED": "true"}),
    )
    .await;

    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .env("LPM_VAULT_ID", "vault-from-environment")
        .env("LPM_OIDC_TOKEN", "ci-oidc-token")
        .env("LPM_OIDC_POLICY_ID", TEST_OIDC_POLICY_ID)
        .args(["--json", "env", "pull", "--oidc", "--env=preview"])
        .output()
        .expect("failed to run env-only OIDC pull");

    assert!(
        output.status.success(),
        "env-only OIDC pull failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let json = parse_json_output(&output.stdout);
    assert_eq!(json["vars"]["BOOTSTRAPPED"], "true");
}

#[tokio::test]
async fn env_pull_oidc_environment_vault_id_overrides_local_vault() {
    let project =
        TempProject::empty(r#"{"name":"vault-oidc-env-precedence-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    project.write_file("lpm.json", r#"{"vault":"vault-from-lpm-json"}"#);

    mock.with_oidc_exchange(
        "ci-oidc-token",
        "vault-from-environment",
        None,
        "lpm-ci-token",
    )
    .await;
    mock.with_ci_pull(
        "vault-from-environment",
        "lpm-ci-token",
        None,
        serde_json::json!({"SOURCE": "environment"}),
    )
    .await;

    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .env("LPM_VAULT_ID", "vault-from-environment")
        .env("LPM_OIDC_TOKEN", "ci-oidc-token")
        .env("LPM_OIDC_POLICY_ID", TEST_OIDC_POLICY_ID)
        .args(["--json", "env", "pull", "--oidc"])
        .output()
        .expect("failed to run OIDC pull with vault override");
    let requests = mock.server().received_requests().await.unwrap();
    let request_bodies = requests
        .iter()
        .map(|request| String::from_utf8_lossy(&request.body).into_owned())
        .collect::<Vec<_>>();

    assert!(
        output.status.success(),
        "OIDC pull did not use the environment vault override:\nstdout: {}\nstderr: {}\nrequests: {request_bodies:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let json = parse_json_output(&output.stdout);
    assert_eq!(json["vars"]["SOURCE"], "environment");
}

#[tokio::test]
async fn env_pull_oidc_whitespace_vault_id_falls_back_to_local_vault() {
    let project =
        TempProject::empty(r#"{"name":"vault-oidc-env-fallback-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    project.write_file("lpm.json", r#"{"vault":"vault-from-lpm-json"}"#);

    mock.with_oidc_exchange("ci-oidc-token", "vault-from-lpm-json", None, "lpm-ci-token")
        .await;
    mock.with_ci_pull(
        "vault-from-lpm-json",
        "lpm-ci-token",
        None,
        serde_json::json!({"SOURCE": "lpm-json"}),
    )
    .await;

    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .env("LPM_VAULT_ID", " \t ")
        .env("LPM_OIDC_TOKEN", "ci-oidc-token")
        .env("LPM_OIDC_POLICY_ID", TEST_OIDC_POLICY_ID)
        .args(["--json", "env", "pull", "--oidc"])
        .output()
        .expect("failed to run OIDC pull with whitespace vault override");

    assert!(
        output.status.success(),
        "OIDC pull did not fall back to the local vault:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let json = parse_json_output(&output.stdout);
    assert_eq!(json["vars"]["SOURCE"], "lpm-json");
}

#[test]
fn env_pull_oidc_without_vault_source_emits_clear_json_error() {
    let project = TempProject::empty(r#"{"name":"vault-oidc-no-vault-test","version":"1.0.0"}"#);

    let output = lpm(&project)
        .env("LPM_VAULT_ID", " \t ")
        .args(["--json", "env", "pull", "--oidc"])
        .output()
        .expect("failed to run OIDC pull without a vault source");

    assert!(
        !output.status.success(),
        "OIDC pull without a vault source unexpectedly succeeded"
    );
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("failure must emit one JSON document");
    let error = json["error"].as_str().expect("error should be a string");
    assert!(
        error.contains("no vault configured")
            && error.contains("non-empty LPM_VAULT_ID")
            && error.contains("lpm.json"),
        "expected clear vault configuration guidance, got: {error}",
    );
}

#[test]
fn env_pull_oidc_rejects_unsafe_environment_vault_id() {
    let project =
        TempProject::empty(r#"{"name":"vault-oidc-unsafe-vault-id-test","version":"1.0.0"}"#);

    let output = lpm(&project)
        .env("LPM_VAULT_ID", "../other-vault")
        .args(["--json", "env", "pull", "--oidc"])
        .output()
        .expect("failed to run OIDC pull with an unsafe vault ID");

    assert!(
        !output.status.success(),
        "OIDC pull unexpectedly accepted an unsafe LPM_VAULT_ID"
    );
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("failure must emit one JSON document");
    assert!(
        json["error"]
            .as_str()
            .is_some_and(|error| error.contains("LPM_VAULT_ID") && error.contains("unsafe")),
        "expected unsafe LPM_VAULT_ID error, got: {json}",
    );
}

#[test]
fn env_pull_oidc_requires_policy_selector_before_resolving_ci_token() {
    let project = TempProject::empty(r#"{"name":"vault-oidc-policy-required","version":"1.0.0"}"#);
    project.write_file("lpm.json", r#"{"vault":"vault-policy-required"}"#);

    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", "http://127.0.0.1:9")
        .args(["env", "pull", "--oidc"])
        .output()
        .expect("run OIDC pull without policy selector");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("LPM_OIDC_POLICY_ID") && stderr.contains("--policy-id"),
        "missing selector error must explain both supported inputs: {stderr}",
    );
    assert!(
        !stderr.contains("no OIDC signal"),
        "selector validation must happen before CI token resolution: {stderr}",
    );
}

#[test]
fn env_pull_oidc_rejects_malformed_policy_selector_before_network() {
    let project = TempProject::empty(r#"{"name":"vault-oidc-policy-invalid","version":"1.0.0"}"#);
    project.write_file("lpm.json", r#"{"vault":"vault-policy-invalid"}"#);

    for (label, args, env_value) in [
        (
            "environment",
            vec!["env", "pull", "--oidc"],
            Some("not-a-uuid"),
        ),
        ("whitespace", vec!["env", "pull", "--oidc"], Some(" \t ")),
        (
            "flag",
            vec!["env", "pull", "--oidc", "--policy-id=not-a-uuid"],
            None,
        ),
    ] {
        let mut command = lpm(&project);
        command
            .env("LPM_REGISTRY_URL", "http://127.0.0.1:9")
            .env("LPM_OIDC_TOKEN", "must-not-be-sent")
            .args(&args);
        if let Some(value) = env_value {
            command.env("LPM_OIDC_POLICY_ID", value);
        }
        let output = command.output().expect("run malformed selector case");
        assert!(
            !output.status.success(),
            "{label} selector unexpectedly passed"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("policy ID") && stderr.contains("UUID"),
            "{label} selector should fail local UUID validation: {stderr}",
        );
        assert!(!stderr.contains("OIDC exchange failed"));
    }
}

#[cfg(unix)]
#[test]
fn env_pull_oidc_rejects_non_utf8_policy_selector_before_network() {
    use std::os::unix::ffi::OsStringExt;

    let project = TempProject::empty(r#"{"name":"vault-oidc-policy-utf8","version":"1.0.0"}"#);
    project.write_file("lpm.json", r#"{"vault":"vault-policy-utf8"}"#);

    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", "http://127.0.0.1:9")
        .env("LPM_OIDC_TOKEN", "must-not-be-sent")
        .env(
            "LPM_OIDC_POLICY_ID",
            std::ffi::OsString::from_vec(vec![0xff]),
        )
        .args(["env", "pull", "--oidc"])
        .output()
        .expect("run OIDC pull with non-UTF-8 selector");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("UTF-8") && stderr.contains("LPM_OIDC_POLICY_ID"));
    assert!(!stderr.contains("OIDC exchange failed"));
}

#[tokio::test]
async fn env_pull_oidc_policy_flag_overrides_environment_selector() {
    const FLAG_POLICY_ID: &str = "22222222-2222-4222-8222-222222222222";
    let project =
        TempProject::empty(r#"{"name":"vault-oidc-policy-precedence","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    project.write_file("lpm.json", r#"{"vault":"vault-policy-precedence"}"#);

    mock.with_oidc_exchange_for_policy(
        "ci-oidc-token",
        "vault-policy-precedence",
        Some("preview"),
        FLAG_POLICY_ID,
        "lpm-ci-token",
    )
    .await;
    mock.with_ci_pull(
        "vault-policy-precedence",
        "lpm-ci-token",
        Some("preview"),
        serde_json::json!({"SOURCE": "flag"}),
    )
    .await;

    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .env("LPM_OIDC_TOKEN", "ci-oidc-token")
        .env("LPM_OIDC_POLICY_ID", TEST_OIDC_POLICY_ID)
        .args([
            "--json",
            "env",
            "pull",
            "--oidc",
            "--env=preview",
            &format!("--policy-id={FLAG_POLICY_ID}"),
        ])
        .output()
        .expect("run OIDC pull with selector precedence");

    assert!(
        output.status.success(),
        "flag selector should override environment:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert_eq!(parse_json_output(&output.stdout)["vars"]["SOURCE"], "flag");
}

#[test]
fn env_pull_oidc_rejects_unknown_selector_flag() {
    let project = TempProject::empty(r#"{"name":"vault-oidc-policy-typo","version":"1.0.0"}"#);
    project.write_file("lpm.json", r#"{"vault":"vault-policy-typo"}"#);

    let output = lpm(&project)
        .env("LPM_OIDC_POLICY_ID", TEST_OIDC_POLICY_ID)
        .args(["env", "pull", "--oidc", "--policyid=typo"])
        .output()
        .expect("run OIDC pull with misspelled selector flag");

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unknown OIDC pull argument"));
}

#[tokio::test]
async fn env_pull_oidc_uses_lpm_oidc_token_canonical_and_ignores_ci_job_jwt_v2() {
    // Locks the contract that LPM_OIDC_TOKEN is the canonical registry-exchange
    // input on every provider, and CI_JOB_JWT_V2 (whose default audience is the
    // GitLab instance URL, NOT https://lpm.dev) is intentionally ignored — the
    // origin's vault verifier rejects anything but `aud=https://lpm.dev`, so
    // honoring CI_JOB_JWT_V2 would produce confusing 401s.
    let project = TempProject::empty(r#"{"name":"vault-oidc-gitlab-json-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;

    project.write_file("lpm.json", r#"{"vault":"vault-gitlab-json-123"}"#);

    mock.with_oidc_exchange(
        "lpm-oidc-token-with-aud-lpm-dev",
        "vault-gitlab-json-123",
        Some("preview"),
        "lpm-gitlab-ci-token",
    )
    .await;
    mock.with_ci_pull(
        "vault-gitlab-json-123",
        "lpm-gitlab-ci-token",
        Some("preview"),
        serde_json::json!({
            "CI_PROVIDER": "gitlab",
            "SECRET_ONE": "value-1",
        }),
    )
    .await;

    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        // Both set: the contract requires LPM_OIDC_TOKEN to win and
        // CI_JOB_JWT_V2 to be ignored. If anyone reverts and starts honoring
        // CI_JOB_JWT_V2 again, the mock's exchange handler will see the wrong
        // input token and the test fails.
        .env("CI_JOB_JWT_V2", "should-be-ignored")
        .env("LPM_OIDC_TOKEN", "lpm-oidc-token-with-aud-lpm-dev")
        .env("LPM_OIDC_POLICY_ID", TEST_OIDC_POLICY_ID)
        .args(["--json", "env", "pull", "--oidc", "--env=preview"])
        .output()
        .expect("failed to run GitLab OIDC pull --json");

    assert!(
        output.status.success(),
        "GitLab OIDC pull --json failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let json = parse_json_output(&output.stdout);
    assert_eq!(json["env"], "preview");
    assert_eq!(json["count"], 2);
    assert_eq!(json["vars"]["CI_PROVIDER"], "gitlab");
    assert_eq!(json["vars"]["SECRET_ONE"], "value-1");

    insta::with_settings!({
        sort_maps => true,
        filters => vec![
            (r#"/var/folders/[^"\s]+"#, "[TEMP]"),
            (r#"/private/var/folders/[^"\s]+"#, "[TEMP]"),
            (r#"/tmp/[^"\s]+"#, "[TEMP]"),
            (r"http://127\.0\.0\.1:\d+", "[MOCK]"),
        ],
    }, {
        insta::assert_json_snapshot!(
            "env_pull_oidc_gitlab_two_vars_envelope",
            json,
            { ".duration_ms" => "[DURATION]" }
        );
    });
}

#[tokio::test]
async fn env_oidc_allow_missing_repo_emits_json_error() {
    let project =
        TempProject::empty(r#"{"name":"vault-oidc-allow-json-error-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;

    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some("session-access-token"),
            refresh_token: Some("refresh-token"),
            session_access_expires_at: Some("2030-01-01T00:00:00Z"),
        }],
    );

    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["--json", "env", "oidc", "allow", "--env=preview"])
        .output()
        .expect("failed to run oidc allow JSON error test");

    assert!(
        !output.status.success(),
        "oidc allow missing repo unexpectedly succeeded"
    );

    let json = parse_json_output(&output.stdout);
    assert_eq!(json["success"], false);
    assert!(
        json["error"]
            .as_str()
            .expect("error should be string")
            .contains("missing --repo flag")
    );
}

#[tokio::test]
async fn env_oidc_allow_missing_workflow_flag_errors_loudly() {
    // `--workflow` is required at the CLI layer. Without it the server's Zod
    // `.min(1)` on `allowedWorkflows` would reject anyway; we surface the
    // failure client-side so the user gets a fast, actionable error.
    let project =
        TempProject::empty(r#"{"name":"vault-oidc-allow-missing-workflow","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;

    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some("session-access-token"),
            refresh_token: Some("refresh-token"),
            session_access_expires_at: Some("2030-01-01T00:00:00Z"),
        }],
    );

    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args([
            "env",
            "oidc",
            "allow",
            "--repo=acme/repo",
            "--branch=main",
            "--env=production",
            // --workflow deliberately omitted
        ])
        .output()
        .expect("failed to run oidc allow missing-workflow test");

    assert!(
        !output.status.success(),
        "missing --workflow should fail closed",
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("missing --workflow flag"),
        "expected missing-workflow message, got: {stderr}",
    );
}

#[tokio::test]
async fn env_oidc_allow_rejects_workflow_in_subdirectory() {
    // The workflow regex pins .github/workflows/<file>.{yml,yaml} only.
    // Subdirectories aren't supported by GitHub Actions and aren't accepted
    // by the server's Zod schema either; the CLI catches it before the
    // network round-trip.
    let project =
        TempProject::empty(r#"{"name":"vault-oidc-allow-workflow-subdir","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;

    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some("session-access-token"),
            refresh_token: Some("refresh-token"),
            session_access_expires_at: Some("2030-01-01T00:00:00Z"),
        }],
    );

    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args([
            "env",
            "oidc",
            "allow",
            "--repo=acme/repo",
            "--workflow=.github/workflows/nested/deploy.yml",
            "--branch=main",
            "--env=production",
        ])
        .output()
        .expect("failed to run oidc allow subdir-workflow test");

    assert!(
        !output.status.success(),
        "subdir workflow path should be rejected",
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(".github/workflows/<file>.yml"),
        "expected workflow-path-shape error, got: {stderr}",
    );
}

#[tokio::test]
async fn env_oidc_list_ignores_lpm_vault_id_without_local_vault() {
    let project =
        TempProject::empty(r#"{"name":"vault-oidc-list-json-error-test","version":"1.0.0"}"#);

    let output = lpm(&project)
        .env("LPM_VAULT_ID", "vault-from-environment")
        .args(["--json", "env", "oidc", "list"])
        .output()
        .expect("failed to run oidc list JSON error test");

    assert!(
        !output.status.success(),
        "oidc list without vault unexpectedly succeeded"
    );

    let json = parse_json_output(&output.stdout);
    assert_eq!(json["success"], false);
    assert!(
        json["error"]
            .as_str()
            .expect("error should be string")
            .contains("no vault configured")
    );
}

#[tokio::test]
async fn env_pull_oidc_uses_github_actions_runtime_token() {
    let project =
        TempProject::empty(r#"{"name":"vault-oidc-github-runtime-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let output_file = project.path().join(".env.github-ci");

    std::fs::write(
        project.path().join("lpm.json"),
        r#"{"vault":"vault-github-oidc-123"}"#,
    )
    .expect("failed to write lpm.json for GitHub OIDC pull");

    mock.with_github_oidc_runtime_token("github-request-token", "github-runtime-oidc-token")
        .await;
    mock.with_oidc_exchange(
        "github-runtime-oidc-token",
        "vault-github-oidc-123",
        Some("preview"),
        "lpm-gh-ci-token",
    )
    .await;
    mock.with_ci_pull(
        "vault-github-oidc-123",
        "lpm-gh-ci-token",
        Some("preview"),
        serde_json::json!({
            "GITHUB_ONLY": "from-runtime-token",
        }),
    )
    .await;

    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .env("GITHUB_ACTIONS", "true")
        .env("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "github-request-token")
        .env("LPM_OIDC_POLICY_ID", TEST_OIDC_POLICY_ID)
        .env(
            "ACTIONS_ID_TOKEN_REQUEST_URL",
            format!("{}/github/oidc?existing=1", mock.url()),
        )
        .args([
            "env",
            "pull",
            "--oidc",
            "--env=preview",
            &format!("--output={}", output_file.display()),
        ])
        .output()
        .expect("failed to run GitHub OIDC pull");

    assert!(
        output.status.success(),
        "GitHub OIDC pull failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let written = std::fs::read_to_string(&output_file)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", output_file.display()));
    assert!(written.contains("GITHUB_ONLY=from-runtime-token"));
}

#[tokio::test]
async fn env_pull_oidc_partial_github_signal_token_only_falls_through() {
    // A partial GitHub Actions signal — only ACTIONS_ID_TOKEN_REQUEST_TOKEN
    // set, no URL — must NOT trigger a runtime fetch attempt. With no other
    // signal present, the resolver falls through to the named-vars error.
    // This is the new contract: GITHUB_ACTIONS by itself is no longer a gate;
    // both runtime vars must be present together to take the GH path.
    let project =
        TempProject::empty(r#"{"name":"vault-oidc-github-partial-token-only","version":"1.0.0"}"#);

    project.write_file("lpm.json", r#"{"vault":"vault-github-partial-token-123"}"#);

    let output = lpm(&project)
        .env("GITHUB_ACTIONS", "true")
        .env("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "partial-gh-token")
        .env("LPM_OIDC_POLICY_ID", TEST_OIDC_POLICY_ID)
        .env_remove("ACTIONS_ID_TOKEN_REQUEST_URL")
        .env_remove("LPM_OIDC_TOKEN")
        .env_remove("LPM_GITLAB_OIDC_TOKEN")
        .args(["env", "pull", "--oidc"])
        .output()
        .expect("failed to run GitHub partial-token-only test");

    assert!(
        !output.status.success(),
        "partial GitHub signal (token only) unexpectedly succeeded"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("no OIDC signal"),
        "stderr should fall through to the named-vars error, got: {stderr}"
    );
    assert!(
        stderr.contains("LPM_OIDC_TOKEN"),
        "error must name the canonical bypass var: {stderr}"
    );
}

#[tokio::test]
async fn env_pull_oidc_partial_github_signal_url_only_falls_through() {
    // Symmetric to the token-only case: only the URL is set, no TOKEN. Must
    // also fall through rather than try the runtime fetch with a half-built
    // request.
    let project =
        TempProject::empty(r#"{"name":"vault-oidc-github-partial-url-only","version":"1.0.0"}"#);

    project.write_file("lpm.json", r#"{"vault":"vault-github-partial-url-123"}"#);

    let output = lpm(&project)
        .env("GITHUB_ACTIONS", "true")
        .env("LPM_OIDC_POLICY_ID", TEST_OIDC_POLICY_ID)
        .env(
            "ACTIONS_ID_TOKEN_REQUEST_URL",
            "https://example.invalid/oidc",
        )
        .env_remove("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
        .env_remove("LPM_OIDC_TOKEN")
        .env_remove("LPM_GITLAB_OIDC_TOKEN")
        .args(["env", "pull", "--oidc"])
        .output()
        .expect("failed to run GitHub partial-url-only test");

    assert!(
        !output.status.success(),
        "partial GitHub signal (URL only) unexpectedly succeeded"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("no OIDC signal"),
        "stderr should fall through to the named-vars error, got: {stderr}"
    );
}

#[tokio::test]
async fn env_pull_oidc_surfaces_github_runtime_request_failures() {
    let project =
        TempProject::empty(r#"{"name":"vault-oidc-github-runtime-failure","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;

    project.write_file(
        "lpm.json",
        r#"{"vault":"vault-github-runtime-failure-123"}"#,
    );

    mock.with_github_oidc_runtime_response(
        "github-request-token",
        500,
        serde_json::json!({
            "error": "runtime unavailable",
        }),
    )
    .await;

    let output = lpm(&project)
        .env("GITHUB_ACTIONS", "true")
        .env("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "github-request-token")
        .env("LPM_OIDC_POLICY_ID", TEST_OIDC_POLICY_ID)
        .env(
            "ACTIONS_ID_TOKEN_REQUEST_URL",
            format!("{}/github/oidc?existing=1", mock.url()),
        )
        .args(["env", "pull", "--oidc"])
        .output()
        .expect("failed to run GitHub runtime failure test");

    assert!(
        !output.status.success(),
        "GitHub runtime failure unexpectedly succeeded"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("GitHub OIDC fetch failed"),
        "stderr should surface the runtime fetch failure, got: {stderr}"
    );
    assert!(
        stderr.contains("500"),
        "stderr should name the upstream status, got: {stderr}"
    );
}

#[tokio::test]
async fn env_pull_oidc_rejects_github_runtime_responses_without_value() {
    let project = TempProject::empty(
        r#"{"name":"vault-oidc-github-runtime-missing-value","version":"1.0.0"}"#,
    );
    let mock = MockRegistry::start().await;

    project.write_file(
        "lpm.json",
        r#"{"vault":"vault-github-runtime-missing-value-123"}"#,
    );

    mock.with_github_oidc_runtime_response(
        "github-request-token",
        200,
        serde_json::json!({
            "unexpected": true,
        }),
    )
    .await;

    let output = lpm(&project)
        .env("GITHUB_ACTIONS", "true")
        .env("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "github-request-token")
        .env("LPM_OIDC_POLICY_ID", TEST_OIDC_POLICY_ID)
        .env(
            "ACTIONS_ID_TOKEN_REQUEST_URL",
            format!("{}/github/oidc?existing=1", mock.url()),
        )
        .args(["env", "pull", "--oidc"])
        .output()
        .expect("failed to run GitHub missing runtime value test");

    assert!(
        !output.status.success(),
        "GitHub runtime response without value unexpectedly succeeded"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("GitHub OIDC response missing 'value' field"));
}

#[tokio::test]
async fn env_pull_oidc_surfaces_exchange_error_hint() {
    let project =
        TempProject::empty(r#"{"name":"vault-oidc-exchange-error-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;

    std::fs::write(
        project.path().join("lpm.json"),
        r#"{"vault":"vault-oidc-error-123"}"#,
    )
    .expect("failed to write lpm.json for OIDC exchange error");

    mock.with_oidc_exchange_failure(
        "ci-oidc-token",
        "vault-oidc-error-123",
        Some("preview"),
        403,
        "OIDC subject is not allowed for this vault",
        Some("Run 'lpm env oidc allow --repo=owner/repo --env=preview' first."),
    )
    .await;

    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .env("LPM_OIDC_TOKEN", "ci-oidc-token")
        .env("LPM_OIDC_POLICY_ID", TEST_OIDC_POLICY_ID)
        .args(["env", "pull", "--oidc", "--env=preview"])
        .output()
        .expect("failed to run oidc pull exchange error test");

    assert!(
        !output.status.success(),
        "OIDC pull unexpectedly succeeded:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("OIDC subject is not allowed for this vault"));
    assert!(stderr.contains("Hint:"));
    assert!(stderr.contains("lpm env oidc allow --repo=owner/repo --env=preview"));
}

#[tokio::test]
async fn env_pull_oidc_exchange_error_emits_json_error() {
    let project =
        TempProject::empty(r#"{"name":"vault-oidc-pull-json-error-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;

    project.write_file("lpm.json", r#"{"vault":"vault-oidc-pull-json-error-123"}"#);

    mock.with_oidc_exchange_failure(
        "ci-oidc-token",
        "vault-oidc-pull-json-error-123",
        Some("preview"),
        403,
        "OIDC subject is not allowed for this vault",
        Some("Add an OIDC policy before pulling secrets."),
    )
    .await;

    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .env("LPM_OIDC_TOKEN", "ci-oidc-token")
        .env("LPM_OIDC_POLICY_ID", TEST_OIDC_POLICY_ID)
        .args(["--json", "env", "pull", "--oidc", "--env=preview"])
        .output()
        .expect("failed to run oidc pull JSON error test");

    assert!(
        !output.status.success(),
        "oidc pull exchange error unexpectedly succeeded"
    );

    let json = parse_json_output(&output.stdout);
    assert_eq!(json["success"], false);
    let error = json["error"].as_str().expect("error should be string");
    assert!(error.contains("OIDC subject is not allowed for this vault"));
    assert!(error.contains("Hint: Add an OIDC policy before pulling secrets."));
}

#[tokio::test]
async fn env_pair_surfaces_expired_code_error() {
    let project = TempProject::empty(r#"{"name":"vault-pair-expired-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;

    mock.with_current_principal("session-access-token", "account-1", 1)
        .await;
    mock.with_pairing_session_error("EXPIRE", "session-access-token", 410, "pairing expired")
        .await;

    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some("session-access-token"),
            refresh_token: Some("refresh-token"),
            session_access_expires_at: Some("2030-01-01T00:00:00Z"),
        }],
    );

    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["env", "pair", "expire", "--yes"])
        .output()
        .expect("failed to run lpm env pair for expired code");

    assert!(
        !output.status.success(),
        "expired pairing unexpectedly succeeded"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("pairing error: pairing expired"),
        "expected expired pairing error, got stderr: {stderr}"
    );
}

#[tokio::test]
async fn env_pair_rejects_non_pending_session_status() {
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    let project = TempProject::empty(r#"{"name":"vault-pair-status-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;

    let browser_secret = P256SecretKey::random(&mut rand::thread_rng());
    let browser_public_key = BASE64.encode(
        browser_secret
            .public_key()
            .to_encoded_point(false)
            .as_bytes(),
    );
    mock.with_current_principal("session-access-token", "account-1", 1)
        .await;
    mock.with_pairing_session_status(
        "USED12",
        "session-access-token",
        "approved",
        Some(&browser_public_key),
    )
    .await;

    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some("session-access-token"),
            refresh_token: Some("refresh-token"),
            session_access_expires_at: Some("2030-01-01T00:00:00Z"),
        }],
    );

    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["env", "pair", "used12", "--yes"])
        .output()
        .expect("failed to run lpm env pair for non-pending code");

    assert!(
        !output.status.success(),
        "non-pending pairing unexpectedly succeeded"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("expected 'pending'") && stderr.contains("approved"),
        "expected non-pending pairing error, got stderr: {stderr}"
    );
}

#[tokio::test]
async fn env_pair_rejects_malformed_browser_key() {
    let project =
        TempProject::empty(r#"{"name":"vault-pair-malformed-key-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;

    mock.with_current_principal("session-access-token", "account-1", 1)
        .await;
    mock.with_pairing_session("BADKEY", "session-access-token", "not-base64")
        .await;

    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some("session-access-token"),
            refresh_token: Some("refresh-token"),
            session_access_expires_at: Some("2030-01-01T00:00:00Z"),
        }],
    );

    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["env", "pair", "badkey", "--yes"])
        .output()
        .expect("failed to run lpm env pair for malformed key");

    assert!(
        !output.status.success(),
        "malformed-key pairing unexpectedly succeeded"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("browser public key decode")
            || stderr.contains("invalid browser P-256 public key"),
        "expected malformed browser key error, got stderr: {stderr}"
    );
}

#[tokio::test]
async fn env_oidc_allow_then_list_shows_policy_and_escrow_success() {
    let project = TempProject::empty(r#"{"name":"vault-oidc-allow-list-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;

    write_personal_bound_manifest(&project, &mock.url(), "vault-policy-123");

    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some("session-access-token"),
            refresh_token: Some("refresh-token"),
            session_access_expires_at: Some("2030-01-01T00:00:00Z"),
        }],
    );

    mock.with_oidc_policy_create(
        "session-access-token",
        "vault-policy-123",
        "acme/repo",
        "987654321",
        &["main", "release"],
        &["production"],
        &[".github/workflows/deploy.yml"],
        &["push"],
    )
    .await;
    mock.with_escrow_upload_success("session-access-token", "vault-policy-123")
        .await;
    mock.with_oidc_policy_list(
        "session-access-token",
        "vault-policy-123",
        serde_json::json!([
            {
                "id": TEST_OIDC_POLICY_ID,
                "provider": "github",
                "subject": "repo:acme/repo",
                "allowedBranches": ["main", "release"],
                "allowedEnvironments": ["production"],
                "allowForks": false,
            }
        ]),
    )
    .await;

    let allow = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args([
            "env",
            "oidc",
            "allow",
            "--provider=github",
            "--repo=acme/repo",
            "--repository-id=987654321",
            "--branch=main,release",
            "--env=production",
            "--workflow=.github/workflows/deploy.yml",
        ])
        .output()
        .expect("failed to run lpm env oidc allow");

    assert!(
        allow.status.success(),
        "oidc allow failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&allow.stdout),
        String::from_utf8_lossy(&allow.stderr),
    );
    let allow_output = format!(
        "{}\n{}",
        String::from_utf8_lossy(&allow.stdout),
        String::from_utf8_lossy(&allow.stderr)
    );
    assert!(allow_output.contains("OIDC policy set: github"));
    assert!(allow_output.contains("CI escrow enabled"));
    assert!(allow_output.contains(TEST_OIDC_POLICY_ID));
    assert!(allow_output.contains("LPM_OIDC_POLICY_ID"));
    assert!(allow_output.contains("GitHub Actions repository variable"));
    assert!(!allow_output.contains("protected CI variable"));

    let list = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["env", "oidc", "list"])
        .output()
        .expect("failed to run lpm env oidc list");

    assert!(list.status.success(), "oidc list failed");
    let list_output = format!(
        "{}\n{}",
        String::from_utf8_lossy(&list.stdout),
        String::from_utf8_lossy(&list.stderr)
    );
    assert!(list_output.contains("github"));
    assert!(list_output.contains("repo:acme/repo"));
    assert!(list_output.contains("main, release") || list_output.contains("main,release"));
    assert!(list_output.contains("production"));
    assert!(list_output.contains(TEST_OIDC_POLICY_ID));
}

#[tokio::test]
async fn env_oidc_allow_discovers_public_github_repository_id() {
    let project = TempProject::empty(r#"{"name":"vault-oidc-discovery","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    write_personal_bound_manifest(&project, &mock.url(), "vault-policy-discovery");
    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some("session-access-token"),
            refresh_token: Some("refresh-token"),
            session_access_expires_at: Some("2030-01-01T00:00:00Z"),
        }],
    );

    Mock::given(method("GET"))
        .and(path("/repos/acme/repo"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": 987654321_u64,
            "full_name": "acme/repo",
        })))
        .expect(1)
        .mount(mock.server())
        .await;
    mock.with_oidc_policy_create(
        "session-access-token",
        "vault-policy-discovery",
        "acme/repo",
        "987654321",
        &["main"],
        &["production"],
        &[".github/workflows/deploy.yml"],
        &["push"],
    )
    .await;
    mock.with_escrow_upload_success("session-access-token", "vault-policy-discovery")
        .await;

    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .env("LPM_ACCEPTANCE_GITHUB_API_BASE_URL", mock.url())
        .env("ACCEPTANCE_RUN_ID", "oidc-repository-discovery")
        .args([
            "env",
            "oidc",
            "allow",
            "--provider=github",
            "--repo=acme/repo",
            "--branch=main",
            "--env=production",
            "--workflow=.github/workflows/deploy.yml",
        ])
        .output()
        .expect("run GitHub OIDC policy creation with ID discovery");

    assert!(
        output.status.success(),
        "OIDC repository-ID discovery failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[tokio::test]
async fn env_oidc_allow_gitlab_uses_numeric_project_subject_without_github_fields() {
    let project = TempProject::empty(r#"{"name":"gitlab-oidc","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    write_personal_bound_manifest(&project, &mock.url(), "vault-gitlab-123");
    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some("session-access-token"),
            refresh_token: Some("refresh-token"),
            session_access_expires_at: Some("2030-01-01T00:00:00Z"),
        }],
    );
    mock.with_gitlab_oidc_policy_create(
        "session-access-token",
        "vault-gitlab-123",
        "12345",
        &["main"],
        &["production"],
    )
    .await;
    mock.with_escrow_upload_success("session-access-token", "vault-gitlab-123")
        .await;

    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args([
            "env",
            "oidc",
            "allow",
            "--provider=gitlab",
            "--project-id=12345",
            "--branch=main",
            "--env=production",
        ])
        .output()
        .expect("run GitLab OIDC policy creation");

    assert!(
        output.status.success(),
        "GitLab OIDC policy failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(combined.contains("project ID 12345"));
    assert!(
        combined.contains("GitLab CI/CD variable")
            && combined.contains("only when every allowed ref is protected"),
        "GitLab output must explain conditional variable protection: {combined}"
    );
    assert!(
        !combined.contains("protected CI variable"),
        "GitLab output must not require protection for policies that allow unprotected refs: {combined}"
    );
    assert!(
        !combined.contains("workflows") && !combined.contains("events"),
        "GitLab output must not describe GitHub-only policy fields: {combined}"
    );
}

#[tokio::test]
async fn env_oidc_allow_gitlab_rejects_github_only_flags_before_network() {
    for flag in [
        "--repo=group/project",
        "--workflow=.github/workflows/deploy.yml",
        "--events=push",
        "--allow-forks",
    ] {
        let project = TempProject::empty(r#"{"name":"gitlab-oidc","version":"1.0.0"}"#);
        let mock = MockRegistry::start().await;
        let output = lpm(&project)
            .env("LPM_REGISTRY_URL", mock.url())
            .args([
                "env",
                "oidc",
                "allow",
                "--provider=gitlab",
                "--project-id=12345",
                "--env=production",
                flag,
            ])
            .output()
            .expect("run rejected GitLab OIDC policy");

        assert!(!output.status.success());
        assert!(mock.server().received_requests().await.unwrap().is_empty());
    }
}

#[tokio::test]
async fn env_oidc_allow_github_rejects_empty_repository_segments_before_network() {
    for repo in ["/repository", "owner/", "/"] {
        let project = TempProject::empty(r#"{"name":"github-oidc","version":"1.0.0"}"#);
        let mock = MockRegistry::start().await;
        project.write_file("lpm.json", r#"{"vault":"vault-github-invalid-repo"}"#);
        seed_sessions(
            project.home(),
            &[SessionSeed {
                registry_url: &mock.url(),
                access_token: Some("session-access-token"),
                refresh_token: Some("refresh-token"),
                session_access_expires_at: Some("2030-01-01T00:00:00Z"),
            }],
        );

        let output = lpm(&project)
            .env("LPM_REGISTRY_URL", mock.url())
            .args([
                "env",
                "oidc",
                "allow",
                &format!("--repo={repo}"),
                "--workflow=.github/workflows/deploy.yml",
                "--env=production",
            ])
            .output()
            .expect("run rejected GitHub OIDC policy");

        assert!(!output.status.success(), "{repo:?} should be rejected");
        assert!(
            mock.server().received_requests().await.unwrap().is_empty(),
            "{repo:?} should fail before authentication or policy creation"
        );
    }
}

#[tokio::test]
async fn env_oidc_allow_github_rejects_malformed_repository_ids_before_network() {
    for repository_id in ["", "0", "01", "abc", "123456789012345678901"] {
        let project = TempProject::empty(r#"{"name":"github-oidc","version":"1.0.0"}"#);
        let mock = MockRegistry::start().await;
        project.write_file("lpm.json", r#"{"vault":"vault-github-invalid-id"}"#);

        let output = lpm(&project)
            .env("LPM_REGISTRY_URL", mock.url())
            .args([
                "env",
                "oidc",
                "allow",
                "--provider=github",
                "--repo=owner/repository",
                &format!("--repository-id={repository_id}"),
                "--workflow=.github/workflows/deploy.yml",
                "--env=production",
            ])
            .output()
            .expect("run rejected GitHub OIDC repository ID");

        assert!(
            !output.status.success(),
            "{repository_id:?} should be rejected"
        );
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("repository ID must be a positive decimal integer of at most 20 digits")
        );
        assert!(mock.server().received_requests().await.unwrap().is_empty());
    }
}

#[tokio::test]
async fn env_push_uses_bound_checkpoint_without_a_version_preflight() {
    let project = TempProject::empty(r#"{"name":"push-bound","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let registry_url = mock.url();
    let vault_id = "vault-push-bound";
    project.write_file(
        "lpm.json",
        &serde_json::json!({
            "vault": vault_id,
            "vaultSync": {
                "authorityCheckpoints": {
                    "personal": {
                        (registry_url.clone()): {
                            "account-1": {
                                "version": 7,
                                "syncedAt": "2026-09-05T00:00:00Z",
                            },
                        },
                    },
                },
            },
        })
        .to_string(),
    );
    write_file_backed_vault(
        project.home(),
        vault_id,
        serde_json::json!({"environments": {"default": {"API_KEY": "secret"}}}),
    );
    write_private_file(
        &project.home().join(".lpm").join(".vault-key"),
        hex::encode([0x31; 32]),
    );
    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &registry_url,
            access_token: Some("session-access-token"),
            refresh_token: Some("refresh-token"),
            session_access_expires_at: Some("2030-01-01T00:00:00Z"),
        }],
    );

    Mock::given(method("GET"))
        .and(path(format!("/api/vaults/{vault_id}/sync")))
        .and(query_param("versionOnly", "true"))
        .respond_with(signed_sync_response(
            serde_json::json!({"version": 7}),
            "session-access-token",
            vault_id,
            TestSyncScope::Personal,
        ))
        .mount(mock.server())
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/api/vaults/{vault_id}/sync")))
        .respond_with(signed_sync_response(
            serde_json::json!({"version": 8, "status": "synced"}),
            "session-access-token",
            vault_id,
            TestSyncScope::Personal,
        ))
        .expect(1)
        .mount(mock.server())
        .await;

    let manifest_read_log = project.path().join("manifest-reads.log");

    let mut command = lpm(&project);
    command
        .env("LPM_REGISTRY_URL", &registry_url)
        .env("LPM_TEST_MANIFEST_READ_LOG", &manifest_read_log);
    let output = command
        .args(["--json", "env", "push", "--yes"])
        .output()
        .expect("run bound personal push");

    assert!(
        output.status.success(),
        "push failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let requests = mock.server().received_requests().await.unwrap();
    assert_eq!(
        requests
            .iter()
            .filter(|request| {
                request.method.as_str() == "GET"
                    && request
                        .url
                        .query_pairs()
                        .any(|(key, value)| key == "versionOnly" && value == "true")
            })
            .count(),
        0,
        "a durable principal-bound checkpoint must avoid the version preflight",
    );
    let push = requests
        .iter()
        .find(|request| request.method.as_str() == "POST")
        .expect("personal push request");
    let body: serde_json::Value = serde_json::from_slice(&push.body).unwrap();
    assert_eq!(body["expectedVersion"], 7);
    assert_eq!(body["expectedPrincipalId"], "account-1");
    let manifest_read_count = std::fs::read_to_string(&manifest_read_log)
        .expect("read manifest access log")
        .lines()
        .count();
    assert_eq!(
        manifest_read_count, 3,
        "one command snapshot, one fresh mutation-boundary check, and one guarded metadata commit are sufficient",
    );
}

#[tokio::test]
async fn env_force_push_recreates_a_deleted_bound_vault_above_its_checkpoint() {
    let project = TempProject::empty(r#"{"name":"push-recreated","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let registry_url = mock.url();
    let vault_id = "vault-push-recreated";
    project.write_file(
        "lpm.json",
        &serde_json::json!({
            "vault": vault_id,
            "vaultSync": {
                "personalVersion": 5,
                "authorityCheckpoints": {
                    "personal": {
                        registry_url.clone(): {
                            "account-1": {
                                "version": 5,
                                "syncedAt": "2026-09-04T00:00:00Z",
                            },
                        },
                    },
                },
            },
        })
        .to_string(),
    );
    write_file_backed_vault(
        project.home(),
        vault_id,
        serde_json::json!({"environments": {"default": {"API_KEY": "secret"}}}),
    );
    write_private_file(
        &project.home().join(".lpm").join(".vault-key"),
        hex::encode([0x32; 32]),
    );
    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &registry_url,
            access_token: Some("session-access-token"),
            refresh_token: Some("refresh-token"),
            session_access_expires_at: Some("2030-01-01T00:00:00Z"),
        }],
    );

    Mock::given(method("GET"))
        .and(path(format!("/api/vaults/{vault_id}/sync")))
        .and(query_param("versionOnly", "true"))
        .respond_with(signed_personal_missing_response(vault_id, "account-1", 5))
        .expect(1)
        .mount(mock.server())
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/api/vaults/{vault_id}/sync")))
        .respond_with(signed_sync_response(
            serde_json::json!({"version": 6, "status": "synced", "principalId": "account-1"}),
            "session-access-token",
            vault_id,
            TestSyncScope::Personal,
        ))
        .expect(1)
        .mount(mock.server())
        .await;

    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", &registry_url)
        .args(["--json", "env", "push", "--yes", "--force"])
        .output()
        .expect("run forced personal recreation");

    assert!(
        output.status.success(),
        "force recreation failed after the remote commit:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert_eq!(
        lpm_vault::vault_id::read_personal_sync_version_for_principal(
            project.path(),
            lpm_vault::vault_id::SyncPrincipal {
                registry_url: &registry_url,
                principal_id: "account-1",
            },
        ),
        Some(6),
    );
    let requests = mock.server().received_requests().await.unwrap();
    let push = requests
        .iter()
        .find(|request| request.method.as_str() == "POST")
        .expect("personal recreation request");
    let body: serde_json::Value = serde_json::from_slice(&push.body).unwrap();
    assert_eq!(body["expectedVersion"], 5);
    assert_eq!(body["expectedPrincipalId"], "account-1");
    assert_eq!(body["ciphertextRevision"], 6);
    assert_eq!(body["recreateMissing"], true);
}

#[tokio::test]
async fn env_rotate_key_preserves_complete_named_remote_payload_with_cas() {
    let project = TempProject::empty(r#"{"name":"rotate-key","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    project.write_file("lpm.json", r#"{"vault":"vault-rotate-123"}"#);
    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some("session-access-token"),
            refresh_token: Some("refresh-token"),
            session_access_expires_at: Some("2030-01-01T00:00:00Z"),
        }],
    );
    let original_wrapping_key = [0x11; 32];
    let wrapping_key_path = project.home().join(".lpm").join(".vault-key");
    std::fs::write(&wrapping_key_path, hex::encode(original_wrapping_key))
        .expect("seed original wrapping key");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&wrapping_key_path, std::fs::Permissions::from_mode(0o600))
            .expect("restrict original wrapping key");
    }
    let original_data_key = [0x22; 32];
    let authoritative_payload = serde_json::json!({
        "environments": {
            "default": {},
            "production": {"API_KEY": "remote-only"},
            "staging": {"API_KEY": "stage"}
        }
    });
    mock.with_personal_pull_keys(
        "vault-rotate-123",
        "session-access-token",
        authoritative_payload.clone(),
        &original_wrapping_key,
        &original_data_key,
        7,
    )
    .await;

    let manifest_read_log = project.path().join("personal-rotation-manifest-reads.log");
    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .env("LPM_TEST_MANIFEST_READ_LOG", &manifest_read_log)
        .args(["--json", "env", "rotate-key"])
        .output()
        .expect("run env rotate-key");

    assert!(
        output.status.success(),
        "rotate-key failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let json = parse_json_output(&output.stdout);
    assert_eq!(json["version"], 8);
    assert_eq!(json["environment_count"], 3);
    assert_eq!(
        json["environments"],
        serde_json::json!(["default", "production", "staging"])
    );
    let manifest_reads = std::fs::read_to_string(manifest_read_log)
        .expect("read personal-rotation manifest access log");
    assert_eq!(
        manifest_reads.lines().count(),
        3,
        "rotation needs one command snapshot, one mutation-boundary check, and one guarded metadata commit:\n{manifest_reads}",
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("remote-only"));

    let requests = mock.server().received_requests().await.unwrap();
    let pushes: Vec<_> = requests
        .iter()
        .filter(|request| request.method.as_str() == "POST")
        .collect();
    assert_eq!(
        pushes.len(),
        1,
        "rotation must perform one CAS push without a preliminary migration write"
    );
    let push = pushes[0];
    let body: serde_json::Value = serde_json::from_slice(&push.body).unwrap();
    assert_eq!(
        requests
            .iter()
            .filter(|request| {
                request.method.as_str() == "GET"
                    && request
                        .url
                        .query_pairs()
                        .any(|(key, value)| key == "versionOnly" && value == "true")
            })
            .count(),
        0,
        "the signed rotation pull must supply the principal and version preconditions",
    );
    assert_eq!(body["expectedVersion"], 7);
    assert_eq!(body["expectedPrincipalId"], "account-1");
    assert_eq!(body["ciphertextRevision"], 8);
    assert_eq!(
        body["cryptoVersion"],
        lpm_vault::crypto::CURRENT_CRYPTO_VERSION
    );
    assert!(body.get("force").is_none());

    let wrapped_key = body["wrappedKey"].as_str().expect("wrapped key");
    let rotated_data_key = lpm_vault::crypto::unwrap_key(&original_wrapping_key, wrapped_key)
        .expect("unwrap data key");
    assert_ne!(
        rotated_data_key, original_data_key,
        "rotation must encrypt the complete payload under a fresh data key"
    );
    let rotated_plaintext = lpm_vault::crypto::decrypt_vault_payload(
        &rotated_data_key,
        body["encryptedBlob"].as_str().expect("encrypted blob"),
        lpm_vault::crypto::VaultScope::Personal,
        "account-1",
        "vault-rotate-123",
        8,
        lpm_vault::crypto::CURRENT_CRYPTO_VERSION,
    )
    .expect("decrypt rotated payload");
    let rotated_payload: serde_json::Value =
        serde_json::from_slice(&rotated_plaintext).expect("parse rotated payload");
    assert_eq!(
        rotated_payload, authoritative_payload,
        "rotation must preserve environments, aliases, inheritance, and schema metadata exactly"
    );
    let persisted_wrapping_key_bytes = hex::decode(
        std::fs::read_to_string(&wrapping_key_path)
            .expect("read wrapping key")
            .trim(),
    )
    .expect("decode wrapping key");
    let persisted_wrapping_key: [u8; 32] = persisted_wrapping_key_bytes
        .try_into()
        .expect("wrapping key must have 32 bytes");
    assert_eq!(
        persisted_wrapping_key, original_wrapping_key,
        "data-key rotation must preserve the shared wrapping key used by browser and CI escrow"
    );
}

#[tokio::test]
async fn env_rotate_key_rejects_a_replaced_manifest_before_the_remote_write() {
    let project = TempProject::empty(r#"{"name":"rotate-replaced","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let registry_url = mock.url();
    let vault_id = "vault-rotate-replaced";
    project.write_file("lpm.json", &format!(r#"{{"vault":"{vault_id}"}}"#));
    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &registry_url,
            access_token: Some("rotation-replaced-token"),
            refresh_token: Some("rotation-replaced-refresh"),
            session_access_expires_at: Some("2030-01-01T00:00:00Z"),
        }],
    );
    let wrapping_key = [0x41; 32];
    write_private_file(
        &project.home().join(".lpm").join(".vault-key"),
        hex::encode(wrapping_key),
    );
    let data_key = [0x42; 32];
    let plaintext = serde_json::to_vec(&serde_json::json!({
        "environments": {"default": {"API_KEY": "remote"}},
    }))
    .expect("serialize rotation payload");
    let encrypted_blob = lpm_vault::crypto::encrypt_vault_payload(
        &data_key,
        &plaintext,
        lpm_vault::crypto::VaultScope::Personal,
        "account-1",
        vault_id,
        7,
    )
    .expect("encrypt rotation payload");
    let wrapped_key =
        lpm_vault::crypto::wrap_key(&wrapping_key, &data_key).expect("wrap rotation payload key");
    let signed_response = signed_sync_response(
        serde_json::json!({
            "encryptedBlob": encrypted_blob,
            "wrappedKey": wrapped_key,
            "version": 7,
            "cryptoVersion": lpm_vault::crypto::CURRENT_CRYPTO_VERSION,
        }),
        "rotation-replaced-token",
        vault_id,
        TestSyncScope::Personal,
    );
    Mock::given(method("GET"))
        .and(path(format!("/api/vaults/{vault_id}/sync")))
        .and(header("authorization", "Bearer rotation-replaced-token"))
        .respond_with(ManifestReplacingSignedResponse {
            manifest_path: project.path().join("lpm.json"),
            replacement: r#"{"vault":"another-vault"}"#.to_owned(),
            response: signed_response,
        })
        .expect(1)
        .mount(mock.server())
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/api/vaults/{vault_id}/sync")))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(mock.server())
        .await;

    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", &registry_url)
        .args(["--json", "env", "rotate-key"])
        .output()
        .expect("run rotation while lpm.json is replaced");

    assert!(!output.status.success());
    let error = parse_clean_json_stdout(&output);
    assert!(
        error["error"]
            .as_str()
            .is_some_and(|message| message.contains("changed to another vault")),
        "unexpected error: {error}",
    );
    assert_eq!(
        mock.server()
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|request| request.method.as_str() == "POST")
            .count(),
        0,
    );
}

#[tokio::test]
async fn env_rotate_key_rejects_semantically_invalid_lpm_json_before_network_access() {
    let project = TempProject::empty(r#"{"name":"rotate-invalid-config","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    project.write_file(
        "lpm.json",
        r#"{"vault":"vault-invalid-rotate","env":{"prod":123}}"#,
    );
    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some("session-access-token"),
            refresh_token: Some("refresh-token"),
            session_access_expires_at: Some("2030-01-01T00:00:00Z"),
        }],
    );

    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["env", "rotate-key"])
        .output()
        .expect("run env rotate-key with semantically invalid lpm.json");

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("lpm.json"),
        "the failure must identify the invalid project configuration"
    );
    assert!(
        mock.server().received_requests().await.unwrap().is_empty(),
        "canonical validation must happen before rotation fetches remote state"
    );
}

#[tokio::test]
async fn env_rotate_key_version_conflict_preserves_local_key_and_version_metadata() {
    let project = TempProject::empty(r#"{"name":"rotate-key-conflict","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    project.write_file("lpm.json", r#"{"vault":"vault-rotate-conflict-123"}"#);
    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some("session-access-token"),
            refresh_token: Some("refresh-token"),
            session_access_expires_at: Some("2030-01-01T00:00:00Z"),
        }],
    );
    let wrapping_key = [0x33; 32];
    let wrapping_key_path = project.home().join(".lpm").join(".vault-key");
    std::fs::write(&wrapping_key_path, hex::encode(wrapping_key)).expect("seed wrapping key");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&wrapping_key_path, std::fs::Permissions::from_mode(0o600))
            .expect("restrict wrapping key");
    }
    mock.with_personal_pull_failure(PersonalPullFailureFixture {
        vault_id: "vault-rotate-conflict-123",
        bearer_token: "session-access-token",
        payload: serde_json::json!({
            "environments": {
                "default": {"API_KEY": "remote"}
            }
        }),
        wrapping_key: &wrapping_key,
        data_key: &[0x34; 32],
        version: 7,
        status: 409,
        error: "vault version conflict",
    })
    .await;

    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["--json", "env", "rotate-key"])
        .output()
        .expect("run conflicting env rotate-key");

    assert!(!output.status.success());
    let error = parse_json_output(&output.stdout);
    assert_eq!(error["success"], false);
    assert!(
        error["error"]
            .as_str()
            .is_some_and(|message| message.contains("vault version conflict")),
        "unexpected error: {error}",
    );
    assert_eq!(
        std::fs::read_to_string(&wrapping_key_path)
            .expect("read wrapping key after conflict")
            .trim(),
        hex::encode(wrapping_key)
    );
    assert_eq!(
        lpm_vault::vault_id::read_personal_sync_version(project.path()),
        None
    );
}

#[tokio::test]
async fn env_rotate_key_encryption_failure_does_not_push_or_update_local_metadata() {
    let project = TempProject::empty(r#"{"name":"rotate-key-encrypt","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    project.write_file("lpm.json", r#"{"vault":"vault-rotate-encrypt-123"}"#);
    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some("session-access-token"),
            refresh_token: Some("refresh-token"),
            session_access_expires_at: Some("2030-01-01T00:00:00Z"),
        }],
    );
    let wrapping_key = [0x44; 32];
    let wrapping_key_path = project.home().join(".lpm").join(".vault-key");
    std::fs::write(&wrapping_key_path, hex::encode(wrapping_key)).expect("seed wrapping key");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&wrapping_key_path, std::fs::Permissions::from_mode(0o600))
            .expect("restrict wrapping key");
    }
    mock.with_personal_pull_keys(
        "vault-rotate-encrypt-123",
        "session-access-token",
        serde_json::json!({
            "environments": {
                "default": {"API_KEY": "remote"}
            }
        }),
        &wrapping_key,
        &[0x45; 32],
        7,
    )
    .await;

    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .env(
            "LPM_TEST_VAULT_WRAPPING_KEY_ERROR",
            "simulated encryption failure",
        )
        .args(["--json", "env", "rotate-key"])
        .output()
        .expect("run env rotate-key with encryption failure");

    assert!(!output.status.success());
    let error = parse_json_output(&output.stdout);
    assert_eq!(error["success"], false);
    assert!(
        error["error"]
            .as_str()
            .is_some_and(|message| message.contains("simulated encryption failure"))
    );
    let requests = mock.server().received_requests().await.unwrap();
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.method.as_str() == "POST")
            .count(),
        0
    );
    assert_eq!(
        std::fs::read_to_string(&wrapping_key_path)
            .expect("read wrapping key after encryption failure")
            .trim(),
        hex::encode(wrapping_key)
    );
    assert_eq!(
        lpm_vault::vault_id::read_personal_sync_version(project.path()),
        None
    );
}

#[tokio::test]
async fn env_rotate_key_org_reencrypts_complete_payload_and_advances_content_key_epoch() {
    let project = TempProject::empty(r#"{"name":"org-rotate","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let payload = serde_json::json!({
        "environments": {
            "default": {},
            "production": {"API_KEY": "remote-only"},
        },
    });
    let prepared = prepare_org_rotation(&project, &mock, &payload, false, true).await;
    let recipient_acceptance = org_rotation_recipient_acceptance(&mock, &prepared.fingerprint);
    mount_org_rotation_push(
        &mock,
        ORG_ROTATION_TOKEN,
        ORG_ROTATION_SLUG,
        ORG_ROTATION_VAULT_ID,
        serde_json::json!({
            "status": "rotated",
            "version": 9,
            "contentKeyVersion": 4,
        }),
    )
    .await;

    let manifest_read_log = project.path().join("org-rotation-manifest-reads.log");
    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .env("LPM_TEST_MANIFEST_READ_LOG", &manifest_read_log)
        .args([
            "--json",
            "env",
            "rotate-key",
            "--org",
            ORG_ROTATION_SLUG,
            "--accept-recipient-keys",
            &recipient_acceptance,
        ])
        .output()
        .expect("run organization content-key rotation");

    assert!(
        output.status.success(),
        "organization rotation failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let result = parse_clean_json_stdout(&output);
    assert_eq!(result["version"], 9);
    assert_eq!(result["content_key_version"], 4);
    assert_eq!(result["previous_content_key_version"], 3);
    assert_eq!(result["environment_count"], 2);
    assert!(!String::from_utf8_lossy(&output.stdout).contains("remote-only"));
    assert_eq!(
        lpm_vault::vault_id::read_org_sync_version(project.path(), ORG_ROTATION_SLUG),
        Some(9),
    );
    assert_eq!(
        std::fs::read_to_string(manifest_read_log)
            .expect("read organization-rotation manifest access log")
            .lines()
            .count(),
        3,
        "organization rotation needs one command snapshot, one mutation-boundary check, and one guarded metadata commit",
    );

    let requests = mock.server().received_requests().await.unwrap();
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.url.path() == "/api/users/me/public-key")
            .count(),
        0,
        "steady-state organization rotation must use the signed pull binding without a public-key preflight",
    );
    let push = requests
        .iter()
        .find(|request| request.method.as_str() == "POST")
        .expect("rotation must push the new ciphertext");
    let body: serde_json::Value =
        serde_json::from_slice(&push.body).expect("organization push body must be JSON");
    assert_eq!(body["expectedVersion"], 8);
    assert_eq!(body["ciphertextRevision"], 9);
    assert_eq!(
        body["cryptoVersion"],
        lpm_vault::crypto::CURRENT_CRYPTO_VERSION
    );
    assert_eq!(body["wrappedKeys"][0]["publicKeyVersion"], 4);
    assert_eq!(
        body["wrappedKeys"][0]["publicKeyFingerprint"],
        prepared.fingerprint,
    );
    let wrapped_key = body["wrappedKeys"][0]["wrappedKey"]
        .as_str()
        .expect("rotation push must contain a wrapped content key");
    let rotated_content_key =
        lpm_vault::crypto::unwrap_key_from_sender(wrapped_key, &prepared.private_key)
            .expect("unwrap rotated organization content key");
    assert_ne!(rotated_content_key, prepared.previous_content_key);
    let rotated_plaintext = lpm_vault::crypto::decrypt_vault_payload(
        &rotated_content_key,
        body["encryptedBlob"]
            .as_str()
            .expect("rotation push must contain ciphertext"),
        lpm_vault::crypto::VaultScope::Organization(ORG_ROTATION_SLUG),
        "00000000-0000-4000-8000-000000000001",
        ORG_ROTATION_VAULT_ID,
        9,
        lpm_vault::crypto::CURRENT_CRYPTO_VERSION,
    )
    .expect("decrypt rotated organization payload");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&rotated_plaintext)
            .expect("rotated organization payload must remain JSON"),
        payload,
    );
    assert_eq!(
        body["wrappedKeys"][0]["publicKeyFingerprint"],
        hex::encode(Sha256::digest(
            BASE64
                .decode(prepared.public_key_base64)
                .expect("decode prepared public key")
        )),
    );
}

#[tokio::test]
async fn env_rotate_key_org_version_conflict_preserves_local_sync_version() {
    let project = TempProject::empty(r#"{"name":"org-rotate-conflict","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let payload = serde_json::json!({
        "environments": {"default": {"API_KEY": "remote"}},
    });
    let prepared = prepare_org_rotation(&project, &mock, &payload, false, true).await;
    let recipient_acceptance = org_rotation_recipient_acceptance(&mock, &prepared.fingerprint);
    lpm_vault::vault_id::write_org_sync_version(project.path(), ORG_ROTATION_SLUG, 7)
        .expect("seed prior organization sync version");
    Mock::given(method("POST"))
        .and(path(format!(
            "/api/orgs/{ORG_ROTATION_SLUG}/vaults/{ORG_ROTATION_VAULT_ID}"
        )))
        .respond_with(SignedOrgRevisionConflictResponse {
            org_slug: ORG_ROTATION_SLUG.to_owned(),
            vault_id: ORG_ROTATION_VAULT_ID.to_owned(),
            current_revision: 9,
        })
        .expect(1)
        .mount(mock.server())
        .await;

    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args([
            "--json",
            "env",
            "rotate-key",
            "--org",
            ORG_ROTATION_SLUG,
            "--accept-recipient-keys",
            &recipient_acceptance,
        ])
        .output()
        .expect("run conflicting organization rotation");

    assert!(!output.status.success());
    let error = parse_clean_json_stdout(&output);
    assert!(
        error["error"]
            .as_str()
            .is_some_and(|message| message.contains("vault changed concurrently")),
        "unexpected error: {error}",
    );
    assert_eq!(
        lpm_vault::vault_id::read_org_sync_version(project.path(), ORG_ROTATION_SLUG),
        Some(7),
    );
}

#[tokio::test]
async fn env_rotate_key_org_rejects_stale_recipient_fingerprint_before_rewrapping() {
    let project = TempProject::empty(r#"{"name":"org-rotate-stale","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let payload = serde_json::json!({"environments": {"default": {"API_KEY": "remote"}}});
    prepare_org_rotation(&project, &mock, &payload, true, false).await;

    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args([
            "--json",
            "env",
            "rotate-key",
            &format!("--org={ORG_ROTATION_SLUG}"),
        ])
        .output()
        .expect("run organization rotation with stale recipient fingerprint");

    assert!(!output.status.success());
    let error = parse_clean_json_stdout(&output);
    assert!(
        error["error"]
            .as_str()
            .is_some_and(|message| message.contains("different local sharing-key fingerprint"))
    );
    let requests = mock.server().received_requests().await.unwrap();
    assert!(
        requests
            .iter()
            .all(|request| request.method.as_str() != "POST")
    );
    assert!(
        requests
            .iter()
            .all(|request| { !request.url.path().ends_with("/members/public-keys") })
    );
}

#[tokio::test]
async fn env_rotate_key_org_rejects_response_without_content_key_epoch() {
    let project = TempProject::empty(r#"{"name":"org-rotate-missing-epoch","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let payload = serde_json::json!({"environments": {"default": {"API_KEY": "remote"}}});
    let prepared = prepare_org_rotation(&project, &mock, &payload, false, true).await;
    let recipient_acceptance = org_rotation_recipient_acceptance(&mock, &prepared.fingerprint);
    mount_org_rotation_push(
        &mock,
        ORG_ROTATION_TOKEN,
        ORG_ROTATION_SLUG,
        ORG_ROTATION_VAULT_ID,
        serde_json::json!({"status": "rotated", "version": 9}),
    )
    .await;

    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args([
            "--json",
            "env",
            "rotate-key",
            "--org",
            ORG_ROTATION_SLUG,
            "--accept-recipient-keys",
            &recipient_acceptance,
        ])
        .output()
        .expect("run organization rotation with incomplete response");

    assert!(!output.status.success());
    let error = parse_clean_json_stdout(&output);
    assert!(
        error["error"]
            .as_str()
            .is_some_and(|message| message.contains("omitted the content key version")),
        "unexpected error: {error}",
    );
    assert_eq!(
        lpm_vault::vault_id::read_org_sync_version(project.path(), ORG_ROTATION_SLUG),
        None,
    );
}

#[tokio::test]
async fn env_rotate_key_org_rejects_response_with_unchanged_content_key_epoch() {
    let project = TempProject::empty(r#"{"name":"org-rotate-static-epoch","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let payload = serde_json::json!({"environments": {"default": {"API_KEY": "remote"}}});
    let prepared = prepare_org_rotation(&project, &mock, &payload, false, true).await;
    let recipient_acceptance = org_rotation_recipient_acceptance(&mock, &prepared.fingerprint);
    mount_org_rotation_push(
        &mock,
        ORG_ROTATION_TOKEN,
        ORG_ROTATION_SLUG,
        ORG_ROTATION_VAULT_ID,
        serde_json::json!({
            "status": "rotated",
            "version": 9,
            "contentKeyVersion": 3,
        }),
    )
    .await;

    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args([
            "--json",
            "env",
            "rotate-key",
            "--org",
            ORG_ROTATION_SLUG,
            "--accept-recipient-keys",
            &recipient_acceptance,
        ])
        .output()
        .expect("run organization rotation with unchanged content-key epoch");

    assert!(!output.status.success());
    let error = parse_clean_json_stdout(&output);
    assert!(
        error["error"]
            .as_str()
            .is_some_and(|message| message.contains("did not advance"))
    );
    assert_eq!(
        lpm_vault::vault_id::read_org_sync_version(project.path(), ORG_ROTATION_SLUG),
        None,
    );
}

#[tokio::test]
async fn env_oidc_allow_emits_json_response() {
    let project = TempProject::empty(r#"{"name":"vault-oidc-allow-json-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;

    write_personal_bound_manifest(&project, &mock.url(), "vault-policy-json-123");

    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some("session-access-token"),
            refresh_token: Some("refresh-token"),
            session_access_expires_at: Some("2030-01-01T00:00:00Z"),
        }],
    );

    mock.with_oidc_policy_create(
        "session-access-token",
        "vault-policy-json-123",
        "acme/repo",
        "987654321",
        &["main"],
        &["production"],
        &[".github/workflows/deploy.yml"],
        &["push"],
    )
    .await;
    mock.with_escrow_upload_success("session-access-token", "vault-policy-json-123")
        .await;

    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args([
            "--json",
            "env",
            "oidc",
            "allow",
            "--provider=github",
            "--repo=acme/repo",
            "--repository-id=987654321",
            "--branch=main",
            "--env=production",
            "--workflow=.github/workflows/deploy.yml",
        ])
        .output()
        .expect("failed to run oidc allow --json");

    assert!(
        output.status.success(),
        "oidc allow --json failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let json = parse_json_output(&output.stdout);
    assert_eq!(json["status"], "ok");
    assert_eq!(json["policyId"], TEST_OIDC_POLICY_ID);
    assert_eq!(json["provider"], "github");
    assert_eq!(json["subject"], "repo:acme/repo");
}

#[tokio::test]
async fn env_oidc_allow_rejects_missing_or_malformed_policy_id_before_escrow() {
    for (label, response) in [
        (
            "missing",
            serde_json::json!({
                "status": "ok",
                "provider": "github",
                "subject": "repo:acme/repo",
            }),
        ),
        (
            "malformed",
            serde_json::json!({
                "status": "ok",
                "policyId": "not-a-uuid",
                "provider": "github",
                "subject": "repo:acme/repo",
            }),
        ),
    ] {
        let project =
            TempProject::empty(r#"{"name":"vault-oidc-invalid-policy-id","version":"1.0.0"}"#);
        let mock = MockRegistry::start().await;
        write_personal_bound_manifest(&project, &mock.url(), "vault-policy-invalid-id");
        seed_sessions(
            project.home(),
            &[SessionSeed {
                registry_url: &mock.url(),
                access_token: Some("session-access-token"),
                refresh_token: Some("refresh-token"),
                session_access_expires_at: Some("2030-01-01T00:00:00Z"),
            }],
        );

        Mock::given(method("POST"))
            .and(path("/api/vault/oidc/policies"))
            .and(header("authorization", "Bearer session-access-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response))
            .expect(1)
            .mount(mock.server())
            .await;
        Mock::given(method("POST"))
            .and(path("/api/vault/oidc/escrow"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(mock.server())
            .await;

        let output = lpm(&project)
            .env("LPM_REGISTRY_URL", mock.url())
            .args([
                "env",
                "oidc",
                "allow",
                "--provider=github",
                "--repo=acme/repo",
                "--repository-id=987654321",
                "--branch=main",
                "--env=production",
                "--workflow=.github/workflows/deploy.yml",
            ])
            .output()
            .expect("run OIDC allow with invalid policy selector response");

        assert!(
            !output.status.success(),
            "{label} policy ID unexpectedly passed"
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("valid OIDC policy ID"),
            "{label} policy ID error was not actionable: {}",
            String::from_utf8_lossy(&output.stderr),
        );
    }
}

#[tokio::test]
async fn env_oidc_list_emits_json_response() {
    let project = TempProject::empty(r#"{"name":"vault-oidc-list-json-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;

    project.write_file("lpm.json", r#"{"vault":"vault-policy-list-json-123"}"#);

    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some("session-access-token"),
            refresh_token: Some("refresh-token"),
            session_access_expires_at: Some("2030-01-01T00:00:00Z"),
        }],
    );

    mock.with_oidc_policy_list(
        "session-access-token",
        "vault-policy-list-json-123",
        serde_json::json!([
            {
                "id": TEST_OIDC_POLICY_ID,
                "provider": "github",
                "subject": "repo:acme/repo",
                "allowedBranches": ["main"],
                "allowedEnvironments": ["production"],
                "allowedWorkflows": [".github/workflows/deploy.yml"],
                "allowedEvents": ["push"],
                "allowForks": false,
            },
            {
                "id": TEST_OIDC_POLICY_ID_2,
                "provider": "github",
                "subject": "repo:acme/preview",
                "allowedBranches": ["develop"],
                "allowedEnvironments": ["preview"],
                "allowedWorkflows": [
                    ".github/workflows/ci.yml",
                    ".github/workflows/preview.yml"
                ],
                "allowedEvents": ["push", "pull_request_target"],
                "allowForks": true,
            }
        ]),
    )
    .await;

    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["--json", "env", "oidc", "list"])
        .output()
        .expect("failed to run oidc list --json");

    assert!(
        output.status.success(),
        "oidc list --json failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let json = parse_json_output(&output.stdout);
    let policies = json["policies"]
        .as_array()
        .expect("policies should be an array");
    assert_eq!(policies.len(), 2);
    assert_eq!(policies[0]["id"], TEST_OIDC_POLICY_ID);
    assert_eq!(policies[0]["provider"], "github");
    assert_eq!(policies[0]["subject"], "repo:acme/repo");
    assert_eq!(policies[0]["allowedBranches"], serde_json::json!(["main"]));
    assert_eq!(
        policies[0]["allowedEnvironments"],
        serde_json::json!(["production"]),
    );
    assert_eq!(
        policies[0]["allowedWorkflows"],
        serde_json::json!([".github/workflows/deploy.yml"]),
    );
    assert_eq!(policies[0]["allowedEvents"], serde_json::json!(["push"]));
    assert_eq!(policies[0]["allowForks"], false);

    assert_eq!(policies[1]["id"], TEST_OIDC_POLICY_ID_2);
    assert_eq!(policies[1]["subject"], "repo:acme/preview");
    assert_eq!(
        policies[1]["allowedWorkflows"],
        serde_json::json!([".github/workflows/ci.yml", ".github/workflows/preview.yml"]),
    );
    assert_eq!(
        policies[1]["allowedEvents"],
        serde_json::json!(["push", "pull_request_target"]),
    );
    assert_eq!(policies[1]["allowForks"], true);
}

#[tokio::test]
async fn env_oidc_list_rejects_policy_without_valid_id() {
    let project = TempProject::empty(r#"{"name":"vault-oidc-list-invalid-id","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    project.write_file("lpm.json", r#"{"vault":"vault-policy-list-invalid-id"}"#);
    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some("session-access-token"),
            refresh_token: Some("refresh-token"),
            session_access_expires_at: Some("2030-01-01T00:00:00Z"),
        }],
    );
    mock.with_oidc_policy_list(
        "session-access-token",
        "vault-policy-list-invalid-id",
        serde_json::json!([{
            "id": "not-a-uuid",
            "provider": "github",
            "subject": "repo:acme/repo",
        }]),
    )
    .await;

    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["env", "oidc", "list"])
        .output()
        .expect("run OIDC policy list with invalid selector");

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("valid policy ID"));
}

#[tokio::test]
async fn env_oidc_list_human_output_renders_new_fields() {
    // The CLI's human-readable `lpm env oidc list` output must surface
    // allowedWorkflows and allowedEvents; without this the dashboard-vs-CLI
    // inspection paths drift and CLI users would not see the policy fields
    // that gate their next CI mint.
    let project =
        TempProject::empty(r#"{"name":"vault-oidc-list-human-fields","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;

    project.write_file("lpm.json", r#"{"vault":"vault-policy-list-human-1"}"#);

    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some("session-access-token"),
            refresh_token: Some("refresh-token"),
            session_access_expires_at: Some("2030-01-01T00:00:00Z"),
        }],
    );

    mock.with_oidc_policy_list(
        "session-access-token",
        "vault-policy-list-human-1",
        serde_json::json!([
            {
                "id": TEST_OIDC_POLICY_ID,
                "provider": "github",
                "subject": "repo:acme/repo",
                "allowedBranches": ["main"],
                "allowedEnvironments": ["production"],
                "allowedWorkflows": [".github/workflows/deploy.yml"],
                "allowedEvents": ["push", "release"],
                "allowForks": false,
            }
        ]),
    )
    .await;

    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["env", "oidc", "list"])
        .output()
        .expect("failed to run oidc list");

    assert!(output.status.success(), "oidc list failed");
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        combined.contains(".github/workflows/deploy.yml"),
        "expected workflow path in human output, got: {combined}",
    );
    assert!(
        combined.contains("push") && combined.contains("release"),
        "expected event names in human output, got: {combined}",
    );
    assert!(
        combined.contains("workflows:"),
        "expected `workflows:` label in human output, got: {combined}",
    );
    assert!(
        combined.contains("events:"),
        "expected `events:` label in human output, got: {combined}",
    );
}

#[tokio::test]
async fn env_oidc_allow_fails_when_escrow_upload_fails() {
    let project =
        TempProject::empty(r#"{"name":"vault-oidc-escrow-failure-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;

    write_personal_bound_manifest(&project, &mock.url(), "vault-policy-456");

    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some("session-access-token"),
            refresh_token: Some("refresh-token"),
            session_access_expires_at: Some("2030-01-01T00:00:00Z"),
        }],
    );

    mock.with_oidc_policy_create(
        "session-access-token",
        "vault-policy-456",
        "acme/repo",
        "987654321",
        &["main"],
        &["preview"],
        &[".github/workflows/deploy.yml"],
        &["push"],
    )
    .await;
    mock.with_escrow_upload_failure(
        "session-access-token",
        "vault-policy-456",
        "escrow backend unavailable",
    )
    .await;

    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args([
            "env",
            "oidc",
            "allow",
            "--provider=github",
            "--repo=acme/repo",
            "--repository-id=987654321",
            "--branch=main",
            "--env=preview",
            "--workflow=.github/workflows/deploy.yml",
        ])
        .output()
        .expect("failed to run oidc allow with escrow failure");

    assert!(
        !output.status.success(),
        "oidc allow unexpectedly succeeded after escrow upload failed"
    );
    let combined_output = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !combined_output.contains("OIDC policy set: github"),
        "policy success must not be reported before escrow completes: {combined_output}",
    );
    assert!(
        combined_output.contains("policy may already have been created")
            && combined_output.contains("CI pulls are not ready")
            && combined_output.contains("escrow backend unavailable")
            && combined_output.contains("rerun the same `lpm env oidc allow` command"),
        "expected partial-completion and safe-rerun guidance, got: {combined_output}",
    );
}

#[tokio::test]
async fn env_oidc_allow_json_escrow_failure_emits_one_error_document() {
    let project =
        TempProject::empty(r#"{"name":"vault-oidc-escrow-json-failure-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    write_personal_bound_manifest(&project, &mock.url(), "vault-policy-json-failure");

    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some("session-access-token"),
            refresh_token: Some("refresh-token"),
            session_access_expires_at: Some("2030-01-01T00:00:00Z"),
        }],
    );

    mock.with_oidc_policy_create(
        "session-access-token",
        "vault-policy-json-failure",
        "acme/repo",
        "987654321",
        &["main"],
        &["preview"],
        &[".github/workflows/deploy.yml"],
        &["push"],
    )
    .await;
    mock.with_escrow_upload_failure(
        "session-access-token",
        "vault-policy-json-failure",
        "escrow backend unavailable",
    )
    .await;

    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args([
            "--json",
            "env",
            "oidc",
            "allow",
            "--provider=github",
            "--repo=acme/repo",
            "--repository-id=987654321",
            "--branch=main",
            "--env=preview",
            "--workflow=.github/workflows/deploy.yml",
        ])
        .output()
        .expect("failed to run JSON oidc allow with escrow failure");

    assert!(
        !output.status.success(),
        "JSON oidc allow unexpectedly succeeded after escrow upload failed"
    );
    let json: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("JSON failure must contain exactly one parseable document");
    assert_eq!(json["success"], false);
    assert_eq!(json["error_code"], "script");
    assert!(
        json["error"]
            .as_str()
            .is_some_and(|error| error.contains("CI pulls are not ready")),
        "expected escrow failure in global JSON error envelope, got: {json}",
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains(r#""success": true"#),
        "JSON failure must not include a policy success document: {stdout}",
    );
}

#[tokio::test]
async fn env_oidc_allow_fails_when_wrapping_key_retrieval_fails() {
    let project =
        TempProject::empty(r#"{"name":"vault-oidc-wrapping-key-failure-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    write_personal_bound_manifest(&project, &mock.url(), "vault-policy-key-failure");

    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some("session-access-token"),
            refresh_token: Some("refresh-token"),
            session_access_expires_at: Some("2030-01-01T00:00:00Z"),
        }],
    );

    mock.with_oidc_policy_create(
        "session-access-token",
        "vault-policy-key-failure",
        "acme/repo",
        "987654321",
        &["main"],
        &["preview"],
        &[".github/workflows/deploy.yml"],
        &["push"],
    )
    .await;

    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .env(
            "LPM_TEST_VAULT_WRAPPING_KEY_ERROR",
            "wrapping key storage unavailable",
        )
        .args([
            "env",
            "oidc",
            "allow",
            "--provider=github",
            "--repo=acme/repo",
            "--repository-id=987654321",
            "--branch=main",
            "--env=preview",
            "--workflow=.github/workflows/deploy.yml",
        ])
        .output()
        .expect("failed to run oidc allow with wrapping-key retrieval failure");

    assert!(
        !output.status.success(),
        "oidc allow unexpectedly succeeded after wrapping-key retrieval failed"
    );
    let combined_output = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        !combined_output.contains("OIDC policy set: github"),
        "policy success must not be reported before escrow completes: {combined_output}",
    );
    assert!(
        combined_output.contains("policy may already have been created")
            && combined_output.contains("CI pulls are not ready")
            && combined_output.contains("wrapping key storage unavailable"),
        "expected wrapping-key failure guidance, got: {combined_output}",
    );
}

#[tokio::test]
async fn env_oidc_allow_and_list_on_refresh_backed_session_then_logout_all_revoke_clears_auth_state()
 {
    let project =
        TempProject::empty(r#"{"name":"vault-oidc-refresh-logout-all-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;

    write_personal_bound_manifest(&project, &mock.url(), "vault-policy-refresh-logout-all-123");

    mock.with_refresh_expected(
        "refresh-seed-token",
        "access-from-refresh",
        "refresh-rotated-token",
        "2030-01-01T00:00:00Z",
        1,
    )
    .await;
    mock.with_oidc_policy_create(
        "access-from-refresh",
        "vault-policy-refresh-logout-all-123",
        "acme/repo",
        "987654321",
        &["main"],
        &["preview"],
        &[".github/workflows/deploy.yml"],
        &["push"],
    )
    .await;
    mock.with_escrow_upload_success("access-from-refresh", "vault-policy-refresh-logout-all-123")
        .await;
    mock.with_oidc_policy_list(
        "access-from-refresh",
        "vault-policy-refresh-logout-all-123",
        serde_json::json!([
            {
                "id": TEST_OIDC_POLICY_ID,
                "provider": "github",
                "subject": "repo:acme/repo",
                "allowedBranches": ["main"],
                "allowedEnvironments": ["preview"],
                "allowForks": false,
            }
        ]),
    )
    .await;
    mock.with_current_principal("access-from-refresh", "account-1", 1)
        .await;
    mock.with_revoke_all_pairings_for_principal_status("access-from-refresh", "account-1", 200, 1)
        .await;
    mock.with_revoke_token("access-from-refresh").await;

    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: None,
            refresh_token: Some("refresh-seed-token"),
            session_access_expires_at: None,
        }],
    );

    let allow = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args([
            "env",
            "oidc",
            "allow",
            "--provider=github",
            "--repo=acme/repo",
            "--repository-id=987654321",
            "--branch=main",
            "--env=preview",
            "--workflow=.github/workflows/deploy.yml",
        ])
        .output()
        .expect("failed to run refresh-backed oidc allow");

    assert!(
        allow.status.success(),
        "refresh-backed oidc allow failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&allow.stdout),
        String::from_utf8_lossy(&allow.stderr),
    );

    let credentials_after_refresh = read_credentials(project.home());
    assert_eq!(
        credentials_after_refresh[&mock.url()],
        "access-from-refresh"
    );
    assert_eq!(
        credentials_after_refresh[&format!("refresh:{}", mock.url())],
        "refresh-rotated-token"
    );

    let list = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["env", "oidc", "list"])
        .output()
        .expect("failed to run refresh-backed oidc list");

    assert!(
        list.status.success(),
        "refresh-backed oidc list failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&list.stdout),
        String::from_utf8_lossy(&list.stderr),
    );
    let list_output = format!(
        "{}\n{}",
        String::from_utf8_lossy(&list.stdout),
        String::from_utf8_lossy(&list.stderr)
    );
    assert!(list_output.contains("repo:acme/repo"));

    let logout_all = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["logout", "--all", "--revoke"])
        .output()
        .expect("failed to run logout --all after refresh-backed oidc allow/list");

    assert!(
        logout_all.status.success(),
        "logout --all after refresh-backed oidc allow/list failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&logout_all.stdout),
        String::from_utf8_lossy(&logout_all.stderr),
    );

    assert!(
        !credentials_path(project.home()).exists(),
        "logout --all should remove credentials after refresh-backed oidc allow/list"
    );

    if token_expiry_path(project.home()).exists() {
        let expiry_after_logout = read_expiry_metadata(project.home());
        assert!(
            expiry_after_logout.get(mock.url()).is_none(),
            "logout --all should remove session expiry metadata after refresh-backed oidc allow/list"
        );
    }

    let list_after_logout = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["env", "oidc", "list"])
        .output()
        .expect("failed to rerun oidc list after logout --all");

    assert!(
        !list_after_logout.status.success(),
        "oidc list unexpectedly succeeded after logout --all:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&list_after_logout.stdout),
        String::from_utf8_lossy(&list_after_logout.stderr),
    );
    let list_after_logout_stderr = String::from_utf8_lossy(&list_after_logout.stderr);
    assert!(
        list_after_logout_stderr.contains("not logged in. Run `lpm login` first"),
        "expected post-logout-all oidc list auth error, got stderr: {list_after_logout_stderr}"
    );
}

#[tokio::test]
async fn env_oidc_allow_escrow_failure_on_refresh_backed_session_then_logout_revoke_clears_auth_state()
 {
    let project =
        TempProject::empty(r#"{"name":"vault-oidc-refresh-escrow-logout-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;

    write_personal_bound_manifest(
        &project,
        &mock.url(),
        "vault-policy-refresh-escrow-logout-123",
    );

    mock.with_refresh_expected(
        "refresh-seed-token",
        "access-from-refresh",
        "refresh-rotated-token",
        "2030-01-01T00:00:00Z",
        1,
    )
    .await;
    mock.with_oidc_policy_create(
        "access-from-refresh",
        "vault-policy-refresh-escrow-logout-123",
        "acme/repo",
        "987654321",
        &["main"],
        &["preview"],
        &[".github/workflows/deploy.yml"],
        &["push"],
    )
    .await;
    mock.with_escrow_upload_failure(
        "access-from-refresh",
        "vault-policy-refresh-escrow-logout-123",
        "escrow backend unavailable",
    )
    .await;
    mock.with_oidc_policy_list(
        "access-from-refresh",
        "vault-policy-refresh-escrow-logout-123",
        serde_json::json!([
            {
                "id": TEST_OIDC_POLICY_ID,
                "provider": "github",
                "subject": "repo:acme/repo",
                "allowedBranches": ["main"],
                "allowedEnvironments": ["preview"],
                "allowForks": false,
            }
        ]),
    )
    .await;
    mock.with_current_principal("access-from-refresh", "account-1", 1)
        .await;
    mock.with_revoke_all_pairings_for_principal_status("access-from-refresh", "account-1", 200, 1)
        .await;
    mock.with_revoke_token("access-from-refresh").await;

    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: None,
            refresh_token: Some("refresh-seed-token"),
            session_access_expires_at: None,
        }],
    );

    let allow = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args([
            "env",
            "oidc",
            "allow",
            "--provider=github",
            "--repo=acme/repo",
            "--repository-id=987654321",
            "--branch=main",
            "--env=preview",
            "--workflow=.github/workflows/deploy.yml",
        ])
        .output()
        .expect("failed to run refresh-backed oidc allow with escrow failure");

    assert!(
        !allow.status.success(),
        "refresh-backed oidc allow unexpectedly succeeded after escrow failure:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&allow.stdout),
        String::from_utf8_lossy(&allow.stderr),
    );
    let allow_output = format!(
        "{}\n{}",
        String::from_utf8_lossy(&allow.stdout),
        String::from_utf8_lossy(&allow.stderr)
    );
    assert!(!allow_output.contains("OIDC policy set: github"));
    assert!(allow_output.contains("CI pulls are not ready"));
    assert!(allow_output.contains("escrow backend unavailable"));

    let credentials_after_refresh = read_credentials(project.home());
    assert_eq!(
        credentials_after_refresh[&mock.url()],
        "access-from-refresh"
    );
    assert_eq!(
        credentials_after_refresh[&format!("refresh:{}", mock.url())],
        "refresh-rotated-token"
    );

    let list = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["env", "oidc", "list"])
        .output()
        .expect("failed to run oidc list after refresh-backed escrow warning");

    assert!(
        list.status.success(),
        "oidc list failed after refresh-backed escrow warning:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&list.stdout),
        String::from_utf8_lossy(&list.stderr),
    );

    let logout = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["logout", "--revoke"])
        .output()
        .expect("failed to run logout after refresh-backed escrow warning flow");

    assert!(
        logout.status.success(),
        "logout after refresh-backed escrow warning flow failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&logout.stdout),
        String::from_utf8_lossy(&logout.stderr),
    );

    assert!(
        !credentials_path(project.home()).exists(),
        "logout should remove credentials after refresh-backed oidc escrow warning flow"
    );

    if token_expiry_path(project.home()).exists() {
        let expiry_after_logout = read_expiry_metadata(project.home());
        assert!(
            expiry_after_logout.get(mock.url()).is_none(),
            "logout should remove session expiry metadata after refresh-backed oidc escrow warning flow"
        );
    }

    let list_after_logout = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["env", "oidc", "list"])
        .output()
        .expect("failed to rerun oidc list after logout");

    assert!(
        !list_after_logout.status.success(),
        "oidc list unexpectedly succeeded after logout:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&list_after_logout.stdout),
        String::from_utf8_lossy(&list_after_logout.stderr),
    );
    let list_after_logout_stderr = String::from_utf8_lossy(&list_after_logout.stderr);
    assert!(
        list_after_logout_stderr.contains("not logged in. Run `lpm login` first"),
        "expected post-logout oidc list auth error, got stderr: {list_after_logout_stderr}"
    );
}

#[tokio::test]
async fn env_oidc_allow_escrow_failure_on_refresh_backed_session_then_logout_all_revoke_clears_auth_state()
 {
    let project = TempProject::empty(
        r#"{"name":"vault-oidc-refresh-escrow-logout-all-test","version":"1.0.0"}"#,
    );
    let mock = MockRegistry::start().await;

    write_personal_bound_manifest(
        &project,
        &mock.url(),
        "vault-policy-refresh-escrow-logout-all-123",
    );

    mock.with_refresh_expected(
        "refresh-seed-token",
        "access-from-refresh",
        "refresh-rotated-token",
        "2030-01-01T00:00:00Z",
        1,
    )
    .await;
    mock.with_oidc_policy_create(
        "access-from-refresh",
        "vault-policy-refresh-escrow-logout-all-123",
        "acme/repo",
        "987654321",
        &["main"],
        &["preview"],
        &[".github/workflows/deploy.yml"],
        &["push"],
    )
    .await;
    mock.with_escrow_upload_failure(
        "access-from-refresh",
        "vault-policy-refresh-escrow-logout-all-123",
        "escrow backend unavailable",
    )
    .await;
    mock.with_oidc_policy_list(
        "access-from-refresh",
        "vault-policy-refresh-escrow-logout-all-123",
        serde_json::json!([
            {
                "id": TEST_OIDC_POLICY_ID,
                "provider": "github",
                "subject": "repo:acme/repo",
                "allowedBranches": ["main"],
                "allowedEnvironments": ["preview"],
                "allowForks": false,
            }
        ]),
    )
    .await;
    mock.with_current_principal("access-from-refresh", "account-1", 1)
        .await;
    mock.with_revoke_all_pairings_for_principal_status("access-from-refresh", "account-1", 200, 1)
        .await;
    mock.with_revoke_token("access-from-refresh").await;

    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: None,
            refresh_token: Some("refresh-seed-token"),
            session_access_expires_at: None,
        }],
    );

    let allow = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args([
            "env",
            "oidc",
            "allow",
            "--provider=github",
            "--repo=acme/repo",
            "--repository-id=987654321",
            "--branch=main",
            "--env=preview",
            "--workflow=.github/workflows/deploy.yml",
        ])
        .output()
        .expect("failed to run refresh-backed oidc allow with escrow failure before logout --all");

    assert!(
        !allow.status.success(),
        "refresh-backed oidc allow unexpectedly succeeded after escrow failure before logout --all:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&allow.stdout),
        String::from_utf8_lossy(&allow.stderr),
    );
    let allow_output = format!(
        "{}\n{}",
        String::from_utf8_lossy(&allow.stdout),
        String::from_utf8_lossy(&allow.stderr)
    );
    assert!(!allow_output.contains("OIDC policy set: github"));
    assert!(allow_output.contains("CI pulls are not ready"));
    assert!(allow_output.contains("escrow backend unavailable"));

    let list = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["env", "oidc", "list"])
        .output()
        .expect("failed to run oidc list after refresh-backed escrow warning before logout --all");

    assert!(
        list.status.success(),
        "oidc list failed after refresh-backed escrow warning before logout --all:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&list.stdout),
        String::from_utf8_lossy(&list.stderr),
    );

    let logout_all = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["logout", "--all", "--revoke"])
        .output()
        .expect("failed to run logout --all after refresh-backed escrow warning flow");

    assert!(
        logout_all.status.success(),
        "logout --all after refresh-backed escrow warning flow failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&logout_all.stdout),
        String::from_utf8_lossy(&logout_all.stderr),
    );

    assert!(
        !credentials_path(project.home()).exists(),
        "logout --all should remove credentials after refresh-backed oidc escrow warning flow"
    );

    if token_expiry_path(project.home()).exists() {
        let expiry_after_logout = read_expiry_metadata(project.home());
        assert!(
            expiry_after_logout.get(mock.url()).is_none(),
            "logout --all should remove session expiry metadata after refresh-backed oidc escrow warning flow"
        );
    }

    let list_after_logout = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["env", "oidc", "list"])
        .output()
        .expect("failed to rerun oidc list after logout --all");

    assert!(
        !list_after_logout.status.success(),
        "oidc list unexpectedly succeeded after logout --all:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&list_after_logout.stdout),
        String::from_utf8_lossy(&list_after_logout.stderr),
    );
    let list_after_logout_stderr = String::from_utf8_lossy(&list_after_logout.stderr);
    assert!(
        list_after_logout_stderr.contains("not logged in. Run `lpm login` first"),
        "expected post-logout-all oidc list auth error, got stderr: {list_after_logout_stderr}"
    );
}

#[tokio::test]
async fn env_oidc_allow_canonicalizes_env_aliases_before_storing_policy() {
    let project =
        TempProject::empty(r#"{"name":"vault-oidc-canonical-env-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;

    let mut manifest = personal_bound_manifest(&mock.url(), "vault-policy-canonical-123");
    manifest["env"] = serde_json::json!({ "dev": ".env.development" });
    project.write_file("lpm.json", &manifest.to_string());

    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some("session-access-token"),
            refresh_token: Some("refresh-token"),
            session_access_expires_at: Some("2030-01-01T00:00:00Z"),
        }],
    );

    mock.with_oidc_policy_create(
        "session-access-token",
        "vault-policy-canonical-123",
        "acme/repo",
        "987654321",
        &["main"],
        &["development"],
        &[".github/workflows/deploy.yml"],
        &["push"],
    )
    .await;
    mock.with_escrow_upload_success("session-access-token", "vault-policy-canonical-123")
        .await;

    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args([
            "env",
            "oidc",
            "allow",
            "--provider=github",
            "--repo=acme/repo",
            "--repository-id=987654321",
            "--branch=main",
            "--env=dev",
            "--workflow=.github/workflows/deploy.yml",
        ])
        .output()
        .expect("failed to run oidc allow canonicalization test");

    assert!(
        output.status.success(),
        "oidc allow canonicalization failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let combined_output = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(combined_output.contains("resolved \"dev\" → canonical \"development\""));
    assert!(combined_output.contains("envs [development]"));
}

#[tokio::test]
async fn env_share_force_requires_a_bound_organization_before_network_access() {
    let project = TempProject::empty(r#"{"name":"share-force-refusal","version":"1.0.0"}"#);
    project.write_file("lpm.json", r#"{"vault":"vault-unbound-force"}"#);

    let output = lpm(&project)
        .args(["env", "share", "--org", "acme", "--force"])
        .output()
        .expect("failed to run lpm env share --force");

    assert!(
        !output.status.success(),
        "unbound share --force must fail with a non-zero exit:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(combined.contains("previously bound to this checkout"));
}

#[tokio::test]
async fn env_share_rejects_semantically_invalid_lpm_json_before_registering_a_sharing_key() {
    let project = TempProject::empty(r#"{"name":"share-invalid-config","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    project.write_file(
        "lpm.json",
        r#"{"vault":"vault-invalid-share","env":{"prod":123}}"#,
    );
    write_file_backed_vault(
        project.home(),
        "vault-invalid-share",
        serde_json::json!({
            "environments": {
                "default": {"SHARE_ME": "value"}
            }
        }),
    );
    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some("session-access-token"),
            refresh_token: Some("refresh-token"),
            session_access_expires_at: Some("2030-01-01T00:00:00Z"),
        }],
    );

    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["env", "share", "--org", "acme"])
        .output()
        .expect("run env share with semantically invalid lpm.json");

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("lpm.json"),
        "the failure must identify the invalid project configuration"
    );
    assert!(
        mock.server().received_requests().await.unwrap().is_empty(),
        "canonical validation must precede sharing-key classification or registration"
    );
}

#[tokio::test]
async fn env_share_force_under_json_emits_error_envelope_on_stdout() {
    let project = TempProject::empty(r#"{"name":"share-force-json","version":"1.0.0"}"#);
    project.write_file("lpm.json", r#"{"vault":"vault-unbound-force-json"}"#);

    let output = lpm(&project)
        .args(["--json", "env", "share", "--org", "acme", "--force"])
        .output()
        .expect("failed to run lpm env share --force --json");

    assert!(
        !output.status.success(),
        "share --force --json must fail with a non-zero exit:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let json = parse_clean_json_stdout(&output);
    assert_eq!(json["success"], false);
    assert_eq!(json["error_code"], "script");
    let error = json["error"].as_str().expect("error should be a string");
    assert!(error.contains("previously bound to this checkout"));
}

#[tokio::test]
async fn env_share_force_recreates_only_a_missing_bound_organization_vault() {
    let project = TempProject::empty(r#"{"name":"share-recreated","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let registry_url = mock.url();
    let auth_token = "org-share-recreate-token";
    let vault_id = "vault-org-share-recreated";
    let organization_id = "00000000-0000-4000-8000-000000000001";
    let (_, public_key_b64, fingerprint) =
        prepare_org_share_project(&project, &mock, auth_token, vault_id);
    project.write_file(
        "lpm.json",
        &serde_json::json!({
            "vault": vault_id,
            "vaultSync": {
                "orgVersions": {
                    (ORG_ROTATION_SLUG): 5,
                    "other": 9,
                },
                "authorityCheckpoints": {
                    "organizations": {
                        (ORG_ROTATION_SLUG): {
                            (registry_url.clone()): {
                                (organization_id): {
                                    "version": 5,
                                    "syncedAt": "2026-09-04T00:00:00Z",
                                },
                            },
                        },
                        "other": {
                            "https://registry.example": {
                                "00000000-0000-4000-8000-000000000009": {
                                    "version": 9,
                                    "syncedAt": "2026-09-04T00:01:00Z",
                                },
                            },
                        },
                    },
                },
            },
        })
        .to_string(),
    );
    mount_org_member_keys(
        &mock,
        auth_token,
        ORG_ROTATION_SLUG,
        &public_key_b64,
        &fingerprint,
    )
    .await;
    Mock::given(method("GET"))
        .and(path(format!(
            "/api/orgs/{ORG_ROTATION_SLUG}/vaults/{vault_id}"
        )))
        .and(header("authorization", format!("Bearer {auth_token}")))
        .respond_with(SignedMissingOrgVaultResponse {
            org_slug: ORG_ROTATION_SLUG.to_owned(),
            vault_id: vault_id.to_owned(),
            retained_revision: 5,
        })
        .expect(1)
        .mount(mock.server())
        .await;
    Mock::given(method("POST"))
        .and(path(format!(
            "/api/orgs/{ORG_ROTATION_SLUG}/vaults/{vault_id}"
        )))
        .and(header("authorization", format!("Bearer {auth_token}")))
        .respond_with(signed_sync_response(
            serde_json::json!({
                "status": "shared",
                "version": 6,
                "contentKeyVersion": 1,
                "principalId": organization_id,
            }),
            auth_token,
            vault_id,
            TestSyncScope::Organization(ORG_ROTATION_SLUG.to_owned()),
        ))
        .expect(1)
        .mount(mock.server())
        .await;
    let acceptance = org_rotation_recipient_acceptance(&mock, &fingerprint);

    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", &registry_url)
        .args([
            "--json",
            "env",
            "share",
            "--org",
            ORG_ROTATION_SLUG,
            "--force",
            "--accept-recipient-keys",
            &acceptance,
        ])
        .output()
        .expect("run forced organization recreation");

    assert!(
        output.status.success(),
        "organization recreation failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert_eq!(
        lpm_vault::vault_id::read_org_sync_version_for_principal(
            project.path(),
            ORG_ROTATION_SLUG,
            lpm_vault::vault_id::SyncPrincipal {
                registry_url: &registry_url,
                principal_id: organization_id,
            },
        ),
        Some(6),
    );
    assert_eq!(
        lpm_vault::vault_id::read_org_sync_version_for_principal(
            project.path(),
            "other",
            lpm_vault::vault_id::SyncPrincipal {
                registry_url: "https://registry.example",
                principal_id: "00000000-0000-4000-8000-000000000009",
            },
        ),
        Some(9),
    );
    let requests = mock.server().received_requests().await.unwrap();
    let push = requests
        .iter()
        .find(|request| request.method.as_str() == "POST")
        .expect("organization recreation request");
    let body: serde_json::Value = serde_json::from_slice(&push.body).unwrap();
    assert_eq!(body["ciphertextRevision"], 6);
    assert_eq!(body["expectedVersion"], 5);
    assert_eq!(body["recreateMissing"], true);
    assert_eq!(body["expectedOrganizationId"], organization_id);
}

#[tokio::test]
async fn env_share_force_refuses_an_existing_bound_organization_vault_without_uploading() {
    let project = TempProject::empty(r#"{"name":"share-existing","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let registry_url = mock.url();
    let auth_token = "org-share-existing-token";
    let vault_id = "vault-org-share-existing";
    let organization_id = "00000000-0000-4000-8000-000000000001";
    let (_, public_key_b64, fingerprint) =
        prepare_org_share_project(&project, &mock, auth_token, vault_id);
    project.write_file(
        "lpm.json",
        &serde_json::json!({
            "vault": vault_id,
            "vaultSync": {
                "orgVersions": {
                    (ORG_ROTATION_SLUG): 5,
                },
                "authorityCheckpoints": {
                    "organizations": {
                        (ORG_ROTATION_SLUG): {
                            (registry_url.clone()): {
                                (organization_id): {
                                    "version": 5,
                                    "syncedAt": "2026-09-04T00:00:00Z",
                                },
                            },
                        },
                    },
                },
            },
        })
        .to_string(),
    );
    mount_org_member_keys(
        &mock,
        auth_token,
        ORG_ROTATION_SLUG,
        &public_key_b64,
        &fingerprint,
    )
    .await;
    Mock::given(method("GET"))
        .and(path(format!(
            "/api/orgs/{ORG_ROTATION_SLUG}/vaults/{vault_id}"
        )))
        .and(query_param("versionOnly", "true"))
        .and(header("authorization", format!("Bearer {auth_token}")))
        .respond_with(signed_sync_response(
            serde_json::json!({ "version": 5 }),
            auth_token,
            vault_id,
            TestSyncScope::Organization(ORG_ROTATION_SLUG.to_owned()),
        ))
        .expect(1)
        .mount(mock.server())
        .await;
    Mock::given(method("POST"))
        .and(path(format!(
            "/api/orgs/{ORG_ROTATION_SLUG}/vaults/{vault_id}"
        )))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(mock.server())
        .await;

    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", &registry_url)
        .args([
            "--json",
            "env",
            "share",
            "--org",
            ORG_ROTATION_SLUG,
            "--force",
        ])
        .output()
        .expect("run forced organization share against an existing remote");

    assert!(!output.status.success());
    let error = parse_clean_json_stdout(&output);
    assert!(
        error["error"]
            .as_str()
            .is_some_and(|message| message.contains("still exists at revision 5")),
        "unexpected error: {error}",
    );
    assert_eq!(
        lpm_vault::vault_id::read_org_sync_version_for_principal(
            project.path(),
            ORG_ROTATION_SLUG,
            lpm_vault::vault_id::SyncPrincipal {
                registry_url: &registry_url,
                principal_id: organization_id,
            },
        ),
        Some(5),
    );
    assert_eq!(
        mock.server()
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|request| request.method.as_str() == "POST")
            .count(),
        0,
    );
}

#[tokio::test]
async fn env_share_force_rejects_a_remote_revision_below_the_durable_checkpoint() {
    let project = TempProject::empty(r#"{"name":"share-rollback","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let registry_url = mock.url();
    let auth_token = "org-share-rollback-token";
    let vault_id = "vault-org-share-rollback";
    let organization_id = "00000000-0000-4000-8000-000000000001";
    let (_, public_key_b64, fingerprint) =
        prepare_org_share_project(&project, &mock, auth_token, vault_id);
    project.write_file(
        "lpm.json",
        &serde_json::json!({
            "vault": vault_id,
            "vaultSync": {
                "orgVersions": {
                    (ORG_ROTATION_SLUG): 5,
                },
                "authorityCheckpoints": {
                    "organizations": {
                        (ORG_ROTATION_SLUG): {
                            (registry_url.clone()): {
                                (organization_id): {
                                    "version": 5,
                                    "syncedAt": "2026-09-04T00:00:00Z",
                                },
                            },
                        },
                    },
                },
            },
        })
        .to_string(),
    );
    mount_org_member_keys(
        &mock,
        auth_token,
        ORG_ROTATION_SLUG,
        &public_key_b64,
        &fingerprint,
    )
    .await;
    Mock::given(method("GET"))
        .and(path(format!(
            "/api/orgs/{ORG_ROTATION_SLUG}/vaults/{vault_id}"
        )))
        .and(query_param("versionOnly", "true"))
        .and(header("authorization", format!("Bearer {auth_token}")))
        .respond_with(signed_sync_response(
            serde_json::json!({ "version": 4 }),
            auth_token,
            vault_id,
            TestSyncScope::Organization(ORG_ROTATION_SLUG.to_owned()),
        ))
        .expect(1)
        .mount(mock.server())
        .await;
    Mock::given(method("POST"))
        .and(path(format!(
            "/api/orgs/{ORG_ROTATION_SLUG}/vaults/{vault_id}"
        )))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(mock.server())
        .await;

    let before = std::fs::read(project.path().join("lpm.json")).expect("snapshot checkpoint");
    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", &registry_url)
        .args([
            "--json",
            "env",
            "share",
            "--org",
            ORG_ROTATION_SLUG,
            "--force",
        ])
        .output()
        .expect("run forced organization share against a rolled-back remote");

    assert!(!output.status.success());
    let error = parse_clean_json_stdout(&output);
    assert!(
        error["error"]
            .as_str()
            .is_some_and(|message| message.contains("older than the durable local version 5")),
        "unexpected error: {error}",
    );
    assert_eq!(
        std::fs::read(project.path().join("lpm.json")).expect("read checkpoint"),
        before,
    );
    assert_eq!(
        mock.server()
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|request| request.method.as_str() == "POST")
            .count(),
        0,
    );
}

fn prepare_org_share_project(
    project: &TempProject,
    mock: &MockRegistry,
    auth_token: &str,
    vault_id: &str,
) -> ([u8; 32], String, String) {
    project.write_file("lpm.json", &format!(r#"{{"vault":"{vault_id}"}}"#));
    write_file_backed_vault(
        project.home(),
        vault_id,
        serde_json::json!({
            "environments": {
                "default": {"SHARE_ME": "value"}
            }
        }),
    );
    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some(auth_token),
            refresh_token: Some("org-share-refresh-token"),
            session_access_expires_at: Some("2030-01-01T00:00:00Z"),
        }],
    );
    let (private_key, _, public_key_b64, fingerprint) = seed_org_sharing_key(project, &mock.url());
    (private_key, public_key_b64, fingerprint)
}

#[tokio::test]
async fn env_share_uses_one_caller_bound_member_inventory_without_a_public_key_preflight() {
    let project = TempProject::empty(r#"{"name":"org-share","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let auth_token = "org-share-session-token";
    let vault_id = "vault-org-share-123";
    let (_, public_key_b64, fingerprint) =
        prepare_org_share_project(&project, &mock, auth_token, vault_id);
    mount_org_member_keys(
        &mock,
        auth_token,
        ORG_ROTATION_SLUG,
        &public_key_b64,
        &fingerprint,
    )
    .await;
    Mock::given(method("POST"))
        .and(path(format!(
            "/api/orgs/{ORG_ROTATION_SLUG}/vaults/{vault_id}"
        )))
        .and(header("authorization", format!("Bearer {auth_token}")))
        .respond_with(signed_sync_response(
            serde_json::json!({
                "status": "shared",
                "version": 1,
                "contentKeyVersion": 1,
            }),
            auth_token,
            vault_id,
            TestSyncScope::Organization(ORG_ROTATION_SLUG.to_owned()),
        ))
        .expect(1)
        .mount(mock.server())
        .await;
    let acceptance = org_rotation_recipient_acceptance(&mock, &fingerprint);

    let manifest_read_log = project.path().join("org-share-manifest-reads.log");
    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .env("LPM_TEST_MANIFEST_READ_LOG", &manifest_read_log)
        .args([
            "--json",
            "env",
            "share",
            "--org",
            ORG_ROTATION_SLUG,
            "--accept-recipient-keys",
            &acceptance,
        ])
        .output()
        .expect("run organization share");

    assert!(
        output.status.success(),
        "organization share failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let requests = mock.server().received_requests().await.unwrap();
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.url.path().ends_with("/members/public-keys"))
            .count(),
        1,
    );
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.url.path() == "/api/users/me/public-key")
            .count(),
        0,
    );
    assert_eq!(
        std::fs::read_to_string(manifest_read_log)
            .expect("read organization-share manifest access log")
            .lines()
            .count(),
        3,
        "organization share needs one command snapshot, one mutation-boundary check, and one guarded metadata commit",
    );
}

#[tokio::test]
async fn env_share_rejects_a_changed_manifest_principal_before_the_remote_write() {
    let project = TempProject::empty(r#"{"name":"org-share-rebound","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let registry_url = mock.url();
    let auth_token = "org-share-rebound-token";
    let vault_id = "vault-org-share-rebound";
    let (_, public_key_b64, fingerprint) =
        prepare_org_share_project(&project, &mock, auth_token, vault_id);
    let replacement = serde_json::json!({
        "vault": vault_id,
        "vaultSync": {
            "authorityCheckpoints": {
                "organizations": {
                    (ORG_ROTATION_SLUG): {
                        (registry_url.clone()): {
                            "00000000-0000-4000-8000-000000000002": {
                                "version": 1,
                                "syncedAt": "2026-09-05T00:00:00Z",
                            },
                        },
                    },
                },
            },
        },
    })
    .to_string();
    let member_response =
        signed_member_inventory_response(ORG_ROTATION_SLUG, &public_key_b64, &fingerprint);
    Mock::given(method("GET"))
        .and(path(format!(
            "/api/orgs/{ORG_ROTATION_SLUG}/members/public-keys"
        )))
        .and(header("authorization", format!("Bearer {auth_token}")))
        .respond_with(ManifestReplacingResponse {
            manifest_path: project.path().join("lpm.json"),
            replacement,
            response: member_response,
        })
        .expect(1)
        .mount(mock.server())
        .await;
    Mock::given(method("POST"))
        .and(path(format!(
            "/api/orgs/{ORG_ROTATION_SLUG}/vaults/{vault_id}"
        )))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(mock.server())
        .await;

    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", &registry_url)
        .args(["--json", "env", "share", "--org", ORG_ROTATION_SLUG])
        .output()
        .expect("run organization share while its manifest binding changes");

    assert!(!output.status.success());
    let error = parse_clean_json_stdout(&output);
    assert!(
        error["error"]
            .as_str()
            .is_some_and(|message| message.contains("manifest principal changed")),
        "unexpected error: {error}",
    );
    assert_eq!(
        mock.server()
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|request| request.method.as_str() == "POST")
            .count(),
        0,
    );
}

#[tokio::test]
async fn env_share_refuses_a_changed_authenticated_caller_key_without_uploading() {
    let project = TempProject::empty(r#"{"name":"org-share-mismatch","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let auth_token = "org-share-mismatch-token";
    let vault_id = "vault-org-share-mismatch-123";
    prepare_org_share_project(&project, &mock, auth_token, vault_id);
    let (_, changed_public_key) = lpm_vault::crypto::generate_x25519_keypair();
    let changed_public_key_b64 = BASE64.encode(changed_public_key);
    let changed_fingerprint = hex::encode(Sha256::digest(changed_public_key));
    mount_org_member_keys(
        &mock,
        auth_token,
        ORG_ROTATION_SLUG,
        &changed_public_key_b64,
        &changed_fingerprint,
    )
    .await;

    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["--json", "env", "share", "--org", ORG_ROTATION_SLUG])
        .output()
        .expect("run organization share with changed caller key");

    assert!(!output.status.success());
    let error = parse_clean_json_stdout(&output);
    assert!(
        error["error"]
            .as_str()
            .is_some_and(|message| message.contains("does NOT match the key on the server"))
    );
    let requests = mock.server().received_requests().await.unwrap();
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.url.path().ends_with("/members/public-keys"))
            .count(),
        1,
    );
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.url.path() == "/api/users/me/public-key")
            .count(),
        0,
    );
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.method.as_str() == "POST")
            .count(),
        0,
    );
}

#[tokio::test]
async fn env_share_keeps_prepared_member_access_on_one_captured_session() {
    let project = TempProject::empty(r#"{"name":"org-share-switch","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let registry_url = mock.url();
    let initial_token = "org-share-caller-a-token";
    let replacement_token = "org-share-caller-b-token";
    let vault_id = "vault-org-share-switch-123";
    let (_, public_key_b64, fingerprint) =
        prepare_org_share_project(&project, &mock, initial_token, vault_id);
    Mock::given(method("GET"))
        .and(path(format!(
            "/api/orgs/{ORG_ROTATION_SLUG}/members/public-keys"
        )))
        .and(header("authorization", format!("Bearer {initial_token}")))
        .respond_with(CredentialsReplacingResponse {
            home: project.home().to_path_buf(),
            registry_url: registry_url.clone(),
            replacement_token: replacement_token.to_owned(),
            response: signed_member_inventory_response(
                ORG_ROTATION_SLUG,
                &public_key_b64,
                &fingerprint,
            ),
        })
        .expect(1)
        .mount(mock.server())
        .await;
    Mock::given(method("POST"))
        .and(path(format!(
            "/api/orgs/{ORG_ROTATION_SLUG}/vaults/{vault_id}"
        )))
        .and(header("authorization", format!("Bearer {initial_token}")))
        .respond_with(signed_sync_response(
            serde_json::json!({
                "status": "shared",
                "version": 1,
                "contentKeyVersion": 1,
            }),
            initial_token,
            vault_id,
            TestSyncScope::Organization(ORG_ROTATION_SLUG.to_owned()),
        ))
        .expect(1)
        .mount(mock.server())
        .await;
    let acceptance = org_rotation_recipient_acceptance(&mock, &fingerprint);

    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", &registry_url)
        .args([
            "--json",
            "env",
            "share",
            "--org",
            ORG_ROTATION_SLUG,
            "--accept-recipient-keys",
            &acceptance,
        ])
        .output()
        .expect("run organization share while the stored caller changes");

    assert!(
        output.status.success(),
        "organization share changed its captured session:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let requests = mock.server().received_requests().await.unwrap();
    let push = requests
        .iter()
        .find(|request| request.method.as_str() == "POST")
        .expect("organization share must reach the authoritative caller check");
    let body: serde_json::Value =
        serde_json::from_slice(&push.body).expect("parse organization share request");
    assert_eq!(
        body["expectedCallerUserId"],
        "11111111-1111-4111-8111-111111111111"
    );
}

#[tokio::test]
async fn env_share_propagates_member_inventory_errors_without_fallback_requests() {
    let project = TempProject::empty(r#"{"name":"org-share-server-error","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let auth_token = "org-share-server-error-token";
    let vault_id = "vault-org-share-server-error-123";
    prepare_org_share_project(&project, &mock, auth_token, vault_id);
    Mock::given(method("GET"))
        .and(path(format!(
            "/api/orgs/{ORG_ROTATION_SLUG}/members/public-keys"
        )))
        .and(header("authorization", format!("Bearer {auth_token}")))
        .respond_with(SignedRejectedMemberInventoryResponse {
            org_slug: ORG_ROTATION_SLUG.to_owned(),
            status: 503,
            code: "service_unavailable".to_owned(),
            message: "temporarily unavailable".to_owned(),
        })
        .expect(1)
        .mount(mock.server())
        .await;

    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["--json", "env", "share", "--org", ORG_ROTATION_SLUG])
        .output()
        .expect("run organization share during member inventory outage");

    assert!(!output.status.success());
    let error = parse_clean_json_stdout(&output);
    assert!(
        error["error"]
            .as_str()
            .is_some_and(|message| message.contains("503")),
        "unexpected error: {error}",
    );
    let requests = mock.server().received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].url.path().ends_with("/members/public-keys"));
}

#[tokio::test]
async fn env_pull_rejects_an_org_slug_rebound_after_the_rewrap_response() {
    let project = TempProject::empty(r#"{"name":"org-pull-rebind","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let auth_token = "org-pull-rebind-token";
    let vault_id = "vault-org-pull-rebind-123";
    let (_, public_key_b64, fingerprint) =
        prepare_org_share_project(&project, &mock, auth_token, vault_id);
    Mock::given(method("GET"))
        .and(path(format!(
            "/api/orgs/{ORG_ROTATION_SLUG}/vaults/{vault_id}"
        )))
        .and(header("authorization", format!("Bearer {auth_token}")))
        .respond_with(SignedOrgMemberRewrapResponse {
            org_slug: ORG_ROTATION_SLUG.to_owned(),
            vault_id: vault_id.to_owned(),
        })
        .expect(1)
        .mount(mock.server())
        .await;
    Mock::given(method("GET"))
        .and(path(format!(
            "/api/orgs/{ORG_ROTATION_SLUG}/members/public-keys"
        )))
        .and(header("authorization", format!("Bearer {auth_token}")))
        .respond_with(signed_member_inventory_response_for_organization(
            ORG_ROTATION_SLUG,
            "00000000-0000-4000-8000-000000000002",
            &public_key_b64,
            &fingerprint,
        ))
        .expect(1)
        .mount(mock.server())
        .await;

    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["--json", "env", "pull", "--org", ORG_ROTATION_SLUG])
        .output()
        .expect("run organization pull across a slug rebound");

    assert!(!output.status.success());
    let error = parse_clean_json_stdout(&output);
    assert!(
        error["error"]
            .as_str()
            .is_some_and(|message| message.contains("organization identity changed"))
    );
    let requests = mock.server().received_requests().await.unwrap();
    assert_eq!(requests.len(), 2);
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.url.path() == "/api/users/me/public-key")
            .count(),
        0,
    );
    assert!(
        requests
            .iter()
            .all(|request| request.method.as_str() == "GET")
    );
}

#[tokio::test]
async fn env_platform_json_success_paths_emit_success_envelopes() {
    let project = TempProject::empty(r#"{"name":"platform-json-contract","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let bearer_token = "platform-json-session-token";
    let vault_id = "vault-platform-json-123";

    project.write_file("lpm.json", &format!(r#"{{"vault":"{vault_id}"}}"#));
    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some(bearer_token),
            refresh_token: Some("platform-json-refresh-token"),
            session_access_expires_at: Some("2030-01-01T00:00:00Z"),
        }],
    );

    mock.with_platform_connect_success(
        bearer_token,
        vault_id,
        "vercel",
        "project-123",
        serde_json::json!({
            "status": "created",
            "connectionId": "10000000-0000-4000-8000-000000000001",
            "label": "production",
        }),
    )
    .await;
    mock.with_platform_credentials_success(
        bearer_token,
        vault_id,
        serde_json::json!({
            "connections": [
                {
                    "id": "connection-1",
                    "platform": "vercel",
                    "token": "vercel-token",
                    "connectionConfig": { "projectId": "project-123" },
                    "label": "production",
                    "lastPushAt": "2030-01-01T00:00:00Z"
                }
            ]
        }),
    )
    .await;
    mock.with_vercel_env_list("vercel-token", "project-123", serde_json::json!([]), 2)
        .await;

    let connect = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .env("ACCEPTANCE_RUN_ID", "workflow-platform-direct")
        .env("LPM_ACCEPTANCE_VERCEL_API_BASE_URL", mock.url())
        .args([
            "--json",
            "env",
            "connect",
            "vercel",
            "--project",
            "project-123",
            "--token",
            "vercel-token",
            "--label",
            "production",
        ])
        .output()
        .expect("failed to run lpm env connect --json");
    assert!(
        connect.status.success(),
        "env connect --json failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&connect.stdout),
        String::from_utf8_lossy(&connect.stderr),
    );
    let connect_json = parse_clean_json_stdout(&connect);
    assert_eq!(connect_json["success"], true);
    assert_eq!(connect_json["status"], "created");
    assert_eq!(connect_json["platform"], "vercel");

    let status = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .env("ACCEPTANCE_RUN_ID", "workflow-platform-direct")
        .env("LPM_ACCEPTANCE_VERCEL_API_BASE_URL", mock.url())
        .args(["--json", "env", "status"])
        .output()
        .expect("failed to run lpm env status --json");
    assert!(
        status.status.success(),
        "env status --json failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&status.stdout),
        String::from_utf8_lossy(&status.stderr),
    );
    let status_json = parse_clean_json_stdout(&status);
    assert_eq!(status_json["success"], true);
    assert_eq!(status_json["count"], 1);
    assert_eq!(status_json["platforms"][0]["platform"], "vercel");
}

#[tokio::test]
async fn failed_platform_connect_keeps_the_manifest_byte_identical() {
    let project = TempProject::empty(r#"{"name":"failed-platform-connect","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let bearer_token = "failed-platform-connect-session-token";
    let vault_id = "vault-failed-platform-connect-123";
    let manifest_path = project.path().join("lpm.json");
    project.write_file(
        "lpm.json",
        &format!(r#"{{"vault":"{vault_id}","name":"byte-stable"}}"#),
    );
    let before = std::fs::read(&manifest_path).expect("snapshot lpm.json");
    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some(bearer_token),
            refresh_token: Some("failed-platform-connect-refresh-token"),
            session_access_expires_at: Some("2030-01-01T00:00:00Z"),
        }],
    );
    mock.with_platform_context_success(bearer_token, vault_id, "vercel")
        .await;
    Mock::given(method("GET"))
        .and(path("/v10/projects/project-123/env"))
        .and(query_param("decrypt", "true"))
        .and(header("authorization", "Bearer rejected-platform-token"))
        .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
            "error": { "message": "invalid platform token" }
        })))
        .expect(1)
        .mount(mock.server())
        .await;

    let connect = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .env("ACCEPTANCE_RUN_ID", "workflow-platform-connect-failure")
        .env("LPM_ACCEPTANCE_VERCEL_API_BASE_URL", mock.url())
        .args([
            "--json",
            "env",
            "connect",
            "vercel",
            "--project",
            "project-123",
            "--token",
            "rejected-platform-token",
        ])
        .output()
        .expect("failed to run rejected lpm env connect");

    assert!(!connect.status.success());
    assert_eq!(
        std::fs::read(&manifest_path).expect("read lpm.json after failed connect"),
        before,
    );
    let manifest: serde_json::Value = serde_json::from_slice(&before).expect("parse lpm.json");
    assert!(manifest.get("vaultSync").is_none());
    let requests = mock.server().received_requests().await.unwrap();
    assert!(
        requests
            .iter()
            .all(|request| { request.url.path() != "/api/vault/platforms/connect" })
    );
}

#[tokio::test]
async fn env_coolify_platform_connect_and_status_use_direct_platform_api() {
    let project = TempProject::empty(r#"{"name":"coolify-platform","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let bearer_token = "coolify-platform-session-token";
    let platform_token = "coolify-platform-token";
    let vault_id = "vault-coolify-platform-123";
    let application_id = "application-123";

    project.write_file("lpm.json", &format!(r#"{{"vault":"{vault_id}"}}"#));
    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some(bearer_token),
            refresh_token: Some("coolify-platform-refresh-token"),
            session_access_expires_at: Some("2030-01-01T00:00:00Z"),
        }],
    );
    let seeded = lpm(&project)
        .args([
            "--json",
            "env",
            "set",
            "--env",
            "production",
            "APPLICATION_SECRET=local-value",
        ])
        .output()
        .expect("failed to seed Coolify env values");
    assert!(
        seeded.status.success(),
        "env set failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&seeded.stdout),
        String::from_utf8_lossy(&seeded.stderr),
    );

    mock.with_platform_connect_application_success(
        bearer_token,
        vault_id,
        "coolify",
        application_id,
        serde_json::json!({
            "status": "created",
            "connectionId": "20000000-0000-4000-8000-000000000002",
            "label": "production",
        }),
    )
    .await;
    mock.with_platform_credentials_success_calls(
        bearer_token,
        vault_id,
        serde_json::json!({
            "connections": [
                {
                    "id": "connection-coolify",
                    "platform": "coolify",
                    "token": platform_token,
                    "connectionConfig": {
                        "url": mock.url(),
                        "applicationId": application_id,
                        "preview": false,
                        "linkedEnv": "production"
                    },
                    "label": "production",
                    "lastPushAt": null
                }
            ]
        }),
        3,
    )
    .await;
    mock.with_coolify_env_list(
        platform_token,
        application_id,
        serde_json::json!([
            {
                "id": 1,
                "uuid": "env-application-secret",
                "key": "APPLICATION_SECRET",
                "value": "remote-value",
                "real_value": "remote-value",
                "is_preview": false,
                "is_literal": false,
                "is_multiline": false,
                "is_shown_once": false,
                "is_shared": false
            }
        ]),
        4,
    )
    .await;
    mock.with_coolify_env_update(
        platform_token,
        application_id,
        "APPLICATION_SECRET",
        "local-value",
    )
    .await;
    mock.with_platform_audit_success(
        bearer_token,
        vault_id,
        "coolify",
        "push",
        &[("added", 0), ("updated", 1), ("removed", 0)],
    )
    .await;
    mock.with_platform_audit_success(
        bearer_token,
        vault_id,
        "coolify",
        "pull",
        &[("imported", 1)],
    )
    .await;

    let connect = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .env("ACCEPTANCE_RUN_ID", "workflow-platform-coolify")
        .args([
            "--json",
            "env",
            "connect",
            "coolify",
            "--url",
            &mock.url(),
            "--application",
            application_id,
            "--token",
            platform_token,
            "--linked-env",
            "production",
            "--label",
            "production",
        ])
        .output()
        .expect("failed to run lpm env connect coolify --json");
    assert!(
        connect.status.success(),
        "env connect coolify --json failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&connect.stdout),
        String::from_utf8_lossy(&connect.stderr),
    );
    let connect_json = parse_clean_json_stdout(&connect);
    assert_eq!(connect_json["success"], true);
    assert_eq!(connect_json["platform"], "coolify");
    insta::assert_json_snapshot!("env_coolify_connect_json_envelope", connect_json);

    let status = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .env("ACCEPTANCE_RUN_ID", "workflow-platform-coolify")
        .args(["--json", "env", "status"])
        .output()
        .expect("failed to run lpm env status --json");
    assert!(
        status.status.success(),
        "env status --json failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&status.stdout),
        String::from_utf8_lossy(&status.stderr),
    );
    let status_json = parse_clean_json_stdout(&status);
    assert_eq!(status_json["success"], true);
    assert_eq!(status_json["platforms"][0]["platform"], "coolify");
    assert_eq!(status_json["platforms"][0]["env"], "production");
    assert_eq!(
        status_json["platforms"][0]["status"], "drifted",
        "{status_json}"
    );
    insta::assert_json_snapshot!("env_coolify_status_json_envelope", status_json);

    let push = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .env("ACCEPTANCE_RUN_ID", "workflow-platform-coolify")
        .args(["--json", "env", "push", "--to", "coolify", "--yes"])
        .output()
        .expect("failed to run lpm env push --to coolify --json");
    assert!(
        push.status.success(),
        "env push --to coolify failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&push.stdout),
        String::from_utf8_lossy(&push.stderr),
    );
    let push_json = parse_clean_json_stdout(&push);
    assert_eq!(push_json["success"], true);
    assert_eq!(push_json["platform"], "coolify");
    assert_eq!(push_json["added"], 0);
    assert_eq!(push_json["updated"], 1);
    assert_eq!(push_json["removed"], 0);
    insta::assert_json_snapshot!("env_coolify_push_json_envelope", push_json);

    let pull = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .env("ACCEPTANCE_RUN_ID", "workflow-platform-coolify")
        .args(["--json", "env", "pull", "--from", "coolify", "--yes"])
        .output()
        .expect("failed to run lpm env pull --from coolify --json");
    assert!(
        pull.status.success(),
        "env pull --from coolify failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&pull.stdout),
        String::from_utf8_lossy(&pull.stderr),
    );
    let pull_json = parse_clean_json_stdout(&pull);
    assert_eq!(pull_json["success"], true);
    assert_eq!(pull_json["platform"], "coolify");
    assert_eq!(pull_json["keys"], serde_json::json!(["APPLICATION_SECRET"]));
    insta::assert_json_snapshot!("env_coolify_pull_json_envelope", pull_json);
}

#[tokio::test]
async fn env_railway_platform_connect_and_status_use_direct_graphql_api() {
    let project = TempProject::empty(r#"{"name":"railway-platform","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let bearer_token = "railway-platform-session-token";
    let platform_token = "railway-platform-token";
    let vault_id = "vault-railway-platform-123";
    let project_id = "project-123";
    let environment_id = "environment-123";
    let service_id = "service-123";

    project.write_file("lpm.json", &format!(r#"{{"vault":"{vault_id}"}}"#));
    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some(bearer_token),
            refresh_token: Some("railway-platform-refresh-token"),
            session_access_expires_at: Some("2030-01-01T00:00:00Z"),
        }],
    );
    let seeded = lpm(&project)
        .args([
            "--json",
            "env",
            "set",
            "--env",
            "production",
            "APPLICATION_SECRET=local-value",
        ])
        .output()
        .expect("failed to seed Railway env values");
    assert!(
        seeded.status.success(),
        "env set failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&seeded.stdout),
        String::from_utf8_lossy(&seeded.stderr),
    );

    mock.with_platform_connect_success(
        bearer_token,
        vault_id,
        "railway",
        project_id,
        serde_json::json!({
            "status": "created",
            "connectionId": "30000000-0000-4000-8000-000000000003",
            "label": "production",
        }),
    )
    .await;
    mock.with_platform_credentials_success_calls(
        bearer_token,
        vault_id,
        serde_json::json!({
            "connections": [
                {
                    "id": "connection-railway",
                    "platform": "railway",
                    "token": platform_token,
                    "connectionConfig": {
                        "projectId": project_id,
                        "environmentId": environment_id,
                        "serviceId": service_id,
                        "projectToken": false,
                        "linkedEnv": "production"
                    },
                    "label": "production",
                    "lastPushAt": null
                }
            ]
        }),
        3,
    )
    .await;
    let initial_variables = serde_json::json!({
        "APPLICATION_SECRET": "${{Shared.SECRET}}",
        "RAILWAY_SERVICE_ID": "managed-service-id"
    });
    let final_variables = serde_json::json!({
        "APPLICATION_SECRET": "local-value",
        "RAILWAY_SERVICE_ID": "managed-service-id"
    });
    mock.with_railway_variables_sequence(
        platform_token,
        project_id,
        environment_id,
        service_id,
        vec![
            initial_variables.clone(),
            initial_variables.clone(),
            initial_variables,
            final_variables.clone(),
            final_variables,
        ],
    )
    .await;
    mock.with_railway_variables_upsert(
        platform_token,
        project_id,
        environment_id,
        service_id,
        "APPLICATION_SECRET",
        "local-value",
    )
    .await;
    mock.with_platform_audit_success(
        bearer_token,
        vault_id,
        "railway",
        "push",
        &[("added", 0), ("updated", 1), ("removed", 0)],
    )
    .await;
    mock.with_platform_audit_success(
        bearer_token,
        vault_id,
        "railway",
        "pull",
        &[("imported", 1)],
    )
    .await;

    let connect = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .env("ACCEPTANCE_RUN_ID", "workflow-platform-railway")
        .env(
            "LPM_ACCEPTANCE_RAILWAY_API_URL",
            format!("{}/graphql/v2", mock.url()),
        )
        .args([
            "--json",
            "env",
            "connect",
            "railway",
            "--project",
            project_id,
            "--environment",
            environment_id,
            "--service",
            service_id,
            "--token",
            platform_token,
            "--linked-env",
            "production",
            "--label",
            "production",
        ])
        .output()
        .expect("failed to run lpm env connect railway --json");
    assert!(
        connect.status.success(),
        "env connect railway --json failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&connect.stdout),
        String::from_utf8_lossy(&connect.stderr),
    );
    let connect_json = parse_clean_json_stdout(&connect);
    assert_eq!(connect_json["success"], true);
    assert_eq!(connect_json["platform"], "railway");
    insta::assert_json_snapshot!("env_railway_connect_json_envelope", connect_json);

    let status = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .env("ACCEPTANCE_RUN_ID", "workflow-platform-railway")
        .env(
            "LPM_ACCEPTANCE_RAILWAY_API_URL",
            format!("{}/graphql/v2", mock.url()),
        )
        .args(["--json", "env", "status"])
        .output()
        .expect("failed to run lpm env status --json");
    assert!(
        status.status.success(),
        "env status --json failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&status.stdout),
        String::from_utf8_lossy(&status.stderr),
    );
    let status_json = parse_clean_json_stdout(&status);
    assert_eq!(status_json["success"], true);
    assert_eq!(status_json["platforms"][0]["platform"], "railway");
    assert_eq!(status_json["platforms"][0]["env"], "production");
    assert_eq!(
        status_json["platforms"][0]["status"], "drifted",
        "{status_json}"
    );
    assert_eq!(status_json["platforms"][0]["changed"], 1);
    insta::assert_json_snapshot!("env_railway_status_json_envelope", status_json);

    let command = || {
        let mut command = lpm(&project);
        command
            .env("LPM_REGISTRY_URL", mock.url())
            .env("ACCEPTANCE_RUN_ID", "workflow-platform-railway")
            .env(
                "LPM_ACCEPTANCE_RAILWAY_API_URL",
                format!("{}/graphql/v2", mock.url()),
            );
        command
    };
    let push = command()
        .args(["--json", "env", "push", "--to", "railway", "--yes"])
        .output()
        .expect("failed to run lpm env push --to railway --json");
    assert!(
        push.status.success(),
        "env push --to railway failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&push.stdout),
        String::from_utf8_lossy(&push.stderr),
    );
    let push_json = parse_clean_json_stdout(&push);
    assert_eq!(push_json["success"], true);
    assert_eq!(push_json["platform"], "railway");
    assert_eq!(push_json["added"], 0);
    assert_eq!(push_json["updated"], 1);
    assert_eq!(push_json["removed"], 0);
    insta::assert_json_snapshot!("env_railway_push_json_envelope", push_json);

    let pull = command()
        .args(["--json", "env", "pull", "--from", "railway", "--yes"])
        .output()
        .expect("failed to run lpm env pull --from railway --json");
    assert!(
        pull.status.success(),
        "env pull --from railway failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&pull.stdout),
        String::from_utf8_lossy(&pull.stderr),
    );
    let pull_json = parse_clean_json_stdout(&pull);
    assert_eq!(pull_json["success"], true);
    assert_eq!(pull_json["platform"], "railway");
    assert_eq!(pull_json["keys"], serde_json::json!(["APPLICATION_SECRET"]));
    insta::assert_json_snapshot!("env_railway_pull_json_envelope", pull_json);
}

#[tokio::test]
async fn env_fly_platform_connect_status_and_pull_use_write_only_app_secrets() {
    let project = TempProject::empty(r#"{"name":"fly-platform","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let bearer_token = "fly-platform-session-token";
    let platform_token = "fo1_fly-platform-token";
    let vault_id = "vault-fly-platform-123";
    let app = "lpm-example";
    let app_id = "app_123";
    let organization_id = "org_123";
    let organization_slug = "personal";

    project.write_file("lpm.json", &format!(r#"{{"vault":"{vault_id}"}}"#));
    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some(bearer_token),
            refresh_token: Some("fly-platform-refresh-token"),
            session_access_expires_at: Some("2030-01-01T00:00:00Z"),
        }],
    );
    let seeded = lpm(&project)
        .args([
            "--json",
            "env",
            "set",
            "--env",
            "production",
            "APPLICATION_SECRET=local-secret",
        ])
        .output()
        .expect("failed to seed Fly.io env values");
    assert!(
        seeded.status.success(),
        "env set failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&seeded.stdout),
        String::from_utf8_lossy(&seeded.stderr),
    );

    mock.with_fly_platform_connect_success(
        bearer_token,
        vault_id,
        app,
        app_id,
        organization_id,
        serde_json::json!({
            "status": "created",
            "connectionId": "40000000-0000-4000-8000-000000000004",
            "label": "production",
        }),
    )
    .await;
    mock.with_platform_credentials_success_calls(
        bearer_token,
        vault_id,
        serde_json::json!({
            "connections": [
                {
                    "id": "connection-fly",
                    "platform": "fly",
                    "token": platform_token,
                    "connectionConfig": {
                        "app": app,
                        "appId": app_id,
                        "organizationId": organization_id,
                        "organizationSlug": organization_slug,
                        "linkedEnv": "production"
                    },
                    "label": "production",
                    "lastPushAt": null
                }
            ]
        }),
        3,
    )
    .await;
    mock.with_fly_app(support::mock_registry::FlyAppFixture {
        token: platform_token,
        app,
        app_id,
        organization_id,
        organization_slug,
        secrets: serde_json::json!([
            { "name": "APPLICATION_SECRET", "digest": "sha256:write-only" },
            { "name": "FLY_APP_NAME", "digest": "managed" }
        ]),
        expected_calls: 7,
    })
    .await;
    mock.with_fly_set_secrets_success(platform_token, app, "APPLICATION_SECRET", "local-secret")
        .await;
    mock.with_platform_audit_success(
        bearer_token,
        vault_id,
        "fly",
        "push",
        &[("added", 0), ("updated", 1), ("removed", 0)],
    )
    .await;
    let command = || {
        let mut command = lpm(&project);
        command
            .env("LPM_REGISTRY_URL", mock.url())
            .env("ACCEPTANCE_RUN_ID", "workflow-platform-fly")
            .env(
                "LPM_ACCEPTANCE_FLY_API_URL",
                format!("{}/graphql", mock.url()),
            );
        command
    };
    let connect = command()
        .args([
            "--json",
            "env",
            "connect",
            "fly",
            "--app",
            app,
            "--token",
            platform_token,
            "--linked-env",
            "production",
            "--label",
            "production",
        ])
        .output()
        .expect("failed to run lpm env connect fly --json");
    assert!(
        connect.status.success(),
        "env connect fly failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&connect.stdout),
        String::from_utf8_lossy(&connect.stderr),
    );
    let connect_json = parse_clean_json_stdout(&connect);
    assert_eq!(connect_json["platform"], "fly");
    insta::assert_json_snapshot!("env_fly_connect_json_envelope", connect_json);

    let status = command()
        .args(["--json", "env", "status"])
        .output()
        .expect("failed to run lpm env status --json");
    assert!(status.status.success(), "env status failed");
    let status_json = parse_clean_json_stdout(&status);
    assert_eq!(status_json["platforms"][0]["platform"], "fly");
    assert_eq!(status_json["platforms"][0]["status"], "names_only");
    assert_eq!(
        status_json["platforms"][0]["secretVerification"],
        "names_only"
    );
    assert_eq!(status_json["platforms"][0]["secretNamesPresent"], 1);
    insta::assert_json_snapshot!("env_fly_status_json_envelope", status_json);

    let pull = command()
        .args(["--json", "env", "pull", "--from", "fly", "--yes"])
        .output()
        .expect("failed to run lpm env pull --from fly");
    assert!(pull.status.success(), "env pull failed");
    let pull_json = parse_clean_json_stdout(&pull);
    assert_eq!(pull_json["status"], "no_readable_values");
    assert_eq!(pull_json["skippedSecrets"], 1);
    assert_eq!(pull_json["secretVerification"], "names_only");
    insta::assert_json_snapshot!("env_fly_pull_json_envelope", pull_json);

    let push = command()
        .args(["--json", "env", "push", "--to", "fly", "--yes"])
        .output()
        .expect("failed to run lpm env push --to fly");
    assert!(
        push.status.success(),
        "env push failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&push.stdout),
        String::from_utf8_lossy(&push.stderr),
    );
    let push_json = parse_clean_json_stdout(&push);
    assert_eq!(push_json["added"], 0);
    assert_eq!(push_json["updated"], 1);
    assert_eq!(push_json["removed"], 0);
    insta::assert_json_snapshot!("env_fly_push_json_envelope", push_json);
}

#[tokio::test]
async fn env_github_actions_platform_reports_names_only_and_audits_failed_pushes() {
    let project = TempProject::empty(r#"{"name":"github-actions-platform","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let bearer_token = "github-actions-session-token";
    let platform_token = "github-actions-platform-token";
    let vault_id = "vault-github-actions-123";
    let repository = "lpm-dev/example";
    let repository_id = "123456789";
    let environment = "production";

    project.write_file(
        "lpm.json",
        &format!(
            r#"{{
                "vault":"{vault_id}",
                "envSchema":{{
                    "vars":{{
                        "PUBLIC_ORIGIN":{{"client":true}},
                        "API_TOKEN":{{"secret":true}}
                    }}
                }}
            }}"#
        ),
    );
    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some(bearer_token),
            refresh_token: Some("github-actions-refresh-token"),
            session_access_expires_at: Some("2030-01-01T00:00:00Z"),
        }],
    );
    let initial_set = lpm(&project)
        .args([
            "--json",
            "env",
            "set",
            "--env",
            environment,
            "PUBLIC_ORIGIN=https://example.test",
            "API_TOKEN=local-secret",
        ])
        .output()
        .expect("failed to seed GitHub Actions env values");
    assert!(
        initial_set.status.success(),
        "env set failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&initial_set.stdout),
        String::from_utf8_lossy(&initial_set.stderr),
    );

    mock.with_github_actions_platform_connect_success(
        bearer_token,
        vault_id,
        repository,
        repository_id,
        serde_json::json!({
            "status": "created",
            "connectionId": "50000000-0000-4000-8000-000000000005",
            "label": "production",
        }),
    )
    .await;
    mock.with_platform_credentials_success_calls(
        bearer_token,
        vault_id,
        serde_json::json!({
            "connections": [
                {
                    "id": "connection-github-actions",
                    "platform": "github-actions",
                    "token": platform_token,
                    "connectionConfig": {
                        "repository": repository,
                        "repositoryId": repository_id,
                        "environment": environment,
                        "linkedEnv": environment
                    },
                    "label": "production",
                    "lastPushAt": null
                }
            ]
        }),
        3,
    )
    .await;
    mock.with_github_actions_repository(platform_token, repository, 123_456_789, 6)
        .await;
    mock.with_github_actions_environment_lists(
        platform_token,
        repository_id,
        environment,
        serde_json::json!([
            { "name": "PUBLIC_ORIGIN", "value": "https://example.test" }
        ]),
        serde_json::json!([{ "name": "API_TOKEN" }]),
        4,
    )
    .await;
    mock.with_platform_audit_success(
        bearer_token,
        vault_id,
        "github-actions",
        "pull",
        &[("imported", 1)],
    )
    .await;
    mock.with_github_actions_public_key(platform_token, repository_id, environment)
        .await;
    mock.with_github_actions_variable_update_failure(
        platform_token,
        repository_id,
        environment,
        "PUBLIC_ORIGIN",
    )
    .await;
    mock.with_platform_audit_success(
        bearer_token,
        vault_id,
        "github-actions",
        "push_failed",
        &[("added", 0), ("updated", 0), ("removed", 0)],
    )
    .await;

    let command = || {
        let mut command = lpm(&project);
        command
            .env("LPM_REGISTRY_URL", mock.url())
            .env("ACCEPTANCE_RUN_ID", "workflow-platform-github-actions")
            .env("LPM_ACCEPTANCE_GITHUB_API_BASE_URL", mock.url());
        command
    };
    let connect = command()
        .args([
            "--json",
            "env",
            "connect",
            "github-actions",
            "--repository",
            repository,
            "--environment",
            environment,
            "--token",
            platform_token,
            "--linked-env",
            environment,
        ])
        .output()
        .expect("failed to run lpm env connect github-actions --json");
    assert!(
        connect.status.success(),
        "env connect github-actions failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&connect.stdout),
        String::from_utf8_lossy(&connect.stderr),
    );
    let connect_json = parse_clean_json_stdout(&connect);
    assert_eq!(connect_json["platform"], "github-actions");
    insta::assert_json_snapshot!("env_github_actions_connect_json_envelope", connect_json);

    let status = command()
        .args(["--json", "env", "status"])
        .output()
        .expect("failed to run lpm env status --json");
    assert!(status.status.success(), "env status failed");
    let status_json = parse_clean_json_stdout(&status);
    assert_eq!(status_json["platforms"][0]["status"], "names_only");
    assert_eq!(
        status_json["platforms"][0]["secretVerification"],
        "names_only"
    );
    assert_eq!(status_json["platforms"][0]["secretNamesPresent"], 1);
    insta::assert_json_snapshot!("env_github_actions_status_json_envelope", status_json);

    let pull = command()
        .args(["--json", "env", "pull", "--from", "github-actions", "--yes"])
        .output()
        .expect("failed to run lpm env pull --from github-actions");
    assert!(pull.status.success(), "env pull failed");
    let pull_json = parse_clean_json_stdout(&pull);
    assert_eq!(pull_json["keys"], serde_json::json!(["PUBLIC_ORIGIN"]));
    assert_eq!(pull_json["skippedSecrets"], 1);
    assert_eq!(pull_json["secretVerification"], "names_only");
    insta::assert_json_snapshot!("env_github_actions_pull_json_envelope", pull_json);

    let changed = lpm(&project)
        .args([
            "--json",
            "env",
            "set",
            "--env",
            environment,
            "PUBLIC_ORIGIN=https://changed.example.test",
        ])
        .output()
        .expect("failed to change GitHub Actions variable");
    assert!(changed.status.success(), "env set change failed");
    let failed_push = command()
        .args(["--json", "env", "push", "--to", "github-actions", "--yes"])
        .output()
        .expect("failed to run lpm env push --to github-actions");
    assert!(!failed_push.status.success(), "denied push must fail");
    let failed_json = parse_clean_json_stdout(&failed_push);
    assert_eq!(failed_json["success"], false);
    assert_eq!(failed_json["error_code"], "script");
    assert_eq!(
        failed_json["error"],
        "script error: GitHub Actions variable update failed with HTTP 403 Forbidden: workflow denied"
    );
    insta::assert_json_snapshot!("env_github_actions_failed_push_json_envelope", failed_json);
}

#[tokio::test]
async fn env_github_actions_platform_snapshots_successful_push_and_clean() {
    let project = TempProject::empty(r#"{"name":"github-actions-sync","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let bearer_token = "github-actions-sync-session-token";
    let platform_token = "github-actions-sync-platform-token";
    let vault_id = "vault-github-actions-sync-123";
    let repository = "lpm-dev/example";
    let repository_id = "123456789";
    let environment = "production";
    let local_origin = "https://local.example.test";
    let registry_url = mock.url();

    project.write_file(
        "lpm.json",
        &format!(
            r#"{{
                "vault":"{vault_id}",
                "envSchema":{{
                    "vars":{{
                        "PUBLIC_ORIGIN":{{"client":true}},
                        "API_TOKEN":{{"secret":true}}
                    }}
                }},
                "vaultSync":{{
                    "personalPlatformBindings":{{
                        "{registry_url}":{{
                            "registryUrl":"{registry_url}",
                            "principalId":"account-1"
                        }}
                    }}
                }}
            }}"#
        ),
    );
    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &registry_url,
            access_token: Some(bearer_token),
            refresh_token: Some("github-actions-sync-refresh-token"),
            session_access_expires_at: Some("2030-01-01T00:00:00Z"),
        }],
    );
    let initial_set = lpm(&project)
        .args([
            "--json",
            "env",
            "set",
            "--env",
            environment,
            &format!("PUBLIC_ORIGIN={local_origin}"),
            "API_TOKEN=local-secret",
        ])
        .output()
        .expect("failed to seed GitHub Actions sync values");
    assert!(
        initial_set.status.success(),
        "env set failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&initial_set.stdout),
        String::from_utf8_lossy(&initial_set.stderr),
    );

    mock.with_platform_credentials_success_calls(
        bearer_token,
        vault_id,
        serde_json::json!({
            "connections": [
                {
                    "id": "connection-github-actions-sync",
                    "platform": "github-actions",
                    "token": platform_token,
                    "connectionConfig": {
                        "repository": repository,
                        "repositoryId": repository_id,
                        "environment": environment,
                        "linkedEnv": environment
                    },
                    "label": "production",
                    "lastPushAt": null
                }
            ]
        }),
        2,
    )
    .await;
    mock.with_github_actions_repository(platform_token, repository, 123_456_789, 6)
        .await;
    mock.with_github_actions_environment_list_sequences(
        platform_token,
        repository_id,
        environment,
        vec![
            serde_json::json!([
                { "name": "PUBLIC_ORIGIN", "value": "https://remote.example.test" },
                { "name": "STALE_PUBLIC", "value": "stale" }
            ]),
            serde_json::json!([
                { "name": "PUBLIC_ORIGIN", "value": local_origin },
                { "name": "STALE_PUBLIC", "value": "stale" }
            ]),
            serde_json::json!([
                { "name": "PUBLIC_ORIGIN", "value": local_origin },
                { "name": "STALE_PUBLIC", "value": "stale" }
            ]),
            serde_json::json!([
                { "name": "PUBLIC_ORIGIN", "value": local_origin }
            ]),
        ],
        vec![
            serde_json::json!([{ "name": "API_TOKEN" }, { "name": "STALE_SECRET" }]),
            serde_json::json!([{ "name": "API_TOKEN" }, { "name": "STALE_SECRET" }]),
            serde_json::json!([{ "name": "API_TOKEN" }, { "name": "STALE_SECRET" }]),
            serde_json::json!([{ "name": "API_TOKEN" }]),
        ],
    )
    .await;
    mock.with_github_actions_public_key_calls(platform_token, repository_id, environment, 2)
        .await;
    mock.with_github_actions_variable_update_success(
        platform_token,
        repository_id,
        environment,
        "PUBLIC_ORIGIN",
        local_origin,
    )
    .await;
    mock.with_github_actions_variable_delete_success(
        platform_token,
        repository_id,
        environment,
        "STALE_PUBLIC",
    )
    .await;
    mock.with_github_actions_secret_upsert_success(
        platform_token,
        repository_id,
        environment,
        "API_TOKEN",
        2,
    )
    .await;
    mock.with_github_actions_secret_delete_success(
        platform_token,
        repository_id,
        environment,
        "STALE_SECRET",
    )
    .await;
    mock.with_platform_audit_success(
        bearer_token,
        vault_id,
        "github-actions",
        "push",
        &[("added", 0), ("updated", 2), ("removed", 0)],
    )
    .await;
    mock.with_platform_audit_success(
        bearer_token,
        vault_id,
        "github-actions",
        "push",
        &[("added", 0), ("updated", 1), ("removed", 2)],
    )
    .await;

    let command = || {
        let mut command = lpm(&project);
        command
            .env("LPM_REGISTRY_URL", mock.url())
            .env("ACCEPTANCE_RUN_ID", "workflow-platform-github-actions-sync")
            .env("LPM_ACCEPTANCE_GITHUB_API_BASE_URL", mock.url());
        command
    };
    let push = command()
        .args(["--json", "env", "push", "--to", "github-actions", "--yes"])
        .output()
        .expect("failed to run lpm env push --to github-actions");
    assert!(
        push.status.success(),
        "env push failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&push.stdout),
        String::from_utf8_lossy(&push.stderr),
    );
    let push_json = parse_clean_json_stdout(&push);
    assert_eq!(push_json["added"], 0);
    assert_eq!(push_json["updated"], 2);
    assert_eq!(push_json["removed"], 0);
    insta::assert_json_snapshot!("env_github_actions_push_json_envelope", push_json);

    let clean = command()
        .args([
            "--json",
            "env",
            "push",
            "--to",
            "github-actions",
            "--clean",
            "--yes",
        ])
        .output()
        .expect("failed to run lpm env push --to github-actions --clean");
    assert!(
        clean.status.success(),
        "env clean failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&clean.stdout),
        String::from_utf8_lossy(&clean.stderr),
    );
    let clean_json = parse_clean_json_stdout(&clean);
    assert_eq!(clean_json["added"], 0);
    assert_eq!(clean_json["updated"], 1);
    assert_eq!(clean_json["removed"], 2);
    insta::assert_json_snapshot!("env_github_actions_clean_json_envelope", clean_json);
}

#[tokio::test]
async fn env_platform_json_error_paths_emit_error_envelopes_on_stdout() {
    let cases: &[(&[&str], &str)] = &[
        (&["--json", "env", "log"], "no vault configured"),
        (&["--json", "env", "rotate-key"], "no vault configured"),
        (&["--json", "env", "list-remote"], "not logged in"),
    ];

    for (args, expected_error) in cases {
        let project = TempProject::empty(r#"{"name":"platform-json-errors","version":"1.0.0"}"#);
        let output = lpm(&project)
            .args(*args)
            .output()
            .unwrap_or_else(|error| panic!("failed to run lpm {args:?}: {error}"));

        assert!(
            !output.status.success(),
            "lpm {args:?} unexpectedly succeeded:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        let json = parse_clean_json_stdout(&output);
        assert_eq!(json["success"], false, "lpm {args:?} envelope: {json}");
        assert_eq!(
            json["error_code"], "script",
            "lpm {args:?} envelope: {json}"
        );
        assert!(
            json["error"]
                .as_str()
                .is_some_and(|error| error.contains(expected_error)),
            "lpm {args:?} should mention {expected_error:?}; got {json}",
        );
    }
}

#[tokio::test]
async fn env_rotate_sharing_key_refuses_without_a_tty() {
    // `lpm env rotate-sharing-key` is an interactive recovery surface
    // — it prompts for typed `ROTATE` confirmation AND for password /
    // TOTP via cliclack. Running it from a non-TTY context (CI,
    // unattended runner, `curl | sh`) would either block on stdin
    // forever or silently accept hostile input. The command MUST
    // refuse outright at flag-parse / TTY-detect time so the operator
    // never gets a half-rotated state.
    //
    // This test runs without a controlling TTY (cargo test inherits
    // the worker's pipe-backed stdin), so the refusal must fire
    // before any network, vault-state, or pending-key side effect.
    let project = TempProject::empty(r#"{"name":"rotate-sharing-key-non-tty","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["env", "rotate-sharing-key"])
        .output()
        .expect("failed to run lpm env rotate-sharing-key");

    assert!(
        !output.status.success(),
        "rotate-sharing-key must fail with non-zero exit when stdin is not a TTY:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    // The cliclack error box wraps long lines and inserts `│`
    // continuation bars between segments, so we match on stable
    // substrings that don't span those wraps. The two pinned phrases
    // are load-bearing for the refusal semantics: the command name
    // (so a future error-message rewrite that drops it gets caught)
    // and "TTY" (so a regression that allows non-interactive flow
    // gets caught).
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        combined.contains("rotate-sharing-key"),
        "refusal must name the command so users know what was rejected; got: {combined}"
    );
    assert!(
        combined.contains("TTY"),
        "refusal must mention the TTY requirement so users know the cause; got: {combined}"
    );
}

#[tokio::test]
async fn env_rotate_sharing_key_refuses_yes_flag_explicitly() {
    // `--yes` is the conventional "skip prompt" flag elsewhere in the
    // CLI, but for the sharing-key rotation flow there is no safe way
    // to bypass the typed ROTATE confirmation + step-up reauth: the
    // command's whole purpose is to be the one rotation surface that
    // CANNOT be driven from an automated context. Pin the refusal so
    // a future change cannot accidentally turn `--yes` into a working
    // CI bypass.
    let project =
        TempProject::empty(r#"{"name":"rotate-sharing-key-yes-refused","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["env", "rotate-sharing-key", "--yes"])
        .output()
        .expect("failed to run lpm env rotate-sharing-key --yes");

    assert!(
        !output.status.success(),
        "rotate-sharing-key --yes must still fail:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        combined.contains("rotate-sharing-key") && combined.contains("TTY"),
        "expected the explicit refusal regardless of --yes; got: {combined}"
    );
}
