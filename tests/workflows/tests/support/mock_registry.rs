#![allow(dead_code)]

//! Mock LPM registry server built on `wiremock`.
//!
//! Provides ergonomic builders for common registry endpoints so workflow
//! tests can validate install, publish, health, and auth flows without
//! any external network calls.

use std::collections::{HashMap, VecDeque};
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use wiremock::matchers::{body_string_contains, header, method, path, path_regex, query_param};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

pub const TEST_OIDC_POLICY_ID: &str = "11111111-1111-4111-8111-111111111111";

/// A mock LPM registry server.
///
/// Wraps `wiremock::MockServer` and provides ergonomic helpers for mounting
/// common endpoint mocks. Pass `mock.url()` as `--registry` to the CLI.
pub struct MockRegistry {
    server: MockServer,
    tarball_integrities: Arc<Mutex<HashMap<(String, String), String>>>,
}

struct JsonResponseSequence {
    bodies: Arc<Mutex<VecDeque<serde_json::Value>>>,
}

struct JsonResponseAndCreateDirectory {
    body: serde_json::Value,
    path: PathBuf,
}

struct ProjectTokenReplacementResponse {
    expires_at: String,
}

struct ProjectTokenReplacementEchoError;

struct ProjectTokenReplacementSequence {
    failures_remaining: AtomicUsize,
    expires_at: String,
}

struct ProjectTokenRetirementSequence {
    failures_remaining: AtomicUsize,
}

struct PublishPreflightResponder;

impl Respond for PublishPreflightResponder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let query = request
            .url
            .query_pairs()
            .collect::<std::collections::HashMap<_, _>>();
        ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true,
            "name": query.get("name").map_or("", |value| value.as_ref()),
            "version": query.get("version").map_or("", |value| value.as_ref()),
            "packageExists": true,
        }))
    }
}

impl Respond for JsonResponseSequence {
    fn respond(&self, _request: &Request) -> ResponseTemplate {
        let mut bodies = self.bodies.lock().expect("response sequence lock");
        let body = if bodies.len() > 1 {
            bodies.pop_front().expect("response sequence body")
        } else {
            bodies.front().cloned().expect("response sequence body")
        };
        ResponseTemplate::new(200).set_body_json(body)
    }
}

impl Respond for JsonResponseAndCreateDirectory {
    fn respond(&self, _request: &Request) -> ResponseTemplate {
        std::fs::create_dir_all(&self.path).expect("create response-side directory");
        ResponseTemplate::new(200).set_body_json(&self.body)
    }
}

impl Respond for ProjectTokenReplacementResponse {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body: serde_json::Value =
            serde_json::from_slice(&request.body).expect("replacement request body must be JSON");
        let token_id = body["tokenId"]
            .as_str()
            .expect("replacement request must contain tokenId");
        ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "tokenId": token_id,
            "scope": "read",
            "expiresAt": self.expires_at,
            "replaced": body.get("previousTokenId").is_some()
                || body.get("previousTokenHash").is_some(),
        }))
    }
}

impl Respond for ProjectTokenReplacementEchoError {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body: serde_json::Value =
            serde_json::from_slice(&request.body).expect("replacement request body must be JSON");
        ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "error": format!("replacement rejected for {}", body["token"].as_str().unwrap()),
        }))
    }
}

impl Respond for ProjectTokenReplacementSequence {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        if self
            .failures_remaining
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
        {
            return ResponseTemplate::new(500)
                .set_body_json(serde_json::json!({ "error": "ambiguous replacement failure" }));
        }
        ProjectTokenReplacementResponse {
            expires_at: self.expires_at.clone(),
        }
        .respond(request)
    }
}

impl Respond for ProjectTokenRetirementSequence {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        if self
            .failures_remaining
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
        {
            return ResponseTemplate::new(500)
                .set_body_json(serde_json::json!({ "error": "ambiguous retirement failure" }));
        }
        let body: serde_json::Value =
            serde_json::from_slice(&request.body).expect("retirement request body must be JSON");
        let token_id = body["tokenId"]
            .as_str()
            .unwrap_or("33333333-3333-4333-8333-333333333333");
        ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "revoked": true,
            "tokenId": token_id,
        }))
    }
}

pub struct RegistrySigningFixture {
    keyid: String,
    public_key: String,
    signing_key: p256::ecdsa::SigningKey,
}

pub struct FlyAppFixture<'a> {
    pub token: &'a str,
    pub app: &'a str,
    pub app_id: &'a str,
    pub organization_id: &'a str,
    pub organization_slug: &'a str,
    pub secrets: serde_json::Value,
    pub expected_calls: u64,
}

impl RegistrySigningFixture {
    pub fn new() -> Self {
        use p256::pkcs8::{EncodePublicKey, LineEnding};

        let signing_key = p256::ecdsa::SigningKey::from_slice(&[7u8; 32])
            .expect("deterministic test signing key must be valid");
        let pem = signing_key
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .expect("test public key must encode as PEM");
        let public_key = pem
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect::<String>();

        Self {
            keyid: "SHA256:test".to_string(),
            public_key,
            signing_key,
        }
    }

    pub fn signature_json(&self, name: &str, version: &str, integrity: &str) -> serde_json::Value {
        use base64::Engine;
        use p256::ecdsa::signature::Signer;

        let message = format!("{name}@{version}:{integrity}");
        let signature: p256::ecdsa::Signature = self.signing_key.sign(message.as_bytes());
        let sig = base64::engine::general_purpose::STANDARD.encode(signature.to_der().as_bytes());
        serde_json::json!({
            "keyid": self.keyid,
            "sig": sig,
        })
    }

    fn key_json(&self) -> serde_json::Value {
        serde_json::json!({
            "expires": null,
            "keyid": self.keyid,
            "keytype": "ecdsa-sha2-nistp256",
            "scheme": "ecdsa-sha2-nistp256",
            "key": self.public_key,
        })
    }
}

fn whoami_response(username: &str, email: &str) -> serde_json::Value {
    serde_json::json!({
        "username": email,
        "profile_username": username,
        "email": email,
        "plan_tier": "pro",
        "mfa_enabled": false,
        "has_pool_access": true,
        "usage": {
            "storage_bytes": 1024 * 1024 * 50,
            "private_packages": 3
        },
        "limits": {
            "storageBytes": 1024 * 1024 * 500,
            "privatePackages": 100
        },
        "organizations": []
    })
}

impl MockRegistry {
    /// Start a new mock registry on a random port.
    ///
    /// Unconfigured package-skill reads return an empty published set. More
    /// specific skill fixtures override this lowest-priority fallback.
    pub async fn start() -> Self {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/registry/skills"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "name": "fixture.package",
                "available": false,
                "skills": [],
            })))
            .with_priority(u8::MAX)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/registry/-/package/publish-preflight"))
            .respond_with(PublishPreflightResponder)
            .with_priority(u8::MAX)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/registry/pool/install-report"))
            .respond_with(ResponseTemplate::new(200))
            .with_priority(u8::MAX)
            .mount(&server)
            .await;
        MockRegistry {
            server,
            tarball_integrities: Arc::default(),
        }
    }

    /// Adopt an already-started `MockServer`. Used by tests that
    /// need control over the wiremock listener — e.g. binding
    /// explicitly to `127.0.0.1` for the loopback-
    /// network-denial test, where the IP-level bind interface is
    /// part of the assertion contract. For the common case where
    /// the listener can be auto-allocated, prefer
    /// [`MockRegistry::start`] (one less moving part to set up).
    pub fn from_server(server: MockServer) -> Self {
        MockRegistry {
            server,
            tarball_integrities: Arc::default(),
        }
    }

    /// The base URL of the mock server (e.g., `http://127.0.0.1:PORT`).
    pub fn url(&self) -> String {
        self.server.uri()
    }

    /// Mount the package-published skills endpoint for one LPM.dev package.
    pub async fn with_package_skills(&self, name: &str, skills: Vec<serde_json::Value>) -> &Self {
        Mock::given(method("GET"))
            .and(path("/api/registry/skills"))
            .and(query_param("name", name))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "name": name,
                "available": true,
                "skills": skills,
            })))
            .expect(1)
            .mount(&self.server)
            .await;
        self
    }

    /// Mount the package-published skills endpoint and require an exact installed version.
    pub async fn with_package_skills_for_version(
        &self,
        name: &str,
        version: &str,
        skills: Vec<serde_json::Value>,
    ) -> &Self {
        self.with_package_skills_for_version_expected(name, version, skills, 1)
            .await
    }

    pub async fn with_package_skills_for_version_expected(
        &self,
        name: &str,
        version: &str,
        skills: Vec<serde_json::Value>,
        expected_calls: u64,
    ) -> &Self {
        Mock::given(method("GET"))
            .and(path("/api/registry/skills"))
            .and(query_param("name", name))
            .and(query_param("version", version))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "name": name,
                "version": version,
                "available": true,
                "skills": skills,
            })))
            .expect(expected_calls)
            .mount(&self.server)
            .await;
        self
    }

    /// Mount a failed package-skill lookup for one exact package version.
    pub async fn with_package_skills_error_for_version(
        &self,
        name: &str,
        version: &str,
        status: u16,
    ) -> &Self {
        Mock::given(method("GET"))
            .and(path("/api/registry/skills"))
            .and(query_param("name", name))
            .and(query_param("version", version))
            .respond_with(
                ResponseTemplate::new(status).set_body_json(serde_json::json!({
                    "error": "package skills unavailable",
                })),
            )
            .with_priority(1)
            .expect(1)
            .mount(&self.server)
            .await;
        self
    }

    /// Mount `GET /api/search/packages` for a specific query + limit.
    pub async fn with_search_results(
        &self,
        query: &str,
        limit: u32,
        packages: Vec<serde_json::Value>,
    ) -> &Self {
        Mock::given(method("GET"))
            .and(path("/api/search/packages"))
            .and(query_param("q", query))
            .and(query_param("limit", limit.min(20).to_string()))
            .and(query_param("mode", "semantic"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "packages": packages,
            })))
            .mount(&self.server)
            .await;
        self
    }

    /// Mount `GET /api/registry/quality` for a specific package.
    pub async fn with_quality_report(&self, name: &str, report: serde_json::Value) -> &Self {
        Mock::given(method("GET"))
            .and(path("/api/registry/quality"))
            .and(query_param("name", name))
            .respond_with(ResponseTemplate::new(200).set_body_json(report))
            .mount(&self.server)
            .await;
        self
    }

    /// Mount `POST /api/registry/-/token/create` for `lpm setup local`.
    pub async fn with_npmrc_token_create(
        &self,
        expiry_days: u32,
        token: &str,
        expires_at: &str,
    ) -> &Self {
        self.with_npmrc_token_create_responses(
            expiry_days,
            vec![serde_json::json!({
                "token": token,
                "tokenId": "11111111-1111-4111-8111-111111111111",
                "scope": "read",
                "expiresAt": expires_at,
            })],
        )
        .await
    }

    pub async fn with_npmrc_token_create_responses(
        &self,
        expiry_days: u32,
        responses: Vec<serde_json::Value>,
    ) -> &Self {
        let expected_calls = responses.len() as u64;
        Mock::given(method("POST"))
            .and(path("/api/registry/-/token/create"))
            .and(body_string_contains("\"scope\":\"read\""))
            .and(body_string_contains(format!(
                "\"expiryDays\":{expiry_days}"
            )))
            .respond_with(JsonResponseSequence {
                bodies: Arc::new(Mutex::new(responses.into())),
            })
            .expect(expected_calls)
            .mount(&self.server)
            .await;
        self
    }

    pub async fn with_npmrc_token_create_then_make_directory(
        &self,
        response: serde_json::Value,
        path_to_create: PathBuf,
    ) -> &Self {
        Mock::given(method("POST"))
            .and(path("/api/registry/-/token/create"))
            .and(body_string_contains("\"scope\":\"read\""))
            .respond_with(JsonResponseAndCreateDirectory {
                body: response,
                path: path_to_create,
            })
            .expect(1)
            .mount(&self.server)
            .await;
        self
    }

    pub async fn with_npmrc_token_revoke(
        &self,
        token_id: &str,
        status: u16,
        expected_calls: u64,
    ) -> &Self {
        let response = if status == 200 {
            serde_json::json!({ "revoked": true, "tokenId": token_id })
        } else {
            serde_json::json!({ "error": "project token revocation failed" })
        };
        Mock::given(method("POST"))
            .and(path("/api/registry/-/token/revoke-project"))
            .and(body_string_contains(format!("\"tokenId\":\"{token_id}\"")))
            .respond_with(ResponseTemplate::new(status).set_body_json(response))
            .expect(expected_calls)
            .mount(&self.server)
            .await;
        self
    }

    pub async fn with_npmrc_token_self_revoke(
        &self,
        token: &str,
        status: u16,
        expected_calls: u64,
    ) -> &Self {
        let response = if status == 200 {
            serde_json::json!({
                "revoked": true,
                "tokenId": "33333333-3333-4333-8333-333333333333",
            })
        } else {
            serde_json::json!({ "error": "project token self-revocation failed" })
        };
        Mock::given(method("POST"))
            .and(path("/api/registry/-/token/revoke-project"))
            .and(header("authorization", format!("Bearer {token}")))
            .and(body_string_contains("\"self\":true"))
            .respond_with(ResponseTemplate::new(status).set_body_json(response))
            .expect(expected_calls)
            .mount(&self.server)
            .await;
        self
    }

    pub async fn with_npmrc_token_self_revoke_error(
        &self,
        token: &str,
        status: u16,
        error: &str,
    ) -> &Self {
        Mock::given(method("POST"))
            .and(path("/api/registry/-/token/revoke-project"))
            .and(header("authorization", format!("Bearer {token}")))
            .and(body_string_contains("\"self\":true"))
            .respond_with(
                ResponseTemplate::new(status).set_body_json(serde_json::json!({ "error": error })),
            )
            .expect(1)
            .mount(&self.server)
            .await;
        self
    }

    pub async fn with_npmrc_token_create_response(&self, response: serde_json::Value) -> &Self {
        Mock::given(method("POST"))
            .and(path("/api/registry/-/token/create"))
            .and(body_string_contains("\"scope\":\"read\""))
            .respond_with(ResponseTemplate::new(200).set_body_json(response))
            .expect(1)
            .mount(&self.server)
            .await;
        self
    }

    pub async fn with_npmrc_token_replace(
        &self,
        expiry_days: u32,
        expires_at: &str,
        expected_calls: u64,
    ) -> &Self {
        Mock::given(method("POST"))
            .and(path("/api/registry/-/token/replace-project"))
            .and(body_string_contains("\"scope\":\"read\""))
            .and(body_string_contains(format!(
                "\"expiryDays\":{expiry_days}"
            )))
            .respond_with(ProjectTokenReplacementResponse {
                expires_at: expires_at.to_string(),
            })
            .expect(expected_calls)
            .mount(&self.server)
            .await;
        self
    }

    pub async fn with_npmrc_token_replace_response(&self, response: serde_json::Value) -> &Self {
        Mock::given(method("POST"))
            .and(path("/api/registry/-/token/replace-project"))
            .and(body_string_contains("\"scope\":\"read\""))
            .respond_with(ResponseTemplate::new(200).set_body_json(response))
            .expect(1)
            .mount(&self.server)
            .await;
        self
    }

    pub async fn with_npmrc_token_replace_error(&self, status: u16) -> &Self {
        Mock::given(method("POST"))
            .and(path("/api/registry/-/token/replace-project"))
            .respond_with(
                ResponseTemplate::new(status)
                    .set_body_json(serde_json::json!({ "error": "replacement rejected" })),
            )
            .expect(1)
            .mount(&self.server)
            .await;
        self
    }

    pub async fn with_npmrc_token_replace_echoed_token_error(&self) -> &Self {
        Mock::given(method("POST"))
            .and(path("/api/registry/-/token/replace-project"))
            .respond_with(ProjectTokenReplacementEchoError)
            .expect(1)
            .mount(&self.server)
            .await;
        self
    }

    pub async fn with_npmrc_token_replace_ambiguous_then_success(
        &self,
        expiry_days: u32,
        expires_at: &str,
    ) -> &Self {
        Mock::given(method("POST"))
            .and(path("/api/registry/-/token/replace-project"))
            .and(body_string_contains(format!(
                "\"expiryDays\":{expiry_days}"
            )))
            .respond_with(ProjectTokenReplacementSequence {
                failures_remaining: AtomicUsize::new(1),
                expires_at: expires_at.to_string(),
            })
            .expect(2)
            .mount(&self.server)
            .await;
        self
    }

    pub async fn with_npmrc_token_revoke_hash(
        &self,
        token_hash: &str,
        expected_calls: u64,
    ) -> &Self {
        Mock::given(method("POST"))
            .and(path("/api/registry/-/token/revoke-project"))
            .and(body_string_contains(format!(
                "\"tokenHash\":\"{token_hash}\""
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "revoked": true,
                "tokenId": "33333333-3333-4333-8333-333333333333",
            })))
            .expect(expected_calls)
            .mount(&self.server)
            .await;
        self
    }

    pub async fn with_npmrc_token_revoke_ambiguous_then_success(&self, token_hash: &str) -> &Self {
        Mock::given(method("POST"))
            .and(path("/api/registry/-/token/revoke-project"))
            .and(body_string_contains(format!(
                "\"tokenHash\":\"{token_hash}\""
            )))
            .respond_with(ProjectTokenRetirementSequence {
                failures_remaining: AtomicUsize::new(1),
            })
            .expect(2)
            .mount(&self.server)
            .await;
        self
    }

    pub async fn with_npmrc_token_self_revoke_ambiguous_then_success(&self, token: &str) -> &Self {
        Mock::given(method("POST"))
            .and(path("/api/registry/-/token/revoke-project"))
            .and(header("authorization", format!("Bearer {token}")))
            .and(body_string_contains("\"self\":true"))
            .respond_with(ProjectTokenRetirementSequence {
                failures_remaining: AtomicUsize::new(1),
            })
            .expect(2)
            .mount(&self.server)
            .await;
        self
    }

    /// Mount `POST /api/registry/-/token/rotate` for `lpm token-rotate`.
    pub async fn with_token_rotate(
        &self,
        bearer_token: &str,
        token: &str,
        expires_at: &str,
    ) -> &Self {
        Mock::given(method("POST"))
            .and(path("/api/registry/-/token/rotate"))
            .and(header("authorization", format!("Bearer {bearer_token}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "token": token,
                "expiresAt": expires_at,
            })))
            .expect(1)
            .mount(&self.server)
            .await;
        self
    }

    /// Mount `GET /api/registry/pool/stats` for `lpm pool`.
    pub async fn with_pool_stats(&self, bearer_token: &str, stats: serde_json::Value) -> &Self {
        Mock::given(method("GET"))
            .and(path("/api/registry/pool/stats"))
            .and(header("authorization", format!("Bearer {bearer_token}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(stats))
            .expect(1)
            .mount(&self.server)
            .await;
        self
    }

    /// Mount a healthy `/api/registry/health` endpoint.
    pub async fn with_health(&self) -> &Self {
        self.with_health_status(200).await
    }

    /// Mount `/api/registry/health` with an explicit HTTP status.
    pub async fn with_health_status(&self, status: u16) -> &Self {
        Mock::given(method("GET"))
            .and(path("/api/registry/health"))
            .respond_with(
                ResponseTemplate::new(status).set_body_json(serde_json::json!({
                    "status": if (200..300).contains(&status) { "ok" } else { "error" }
                })),
            )
            .mount(&self.server)
            .await;
        self
    }

    pub async fn with_npm_firewall_block(&self, name: &str, version: &str) -> &Self {
        Mock::given(method("POST"))
            .and(path("/api/registry/-/npm-firewall/verdicts"))
            .and(body_string_contains(format!("\"name\":\"{name}\"")))
            .and(body_string_contains(format!("\"version\":\"{version}\"")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "requestId": "test-firewall-block",
                "policyMode": "enforce",
                "summary": {
                    "total": 1,
                    "allow": 0,
                    "warn": 0,
                    "block": 1,
                    "unknown": 0,
                    "matched": 1
                },
                "decisions": [{
                    "decisionId": "dec_test_block",
                    "name": name,
                    "version": version,
                    "action": "block",
                    "verdict": "malicious",
                    "reason": "test blocked package",
                    "matchSource": "package",
                    "matchedKey": format!("package:npm:{name}@{version}"),
                    "policyMode": "enforce",
                    "enqueueScan": false,
                    "scannedAt": null,
                    "scanRunId": null,
                    "reportPath": null,
                    "confidence": 1.0
                }]
            })))
            .expect(1)
            .mount(&self.server)
            .await;
        self
    }

    pub async fn with_npm_firewall_allow(&self, name: &str, version: &str) -> &Self {
        self.with_npm_firewall_allow_expected(name, version, 1..=1)
            .await
    }

    pub async fn with_npm_firewall_allow_expected(
        &self,
        name: &str,
        version: &str,
        expected_calls: std::ops::RangeInclusive<u64>,
    ) -> &Self {
        Mock::given(method("POST"))
            .and(path("/api/registry/-/npm-firewall/verdicts"))
            .and(body_string_contains(format!("\"name\":\"{name}\"")))
            .and(body_string_contains(format!("\"version\":\"{version}\"")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "requestId": "test-firewall-allow",
                "policyMode": "enforce",
                "summary": {
                    "total": 1,
                    "allow": 1,
                    "warn": 0,
                    "block": 0,
                    "unknown": 0,
                    "matched": 1
                },
                "decisions": [{
                    "decisionId": "dec_test_allow",
                    "name": name,
                    "version": version,
                    "action": "allow",
                    "verdict": "clean",
                    "reason": "test allowed package",
                    "matchSource": "package",
                    "matchedKey": format!("package:npm:{name}@{version}"),
                    "policyMode": "enforce",
                    "enqueueScan": false,
                    "scannedAt": null,
                    "scanRunId": null,
                    "reportPath": null,
                    "confidence": 1.0
                }]
            })))
            .expect(expected_calls)
            .mount(&self.server)
            .await;
        self
    }

    /// Mount a `/api/registry/-/whoami` endpoint returning a test user.
    pub async fn with_whoami(&self, username: &str, email: &str) -> &Self {
        Mock::given(method("GET"))
            .and(path("/api/registry/-/whoami"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(whoami_response(username, email)),
            )
            .mount(&self.server)
            .await;
        self
    }

    /// Mount a `/api/registry/-/whoami` endpoint with an explicit expected call count.
    pub async fn with_whoami_expected(
        &self,
        username: &str,
        email: &str,
        expected_calls: u64,
    ) -> &Self {
        Mock::given(method("GET"))
            .and(path("/api/registry/-/whoami"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(whoami_response(username, email)),
            )
            .expect(expected_calls)
            .mount(&self.server)
            .await;
        self
    }

    /// Mount a `/api/registry/-/whoami` endpoint that requires a specific bearer token.
    pub async fn with_authenticated_whoami(
        &self,
        bearer_token: &str,
        username: &str,
        email: &str,
    ) -> &Self {
        Mock::given(method("GET"))
            .and(path("/api/registry/-/whoami"))
            .and(header("authorization", format!("Bearer {bearer_token}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "username": email,
                "profile_username": username,
                "email": email,
                "plan_tier": "pro",
                "mfa_enabled": false,
                "has_pool_access": true,
                "usage": {
                    "storage_bytes": 1024 * 1024 * 50,
                    "private_packages": 3
                },
                "limits": {
                    "storageBytes": 1024 * 1024 * 500,
                    "privatePackages": 100
                },
                "organizations": []
            })))
            .mount(&self.server)
            .await;
        self
    }

    /// Mount a `/api/registry/-/whoami` error for a specific bearer token.
    pub async fn with_authenticated_whoami_error(
        &self,
        bearer_token: &str,
        status: u16,
        expected_calls: u64,
    ) -> &Self {
        Mock::given(method("GET"))
            .and(path("/api/registry/-/whoami"))
            .and(header("authorization", format!("Bearer {bearer_token}")))
            .respond_with(ResponseTemplate::new(status))
            .expect(expected_calls)
            .mount(&self.server)
            .await;
        self
    }

    /// Mount a successful `/api/cli/refresh` response for a specific refresh token.
    pub async fn with_refresh(
        &self,
        refresh_token: &str,
        access_token: &str,
        rotated_refresh_token: &str,
        expires_at: &str,
    ) -> &Self {
        Mock::given(method("POST"))
            .and(path("/api/cli/refresh"))
            .and(body_string_contains(refresh_token.to_string()))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "token": access_token,
                "refreshToken": rotated_refresh_token,
                "expiresAt": expires_at,
            })))
            .mount(&self.server)
            .await;
        self
    }

    /// Mount a successful `/api/cli/refresh` response with an explicit expected call count.
    pub async fn with_refresh_expected(
        &self,
        refresh_token: &str,
        access_token: &str,
        rotated_refresh_token: &str,
        expires_at: &str,
        expected_calls: u64,
    ) -> &Self {
        Mock::given(method("POST"))
            .and(path("/api/cli/refresh"))
            .and(body_string_contains(refresh_token.to_string()))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "token": access_token,
                "refreshToken": rotated_refresh_token,
                "expiresAt": expires_at,
            })))
            .expect(expected_calls)
            .mount(&self.server)
            .await;
        self
    }

    /// Mount a successful pairing revocation endpoint.
    pub async fn with_revoke_all_pairings(&self) -> &Self {
        self.with_revoke_all_pairings_expected(1).await
    }

    /// Mount pairing revocation with an explicit expected call count.
    pub async fn with_revoke_all_pairings_expected(&self, expected_calls: u64) -> &Self {
        Mock::given(method("POST"))
            .and(path("/api/vault/pair/revoke-all"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true
            })))
            .expect(expected_calls)
            .mount(&self.server)
            .await;
        self
    }

    pub async fn with_revoke_all_pairings_for(&self, bearer_token: &str) -> &Self {
        self.with_revoke_all_pairings_for_status(bearer_token, 200, 1)
            .await
    }

    pub async fn with_revoke_all_pairings_for_status(
        &self,
        bearer_token: &str,
        status: u16,
        expected_calls: u64,
    ) -> &Self {
        let response = if status == 200 {
            serde_json::json!({ "success": true })
        } else {
            serde_json::json!({ "error": "pairing revocation unauthorized" })
        };
        Mock::given(method("POST"))
            .and(path("/api/vault/pair/revoke-all"))
            .and(header("authorization", format!("Bearer {bearer_token}")))
            .respond_with(ResponseTemplate::new(status).set_body_json(response))
            .expect(expected_calls)
            .mount(&self.server)
            .await;
        self
    }

    pub async fn with_revoke_all_pairings_status(&self, status: u16) -> &Self {
        Mock::given(method("POST"))
            .and(path("/api/vault/pair/revoke-all"))
            .respond_with(
                ResponseTemplate::new(status).set_body_json(serde_json::json!({
                    "error": "pairing revocation unavailable"
                })),
            )
            .expect(1)
            .mount(&self.server)
            .await;
        self
    }

    /// Mount a successful token revocation endpoint.
    pub async fn with_revoke_token(&self, bearer_token: &str) -> &Self {
        self.with_revoke_token_expected(bearer_token, 1).await
    }

    /// Mount token revocation with an explicit expected call count.
    pub async fn with_revoke_token_expected(
        &self,
        bearer_token: &str,
        expected_calls: u64,
    ) -> &Self {
        Mock::given(method("POST"))
            .and(path("/api/cli/revoke"))
            .and(header("authorization", format!("Bearer {bearer_token}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "status": "revoked",
                "alreadyRevoked": false
            })))
            .expect(expected_calls)
            .mount(&self.server)
            .await;
        self
    }

    /// Mount a pending pairing session for a specific code.
    pub async fn with_pairing_session(
        &self,
        code: &str,
        bearer_token: &str,
        browser_public_key: &str,
    ) -> &Self {
        Mock::given(method("GET"))
            .and(path(format!("/api/vault/pair/{code}")))
            .and(header("authorization", format!("Bearer {bearer_token}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "status": "pending",
                "browserPublicKey": browser_public_key,
            })))
            .expect(1)
            .mount(&self.server)
            .await;
        self
    }

    /// Like [`with_pairing_session`] but with an explicit expected call
    /// count — `expected_calls: 0` is the regression guard used by tests
    /// that pin "the CLI must NOT reach this endpoint" (e.g. confirmation
    /// refusal paths).
    pub async fn with_pairing_session_call_count(
        &self,
        code: &str,
        bearer_token: &str,
        browser_public_key: &str,
        expected_calls: u64,
    ) -> &Self {
        Mock::given(method("GET"))
            .and(path(format!("/api/vault/pair/{code}")))
            .and(header("authorization", format!("Bearer {bearer_token}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "status": "pending",
                "browserPublicKey": browser_public_key,
            })))
            .expect(expected_calls)
            .mount(&self.server)
            .await;
        self
    }

    /// Mount a pending pairing session that includes the optional
    /// binding-metadata fields the new server returns (`deviceLabel`,
    /// `createdAt`, `createdFromIp`). Any of the three may be `None` to
    /// pin "this field absent" behavior.
    pub async fn with_pairing_session_with_metadata(
        &self,
        code: &str,
        bearer_token: &str,
        browser_public_key: &str,
        device_label: Option<&str>,
        created_at: Option<&str>,
        created_from_ip: Option<&str>,
    ) -> &Self {
        let mut body = serde_json::json!({
            "status": "pending",
            "browserPublicKey": browser_public_key,
        });
        if let Some(label) = device_label {
            body["deviceLabel"] = serde_json::Value::String(label.to_string());
        }
        if let Some(created) = created_at {
            body["createdAt"] = serde_json::Value::String(created.to_string());
        }
        if let Some(ip) = created_from_ip {
            body["createdFromIp"] = serde_json::Value::String(ip.to_string());
        }
        Mock::given(method("GET"))
            .and(path(format!("/api/vault/pair/{code}")))
            .and(header("authorization", format!("Bearer {bearer_token}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .expect(1)
            .mount(&self.server)
            .await;
        self
    }

    /// Mount a pairing session with a custom status.
    pub async fn with_pairing_session_status(
        &self,
        code: &str,
        bearer_token: &str,
        status: &str,
        browser_public_key: Option<&str>,
    ) -> &Self {
        let mut body = serde_json::json!({
            "status": status,
        });
        if let Some(browser_public_key) = browser_public_key {
            body["browserPublicKey"] = serde_json::Value::String(browser_public_key.to_string());
        }

        Mock::given(method("GET"))
            .and(path(format!("/api/vault/pair/{code}")))
            .and(header("authorization", format!("Bearer {bearer_token}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .expect(1)
            .mount(&self.server)
            .await;
        self
    }

    /// Mount a pairing session fetch error for a specific code.
    pub async fn with_pairing_session_error(
        &self,
        code: &str,
        bearer_token: &str,
        status_code: u16,
        body: &str,
    ) -> &Self {
        Mock::given(method("GET"))
            .and(path(format!("/api/vault/pair/{code}")))
            .and(header("authorization", format!("Bearer {bearer_token}")))
            .respond_with(ResponseTemplate::new(status_code).set_body_string(body))
            .expect(1)
            .mount(&self.server)
            .await;
        self
    }

    /// Mount a successful pairing approval endpoint for a specific code.
    pub async fn with_pairing_approval(&self, code: &str, bearer_token: &str) -> &Self {
        self.with_pairing_approval_call_count(code, bearer_token, 1)
            .await
    }

    /// Like [`with_pairing_approval`] but with an explicit expected call
    /// count — `expected_calls: 0` pins "the CLI must NOT reach the
    /// approve POST" (used by confirmation-refusal regression tests).
    pub async fn with_pairing_approval_call_count(
        &self,
        code: &str,
        bearer_token: &str,
        expected_calls: u64,
    ) -> &Self {
        Mock::given(method("POST"))
            .and(path(format!("/api/vault/pair/{code}")))
            .and(header("authorization", format!("Bearer {bearer_token}")))
            .and(body_string_contains("encryptedWrappingKey"))
            .and(body_string_contains("ephemeralPublicKey"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
            })))
            .expect(expected_calls)
            .mount(&self.server)
            .await;
        self
    }

    /// Mount a successful OIDC exchange endpoint.
    pub async fn with_oidc_exchange(
        &self,
        oidc_token: &str,
        vault_id: &str,
        env_name: Option<&str>,
        lpm_token: &str,
    ) -> &Self {
        self.with_oidc_exchange_for_policy(
            oidc_token,
            vault_id,
            env_name,
            TEST_OIDC_POLICY_ID,
            lpm_token,
        )
        .await
    }

    pub async fn with_oidc_exchange_for_policy(
        &self,
        oidc_token: &str,
        vault_id: &str,
        env_name: Option<&str>,
        policy_id: &str,
        lpm_token: &str,
    ) -> &Self {
        let mut mock = Mock::given(method("POST"))
            .and(path("/api/vault/oidc"))
            .and(body_string_contains(format!(
                "\"oidcToken\":\"{oidc_token}\""
            )))
            .and(body_string_contains(format!("\"vaultId\":\"{vault_id}\"")))
            .and(body_string_contains(format!(
                "\"policyId\":\"{policy_id}\""
            )));

        if let Some(env_name) = env_name {
            mock = mock.and(body_string_contains(format!("\"env\":\"{env_name}\"")));
        }

        mock.respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "token": lpm_token,
        })))
        .expect(1)
        .mount(&self.server)
        .await;
        self
    }

    /// Mount a failed OIDC exchange endpoint.
    pub async fn with_oidc_exchange_failure(
        &self,
        oidc_token: &str,
        vault_id: &str,
        env_name: Option<&str>,
        status_code: u16,
        error: &str,
        hint: Option<&str>,
    ) -> &Self {
        let mut mock = Mock::given(method("POST"))
            .and(path("/api/vault/oidc"))
            .and(body_string_contains(format!(
                "\"oidcToken\":\"{oidc_token}\""
            )))
            .and(body_string_contains(format!("\"vaultId\":\"{vault_id}\"")))
            .and(body_string_contains(format!(
                "\"policyId\":\"{}\"",
                TEST_OIDC_POLICY_ID
            )));

        if let Some(env_name) = env_name {
            mock = mock.and(body_string_contains(format!("\"env\":\"{env_name}\"")));
        }

        let mut body = serde_json::json!({
            "error": error,
        });
        if let Some(hint) = hint {
            body["hint"] = serde_json::Value::String(hint.to_string());
        }

        mock.respond_with(ResponseTemplate::new(status_code).set_body_json(body))
            .expect(1)
            .mount(&self.server)
            .await;
        self
    }

    /// Mount a successful GitHub Actions runtime OIDC token response.
    pub async fn with_github_oidc_runtime_token(
        &self,
        request_token: &str,
        runtime_token: &str,
    ) -> &Self {
        Mock::given(method("GET"))
            .and(path("/github/oidc"))
            .and(query_param("existing", "1"))
            .and(query_param("audience", "https://lpm.dev"))
            .and(header("authorization", format!("Bearer {request_token}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": runtime_token,
            })))
            .expect(1)
            .mount(&self.server)
            .await;
        self
    }

    /// Mount a custom GitHub Actions runtime OIDC token response.
    pub async fn with_github_oidc_runtime_response(
        &self,
        request_token: &str,
        status_code: u16,
        body: serde_json::Value,
    ) -> &Self {
        Mock::given(method("GET"))
            .and(path("/github/oidc"))
            .and(query_param("existing", "1"))
            .and(query_param("audience", "https://lpm.dev"))
            .and(header("authorization", format!("Bearer {request_token}")))
            .respond_with(ResponseTemplate::new(status_code).set_body_json(body))
            .expect(1)
            .mount(&self.server)
            .await;
        self
    }

    /// Mount a successful CI pull endpoint.
    pub async fn with_ci_pull(
        &self,
        vault_id: &str,
        bearer_token: &str,
        env_name: Option<&str>,
        vars: serde_json::Value,
    ) -> &Self {
        let mut mock = Mock::given(method("GET"))
            .and(path(format!("/api/vaults/{vault_id}/ci-pull")))
            .and(header("authorization", format!("Bearer {bearer_token}")));

        if let Some(env_name) = env_name {
            mock = mock.and(query_param("env", env_name));
        }

        mock.respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "env": env_name.unwrap_or("default"),
            "vars": vars,
        })))
        .expect(1)
        .mount(&self.server)
        .await;
        self
    }

    /// Mount a successful personal sync pull endpoint.
    ///
    /// The payload is encrypted with the legacy token-derived wrapping key so
    /// workflow tests can exercise the real pull path without sharing a local
    /// wrapping-key file between the test process and the CLI subprocess.
    pub async fn with_personal_pull(
        &self,
        vault_id: &str,
        bearer_token: &str,
        payload: serde_json::Value,
        version: i32,
    ) -> &Self {
        let plaintext = serde_json::to_string(&payload).expect("failed to serialize vault payload");
        let aes_key = lpm_vault::crypto::generate_aes_key();
        let wrapping_key = lpm_vault::crypto::derive_legacy_wrapping_key(bearer_token);
        let encrypted_blob = lpm_vault::crypto::encrypt(&aes_key, plaintext.as_bytes())
            .expect("failed to encrypt vault payload");
        let wrapped_key = lpm_vault::crypto::wrap_key(&wrapping_key, &aes_key)
            .expect("failed to wrap vault payload key");
        self.mount_personal_pull(
            vault_id,
            bearer_token,
            encrypted_blob,
            wrapped_key,
            version,
            None,
        )
        .await
    }

    pub async fn with_personal_pull_keys(
        &self,
        vault_id: &str,
        bearer_token: &str,
        payload: serde_json::Value,
        wrapping_key: &[u8; 32],
        data_key: &[u8; 32],
        version: i32,
    ) -> &Self {
        let plaintext = serde_json::to_string(&payload).expect("failed to serialize vault payload");
        let encrypted_blob = lpm_vault::crypto::encrypt(data_key, plaintext.as_bytes())
            .expect("failed to encrypt vault payload");
        let wrapped_key = lpm_vault::crypto::wrap_key(wrapping_key, data_key)
            .expect("failed to wrap vault payload key");
        self.mount_personal_pull(
            vault_id,
            bearer_token,
            encrypted_blob,
            wrapped_key,
            version,
            None,
        )
        .await
    }

    pub async fn with_personal_pull_failure(
        &self,
        vault_id: &str,
        bearer_token: &str,
        payload: serde_json::Value,
        version: i32,
        status: u16,
        error: &str,
    ) -> &Self {
        let plaintext = serde_json::to_string(&payload).expect("failed to serialize vault payload");
        let data_key = lpm_vault::crypto::generate_aes_key();
        let wrapping_key = lpm_vault::crypto::derive_legacy_wrapping_key(bearer_token);
        let encrypted_blob = lpm_vault::crypto::encrypt(&data_key, plaintext.as_bytes())
            .expect("failed to encrypt vault payload");
        let wrapped_key = lpm_vault::crypto::wrap_key(&wrapping_key, &data_key)
            .expect("failed to wrap vault payload key");
        self.mount_personal_pull(
            vault_id,
            bearer_token,
            encrypted_blob,
            wrapped_key,
            version,
            Some((status, error.to_string())),
        )
        .await
    }

    async fn mount_personal_pull(
        &self,
        vault_id: &str,
        bearer_token: &str,
        encrypted_blob: String,
        wrapped_key: String,
        version: i32,
        push_failure: Option<(u16, String)>,
    ) -> &Self {
        // Sync endpoints carry an X-LPM-Signature header on success — the
        // CLI hard-fails any 2xx response without it (HMAC verification
        // is mandatory). Sign both GET and POST mock bodies with the
        // bearer token so the harness mirrors what the real origin sends.
        let pull_body = serde_json::to_string(&serde_json::json!({
            "vaultId": vault_id,
            "encryptedBlob": encrypted_blob,
            "wrappedKey": wrapped_key,
            "version": version,
        }))
        .expect("test pull body should serialize");
        let pull_sig = lpm_vault::signature::sign_body(pull_body.as_bytes(), bearer_token);

        let push_body = serde_json::to_string(&serde_json::json!({
            "status": "updated",
            "version": version + 1,
        }))
        .expect("test push body should serialize");
        let push_sig = lpm_vault::signature::sign_body(push_body.as_bytes(), bearer_token);
        let push_response = match push_failure {
            Some((status, error)) => {
                ResponseTemplate::new(status).set_body_json(serde_json::json!({ "error": error }))
            }
            None => ResponseTemplate::new(200)
                .insert_header("Content-Type", "application/json")
                .insert_header(lpm_vault::signature::SIGNATURE_HEADER, push_sig.as_str())
                .set_body_string(push_body),
        };

        Mock::given(method("GET"))
            .and(path(format!("/api/vaults/{vault_id}/sync")))
            .and(header("authorization", format!("Bearer {bearer_token}")))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Content-Type", "application/json")
                    .insert_header(lpm_vault::signature::SIGNATURE_HEADER, pull_sig.as_str())
                    .set_body_string(pull_body),
            )
            .expect(1)
            .mount(&self.server)
            .await;

        Mock::given(method("POST"))
            .and(path(format!("/api/vaults/{vault_id}/sync")))
            .and(header("authorization", format!("Bearer {bearer_token}")))
            .respond_with(push_response)
            .mount(&self.server)
            .await;

        self
    }

    /// Mount a STATEFUL personal-sync endpoint that retains POSTed
    /// blobs in memory and serves them on subsequent GETs.
    ///
    /// `with_personal_pull` is static — both GET and POST return
    /// fixed payloads. That makes single-machine round-trip tests
    /// easy but cross-machine round-trip tests impossible: machine A
    /// pushes a blob into the void, machine B's pull returns the
    /// canned fixture, and the test can't compare what A pushed with
    /// what B pulled.
    ///
    /// This helper mounts the same `/api/vaults/{vault_id}/sync`
    /// endpoint but with shared `Arc<Mutex<...>>` state:
    /// - POST: parses the body, extracts `encryptedBlob` + `wrappedKey`,
    ///   stores them under the vault_id key, bumps the version, returns
    ///   `{"status":"updated","version":N+1}` signed with the bearer.
    /// - GET: looks up the stored blob; if present returns
    ///   `{"vaultId", "encryptedBlob", "wrappedKey", "version"}` signed
    ///   with the bearer. If absent (no prior POST), returns 404 — the
    ///   natural "fresh machine pulls before anyone pushed" shape.
    ///
    /// **Same-bearer constraint.** This helper authorizes both methods
    /// with the SAME bearer token — a deliberate simplification for the
    /// pairing-already-completed case. Tests that want to model
    /// pairing-failure semantics should keep using `with_personal_pull`.
    ///
    /// **Wrapping-key sharing is the caller's responsibility.** For
    /// machine B's `env pull` to decrypt machine A's payload, both
    /// HOMEs need the same wrapping key. Set `LPM_FORCE_FILE_VAULT=1`
    /// on each `lpm` invocation and pre-write the same hex-encoded
    /// 32-byte key to `<HOME>/.lpm/.vault-key` on both machines.
    pub async fn with_stateful_personal_sync(&self, vault_id: &str, bearer_token: &str) -> &Self {
        let state: Arc<Mutex<Option<StoredSyncBlob>>> = Arc::new(Mutex::new(None));
        let vault_id_owned = vault_id.to_string();
        let bearer_owned = bearer_token.to_string();

        // GET responder — looks up state, returns blob if present.
        let get_state = Arc::clone(&state);
        let get_vault = vault_id_owned.clone();
        let get_bearer = bearer_owned.clone();
        Mock::given(method("GET"))
            .and(path(format!("/api/vaults/{vault_id}/sync")))
            .and(header("authorization", format!("Bearer {bearer_token}")))
            .respond_with(StatefulSyncGetResponder {
                state: get_state,
                vault_id: get_vault,
                bearer_token: get_bearer,
            })
            .mount(&self.server)
            .await;

        // POST responder — captures body, bumps version, stores.
        Mock::given(method("POST"))
            .and(path(format!("/api/vaults/{vault_id}/sync")))
            .and(header("authorization", format!("Bearer {bearer_token}")))
            .respond_with(StatefulSyncPostResponder {
                state: Arc::clone(&state),
                bearer_token: bearer_owned,
            })
            .mount(&self.server)
            .await;

        self
    }

    /// Mount a successful OIDC policy creation endpoint.
    ///
    /// The mock verifies the CLI sends both `allowedWorkflows` and
    /// `allowedEvents`, so a regression that drops a field is caught here
    /// (the mock's `.expect(1)` only fires if every `body_string_contains`
    /// gate matches the actual request body).
    ///
    /// Nine parameters is intentional — the test-fixture call sites in
    /// `env_vault.rs` are documentation-as-test for what the CLI sends.
    /// Converting to an options struct hides the per-field intent at the
    /// call site, which is the opposite of what these tests want.
    #[allow(clippy::too_many_arguments)]
    pub async fn with_oidc_policy_create(
        &self,
        bearer_token: &str,
        vault_id: &str,
        repo: &str,
        repository_id: &str,
        branches: &[&str],
        envs: &[&str],
        workflows: &[&str],
        events: &[&str],
    ) -> &Self {
        let mut mock = Mock::given(method("POST"))
            .and(path("/api/vault/oidc/policies"))
            .and(header("authorization", format!("Bearer {bearer_token}")))
            .and(body_string_contains(format!("\"vaultId\":\"{vault_id}\"")))
            .and(body_string_contains(format!("\"subject\":\"repo:{repo}\"")))
            .and(body_string_contains(format!(
                "\"repositoryId\":\"{repository_id}\""
            )));

        for branch in branches {
            mock = mock.and(body_string_contains(format!("\"{branch}\"")));
        }
        for env_name in envs {
            mock = mock.and(body_string_contains(format!("\"{env_name}\"")));
        }
        for workflow in workflows {
            mock = mock.and(body_string_contains(format!("\"{workflow}\"")));
        }
        for event_name in events {
            mock = mock.and(body_string_contains(format!("\"{event_name}\"")));
        }

        mock.respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status": "ok",
            "policyId": TEST_OIDC_POLICY_ID,
            "provider": "github",
            "subject": format!("repo:{repo}"),
        })))
        .expect(1)
        .mount(&self.server)
        .await;
        self
    }

    pub async fn with_gitlab_oidc_policy_create(
        &self,
        bearer_token: &str,
        vault_id: &str,
        project_id: &str,
        branches: &[&str],
        envs: &[&str],
    ) -> &Self {
        let mut mock = Mock::given(method("POST"))
            .and(path("/api/vault/oidc/policies"))
            .and(header("authorization", format!("Bearer {bearer_token}")))
            .and(body_string_contains(format!("\"vaultId\":\"{vault_id}\"")))
            .and(body_string_contains("\"provider\":\"gitlab\""))
            .and(body_string_contains(format!(
                "\"subject\":\"project:{project_id}\""
            )))
            .and(body_string_contains("\"allowedWorkflows\":[]"))
            .and(body_string_contains("\"allowedEvents\":[]"))
            .and(body_string_contains("\"allowForks\":false"));

        for branch in branches {
            mock = mock.and(body_string_contains(format!("\"{branch}\"")));
        }
        for env_name in envs {
            mock = mock.and(body_string_contains(format!("\"{env_name}\"")));
        }

        mock.respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status": "ok",
            "policyId": TEST_OIDC_POLICY_ID,
            "provider": "gitlab",
            "subject": format!("project:{project_id}"),
        })))
        .expect(1)
        .mount(&self.server)
        .await;
        self
    }

    /// Mount an OIDC policy list endpoint.
    pub async fn with_oidc_policy_list(
        &self,
        bearer_token: &str,
        vault_id: &str,
        policies: serde_json::Value,
    ) -> &Self {
        Mock::given(method("GET"))
            .and(path("/api/vault/oidc/policies"))
            .and(query_param("vaultId", vault_id))
            .and(header("authorization", format!("Bearer {bearer_token}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "policies": policies,
            })))
            .expect(1)
            .mount(&self.server)
            .await;
        self
    }

    pub async fn with_platform_connect_success(
        &self,
        bearer_token: &str,
        vault_id: &str,
        platform: &str,
        project_id: &str,
        response: serde_json::Value,
    ) -> &Self {
        Mock::given(method("POST"))
            .and(path("/api/vault/platforms/connect"))
            .and(header("authorization", format!("Bearer {bearer_token}")))
            .and(body_string_contains(format!("\"vaultId\":\"{vault_id}\"")))
            .and(body_string_contains(format!("\"platform\":\"{platform}\"")))
            .and(body_string_contains(format!(
                "\"projectId\":\"{project_id}\""
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(response))
            .expect(1)
            .mount(&self.server)
            .await;
        self
    }

    pub async fn with_platform_connect_application_success(
        &self,
        bearer_token: &str,
        vault_id: &str,
        platform: &str,
        application_id: &str,
        response: serde_json::Value,
    ) -> &Self {
        Mock::given(method("POST"))
            .and(path("/api/vault/platforms/connect"))
            .and(header("authorization", format!("Bearer {bearer_token}")))
            .and(body_string_contains(format!("\"vaultId\":\"{vault_id}\"")))
            .and(body_string_contains(format!("\"platform\":\"{platform}\"")))
            .and(body_string_contains(format!(
                "\"applicationId\":\"{application_id}\""
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(response))
            .expect(1)
            .mount(&self.server)
            .await;
        self
    }

    pub async fn with_github_actions_platform_connect_success(
        &self,
        bearer_token: &str,
        vault_id: &str,
        repository: &str,
        repository_id: &str,
        response: serde_json::Value,
    ) -> &Self {
        Mock::given(method("POST"))
            .and(path("/api/vault/platforms/connect"))
            .and(header("authorization", format!("Bearer {bearer_token}")))
            .and(body_string_contains(format!("\"vaultId\":\"{vault_id}\"")))
            .and(body_string_contains("\"platform\":\"github-actions\""))
            .and(body_string_contains(format!(
                "\"repository\":\"{repository}\""
            )))
            .and(body_string_contains(format!(
                "\"repositoryId\":\"{repository_id}\""
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(response))
            .expect(1)
            .mount(&self.server)
            .await;
        self
    }

    pub async fn with_fly_platform_connect_success(
        &self,
        bearer_token: &str,
        vault_id: &str,
        app: &str,
        app_id: &str,
        organization_id: &str,
        response: serde_json::Value,
    ) -> &Self {
        Mock::given(method("POST"))
            .and(path("/api/vault/platforms/connect"))
            .and(header("authorization", format!("Bearer {bearer_token}")))
            .and(body_string_contains(format!("\"vaultId\":\"{vault_id}\"")))
            .and(body_string_contains("\"platform\":\"fly\""))
            .and(body_string_contains(format!("\"app\":\"{app}\"")))
            .and(body_string_contains(format!("\"appId\":\"{app_id}\"")))
            .and(body_string_contains(format!(
                "\"organizationId\":\"{organization_id}\""
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(response))
            .expect(1)
            .mount(&self.server)
            .await;
        self
    }

    pub async fn with_platform_credentials_success(
        &self,
        bearer_token: &str,
        vault_id: &str,
        response: serde_json::Value,
    ) -> &Self {
        self.with_platform_credentials_success_calls(bearer_token, vault_id, response, 1)
            .await
    }

    pub async fn with_platform_credentials_success_calls(
        &self,
        bearer_token: &str,
        vault_id: &str,
        response: serde_json::Value,
        expected_calls: u64,
    ) -> &Self {
        let body = serde_json::to_string(&response).expect("platform credentials should serialize");
        let signature = lpm_vault::signature::sign_body(body.as_bytes(), bearer_token);
        Mock::given(method("POST"))
            .and(path("/api/vault/platforms/credentials"))
            .and(header("authorization", format!("Bearer {bearer_token}")))
            .and(body_string_contains(format!("\"vaultId\":\"{vault_id}\"")))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/json")
                    .insert_header(lpm_vault::signature::SIGNATURE_HEADER, signature.as_str())
                    .set_body_string(body),
            )
            .expect(expected_calls)
            .mount(&self.server)
            .await;
        self
    }

    pub async fn with_github_actions_repository(
        &self,
        token: &str,
        repository: &str,
        repository_id: u64,
        expected_calls: u64,
    ) -> &Self {
        Mock::given(method("GET"))
            .and(path(format!("/repos/{repository}")))
            .and(header("authorization", format!("Bearer {token}")))
            .and(header("accept", "application/vnd.github+json"))
            .and(header("x-github-api-version", "2022-11-28"))
            .and(header("user-agent", "lpm-env-github-actions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": repository_id,
                "full_name": repository,
            })))
            .expect(expected_calls)
            .mount(&self.server)
            .await;
        self
    }

    pub async fn with_github_actions_environment_lists(
        &self,
        token: &str,
        repository_id: &str,
        environment: &str,
        variables: serde_json::Value,
        secrets: serde_json::Value,
        expected_calls: u64,
    ) -> &Self {
        Mock::given(method("GET"))
            .and(path(format!(
                "/repositories/{repository_id}/environments/{environment}/variables"
            )))
            .and(query_param("per_page", "100"))
            .and(query_param("page", "1"))
            .and(header("authorization", format!("Bearer {token}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "total_count": variables.as_array().map_or(0, Vec::len),
                "variables": variables,
            })))
            .expect(expected_calls)
            .mount(&self.server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/repositories/{repository_id}/environments/{environment}/secrets"
            )))
            .and(query_param("per_page", "100"))
            .and(query_param("page", "1"))
            .and(header("authorization", format!("Bearer {token}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "total_count": secrets.as_array().map_or(0, Vec::len),
                "secrets": secrets,
            })))
            .expect(expected_calls)
            .mount(&self.server)
            .await;
        self
    }

    pub async fn with_github_actions_environment_list_sequences(
        &self,
        token: &str,
        repository_id: &str,
        environment: &str,
        variables: Vec<serde_json::Value>,
        secrets: Vec<serde_json::Value>,
    ) -> &Self {
        let variable_calls = variables.len() as u64;
        let variable_bodies = variables
            .into_iter()
            .map(|variables| {
                serde_json::json!({
                    "total_count": variables.as_array().map_or(0, Vec::len),
                    "variables": variables,
                })
            })
            .collect::<VecDeque<_>>();
        Mock::given(method("GET"))
            .and(path(format!(
                "/repositories/{repository_id}/environments/{environment}/variables"
            )))
            .and(query_param("per_page", "100"))
            .and(query_param("page", "1"))
            .and(header("authorization", format!("Bearer {token}")))
            .respond_with(JsonResponseSequence {
                bodies: Arc::new(Mutex::new(variable_bodies)),
            })
            .expect(variable_calls)
            .mount(&self.server)
            .await;

        let secret_calls = secrets.len() as u64;
        let secret_bodies = secrets
            .into_iter()
            .map(|secrets| {
                serde_json::json!({
                    "total_count": secrets.as_array().map_or(0, Vec::len),
                    "secrets": secrets,
                })
            })
            .collect::<VecDeque<_>>();
        Mock::given(method("GET"))
            .and(path(format!(
                "/repositories/{repository_id}/environments/{environment}/secrets"
            )))
            .and(query_param("per_page", "100"))
            .and(query_param("page", "1"))
            .and(header("authorization", format!("Bearer {token}")))
            .respond_with(JsonResponseSequence {
                bodies: Arc::new(Mutex::new(secret_bodies)),
            })
            .expect(secret_calls)
            .mount(&self.server)
            .await;
        self
    }

    pub async fn with_github_actions_public_key(
        &self,
        token: &str,
        repository_id: &str,
        environment: &str,
    ) -> &Self {
        self.with_github_actions_public_key_calls(token, repository_id, environment, 1)
            .await
    }

    pub async fn with_github_actions_public_key_calls(
        &self,
        token: &str,
        repository_id: &str,
        environment: &str,
        expected_calls: u64,
    ) -> &Self {
        use base64::Engine;

        Mock::given(method("GET"))
            .and(path(format!(
                "/repositories/{repository_id}/environments/{environment}/secrets/public-key"
            )))
            .and(header("authorization", format!("Bearer {token}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "key_id": "workflow-key",
                "key": base64::engine::general_purpose::STANDARD.encode([7u8; 32]),
            })))
            .expect(expected_calls)
            .mount(&self.server)
            .await;
        self
    }

    pub async fn with_github_actions_variable_update_success(
        &self,
        token: &str,
        repository_id: &str,
        environment: &str,
        name: &str,
        value: &str,
    ) -> &Self {
        Mock::given(method("PATCH"))
            .and(path(format!(
                "/repositories/{repository_id}/environments/{environment}/variables/{name}"
            )))
            .and(header("authorization", format!("Bearer {token}")))
            .and(body_string_contains(format!("\"name\":\"{name}\"")))
            .and(body_string_contains(format!("\"value\":\"{value}\"")))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&self.server)
            .await;
        self
    }

    pub async fn with_github_actions_variable_delete_success(
        &self,
        token: &str,
        repository_id: &str,
        environment: &str,
        name: &str,
    ) -> &Self {
        Mock::given(method("DELETE"))
            .and(path(format!(
                "/repositories/{repository_id}/environments/{environment}/variables/{name}"
            )))
            .and(header("authorization", format!("Bearer {token}")))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&self.server)
            .await;
        self
    }

    pub async fn with_github_actions_secret_upsert_success(
        &self,
        token: &str,
        repository_id: &str,
        environment: &str,
        name: &str,
        expected_calls: u64,
    ) -> &Self {
        Mock::given(method("PUT"))
            .and(path(format!(
                "/repositories/{repository_id}/environments/{environment}/secrets/{name}"
            )))
            .and(header("authorization", format!("Bearer {token}")))
            .and(body_string_contains("\"encrypted_value\":"))
            .and(body_string_contains("\"key_id\":\"workflow-key\""))
            .respond_with(ResponseTemplate::new(204))
            .expect(expected_calls)
            .mount(&self.server)
            .await;
        self
    }

    pub async fn with_github_actions_secret_delete_success(
        &self,
        token: &str,
        repository_id: &str,
        environment: &str,
        name: &str,
    ) -> &Self {
        Mock::given(method("DELETE"))
            .and(path(format!(
                "/repositories/{repository_id}/environments/{environment}/secrets/{name}"
            )))
            .and(header("authorization", format!("Bearer {token}")))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&self.server)
            .await;
        self
    }

    pub async fn with_github_actions_variable_update_failure(
        &self,
        token: &str,
        repository_id: &str,
        environment: &str,
        name: &str,
    ) -> &Self {
        Mock::given(method("PATCH"))
            .and(path(format!(
                "/repositories/{repository_id}/environments/{environment}/variables/{name}"
            )))
            .and(header("authorization", format!("Bearer {token}")))
            .and(body_string_contains(format!("\"name\":\"{name}\"")))
            .respond_with(
                ResponseTemplate::new(403)
                    .set_body_json(serde_json::json!({ "message": "workflow denied" })),
            )
            .expect(1)
            .mount(&self.server)
            .await;
        self
    }

    pub async fn with_platform_audit_success(
        &self,
        bearer_token: &str,
        vault_id: &str,
        platform: &str,
        operation: &str,
        expected_body_fields: &[(&str, usize)],
    ) -> &Self {
        let mut mock = Mock::given(method("POST"))
            .and(path("/api/vault/platforms/audit"))
            .and(header("authorization", format!("Bearer {bearer_token}")))
            .and(body_string_contains(format!("\"vaultId\":\"{vault_id}\"")))
            .and(body_string_contains(format!("\"platform\":\"{platform}\"")))
            .and(body_string_contains(format!(
                "\"operation\":\"{operation}\""
            )));
        for (field, value) in expected_body_fields {
            mock = mock.and(body_string_contains(format!("\"{field}\":{value}")));
        }
        let body = serde_json::to_string(&serde_json::json!({ "success": true }))
            .expect("platform audit response should serialize");
        let signature = lpm_vault::signature::sign_body(body.as_bytes(), bearer_token);
        mock.respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .insert_header(lpm_vault::signature::SIGNATURE_HEADER, signature.as_str())
                .set_body_string(body),
        )
        .expect(1)
        .mount(&self.server)
        .await;
        self
    }

    pub async fn with_vercel_env_list(
        &self,
        token: &str,
        project_id: &str,
        envs: serde_json::Value,
        expected_calls: u64,
    ) -> &Self {
        Mock::given(method("GET"))
            .and(path(format!("/v10/projects/{project_id}/env")))
            .and(query_param("decrypt", "true"))
            .and(header("authorization", format!("Bearer {token}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "envs": envs,
                "pagination": { "next": null },
            })))
            .expect(expected_calls)
            .mount(&self.server)
            .await;
        self
    }

    pub async fn with_coolify_env_list(
        &self,
        token: &str,
        application_id: &str,
        envs: serde_json::Value,
        expected_calls: u64,
    ) -> &Self {
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/applications/{application_id}/envs")))
            .and(header("authorization", format!("Bearer {token}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(envs))
            .expect(expected_calls)
            .mount(&self.server)
            .await;
        self
    }

    pub async fn with_coolify_env_update(
        &self,
        token: &str,
        application_id: &str,
        key: &str,
        value: &str,
    ) -> &Self {
        Mock::given(method("PATCH"))
            .and(path(format!("/api/v1/applications/{application_id}/envs")))
            .and(header("authorization", format!("Bearer {token}")))
            .and(body_string_contains(format!("\"key\":\"{key}\"")))
            .and(body_string_contains(format!("\"value\":\"{value}\"")))
            .and(body_string_contains("\"is_preview\":false"))
            .and(body_string_contains("\"is_literal\":false"))
            .and(body_string_contains("\"is_multiline\":false"))
            .and(body_string_contains("\"is_shown_once\":false"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "uuid": "updated-coolify-variable",
            })))
            .expect(1)
            .mount(&self.server)
            .await;
        self
    }

    pub async fn with_railway_variables_list(
        &self,
        token: &str,
        project_id: &str,
        environment_id: &str,
        service_id: &str,
        variables: serde_json::Value,
        expected_calls: u64,
    ) -> &Self {
        Mock::given(method("POST"))
            .and(path("/graphql/v2"))
            .and(header("authorization", format!("Bearer {token}")))
            .and(body_string_contains("\"unrendered\":true"))
            .and(body_string_contains(format!(
                "\"projectId\":\"{project_id}\""
            )))
            .and(body_string_contains(format!(
                "\"environmentId\":\"{environment_id}\""
            )))
            .and(body_string_contains(format!(
                "\"serviceId\":\"{service_id}\""
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": { "variables": variables },
            })))
            .expect(expected_calls)
            .mount(&self.server)
            .await;
        self
    }

    pub async fn with_railway_variables_sequence(
        &self,
        token: &str,
        project_id: &str,
        environment_id: &str,
        service_id: &str,
        variables: Vec<serde_json::Value>,
    ) -> &Self {
        let expected_calls = variables.len() as u64;
        let bodies = variables
            .into_iter()
            .map(|variables| {
                serde_json::json!({
                    "data": { "variables": variables },
                })
            })
            .collect::<VecDeque<_>>();
        Mock::given(method("POST"))
            .and(path("/graphql/v2"))
            .and(header("authorization", format!("Bearer {token}")))
            .and(body_string_contains("\"unrendered\":true"))
            .and(body_string_contains(format!(
                "\"projectId\":\"{project_id}\""
            )))
            .and(body_string_contains(format!(
                "\"environmentId\":\"{environment_id}\""
            )))
            .and(body_string_contains(format!(
                "\"serviceId\":\"{service_id}\""
            )))
            .respond_with(JsonResponseSequence {
                bodies: Arc::new(Mutex::new(bodies)),
            })
            .expect(expected_calls)
            .mount(&self.server)
            .await;
        self
    }

    pub async fn with_railway_variables_upsert(
        &self,
        token: &str,
        project_id: &str,
        environment_id: &str,
        service_id: &str,
        key: &str,
        value: &str,
    ) -> &Self {
        Mock::given(method("POST"))
            .and(path("/graphql/v2"))
            .and(header("authorization", format!("Bearer {token}")))
            .and(body_string_contains("variableCollectionUpsert"))
            .and(body_string_contains(format!(
                "\"projectId\":\"{project_id}\""
            )))
            .and(body_string_contains(format!(
                "\"environmentId\":\"{environment_id}\""
            )))
            .and(body_string_contains(format!(
                "\"serviceId\":\"{service_id}\""
            )))
            .and(body_string_contains(format!("\"{key}\":\"{value}\"")))
            .and(body_string_contains("\"replace\":false"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": { "variableCollectionUpsert": true },
            })))
            .expect(1)
            .mount(&self.server)
            .await;
        self
    }

    pub async fn with_fly_app(&self, fixture: FlyAppFixture<'_>) -> &Self {
        Mock::given(method("POST"))
            .and(path("/graphql"))
            .and(header("authorization", format!("Bearer {}", fixture.token)))
            .and(header("user-agent", "lpm-env-fly"))
            .and(body_string_contains("query app($appName: String!)"))
            .and(body_string_contains(format!(
                "\"appName\":\"{}\"",
                fixture.app
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "app": {
                        "id": fixture.app_id,
                        "name": fixture.app,
                        "organization": {
                            "id": fixture.organization_id,
                            "slug": fixture.organization_slug,
                        },
                        "secrets": fixture.secrets,
                    }
                }
            })))
            .expect(fixture.expected_calls)
            .mount(&self.server)
            .await;
        self
    }

    pub async fn with_fly_set_secrets_success(
        &self,
        token: &str,
        app: &str,
        key: &str,
        value: &str,
    ) -> &Self {
        Mock::given(method("POST"))
            .and(path("/graphql"))
            .and(header("authorization", format!("Bearer {token}")))
            .and(header("user-agent", "lpm-env-fly"))
            .and(body_string_contains(
                "mutation setSecrets($input: SetSecretsInput!)",
            ))
            .and(body_string_contains(format!("\"appId\":\"{app}\"")))
            .and(body_string_contains(format!("\"key\":\"{key}\"")))
            .and(body_string_contains(format!("\"value\":\"{value}\"")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "setSecrets": {
                        "release": {
                            "id": "release-123",
                            "version": 7
                        }
                    }
                }
            })))
            .expect(1)
            .mount(&self.server)
            .await;
        self
    }

    /// Mount a successful wrapping-key escrow upload.
    pub async fn with_escrow_upload_success(&self, bearer_token: &str, vault_id: &str) -> &Self {
        Mock::given(method("POST"))
            .and(path("/api/vault/oidc/escrow"))
            .and(header("authorization", format!("Bearer {bearer_token}")))
            .and(body_string_contains(format!("\"vaultId\":\"{vault_id}\"")))
            .and(body_string_contains("wrappingKeyHex"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
            })))
            .expect(1)
            .mount(&self.server)
            .await;
        self
    }

    /// Mount a failed wrapping-key escrow upload.
    pub async fn with_escrow_upload_failure(
        &self,
        bearer_token: &str,
        vault_id: &str,
        message: &str,
    ) -> &Self {
        Mock::given(method("POST"))
            .and(path("/api/vault/oidc/escrow"))
            .and(header("authorization", format!("Bearer {bearer_token}")))
            .and(body_string_contains(format!("\"vaultId\":\"{vault_id}\"")))
            .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
                "error": message,
            })))
            .expect(1)
            .mount(&self.server)
            .await;
        self
    }

    /// **Production-shaped tarball URL path for a given `name@version`.**
    ///
    /// Returns the path-only portion (leading `/`); callers prepend the
    /// registry origin. **All mock-registry tarball mounts and metadata
    /// `dist.tarball` URLs MUST use this shape.**
    ///
    /// Shape: `/tarballs/{name}/-/{name}-{version}.tgz` — keeps the
    /// mock-specific `/tarballs/` routing prefix while inserting the
    /// `/-/` segment that the registry-client's `evaluate_cached_url`
    /// gate at [crates/lpm-registry/src/client.rs::evaluate_cached_url](../../../crates/lpm-registry/src/client.rs)
    /// requires (`.tgz` suffix AND `/-/` substring). The gate blocks
    /// the H1 auth-token leak: a tampered lockfile pointing at
    /// `/api/admin/foo.tgz` (no `/-/`) would otherwise attach the
    /// bearer to a non-registry endpoint.
    ///
    /// **Why this exists:** prior workflow tests used
    /// `/tarballs/{name}-{version}.tgz` (no `/-/`). The gate rejected
    /// every cached lockfile URL written by those tests and emitted
    /// `WARN cached tarball URL for X@Y failed shape check; falling
    /// back to on-demand lookup` on every offline-install test run.
    /// In test environments the install converged anyway (the mock
    /// happily served the on-demand re-lookup), but the WARN noise
    /// polluted every install test's stderr AND the `shape_mismatch`
    /// counter — documented as "BUG signal — the writer should never
    /// emit a gate-rejectable URL" — fired on every test run, making
    /// the counter useless for catching real bugs.
    ///
    /// **Future tests:** use this helper, or inline the same shape
    /// (`/tarballs/{name}/-/{name}-{version}.tgz`). Do NOT re-introduce
    /// the legacy `/tarballs/{name}-{version}.tgz` shape — it trips
    /// the gate and degrades the workflow-tier signal-to-noise.
    pub fn tarball_path(name: &str, version: &str) -> String {
        format!("/tarballs/{name}/-/{name}-{version}.tgz")
    }

    /// Convenience: full tarball URL with the server origin prepended.
    /// Equivalent to `format!("{}{}", mock.url(), MockRegistry::tarball_path(name, version))`.
    pub fn tarball_url(&self, name: &str, version: &str) -> String {
        format!("{}{}", self.server.uri(), Self::tarball_path(name, version))
    }

    pub async fn tarball_request_count(&self, name: &str, version: &str) -> usize {
        let path = Self::tarball_path(name, version);
        self.server()
            .received_requests()
            .await
            .expect("wiremock request log must be available")
            .into_iter()
            .filter(|request| request.url.path() == path)
            .count()
    }

    pub fn register_tarball_bytes(&self, name: &str, version: &str, tarball_bytes: &[u8]) {
        self.register_tarball_integrity(name, version, compute_integrity(tarball_bytes));
    }

    pub fn register_tarball_integrity(&self, name: &str, version: &str, integrity: String) {
        self.tarball_integrities
            .lock()
            .expect("mock tarball integrity registry poisoned")
            .insert((name.to_string(), version.to_string()), integrity);
    }

    fn registered_tarball_integrity(&self, name: &str, version: &str) -> Option<String> {
        self.tarball_integrities
            .lock()
            .expect("mock tarball integrity registry poisoned")
            .get(&(name.to_string(), version.to_string()))
            .cloned()
    }

    fn normalize_batch_metadata_integrity(&self, metadata: &mut serde_json::Value) {
        let Some(name) = metadata.get("name").and_then(|value| value.as_str()) else {
            return;
        };
        let name = name.to_string();
        let Some(versions) = metadata
            .get_mut("versions")
            .and_then(|value| value.as_object_mut())
        else {
            return;
        };
        for (version, version_meta) in versions {
            let Some(dist) = version_meta
                .get_mut("dist")
                .and_then(|value| value.as_object_mut())
            else {
                continue;
            };
            if dist.get("integrity").and_then(|value| value.as_str()) != Some("sha512-placeholder")
            {
                continue;
            }
            if let Some(integrity) = self.registered_tarball_integrity(&name, version) {
                dist.insert(
                    "integrity".to_string(),
                    serde_json::Value::String(integrity),
                );
            }
        }
    }

    pub fn package_metadata(
        &self,
        name: &str,
        version: &str,
        tarball_bytes: &[u8],
    ) -> serde_json::Value {
        let integrity = compute_integrity(tarball_bytes);
        self.register_tarball_integrity(name, version, integrity.clone());
        serde_json::json!({
            "name": name,
            "dist-tags": { "latest": version },
            "versions": {
                version: {
                    "name": name,
                    "version": version,
                    "dist": {
                        "tarball": self.tarball_url(name, version),
                        "integrity": integrity,
                    },
                    "dependencies": {}
                }
            },
            "time": { version: "2025-01-01T00:00:00.000Z" }
        })
    }

    pub fn signed_package_metadata(
        &self,
        name: &str,
        version: &str,
        tarball_bytes: &[u8],
        signer: &RegistrySigningFixture,
    ) -> serde_json::Value {
        let integrity = compute_integrity(tarball_bytes);
        self.register_tarball_integrity(name, version, integrity.clone());
        let signature = signer.signature_json(name, version, &integrity);
        serde_json::json!({
            "name": name,
            "dist-tags": { "latest": version },
            "versions": {
                version: {
                    "name": name,
                    "version": version,
                    "dist": {
                        "tarball": self.tarball_url(name, version),
                        "integrity": integrity,
                        "signatures": [signature],
                    },
                    "dependencies": {}
                }
            },
            "time": { version: "2025-01-01T00:00:00.000Z" }
        })
    }

    pub async fn with_registry_signing_keys(&self, signer: &RegistrySigningFixture) -> &Self {
        Mock::given(method("GET"))
            .and(path("/-/npm/v1/keys"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "keys": [signer.key_json()],
            })))
            .mount(&self.server)
            .await;
        self
    }

    pub async fn with_package_metadata(
        &self,
        name: &str,
        version: &str,
        tarball_bytes: &[u8],
        metadata: serde_json::Value,
    ) -> &Self {
        let metadata_path = format!("/api/registry/{name}");
        Mock::given(method("GET"))
            .and(path(&metadata_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(metadata.clone()))
            .mount(&self.server)
            .await;
        let npm_direct_path = format!("/{name}");
        Mock::given(method("GET"))
            .and(path(&npm_direct_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(metadata))
            .mount(&self.server)
            .await;

        let tarball_path = Self::tarball_path(name, version);
        self.register_tarball_bytes(name, version, tarball_bytes);
        Mock::given(method("GET"))
            .and(path(&tarball_path))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_bytes(tarball_bytes.to_vec())
                    .insert_header("content-type", "application/octet-stream"),
            )
            .mount(&self.server)
            .await;
        self
    }

    /// Mount a package metadata endpoint for a simple npm package (no deps).
    ///
    /// Mounts:
    /// - `GET /api/registry/{name}` — npm-compatible metadata with single version
    /// - `GET /tarballs/{name}/-/{name}-{version}.tgz` — tarball download (production-shaped per [`tarball_path`](Self::tarball_path))
    ///
    /// Also mounts on the unscoped path variant that the resolver uses.
    pub async fn with_package(&self, name: &str, version: &str, tarball_bytes: &[u8]) -> &Self {
        self.with_package_and_deps(name, version, tarball_bytes, serde_json::json!({}))
            .await
    }

    /// Mount a package using one manifest-shaped JSON value as both
    /// tarball `package.json` and registry metadata.
    ///
    /// Prefer this in compatibility tests where fields such as
    /// `peerDependencies`, `peerDependenciesMeta`, `bin`, or platform
    /// constraints are part of the behavior under test.
    pub async fn with_manifest_package(
        &self,
        pkg_json: serde_json::Value,
        extra_files: &[(&str, &[u8])],
    ) -> &Self {
        let name = pkg_json
            .get("name")
            .and_then(|value| value.as_str())
            .expect("with_manifest_package: package.json must contain string `name`")
            .to_string();
        let version = pkg_json
            .get("version")
            .and_then(|value| value.as_str())
            .expect("with_manifest_package: package.json must contain string `version`")
            .to_string();

        let tarball_bytes = make_tarball_from_pkg_json(pkg_json.clone(), extra_files);
        let tarball_url = self.tarball_url(&name, &version);
        let integrity = compute_integrity(&tarball_bytes);
        self.register_tarball_integrity(&name, &version, integrity.clone());

        let mut version_meta = serde_json::Map::new();
        version_meta.insert("name".to_string(), serde_json::Value::String(name.clone()));
        version_meta.insert(
            "version".to_string(),
            serde_json::Value::String(version.clone()),
        );
        version_meta.insert(
            "dist".to_string(),
            serde_json::json!({
                "tarball": tarball_url,
                "integrity": integrity,
            }),
        );
        for field in [
            "dependencies",
            "optionalDependencies",
            "peerDependencies",
            "peerDependenciesMeta",
            "bin",
            "scripts",
            "engines",
            "os",
            "cpu",
            "libc",
        ] {
            if let Some(value) = pkg_json.get(field) {
                version_meta.insert(field.to_string(), value.clone());
            }
        }

        let mut versions = serde_json::Map::new();
        versions.insert(version.clone(), serde_json::Value::Object(version_meta));
        let mut time = serde_json::Map::new();
        time.insert(
            version.clone(),
            serde_json::Value::String("2025-01-01T00:00:00.000Z".into()),
        );

        let metadata = serde_json::json!({
            "name": name,
            "dist-tags": {
                "latest": version,
            },
            "versions": versions,
            "time": time,
        });

        let metadata_path = format!("/api/registry/{name}");
        Mock::given(method("GET"))
            .and(path(&metadata_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(metadata.clone()))
            .mount(&self.server)
            .await;
        let npm_direct_path = format!("/{name}");
        Mock::given(method("GET"))
            .and(path(&npm_direct_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(metadata.clone()))
            .mount(&self.server)
            .await;

        let tarball_path = Self::tarball_path(&name, &version);
        Mock::given(method("GET"))
            .and(path(&tarball_path))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_bytes(tarball_bytes)
                    .insert_header("content-type", "application/octet-stream"),
            )
            .mount(&self.server)
            .await;

        self.with_batch_metadata(vec![metadata]).await;
        self
    }

    /// Mount a package with explicit dependencies.
    pub async fn with_package_and_deps(
        &self,
        name: &str,
        version: &str,
        tarball_bytes: &[u8],
        dependencies: serde_json::Value,
    ) -> &Self {
        let tarball_url = self.tarball_url(name, version);

        // Compute real sha512 integrity for the tarball
        let integrity = compute_integrity(tarball_bytes);
        self.register_tarball_integrity(name, version, integrity.clone());

        let metadata = serde_json::json!({
            "name": name,
            "dist-tags": {
                "latest": version
            },
            "versions": {
                version: {
                    "name": name,
                    "version": version,
                    "dist": {
                        "tarball": tarball_url,
                        "integrity": integrity,
                    },
                    "dependencies": dependencies
                }
            },
            "time": {
                version: "2025-01-01T00:00:00.000Z"
            }
        });

        // Mount on /api/registry/{name} (the LPM proxy path — Proxy
        // mode) AND on /{name} (npm-direct path — Direct mode, the
        // Serving both keeps tests mode-
        // agnostic so a route-mode flip in the client doesn't
        // retroactively break workflow fixtures.
        let metadata_path = format!("/api/registry/{name}");
        Mock::given(method("GET"))
            .and(path(&metadata_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(metadata.clone()))
            .mount(&self.server)
            .await;
        let npm_direct_path = format!("/{name}");
        Mock::given(method("GET"))
            .and(path(&npm_direct_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(metadata.clone()))
            .mount(&self.server)
            .await;

        // Mount tarball endpoint
        let tarball_path = Self::tarball_path(name, version);
        Mock::given(method("GET"))
            .and(path(&tarball_path))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_bytes(tarball_bytes.to_vec())
                    .insert_header("content-type", "application/octet-stream"),
            )
            .mount(&self.server)
            .await;

        self
    }

    /// Mount a single-version package whose `time[version]` is the
    /// caller-supplied ISO-8601 timestamp. Used by the cooldown gate
    /// (release-age) tests where the publication time must be a fixed
    /// offset from `now()` rather than the static date `with_package`
    /// hardcodes.
    ///
    /// Mounts: single-package GET metadata + tarball GET. Pair with
    /// `with_batch_metadata` for resolver-batch coverage.
    pub async fn with_package_published_at(
        &self,
        name: &str,
        version: &str,
        tarball_bytes: &[u8],
        published_at: &str,
    ) -> &Self {
        let tarball_url = self.tarball_url(name, version);
        let integrity = compute_integrity(tarball_bytes);
        self.register_tarball_integrity(name, version, integrity.clone());

        let metadata = serde_json::json!({
            "name": name,
            "dist-tags": { "latest": version },
            "versions": {
                version: {
                    "name": name,
                    "version": version,
                    "dist": {
                        "tarball": tarball_url,
                        "integrity": integrity,
                    },
                    "dependencies": {}
                }
            },
            "time": { version: published_at }
        });

        let metadata_path = format!("/api/registry/{name}");
        Mock::given(method("GET"))
            .and(path(&metadata_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(metadata.clone()))
            .mount(&self.server)
            .await;
        let npm_direct_path = format!("/{name}");
        Mock::given(method("GET"))
            .and(path(&npm_direct_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(metadata.clone()))
            .mount(&self.server)
            .await;

        let tarball_path = Self::tarball_path(name, version);
        Mock::given(method("GET"))
            .and(path(&tarball_path))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_bytes(tarball_bytes.to_vec())
                    .insert_header("content-type", "application/octet-stream"),
            )
            .mount(&self.server)
            .await;

        self
    }

    /// Mount a package with multiple versions in its `versions` map and
    /// expose BOTH the per-package GET (`/api/registry/{name}`,
    /// `/{name}` for npm-direct routing) AND the batch-metadata POST.
    ///
    /// Required for surfaces that read the per-package GET endpoint —
    /// notably `lpm upgrade`'s candidate selector, which calls
    /// `GET /api/registry/{name}` to enumerate candidate versions.
    /// `with_package` only registers a single-version metadata document
    /// and `with_batch_metadata` only registers the POST endpoint, so
    /// neither alone makes multi-version surfaces (upgrade, outdated)
    /// observable to the workflow tier.
    ///
    /// Each `versions` entry is `(version, dependencies, Option<tarball_bytes>)`:
    /// - `Some(bytes)` mounts the tarball at `/tarballs/{name}-{ver}.tgz` with the bytes.
    /// - `None` mounts a 404 at the tarball endpoint — emulates the
    ///   "version exists in metadata but tarball is gone" failure path
    ///   used by upgrade's install-failure restore test.
    ///
    /// `latest_version` is what gets surfaced as `dist-tags.latest`.
    ///
    /// All version timestamps default to `2025-01-01T00:00:00.000Z`.
    /// Tests that need cooldown-aware timestamps should use
    /// `with_package_published_at` instead.
    ///
    /// Lifted from the formerly-private `mount_upgrade_package` helper
    /// in `tests/workflows/tests/upgrade.rs` so cross-command flow
    /// tests can drive upgrade's candidate-selector path without
    /// reaching into another test's internals.
    pub async fn with_full_package_metadata(
        &self,
        name: &str,
        latest_version: &str,
        versions: &[(&str, serde_json::Value, Option<Vec<u8>>)],
    ) -> &Self {
        let metadata = self
            .mount_full_package_metadata_routes(name, latest_version, versions)
            .await;
        self.with_batch_metadata(vec![metadata]).await
    }

    /// Mount per-package metadata and tarball routes without installing a
    /// batch-metadata responder, returning the metadata for a caller-owned
    /// combined batch fixture.
    pub async fn mount_full_package_metadata_routes(
        &self,
        name: &str,
        latest_version: &str,
        versions: &[(&str, serde_json::Value, Option<Vec<u8>>)],
    ) -> serde_json::Value {
        let mut versions_map = serde_json::Map::new();
        let mut times_map = serde_json::Map::new();

        for (v, deps, bytes_opt) in versions {
            let tarball_url = self.tarball_url(name, v);
            let integrity = match bytes_opt {
                Some(bytes) => compute_integrity(bytes),
                // Synthetic integrity for the missing-tarball case —
                // the metadata still has to advertise SOME integrity so
                // the resolver's preflight doesn't reject the version
                // record. The actual fetch will 404 before integrity is
                // checked.
                None => compute_integrity(b"missing tarball fixture"),
            };
            if bytes_opt.is_some() {
                self.register_tarball_integrity(name, v, integrity.clone());
            }
            versions_map.insert(
                (*v).to_string(),
                serde_json::json!({
                    "name": name,
                    "version": v,
                    "dist": {
                        "tarball": tarball_url,
                        "integrity": integrity,
                    },
                    "dependencies": deps,
                }),
            );
            times_map.insert(
                (*v).to_string(),
                serde_json::Value::String("2025-01-01T00:00:00.000Z".into()),
            );

            let tarball_path = Self::tarball_path(name, v);
            let response = match bytes_opt {
                Some(bytes) => ResponseTemplate::new(200)
                    .set_body_bytes(bytes.clone())
                    .insert_header("content-type", "application/octet-stream"),
                None => ResponseTemplate::new(404).set_body_string("missing tarball"),
            };
            Mock::given(method("GET"))
                .and(path(&tarball_path))
                .respond_with(response)
                .mount(&self.server)
                .await;
        }

        let metadata = serde_json::json!({
            "name": name,
            "dist-tags": { "latest": latest_version },
            "versions": versions_map,
            "time": times_map,
        });

        let metadata_path = format!("/api/registry/{name}");
        Mock::given(method("GET"))
            .and(path(&metadata_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(metadata.clone()))
            .mount(&self.server)
            .await;
        let npm_direct_path = format!("/{name}");
        Mock::given(method("GET"))
            .and(path(&npm_direct_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(metadata.clone()))
            .mount(&self.server)
            .await;

        metadata
    }

    /// Mount caller-built package metadata plus tarballs for the listed versions.
    ///
    /// This is useful for registry-policy tests that need fields not modeled by
    /// the higher-level helpers, such as per-version publish times or trust
    /// evidence in full packuments.
    pub async fn with_package_metadata_and_tarballs(
        &self,
        name: &str,
        metadata: serde_json::Value,
        tarballs: &[(&str, Vec<u8>)],
    ) -> &Self {
        let metadata_path = format!("/api/registry/{name}");
        Mock::given(method("GET"))
            .and(path(&metadata_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(metadata.clone()))
            .mount(&self.server)
            .await;
        let npm_direct_path = format!("/{name}");
        Mock::given(method("GET"))
            .and(path(&npm_direct_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(metadata.clone()))
            .mount(&self.server)
            .await;

        for (version, tarball_bytes) in tarballs {
            self.register_tarball_bytes(name, version, tarball_bytes);
            let tarball_path = Self::tarball_path(name, version);
            Mock::given(method("GET"))
                .and(path(&tarball_path))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_bytes(tarball_bytes.clone())
                        .insert_header("content-type", "application/octet-stream"),
                )
                .mount(&self.server)
                .await;
        }

        self.with_batch_metadata(vec![metadata]).await;
        self
    }

    pub async fn with_npm_package_error(
        &self,
        name: &str,
        status: u16,
        body: serde_json::Value,
    ) -> &Self {
        Mock::given(method("GET"))
            .and(path(format!("/{name}")))
            .respond_with(ResponseTemplate::new(status).set_body_json(body))
            .mount(&self.server)
            .await;
        self
    }

    /// Mount a batch-metadata endpoint that returns metadata for all registered packages.
    ///
    /// The install pipeline calls `POST /api/registry/batch-metadata` with `{"packages": [...], "deep": true}`
    /// before resolving. This mock returns NDJSON (one JSON object per line).
    pub async fn with_batch_metadata(&self, packages: Vec<serde_json::Value>) -> &Self {
        // Build NDJSON response body. The client's `parse_ndjson_batch`
        // deserializes each line as `{ name, metadata }` envelopes; a
        // bare `PackageMetadata` line fails that schema and is silently
        // dropped. Auto-wrap callers who pass raw metadata.
        let mut ndjson = String::new();
        for pkg in packages {
            let mut pkg = pkg;
            let line = match pkg.get_mut("metadata") {
                Some(metadata) => {
                    self.normalize_batch_metadata_integrity(metadata);
                    serde_json::to_string(&pkg).unwrap()
                }
                None => {
                    self.normalize_batch_metadata_integrity(&mut pkg);
                    let name = pkg
                        .get("name")
                        .and_then(|v| v.as_str())
                        .expect("with_batch_metadata: entry must have a top-level `name` field");
                    serde_json::to_string(&serde_json::json!({
                        "name": name,
                        "metadata": pkg,
                    }))
                    .unwrap()
                }
            };
            ndjson.push_str(&line);
            ndjson.push('\n');
        }

        Mock::given(method("POST"))
            .and(path("/api/registry/batch-metadata"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(ndjson, "application/x-ndjson"))
            .mount(&self.server)
            .await;
        self
    }

    /// Mount a publish endpoint that accepts PUT and returns success.
    pub async fn with_publish_endpoint(&self) -> &Self {
        Mock::given(method("PUT"))
            .and(path_regex("/api/registry/.*"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "message": "Package published"
            })))
            .mount(&self.server)
            .await;
        self
    }

    /// Mount a 401 response on all API endpoints to simulate unauthenticated access.
    pub async fn with_auth_required(&self) -> &Self {
        Mock::given(method("GET"))
            .and(path_regex("/api/.*"))
            .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
                "error": "Unauthorized",
                "message": "Authentication required"
            })))
            .mount(&self.server)
            .await;
        self
    }

    /// Mount production-shaped OSV batch and advisory endpoints.
    ///
    /// Tests redirect `lpm audit`'s OSV calls here by setting
    /// `LPM_OSV_URL = "{mock.url()}/v1/querybatch"`. `vulns_per_query`
    /// is a list with one entry per query slot — pass an empty Vec for
    /// "no vulns for this package" or one or more full OSV advisory JSON
    /// values for "this package matched these vulns." The batch endpoint
    /// returns only sparse advisory references; each full advisory is mounted
    /// at `GET /v1/vulns/{id}`, matching the public OSV API contract.
    pub async fn with_osv_querybatch(&self, vulns_per_query: Vec<Vec<serde_json::Value>>) -> &Self {
        let mut advisories = HashMap::new();
        let results: Vec<serde_json::Value> = vulns_per_query
            .into_iter()
            .map(|vulns| {
                let sparse = vulns
                    .into_iter()
                    .map(|advisory| {
                        let id = advisory
                            .get("id")
                            .and_then(|value| value.as_str())
                            .expect("OSV advisory fixture must include an id")
                            .to_string();
                        advisories.entry(id.clone()).or_insert(advisory);
                        serde_json::json!({
                            "id": id,
                            "modified": "2026-01-01T00:00:00Z"
                        })
                    })
                    .collect::<Vec<_>>();
                serde_json::json!({ "vulns": sparse })
            })
            .collect();

        for (id, advisory) in advisories {
            Mock::given(method("GET"))
                .and(path(format!("/v1/vulns/{id}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(advisory))
                .mount(&self.server)
                .await;
        }

        Mock::given(method("POST"))
            .and(path("/v1/querybatch"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "results": results,
            })))
            .mount(&self.server)
            .await;
        self
    }

    /// Build a complete OSV vulnerability affecting every version of `package`.
    pub fn osv_vuln(id: &str, package: &str, summary: &str, cvss_score: &str) -> serde_json::Value {
        serde_json::json!({
            "id": id,
            "summary": summary,
            "severity": [{ "type": "CVSS_V3", "score": cvss_score }],
            "affected": [{
                "package": {"ecosystem": "npm", "name": package},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]
            }]
        })
    }

    /// Access the underlying `MockServer` for custom mock setups.
    pub fn server(&self) -> &MockServer {
        &self.server
    }
}

/// Compute sha512 SRI integrity hash for tarball bytes.
pub fn compute_integrity(data: &[u8]) -> String {
    // Simple SHA-512: read all bytes, hash, base64-encode
    let digest = {
        // Use a basic sha2 approach — we have it as a transitive dep
        // but for test code, just shell out a manual computation
        // Actually, compute manually with ring-like approach
        // For simplicity in tests, use a fixed known hash
        // We compute the real hash to make integrity verification pass
        sha512_base64(data)
    };
    format!("sha512-{digest}")
}

/// SHA-512 hash of data, base64 encoded (for SRI).
fn sha512_base64(data: &[u8]) -> String {
    use std::process::Command;
    // Use openssl from the system for test simplicity
    let mut child = Command::new("openssl")
        .args(["dgst", "-sha512", "-binary"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("openssl required for test integrity hashes");

    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(data)
        .expect("failed to write to openssl stdin");

    let output = child.wait_with_output().expect("openssl failed");
    assert!(output.status.success(), "openssl sha512 failed");

    // base64-encode the raw digest
    let mut b64_child = Command::new("openssl")
        .args(["base64", "-A"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("openssl base64 required");

    b64_child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(&output.stdout)
        .expect("failed to write to base64 stdin");

    let b64_output = b64_child.wait_with_output().expect("base64 failed");
    String::from_utf8(b64_output.stdout)
        .unwrap()
        .trim()
        .to_string()
}

/// Create a minimal valid npm-format tarball (.tgz) containing a package.json.
///
/// npm tarballs are gzipped tar archives where files live under a `package/` prefix.
/// This creates the smallest valid tarball that `lpm-extractor` will accept.
pub fn make_tarball(name: &str, version: &str) -> Vec<u8> {
    make_tarball_with_files(name, version, &[])
}

/// Create a tarball with a fully custom package.json and extra files.
///
/// Use this when you need to declare non-standard fields like `bin`, `scripts`,
/// or `peerDependencies` in the installed package's manifest.
///
/// `pkg_json` is written verbatim as `package/package.json`; `extra_files` are
/// additional paths (relative to `package/`) with their byte contents.
pub fn make_tarball_from_pkg_json(
    pkg_json: serde_json::Value,
    extra_files: &[(&str, &[u8])],
) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());

    let pkg_json_bytes = serde_json::to_vec_pretty(&pkg_json).unwrap();
    let mut header = tar::Header::new_gnu();
    header.set_path("package/package.json").unwrap();
    header.set_size(pkg_json_bytes.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    builder.append(&header, &pkg_json_bytes[..]).unwrap();

    let index_js = b"module.exports = {};";
    let mut header = tar::Header::new_gnu();
    header.set_path("package/index.js").unwrap();
    header.set_size(index_js.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    builder.append(&header, &index_js[..]).unwrap();

    for (file_path, content) in extra_files {
        let mut header = tar::Header::new_gnu();
        header.set_path(format!("package/{file_path}")).unwrap();
        header.set_size(content.len() as u64);
        header.set_mode(0o755);
        header.set_cksum();
        builder.append(&header, *content).unwrap();
    }

    let tar_bytes = builder.into_inner().unwrap();
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&tar_bytes).unwrap();
    encoder.finish().unwrap()
}

/// Create a tarball with additional files beyond package.json.
pub fn make_tarball_with_files(
    name: &str,
    version: &str,
    extra_files: &[(&str, &[u8])],
) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());

    // Add package.json under the standard `package/` prefix
    let pkg_json = serde_json::json!({
        "name": name,
        "version": version,
        "main": "index.js"
    });
    let pkg_json_bytes = serde_json::to_vec_pretty(&pkg_json).unwrap();
    let mut header = tar::Header::new_gnu();
    header.set_path("package/package.json").unwrap();
    header.set_size(pkg_json_bytes.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    builder.append(&header, &pkg_json_bytes[..]).unwrap();

    // Add index.js
    let index_js = b"module.exports = {};";
    let mut header = tar::Header::new_gnu();
    header.set_path("package/index.js").unwrap();
    header.set_size(index_js.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    builder.append(&header, &index_js[..]).unwrap();

    // Add any extra files
    for (file_path, content) in extra_files {
        let mut header = tar::Header::new_gnu();
        header.set_path(format!("package/{file_path}")).unwrap();
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append(&header, *content).unwrap();
    }

    let tar_bytes = builder.into_inner().unwrap();

    // gzip compress
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&tar_bytes).unwrap();
    encoder.finish().unwrap()
}

// ─── Stateful personal-sync support ────────────────────────────────────

#[derive(Clone)]
struct StoredSyncBlob {
    encrypted_blob: String,
    wrapped_key: String,
    version: i32,
}

struct StatefulSyncGetResponder {
    state: Arc<Mutex<Option<StoredSyncBlob>>>,
    vault_id: String,
    bearer_token: String,
}

impl Respond for StatefulSyncGetResponder {
    fn respond(&self, _request: &Request) -> ResponseTemplate {
        let stored = self
            .state
            .lock()
            .expect("StatefulSyncGetResponder mutex poisoned")
            .clone();
        let Some(blob) = stored else {
            // No prior POST — represent as 404 so the CLI surfaces a
            // "vault has no payload yet" error rather than silently
            // succeeding with an empty body.
            return ResponseTemplate::new(404)
                .insert_header("Content-Type", "application/json")
                .set_body_string(r#"{"error":"vault has no synced state"}"#);
        };
        let body = serde_json::to_string(&serde_json::json!({
            "vaultId": self.vault_id,
            "encryptedBlob": blob.encrypted_blob,
            "wrappedKey": blob.wrapped_key,
            "version": blob.version,
        }))
        .expect("stateful sync GET body must serialize");
        let sig = lpm_vault::signature::sign_body(body.as_bytes(), &self.bearer_token);
        ResponseTemplate::new(200)
            .insert_header("Content-Type", "application/json")
            .insert_header(lpm_vault::signature::SIGNATURE_HEADER, sig.as_str())
            .set_body_string(body)
    }
}

struct StatefulSyncPostResponder {
    state: Arc<Mutex<Option<StoredSyncBlob>>>,
    bearer_token: String,
}

impl Respond for StatefulSyncPostResponder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body_value: serde_json::Value = match serde_json::from_slice(&request.body) {
            Ok(v) => v,
            Err(_) => {
                return ResponseTemplate::new(400)
                    .set_body_string(r#"{"error":"stateful sync POST: body not valid JSON"}"#);
            }
        };
        let encrypted_blob = body_value
            .get("encryptedBlob")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let wrapped_key = body_value
            .get("wrappedKey")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let (Some(encrypted_blob), Some(wrapped_key)) = (encrypted_blob, wrapped_key) else {
            return ResponseTemplate::new(400).set_body_string(
                r#"{"error":"stateful sync POST: missing encryptedBlob or wrappedKey"}"#,
            );
        };

        let mut guard = self
            .state
            .lock()
            .expect("StatefulSyncPostResponder mutex poisoned");
        let new_version = guard.as_ref().map_or(1, |b| b.version + 1);
        *guard = Some(StoredSyncBlob {
            encrypted_blob,
            wrapped_key,
            version: new_version,
        });
        drop(guard);

        let body = serde_json::to_string(&serde_json::json!({
            "status": "updated",
            "version": new_version,
        }))
        .expect("stateful sync POST body must serialize");
        let sig = lpm_vault::signature::sign_body(body.as_bytes(), &self.bearer_token);
        ResponseTemplate::new(200)
            .insert_header("Content-Type", "application/json")
            .insert_header(lpm_vault::signature::SIGNATURE_HEADER, sig.as_str())
            .set_body_string(body)
    }
}
