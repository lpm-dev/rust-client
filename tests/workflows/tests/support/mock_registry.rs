#![allow(dead_code)]

//! Mock LPM registry server built on `wiremock`.
//!
//! Provides ergonomic builders for common registry endpoints so workflow
//! tests can validate install, publish, health, and auth flows without
//! any external network calls.

use std::io::Write;
use wiremock::matchers::{body_string_contains, header, method, path, path_regex, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// A mock LPM registry server.
///
/// Wraps `wiremock::MockServer` and provides ergonomic helpers for mounting
/// common endpoint mocks. Pass `mock.url()` as `--registry` to the CLI.
pub struct MockRegistry {
    server: MockServer,
}

impl MockRegistry {
    /// Start a new mock registry on a random port.
    pub async fn start() -> Self {
        let server = MockServer::start().await;
        MockRegistry { server }
    }

    /// The base URL of the mock server (e.g., `http://127.0.0.1:PORT`).
    pub fn url(&self) -> String {
        self.server.uri()
    }

    /// Mount a healthy `/api/registry/health` endpoint.
    pub async fn with_health(&self) -> &Self {
        Mock::given(method("GET"))
            .and(path("/api/registry/health"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "status": "ok"
            })))
            .mount(&self.server)
            .await;
        self
    }

    /// Mount a `/api/registry/-/whoami` endpoint returning a test user.
    pub async fn with_whoami(&self, username: &str, email: &str) -> &Self {
        Mock::given(method("GET"))
            .and(path("/api/registry/-/whoami"))
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
                    "storage_bytes": 1024 * 1024 * 500,
                    "private_packages": 100
                },
                "organizations": []
            })))
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
                    "storage_bytes": 1024 * 1024 * 500,
                    "private_packages": 100
                },
                "organizations": []
            })))
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
        Mock::given(method("POST"))
            .and(path(format!("/api/vault/pair/{code}")))
            .and(header("authorization", format!("Bearer {bearer_token}")))
            .and(body_string_contains("encryptedWrappingKey"))
            .and(body_string_contains("ephemeralPublicKey"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
            })))
            .expect(1)
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
        let mut mock = Mock::given(method("POST"))
            .and(path("/api/vault/oidc"))
            .and(body_string_contains(format!(
                "\"oidcToken\":\"{oidc_token}\""
            )))
            .and(body_string_contains(format!("\"vaultId\":\"{vault_id}\"")));

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
            .and(body_string_contains(format!("\"vaultId\":\"{vault_id}\"")));

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

        Mock::given(method("GET"))
            .and(path(format!("/api/vaults/{vault_id}/sync")))
            .and(header("authorization", format!("Bearer {bearer_token}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "vaultId": vault_id,
                "encryptedBlob": encrypted_blob,
                "wrappedKey": wrapped_key,
                "version": version,
            })))
            .expect(1)
            .mount(&self.server)
            .await;

        Mock::given(method("POST"))
            .and(path(format!("/api/vaults/{vault_id}/sync")))
            .and(header("authorization", format!("Bearer {bearer_token}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "status": "updated",
                "version": version + 1,
            })))
            .mount(&self.server)
            .await;

        self
    }

    /// Mount a successful OIDC policy creation endpoint.
    pub async fn with_oidc_policy_create(
        &self,
        bearer_token: &str,
        vault_id: &str,
        repo: &str,
        branches: &[&str],
        envs: &[&str],
    ) -> &Self {
        let mut mock = Mock::given(method("POST"))
            .and(path("/api/vault/oidc/policies"))
            .and(header("authorization", format!("Bearer {bearer_token}")))
            .and(body_string_contains(format!("\"vaultId\":\"{vault_id}\"")))
            .and(body_string_contains(format!("\"subject\":\"repo:{repo}\"")));

        for branch in branches {
            mock = mock.and(body_string_contains(format!("\"{branch}\"")));
        }
        for env_name in envs {
            mock = mock.and(body_string_contains(format!("\"{env_name}\"")));
        }

        mock.respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true,
            "provider": "github",
            "subject": format!("repo:{repo}"),
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

    /// Mount a package metadata endpoint for a simple npm package (no deps).
    ///
    /// Mounts:
    /// - `GET /api/registry/{name}` — npm-compatible metadata with single version
    /// - `GET /tarballs/{name}-{version}.tgz` — tarball download
    ///
    /// Also mounts on the unscoped path variant that the resolver uses.
    pub async fn with_package(&self, name: &str, version: &str, tarball_bytes: &[u8]) -> &Self {
        self.with_package_and_deps(name, version, tarball_bytes, serde_json::json!({}))
            .await
    }

    /// Mount a package with explicit dependencies.
    pub async fn with_package_and_deps(
        &self,
        name: &str,
        version: &str,
        tarball_bytes: &[u8],
        dependencies: serde_json::Value,
    ) -> &Self {
        let tarball_url = format!("{}/tarballs/{name}-{version}.tgz", self.server.uri());

        // Compute real sha512 integrity for the tarball
        let integrity = compute_integrity(tarball_bytes);

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
        // Phase 49 shipped default). Serving both keeps tests mode-
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
        let tarball_path = format!("/tarballs/{name}-{version}.tgz");
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

    /// Mount a batch-metadata endpoint that returns metadata for all registered packages.
    ///
    /// The install pipeline calls `POST /api/registry/batch-metadata` with `{"packages": [...], "deep": true}`
    /// before resolving. This mock returns NDJSON (one JSON object per line).
    pub async fn with_batch_metadata(&self, packages: Vec<serde_json::Value>) -> &Self {
        // Build NDJSON response body
        let mut ndjson = String::new();
        for pkg in &packages {
            ndjson.push_str(&serde_json::to_string(pkg).unwrap());
            ndjson.push('\n');
        }

        Mock::given(method("POST"))
            .and(path("/api/registry/batch-metadata"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(ndjson)
                    .insert_header("content-type", "application/x-ndjson"),
            )
            .mount(&self.server)
            .await;
        self
    }

    /// Mount a publish endpoint that accepts PUT and returns success.
    pub async fn with_publish_endpoint(&self) -> &Self {
        Mock::given(method("PUT"))
            .and(path_regex("/api/registry/packages/.*"))
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

    /// Access the underlying `MockServer` for custom mock setups.
    pub fn server(&self) -> &MockServer {
        &self.server
    }
}

/// Compute sha512 SRI integrity hash for tarball bytes.
fn compute_integrity(data: &[u8]) -> String {
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
