//! Mock LPM registry server built on `wiremock`.
//!
//! Provides ergonomic builders for common registry endpoints so workflow
//! tests can validate install, publish, health, and auth flows without
//! any external network calls.

use std::io::Write;
use wiremock::matchers::{method, path, path_regex};
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

    /// Mount a package metadata endpoint for a simple npm package (no deps).
    ///
    /// Mounts:
    /// - `GET /api/registry/{name}` — npm-compatible metadata with single version
    /// - `GET /tarballs/{name}-{version}.tgz` — tarball download
    ///
    /// Also mounts on the unscoped path variant that the resolver uses.
    pub async fn with_package(
        &self,
        name: &str,
        version: &str,
        tarball_bytes: &[u8],
    ) -> &Self {
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

        // Mount on /api/registry/{name} (the LPM proxy path)
        let metadata_path = format!("/api/registry/{name}");
        Mock::given(method("GET"))
            .and(path(&metadata_path))
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
    use std::io::Read;
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

    use std::io::Read;
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
    String::from_utf8(b64_output.stdout).unwrap().trim().to_string()
}

/// Create a minimal valid npm-format tarball (.tgz) containing a package.json.
///
/// npm tarballs are gzipped tar archives where files live under a `package/` prefix.
/// This creates the smallest valid tarball that `lpm-extractor` will accept.
pub fn make_tarball(name: &str, version: &str) -> Vec<u8> {
    make_tarball_with_files(name, version, &[])
}

/// Create a tarball with additional files beyond package.json.
pub fn make_tarball_with_files(name: &str, version: &str, extra_files: &[(&str, &[u8])]) -> Vec<u8> {
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
    builder
        .append(&header, &pkg_json_bytes[..])
        .unwrap();

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
        header
            .set_path(format!("package/{file_path}"))
            .unwrap();
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
