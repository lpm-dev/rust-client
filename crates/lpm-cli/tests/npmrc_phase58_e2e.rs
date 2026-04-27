//! Phase 58 day-5 — `.npmrc` end-to-end install regression.
//!
//! This is the install-level regression Gemini specifically asked for
//! during the day-4.6 review: an executable assertion that a custom-
//! registry install does NOT issue any unauthenticated request to its
//! configured registry — covering the resolution + tarball-fetch slice
//! (day-4.5 fix) AND the post-resolve policy/metadata slice (day-4.6
//! fix: minimumReleaseAge / provenance / build_blocked_set_metadata).
//!
//! ## Harness shape
//!
//! Pattern lifted from `crates/lpm-cli/tests/release_age_p3_ship_criteria.rs`:
//! spin up a `wiremock::MockServer`, mount a single-version package
//! whose metadata + tarball BOTH require `Authorization: Bearer
//! <TOKEN>`, write a `package.json` + `.npmrc` into a tempdir, spawn
//! the `lpm-rs` binary against that tempdir with a scoped `HOME`, and
//! run `lpm install`.
//!
//! ## What's asserted
//!
//! 1. Install exits zero.
//! 2. The package lands in `node_modules/`.
//! 3. **Every** request that reached the wiremock carried the right
//!    `Authorization` header. This is the load-bearing security check
//!    — any post-resolve helper that reverted to the unrouted path
//!    would arrive without auth (no LPM session bearer in the test
//!    env) and the iteration over `received_requests()` would catch
//!    it.
//! 4. At least the metadata + tarball requests fired (>= 2 received),
//!    so the test isn't vacuously satisfied by a no-op install.
//!
//! ## Known limitation
//!
//! A silent fall-through to public `registry.npmjs.org` (the failure
//! mode in the pre-day-4.6 code path) would NOT be visible in the
//! wiremock's `received_requests()` because the request would never
//! reach our mock. A future hardening could add `NPM_REGISTRY_URL` as
//! an env override so this test can pin npm.org to an unreachable URL
//! and catch fall-throughs as connection-refused. Out of scope for
//! Phase 58.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use chrono::{SecondsFormat, Utc};
use sha2::{Digest, Sha512};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TOKEN: &str = "PHASE58-E2E-SECRET-TOKEN";
const PACKAGE_NAME: &str = "phase58-e2e-package";
const VERSION: &str = "1.0.0";

struct CommandOutput {
    status: ExitStatus,
    stdout: String,
    stderr: String,
}

fn make_minimal_tarball() -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());

    let package_json = serde_json::json!({
        "name": PACKAGE_NAME,
        "version": VERSION,
        "main": "index.js",
    });
    let package_json_bytes = serde_json::to_vec_pretty(&package_json).unwrap();
    let mut header = tar::Header::new_gnu();
    header.set_path("package/package.json").unwrap();
    header.set_size(package_json_bytes.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    builder.append(&header, &package_json_bytes[..]).unwrap();

    let index_js = b"module.exports = {};\n";
    let mut header = tar::Header::new_gnu();
    header.set_path("package/index.js").unwrap();
    header.set_size(index_js.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    builder.append(&header, &index_js[..]).unwrap();

    let tar_bytes = builder.into_inner().unwrap();
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&tar_bytes).unwrap();
    encoder.finish().unwrap()
}

fn integrity(data: &[u8]) -> String {
    let digest = Sha512::digest(data);
    format!("sha512-{}", BASE64.encode(digest))
}

fn iso8601_30_days_ago() -> String {
    // Far enough in the past that the default 24h `minimumReleaseAge`
    // window passes — we want to **exercise** the cooldown gate (which
    // reads metadata via the routed path post-day-4.6), not bypass it.
    (Utc::now() - chrono::Duration::days(30)).to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn project_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir()
        .join("lpm-phase58-npmrc-e2e")
        .join(format!("{name}.{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn write_manifest(dir: &Path) {
    let manifest = serde_json::json!({
        "name": "phase58-npmrc-e2e",
        "version": "1.0.0",
        "dependencies": { PACKAGE_NAME: VERSION },
    });
    fs::write(
        dir.join("package.json"),
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();
}

fn write_npmrc(dir: &Path, server_url: &str) {
    // Strip scheme to derive the nerf-dart auth-key host. Wiremock
    // serves on http://127.0.0.1:<port> so the npmrc origin matches
    // exactly.
    let host_no_scheme = server_url
        .strip_prefix("http://")
        .or_else(|| server_url.strip_prefix("https://"))
        .unwrap_or(server_url);
    let body = format!("registry={server_url}/\n//{host_no_scheme}/:_authToken={TOKEN}\n",);
    fs::write(dir.join(".npmrc"), body).unwrap();
}

fn run_lpm(cwd: &Path, args: &[&str]) -> CommandOutput {
    let exe = env!("CARGO_BIN_EXE_lpm-rs");
    let home = cwd.join(".home");
    fs::create_dir_all(&home).unwrap();

    let mut command = Command::new(exe);
    command
        .args(args)
        .current_dir(cwd)
        .env("HOME", &home)
        .env("NO_COLOR", "1")
        .env("LPM_NO_UPDATE_CHECK", "1")
        .env("LPM_DISABLE_TELEMETRY", "1")
        .env("LPM_FORCE_FILE_VAULT", "1")
        // Critical: NO LPM_TOKEN. The npmrc bearer is the only credential
        // that should flow into the install. If anything mistakenly
        // attaches a session bearer, this absence makes the failure
        // visible (rather than masking it under a coincidentally-valid
        // env token).
        .env_remove("LPM_TOKEN")
        .env_remove("RUST_LOG")
        // Pin the LPM Worker URL to a deliberately unreachable port.
        // Any incidental Worker call (e.g., a stray `@lpm.dev/*`
        // resolution path) would refuse-connect; the test fails
        // loudly instead of silently hitting real lpm.dev.
        .env("LPM_REGISTRY_URL", "http://127.0.0.1:1");

    let output = command.output().expect("failed to spawn lpm-rs");
    CommandOutput {
        status: output.status,
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    }
}

fn fail_with_context(out: &CommandOutput, what: &str) -> ! {
    panic!(
        "{what}\n  exit: {:?}\n  stdout:\n{}\n  stderr:\n{}",
        out.status.code(),
        out.stdout,
        out.stderr,
    );
}

#[tokio::test]
async fn npmrc_authenticated_install_round_trip() {
    let server = MockServer::start().await;
    let server_url = server.uri();

    let tarball = make_minimal_tarball();
    let tarball_url = format!("{server_url}/{PACKAGE_NAME}/-/{PACKAGE_NAME}-{VERSION}.tgz");
    let metadata = serde_json::json!({
        "name": PACKAGE_NAME,
        "dist-tags": { "latest": VERSION },
        "versions": {
            VERSION: {
                "name": PACKAGE_NAME,
                "version": VERSION,
                "dist": {
                    "tarball": tarball_url,
                    "integrity": integrity(&tarball),
                },
                "dependencies": {},
            }
        },
        "time": { VERSION: iso8601_30_days_ago() },
    });

    // Auth-required metadata endpoint: only matches when the request
    // carries the right Bearer. Without it, the request 404s (no mock
    // matched) — that's caught by the `received_requests` assertion
    // below.
    let auth_value = format!("Bearer {TOKEN}");
    Mock::given(method("GET"))
        .and(path(format!("/{PACKAGE_NAME}")))
        .and(header("Authorization", auth_value.as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_json(metadata.clone()))
        .mount(&server)
        .await;

    // Auth-required tarball endpoint.
    Mock::given(method("GET"))
        .and(path(format!(
            "/{PACKAGE_NAME}/-/{PACKAGE_NAME}-{VERSION}.tgz"
        )))
        .and(header("Authorization", auth_value.as_str()))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_bytes(tarball.clone())
                .insert_header("content-type", "application/octet-stream"),
        )
        .mount(&server)
        .await;

    let dir = project_dir("round_trip");
    write_manifest(&dir);
    write_npmrc(&dir, &server_url);

    let out = run_lpm(&dir, &["install"]);
    if !out.status.success() {
        fail_with_context(
            &out,
            "install must succeed against the auth-gated custom registry",
        );
    }

    // Package landed.
    let installed_pkg = dir.join("node_modules").join(PACKAGE_NAME);
    if !installed_pkg.exists() {
        fail_with_context(
            &out,
            &format!("expected node_modules/{PACKAGE_NAME} to exist after install"),
        );
    }

    // ── Load-bearing security assertion ─────────────────────────────
    // Every request that reached the wiremock MUST carry the npmrc
    // Bearer. Pre-day-4.5 the tarball requests arrived without auth;
    // pre-day-4.6 the post-resolve metadata helpers (cooldown gate,
    // build_blocked_set_metadata) re-fetched without auth via the
    // unrouted `get_npm_package_metadata`. Either regression would
    // leave at least one entry here without the Authorization header.
    let received = server
        .received_requests()
        .await
        .expect("wiremock recorded request log");
    if received.is_empty() {
        fail_with_context(
            &out,
            "wiremock received zero requests — install bypassed the custom registry",
        );
    }
    if received.len() < 2 {
        fail_with_context(
            &out,
            &format!(
                "expected at least metadata + tarball requests; received {}",
                received.len()
            ),
        );
    }
    for (i, req) in received.iter().enumerate() {
        let auth_header = req
            .headers
            .get("Authorization")
            .and_then(|h| h.to_str().ok());
        if auth_header != Some(auth_value.as_str()) {
            panic!(
                "request #{i} ({} {}) arrived with Authorization={:?}, expected {:?}\n  full request log:\n{}",
                req.method,
                req.url,
                auth_header,
                auth_value,
                received
                    .iter()
                    .enumerate()
                    .map(|(j, r)| format!(
                        "    [{j}] {} {} auth={:?}",
                        r.method,
                        r.url,
                        r.headers.get("Authorization").and_then(|h| h.to_str().ok())
                    ))
                    .collect::<Vec<_>>()
                    .join("\n"),
            );
        }
    }
}
