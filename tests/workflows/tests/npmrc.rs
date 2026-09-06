//! Workflow test for `.npmrc`-driven authenticated install round-trips.
//!
//! Regression: a custom-registry install configured via
//! `.npmrc` (`registry=` + nerf-dart `_authToken=`) MUST attach the
//! bearer token on every request that reaches the registry — including
//! the post-resolve metadata helpers (cooldown gate's
//! `minimumReleaseAge` lookup, `build_blocked_set_metadata`) that
//! pre-day-4.6 took an unrouted code path and arrived without auth.
//!
//! The load-bearing assertion iterates `wiremock::received_requests()`
//! and verifies EVERY request carried the right `Authorization: Bearer
//! <token>` header. A regression that re-routed any helper through the
//! unrouted path would leave at least one entry here without auth.
//!
//! ## Why a separate file
//!
//! This is the only `.npmrc`-driven test in the workflow tier today.
//! It needs the npm-direct route (the `lpm-workflows` default forces
//! `LPM_NPM_ROUTE=proxy` for harness-uniformity reasons), so the test
//! explicitly removes that env override and lets `.npmrc` drive
//! routing. Putting it in its own file documents the divergence
//! cleanly rather than burying the override in `install.rs`.

mod support;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use chrono::SecondsFormat;
use sha2::{Digest, Sha512};
use std::io::Write;
use support::mock_registry::MockRegistry;
use support::{TempProject, lpm};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, ResponseTemplate};

const TOKEN: &str = "PHASE58-WORKFLOW-SECRET-TOKEN";
const PACKAGE_NAME: &str = "npmrc-workflow-package";
const VERSION: &str = "1.0.0";

// ─── Tarball + metadata builders (auth-gated; can't reuse MockRegistry's helpers) ──

fn make_minimal_tarball() -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());

    let pkg_json = serde_json::json!({
        "name": PACKAGE_NAME,
        "version": VERSION,
        "main": "index.js",
    });
    let pkg_bytes = serde_json::to_vec_pretty(&pkg_json).unwrap();
    let mut h = tar::Header::new_gnu();
    h.set_path("package/package.json").unwrap();
    h.set_size(pkg_bytes.len() as u64);
    h.set_mode(0o644);
    h.set_cksum();
    builder.append(&h, &pkg_bytes[..]).unwrap();

    let index_js = b"module.exports = {};\n";
    let mut h = tar::Header::new_gnu();
    h.set_path("package/index.js").unwrap();
    h.set_size(index_js.len() as u64);
    h.set_mode(0o644);
    h.set_cksum();
    builder.append(&h, &index_js[..]).unwrap();

    let tar_bytes = builder.into_inner().unwrap();
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&tar_bytes).unwrap();
    encoder.finish().unwrap()
}

fn integrity(data: &[u8]) -> String {
    format!("sha512-{}", BASE64.encode(Sha512::digest(data)))
}

fn iso8601_30_days_ago() -> String {
    (chrono::Utc::now() - chrono::Duration::days(30)).to_rfc3339_opts(SecondsFormat::Millis, true)
}

// ─── Test ───────────────────────────────────────────────────────────────

/// `lpm install` against an auth-gated `.npmrc`-configured registry must
/// attach `Authorization: Bearer <token>` on EVERY request — metadata
/// (resolution + cooldown gate + build-blocked-set lookup) and tarball.
/// Any helper that fell back to the unrouted code path would arrive
/// without auth and trip the per-request iteration assertion.
#[tokio::test]
async fn npmrc_authenticated_install_attaches_bearer_on_every_registry_request() {
    let mock = MockRegistry::start().await;
    let server = mock.server();
    let server_url = mock.url();

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

    // Auth-required metadata + tarball endpoints. Without the right
    // bearer the request 404s (no mock matched) — caught by the
    // received_requests iteration below.
    let auth_value = format!("Bearer {TOKEN}");
    Mock::given(method("GET"))
        .and(path(format!("/{PACKAGE_NAME}")))
        .and(header("Authorization", auth_value.as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_json(metadata.clone()))
        .mount(server)
        .await;
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
        .mount(server)
        .await;

    let project = TempProject::empty(&format!(
        r#"{{"name":"npmrc-auth-test","version":"1.0.0","dependencies":{{"{PACKAGE_NAME}":"{VERSION}"}}}}"#
    ));

    // `.npmrc` with registry + nerf-dart auth token. The host on the
    // auth line must match wiremock's host:port exactly.
    let host_no_scheme = server_url
        .strip_prefix("http://")
        .or_else(|| server_url.strip_prefix("https://"))
        .unwrap_or(&server_url);
    project.write_private_file(
        ".npmrc",
        &format!("registry={server_url}/\n//{host_no_scheme}/:_authToken={TOKEN}\n"),
    );

    // Use `lpm()` (no --registry override) so .npmrc drives routing,
    // and switch off the workflow tier's default proxy mode so npm
    // packages take the npm-direct path (the .npmrc registry).
    // Critical: NO LPM_TOKEN — the .npmrc bearer must be the only
    // credential flowing into the install. If a session bearer leaked
    // in, the auth assertion below could pass for the wrong reason.
    let out = lpm(&project)
        .env_remove("LPM_NPM_ROUTE")
        .env_remove("LPM_TOKEN")
        .args(["install"])
        .output()
        .expect("spawn lpm install");
    assert!(
        out.status.success(),
        "install must succeed against the auth-gated custom registry; \
         stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    // Package landed in node_modules.
    assert!(
        project
            .path()
            .join("node_modules")
            .join(PACKAGE_NAME)
            .exists(),
        "expected node_modules/{PACKAGE_NAME} to exist after install; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    // ── Load-bearing security assertion ────────────────────────────────
    // Every request that reached wiremock MUST carry the npmrc bearer.
    // Pre-day-4.5 the tarball requests arrived without auth; pre-
    // day-4.6 the post-resolve metadata helpers re-fetched without
    // auth via the unrouted `get_npm_package_metadata`. Either
    // regression leaves an entry here without the header.
    let received = server
        .received_requests()
        .await
        .expect("wiremock recorded request log");
    assert!(
        !received.is_empty(),
        "wiremock received zero requests — install bypassed the custom registry"
    );
    assert!(
        received.len() >= 2,
        "expected at least metadata + tarball requests; received {}",
        received.len()
    );

    for (i, req) in received.iter().enumerate() {
        let auth_header = req
            .headers
            .get("Authorization")
            .and_then(|h| h.to_str().ok());
        assert_eq!(
            auth_header,
            Some(auth_value.as_str()),
            "request #{i} ({} {}) arrived with Authorization={auth_header:?}, \
             expected {auth_value:?}\n  full request log:\n{}",
            req.method,
            req.url,
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
                .join("\n")
        );
    }
}
