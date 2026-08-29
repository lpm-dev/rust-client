//! **Tier placement: cli-binary.** Justification class: **intentionally
//! minimal binary-surface repros**. These are contract pins for the exact
//! request shape the binary emits to lpm.dev's OIDC exchange route.
//! The assertions inspect specific JSON fields on the wiremock-recorded
//! request body (`scope`, `package`, `targets_lpm` gating). The
//! workflow harness's higher-level abstractions (`MockRegistry::with_*`
//! helpers) would obscure the byte-level request inspection these
//! tests need; a focused cli-binary file with raw `wiremock` access
//! reads cleaner.
//!
//! Regression tests for the `lpm publish` OIDC auto-exchange contract:
//!
//! 1. **`package` field**: the origin's OIDC exchange route requires `package`
//!    for `scope=publish`.
//!    An earlier revision called `exchange_oidc_token(..., None, "publish")`,
//!    so every CI publish silently 400'd and fell back to stored auth —
//!    defeating OIDC for publish-only CI runners.
//! 2. **Gated on `targets_lpm && !check_only`**: the exchange must NOT fire
//!    when LPM isn't a target (privacy: don't leak package metadata to lpm.dev
//!    when publishing only to npm/github/gitlab) or in `--check` mode (local
//!    validation surface).
//!
//! Tests use `--dry-run` to exercise the real publish path through the OIDC
//! exchange and out via the dry-run short-circuit, without needing a publish
//! endpoint mock.

use std::fs;
use std::process::{Command, Output};
use wiremock::matchers::{body_partial_json, header, method, path, path_regex, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const PACKAGE_NAME: &str = "@lpm.dev/owner.publish-oidc-contract";
const SUPPLIED_JWT: &str = "publish-jwt-with-aud-lpm-dev";
const EXCHANGED_TOKEN: &str = "EXCHANGED-PUBLISH-SESSION-TOKEN";
const PUBLICATION_STATUS_TOKEN: &str = "EXCHANGED-PUBLICATION-STATUS-TOKEN";

fn write_minimal_project(cwd: &std::path::Path) {
    fs::create_dir_all(cwd.join(".home")).unwrap();
    fs::write(
        cwd.join("package.json"),
        format!(r#"{{"name":"{PACKAGE_NAME}","version":"0.1.0","description":"contract test"}}"#),
    )
    .unwrap();
}

fn write_authored_skill(cwd: &std::path::Path) {
    let skills_dir = cwd.join(".lpm/skills");
    fs::create_dir_all(&skills_dir).unwrap();
    fs::write(
        skills_dir.join("publish.md"),
        format!(
            "---\nname: publish\ndescription: Publishing guidance\n---\n\n{}",
            "Use this package safely with concrete steps and examples. ".repeat(4)
        ),
    )
    .unwrap();
}

fn lpm_command(cwd: &std::path::Path) -> Command {
    let exe = env!("CARGO_BIN_EXE_lpm-rs");
    let home = cwd.join(".home");
    let lpm_home = home.join(".lpm");
    let mut command = Command::new(exe);

    command
        .current_dir(cwd)
        .env("HOME", &home)
        .env("LPM_HOME", &lpm_home)
        .env("NO_COLOR", "1")
        .env("LPM_NO_UPDATE_CHECK", "1")
        .env("LPM_DISABLE_TELEMETRY", "1")
        .env("LPM_FORCE_FILE_AUTH", "1")
        .env("LPM_TEST_FAST_SCRYPT", "1")
        .env("LPM_FORCE_FILE_VAULT", "1")
        .env("LPM_DISABLE_HOST_CLI_AUTH", "1")
        .env(
            "LPM_SECURITY_POLICY_PATH",
            lpm_home.join("security-policy.toml"),
        )
        .env("LPM_OIDC_TOKEN", SUPPLIED_JWT)
        .env_remove("ACTIONS_ID_TOKEN_REQUEST_URL")
        .env_remove("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
        .env_remove("LPM_GITLAB_OIDC_TOKEN")
        .env_remove("SIGSTORE_ID_TOKEN")
        .env_remove("LPM_TOKEN")
        .env_remove("NPM_TOKEN")
        .env_remove("RUST_LOG");
    command
}

fn spawn_publish(cwd: &std::path::Path, registry: &str, args: &[&str]) -> Output {
    let mut argv: Vec<&str> = vec!["publish"];
    argv.extend_from_slice(args);
    argv.extend(["--registry", registry]);

    lpm_command(cwd)
        .args(&argv)
        .env("LPM_OIDC_TOKEN", SUPPLIED_JWT)
        .output()
        .expect("failed to spawn lpm-rs")
}

fn store_custom_registry_token(cwd: &std::path::Path, registry: &str, token: &str) {
    let output = lpm_command(cwd)
        .args(["login", "--login-registry", registry, "--token", token])
        .output()
        .expect("failed to store custom registry token");
    assert!(
        output.status.success(),
        "custom registry login failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
async fn publish_dry_run_lpm_target_exchange_includes_package_field() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/api/registry/-/token/oidc"))
        .and(query_param("scope", "publish"))
        .and(body_partial_json(serde_json::json!({
            "token": SUPPLIED_JWT,
            "package": PACKAGE_NAME,
        })))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({ "token": EXCHANGED_TOKEN })),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/registry/-/package/publish-preflight"))
        .and(query_param("name", PACKAGE_NAME))
        .and(query_param("version", "0.1.0"))
        .and(header("authorization", format!("Bearer {EXCHANGED_TOKEN}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true,
            "name": PACKAGE_NAME,
            "version": "0.1.0",
            "packageExists": true
        })))
        .expect(1)
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    write_minimal_project(tmp.path());

    let output = spawn_publish(tmp.path(), &server.uri(), &["--dry-run"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    // wiremock's `.expect(1)` panics on Drop if the mock didn't match exactly
    // once with the required body fields, so reaching this point is itself
    // the contract assertion. We additionally verify the process exited
    // cleanly — a stray 400 from the origin (which is what the old
    // `package=None` path produced on a real server) would leave the run in
    // some failure state we'd rather not paper over.
    assert!(
        output.status.success(),
        "lpm publish --dry-run must succeed when LPM_OIDC_TOKEN is set and \
         the mock accepts the exchange\n  exit: {:?}\n  stdout:\n{stdout}\n  stderr:\n{stderr}",
        output.status.code(),
    );

    let received = server.received_requests().await.unwrap();
    let exchange_calls: Vec<_> = received
        .iter()
        .filter(|r| r.method.as_str() == "POST" && r.url.path() == "/api/registry/-/token/oidc")
        .collect();
    assert_eq!(
        exchange_calls.len(),
        1,
        "exactly one OIDC exchange request expected for `lpm publish --dry-run`, got {}",
        exchange_calls.len()
    );

    // Independent decode of the body, in case the partial-match matcher
    // drifts: the request body must literally carry both fields.
    let body: serde_json::Value =
        serde_json::from_slice(&exchange_calls[0].body).expect("exchange body must be JSON");
    assert_eq!(body["token"], SUPPLIED_JWT);
    assert_eq!(
        body["package"], PACKAGE_NAME,
        "publish auto-exchange must include `package` — origin requires it for scope=publish"
    );
    assert!(
        body.get("publicationWaitTimeoutSeconds").is_none(),
        "a publish without --wait must not request a status-only credential"
    );
}

#[tokio::test]
async fn multi_target_dry_run_changes_only_the_resolved_lpm_name() {
    const RESOLVED_NAME: &str = "@lpm.dev/owner.resolved-publish-name";
    const NPM_TOKEN: &str = "npm-preflight-token";
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/registry/-/token/oidc"))
        .and(query_param("scope", "publish"))
        .and(body_partial_json(serde_json::json!({
            "token": SUPPLIED_JWT,
            "package": RESOLVED_NAME,
        })))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({ "token": EXCHANGED_TOKEN })),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/registry/-/package/publish-preflight"))
        .and(query_param("name", RESOLVED_NAME))
        .and(query_param("version", "0.1.0"))
        .and(header("authorization", format!("Bearer {EXCHANGED_TOKEN}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true,
            "name": RESOLVED_NAME,
            "version": "0.1.0",
            "packageExists": false
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/source-package"))
        .and(header("authorization", format!("Bearer {NPM_TOKEN}")))
        .respond_with(ResponseTemplate::new(404))
        .expect(1)
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    write_minimal_project(tmp.path());
    fs::write(
        tmp.path().join("package.json"),
        r#"{"name":"source-package","version":"0.1.0","description":"contract test"}"#,
    )
    .unwrap();
    fs::write(
        tmp.path().join("lpm.json"),
        format!(
            r#"{{"publish":{{"lpm":{{"name":"{RESOLVED_NAME}"}},"npm":{{"registry":"{}"}}}}}}"#,
            server.uri()
        ),
    )
    .unwrap();
    store_custom_registry_token(tmp.path(), &server.uri(), NPM_TOKEN);
    let output = spawn_publish(
        tmp.path(),
        &server.uri(),
        &["--dry-run", "--lpm", "--npm", "--json"],
    );
    assert!(
        output.status.success(),
        "resolved-name dry run failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let targets = json["targets"].as_array().unwrap();
    let lpm_target = targets
        .iter()
        .find(|target| target["registry"] == "lpm")
        .unwrap();
    let npm_target = targets
        .iter()
        .find(|target| target["registry"] == "npm")
        .unwrap();
    assert_eq!(lpm_target["name"], RESOLVED_NAME);
    assert_eq!(npm_target["name"], "source-package");
}

#[tokio::test]
async fn publish_dry_run_surfaces_oidc_failure_for_resolved_lpm_name() {
    const RESOLVED_NAME: &str = "@lpm.dev/owner.denied-name";
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/registry/-/token/oidc"))
        .respond_with(
            ResponseTemplate::new(403)
                .set_body_json(serde_json::json!({"error":"publisher policy denied"})),
        )
        .expect(1)
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    write_minimal_project(tmp.path());
    fs::write(
        tmp.path().join("lpm.json"),
        format!(r#"{{"publish":{{"lpm":{{"name":"{RESOLVED_NAME}"}}}}}}"#),
    )
    .unwrap();
    let output = spawn_publish(tmp.path(), &server.uri(), &["--dry-run", "--json"]);
    assert!(!output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["success"], false);
    assert!(
        json["error"]
            .as_str()
            .is_some_and(|error| error.contains(RESOLVED_NAME))
    );
}

#[tokio::test]
async fn publish_dry_run_human_failure_surfaces_remote_preflight_denial() {
    const RESOLVED_NAME: &str = "@lpm.dev/owner.human-preflight-denied";
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/registry/-/token/oidc"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({ "token": EXCHANGED_TOKEN })),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/registry/-/package/publish-preflight"))
        .and(query_param("name", RESOLVED_NAME))
        .respond_with(
            ResponseTemplate::new(403)
                .set_body_json(serde_json::json!({"error":"version already exists"})),
        )
        .expect(1)
        .mount(&server)
        .await;
    let tmp = tempfile::tempdir().unwrap();
    write_minimal_project(tmp.path());
    fs::write(
        tmp.path().join("lpm.json"),
        format!(r#"{{"publish":{{"lpm":{{"name":"{RESOLVED_NAME}"}}}}}}"#),
    )
    .unwrap();

    let output = spawn_publish(tmp.path(), &server.uri(), &["--dry-run"]);

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).trim().is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(RESOLVED_NAME), "{stderr}");
    assert!(stderr.contains("0.1.0"), "{stderr}");
    assert!(stderr.contains("version already exists"), "{stderr}");
}

#[tokio::test]
async fn publish_dry_run_json_preflight_denial_emits_one_failure_document() {
    const RESOLVED_NAME: &str = "@lpm.dev/owner.preflight-denied";
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/registry/-/token/oidc"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({ "token": EXCHANGED_TOKEN })),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/registry/-/package/publish-preflight"))
        .respond_with(
            ResponseTemplate::new(403)
                .set_body_json(serde_json::json!({"error":"publisher permission denied"})),
        )
        .expect(1)
        .mount(&server)
        .await;
    let tmp = tempfile::tempdir().unwrap();
    write_minimal_project(tmp.path());
    fs::write(
        tmp.path().join("lpm.json"),
        format!(r#"{{"publish":{{"lpm":{{"name":"{RESOLVED_NAME}"}}}}}}"#),
    )
    .unwrap();

    let output = spawn_publish(tmp.path(), &server.uri(), &["--dry-run", "--json"]);

    assert!(!output.status.success());
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout must be exactly one JSON document");
    assert_eq!(json["success"], false);
    assert!(
        json["error"]
            .as_str()
            .is_some_and(|error| error.contains(RESOLVED_NAME))
    );
    assert!(String::from_utf8_lossy(&output.stderr).trim().is_empty());
}

#[tokio::test]
async fn publish_dry_run_surfaces_required_skills_lookup_failure() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/registry/-/token/oidc"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({ "token": EXCHANGED_TOKEN })),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/registry/skills"))
        .and(query_param("name", "owner.publish-oidc-contract"))
        .respond_with(ResponseTemplate::new(503).set_body_string("skills unavailable"))
        .expect(4)
        .mount(&server)
        .await;
    let tmp = tempfile::tempdir().unwrap();
    write_minimal_project(tmp.path());
    write_authored_skill(tmp.path());

    let output = spawn_publish(tmp.path(), &server.uri(), &["--dry-run", "--json"]);

    assert!(!output.status.success());
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout must be one JSON document");
    assert_eq!(json["success"], false);
    assert!(
        json["error"]
            .as_str()
            .is_some_and(|error| error.contains("previously published skills"))
    );
}

#[tokio::test]
async fn first_publish_dry_run_treats_missing_published_skills_as_an_empty_set() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/registry/-/token/oidc"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({ "token": EXCHANGED_TOKEN })),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/registry/skills"))
        .and(query_param("name", "owner.publish-oidc-contract"))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_json(serde_json::json!({ "error": "Package not found" })),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/registry/-/package/publish-preflight"))
        .and(query_param("name", PACKAGE_NAME))
        .and(query_param("version", "0.1.0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true,
            "name": PACKAGE_NAME,
            "version": "0.1.0",
            "packageExists": false
        })))
        .expect(1)
        .mount(&server)
        .await;
    let tmp = tempfile::tempdir().unwrap();
    write_minimal_project(tmp.path());
    write_authored_skill(tmp.path());

    let output = spawn_publish(tmp.path(), &server.uri(), &["--dry-run", "--json"]);

    assert!(
        output.status.success(),
        "first-publish dry run failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["success"], true);
    assert_eq!(json["dry_run"], true);
}

#[tokio::test]
async fn first_publish_with_authored_skills_continues_after_missing_published_skills() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/registry/-/token/oidc"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({ "token": EXCHANGED_TOKEN })),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/registry/skills"))
        .and(query_param("name", "owner.publish-oidc-contract"))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_json(serde_json::json!({ "error": "Package not found" })),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/registry/-/whoami"))
        .and(header("authorization", format!("Bearer {EXCHANGED_TOKEN}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "username": "owner",
            "mfa_enabled": false
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path_regex("/api/registry/.*"))
        .and(header("authorization", format!("Bearer {EXCHANGED_TOKEN}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true,
            "message": "Package published"
        })))
        .expect(1)
        .mount(&server)
        .await;
    let tmp = tempfile::tempdir().unwrap();
    write_minimal_project(tmp.path());
    write_authored_skill(tmp.path());

    let output = spawn_publish(tmp.path(), &server.uri(), &["--yes", "--json"]);

    assert!(
        output.status.success(),
        "first publish failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["success"], true);
    assert_eq!(json["results"][0]["success"], true);
}

#[tokio::test]
async fn publish_wait_uses_the_status_only_oidc_credential() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/registry/-/token/oidc"))
        .and(query_param("scope", "publish"))
        .and(body_partial_json(serde_json::json!({
            "publicationWaitTimeoutSeconds": 10
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "token": EXCHANGED_TOKEN,
            "publicationStatusToken": PUBLICATION_STATUS_TOKEN,
            "publicationStatusExpiresAt": "2099-08-11T12:00:00.000Z"
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/registry/-/whoami"))
        .and(header("authorization", format!("Bearer {EXCHANGED_TOKEN}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "username": "owner",
            "mfa_enabled": false
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path_regex("/api/registry/.*"))
        .and(header("authorization", format!("Bearer {EXCHANGED_TOKEN}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true,
            "publicationStatus": "pending_review",
            "currentLatestVersion": null
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/registry/-/package/publication-status"))
        .and(header(
            "authorization",
            format!("Bearer {PUBLICATION_STATUS_TOKEN}"),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": PACKAGE_NAME,
            "version": "0.1.0",
            "status": "active",
            "reviewStatus": "approved",
            "currentLatestVersion": "0.1.0"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    write_minimal_project(tmp.path());

    let output = spawn_publish(
        tmp.path(),
        &server.uri(),
        &["--yes", "--wait", "--wait-timeout", "10"],
    );

    assert!(
        output.status.success(),
        "OIDC publication wait must use the status credential\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[tokio::test]
async fn publish_check_skips_oidc_exchange() {
    // `--check` is a local-validation surface. Even with LPM as target and
    // LPM_OIDC_TOKEN set, the exchange must NOT fire. Mock asserts the
    // negative: any POST to the OIDC endpoint is unexpected.
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/api/registry/-/token/oidc"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0) // ← contract: this endpoint must NOT be hit
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    write_minimal_project(tmp.path());

    let output = spawn_publish(tmp.path(), &server.uri(), &["--check"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "lpm publish --check must succeed without OIDC\n  exit: {:?}\n  stdout:\n{stdout}\n  stderr:\n{stderr}",
        output.status.code(),
    );

    let received = server.received_requests().await.unwrap();
    let exchange_calls: Vec<_> = received
        .iter()
        .filter(|r| r.method.as_str() == "POST" && r.url.path() == "/api/registry/-/token/oidc")
        .collect();
    assert!(
        exchange_calls.is_empty(),
        "--check must not trigger OIDC exchange, but got {} call(s)",
        exchange_calls.len()
    );
}

#[tokio::test]
async fn publish_check_skips_all_lpm_network_calls_for_skills_packages() {
    // Skills packages exercise an additional pre-publish LPM network call:
    // the skills-staleness lookup (`GET /api/registry/skills?name=...`).
    // The contract is "`--check` is a local-validation surface" — that has
    // to hold even when the package ships skills. Mounted as a catch-all
    // (any method/path) with `.expect(0)`, so any LPM request at all fails.
    let server = MockServer::start().await;

    Mock::given(wiremock::matchers::any())
        .respond_with(ResponseTemplate::new(500))
        .expect(0) // ← contract: zero LPM network calls in --check, period
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();
    write_minimal_project(cwd);

    // Ship a single valid skill so `has_skills && targets_lpm` is true and
    // the skills validation + staleness paths both light up.
    let skills_dir = cwd.join(".lpm").join("skills");
    fs::create_dir_all(&skills_dir).unwrap();
    let skill_body = "---\nname: probe\ndescription: probe skill used to exercise the skills-staleness path during testing\n---\n\nProbe skill body. The skills validator requires at least 100 characters of content past the frontmatter so we pad to satisfy the floor.\n";
    fs::write(skills_dir.join("probe.md"), skill_body).unwrap();

    let output = spawn_publish(cwd, &server.uri(), &["--check"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "lpm publish --check must succeed for a skills package with no network\n  exit: {:?}\n  stdout:\n{stdout}\n  stderr:\n{stderr}",
        output.status.code(),
    );

    let received = server.received_requests().await.unwrap();
    assert!(
        received.is_empty(),
        "--check on a skills package must make zero LPM network calls, got {} request(s):\n{:#?}",
        received.len(),
        received
            .iter()
            .map(|r| (r.method.to_string(), r.url.to_string()))
            .collect::<Vec<_>>(),
    );
}

#[tokio::test]
async fn publish_npm_only_skips_lpm_oidc_exchange() {
    // `--npm` removes LPM from the target set. The LPM exchange endpoint
    // must NOT see a request — that would leak package metadata to lpm.dev
    // for a publish that has nothing to do with lpm.dev.
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/api/registry/-/token/oidc"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0) // ← contract: never hit when LPM isn't a target
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    write_minimal_project(tmp.path());

    // `--dry-run` keeps the test from needing an npm-side mock; the
    // assertion we care about is that the *LPM* exchange wasn't called.
    let output = spawn_publish(tmp.path(), &server.uri(), &["--dry-run", "--npm"]);
    let _stderr = String::from_utf8_lossy(&output.stderr);
    // We don't assert on success here — `--npm --dry-run` may exit non-zero
    // for unrelated npm-side validation reasons. The contract under test is
    // strictly the absence of the LPM exchange call.

    let received = server.received_requests().await.unwrap();
    let exchange_calls: Vec<_> = received
        .iter()
        .filter(|r| r.method.as_str() == "POST" && r.url.path() == "/api/registry/-/token/oidc")
        .collect();
    assert!(
        exchange_calls.is_empty(),
        "--npm-only publish must not trigger LPM OIDC exchange, but got {} call(s)",
        exchange_calls.len()
    );
}
