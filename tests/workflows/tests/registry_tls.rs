//! Workflow tests for `.npmrc` TLS settings on commands that talk to a
//! registry outside a project install, reading or sending: each one must
//! reach a registry whose certificate only `~/.npmrc`'s `cafile=` makes
//! trustworthy, without loading the TLS files of a registry it doesn't
//! contact.

mod support;

use support::TempProject;
use support::auth_state::{SessionSeed, credentials_path, seed_sessions};
use support::mock_registry::{MockRegistry, make_tarball_from_pkg_json, mount_tarball_uploads};
use support::tls_front::TlsFront;
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, Request, ResponseTemplate};

#[tokio::test]
async fn registry_api_reads_trust_the_npmrc_cafile_of_the_registry() {
    let project = TempProject::empty(r#"{"name":"registry-tls","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    mock.with_health().await;
    mock.with_whoami("tls-user", "tls-user@example.com").await;
    mock.with_pool_stats(
        "tls-session-token",
        serde_json::json!({
            "billingPeriod": "2026-11",
            "totalWeightedDownloads": 0,
            "estimatedEarningsCents": 0,
            "packages": []
        }),
    )
    .await;
    mock.with_quality_report(
        "owner.widget",
        serde_json::json!({
            "name": "owner.widget",
            "status": "complete",
            "rulesVersion": 1,
            "score": 50,
            "maxScore": 100,
            "tier": "fair",
            "ecosystem": "js",
            "categories": {},
            "checks": []
        }),
    )
    .await;
    mock.with_package_skills(
        "owner.package",
        vec![serde_json::json!({
            "name": "guide",
            "description": "Use package-specific conventions",
            "rawContent": "---\nname: guide\ndescription: Use package-specific conventions\n---\nFollow the package guide.",
            "sizeBytes": 96,
        })],
    )
    .await;
    let front = TlsFront::start(&mock, project.home());
    let unreadable = project.home().join("missing-npm-ca.pem");
    front.write_user_npmrc(
        project.home(),
        &format!("//registry.npmjs.org/:cafile={}\n", unreadable.display()),
    );

    let failures: Vec<String> = [
        &["--json", "health"][..],
        &["--json", "whoami"][..],
        &["--json", "pool"][..],
        &["--json", "quality", "owner.widget"][..],
        &["skills", "add", "@lpm.dev/owner.package", "--yes"][..],
    ]
    .into_iter()
    .filter_map(|args| {
        let output = support::lpm(&project)
            .env("LPM_TOKEN", "tls-session-token")
            .args(["--registry", &front.url])
            .args(args)
            .output()
            .expect("run lpm");
        (!output.status.success()).then(|| {
            format!(
                "lpm {args:?}\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            )
        })
    })
    .collect();
    assert!(
        failures.is_empty(),
        "every command must reach a registry its .npmrc cafile trusts:\n{}",
        failures.join("\n")
    );
    assert!(project.file_exists(".lpm/skills/owner.package/guide.md"));
}

#[tokio::test]
async fn a_registry_certificate_nothing_trusts_fails_on_the_first_handshake() {
    let project = TempProject::empty(r#"{"name":"registry-tls","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    mock.with_whoami("tls-user", "tls-user@example.com").await;
    let front = TlsFront::start(&mock, project.home());

    let output = support::lpm(&project)
        .env("LPM_TOKEN", "tls-session-token")
        .env("LPM_RETRY_BACKOFF_MS_OVERRIDE", "1")
        .args(["--registry", &front.url, "--json", "whoami"])
        .output()
        .expect("run lpm");

    let rendered = format!(
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(!output.status.success(), "{rendered}");
    assert!(rendered.contains("UnknownIssuer"), "{rendered}");
    assert_eq!(
        front.connections(),
        1,
        "a certificate no configured authority issued can't pass on a retry:\n{rendered}"
    );
}

const SESSION_TOKEN: &str = "tls-session-token";

/// `~/.npmrc` for `project` trusting `front` and naming a `cafile=` for npm's
/// registry that doesn't exist, which only a command contacting npm reads.
fn trust_only_the_front(project: &TempProject, front: &TlsFront) {
    let unreadable = project.home().join("missing-npm-ca.pem");
    front.write_user_npmrc(
        project.home(),
        &format!("//registry.npmjs.org/:cafile={}\n", unreadable.display()),
    );
}

fn signed_in(project: &TempProject, registry_url: &str) {
    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url,
            access_token: Some(SESSION_TOKEN),
            ..Default::default()
        }],
    );
}

fn run(project: &TempProject, front: &TlsFront, args: &[&str]) -> Result<String, String> {
    let output = support::lpm(project)
        .args(["--registry", &front.url])
        .args(args)
        .output()
        .expect("run lpm");
    let rendered = format!(
        "lpm {args:?}\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    if output.status.success() {
        Ok(rendered)
    } else {
        Err(rendered)
    }
}

async fn answer(mock: &MockRegistry, verb: &str, route: &str, body: serde_json::Value) {
    Mock::given(method(verb))
        .and(path(route))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(mock.server())
        .await;
}

#[tokio::test]
async fn lpm_dev_changes_trust_the_npmrc_cafile_of_the_registry() {
    let project = TempProject::empty(r#"{"name":"registry-tls-writes","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let front = TlsFront::start(&mock, project.home());
    trust_only_the_front(&project, &front);
    signed_in(&project, &front.url);
    answer(
        &mock,
        "POST",
        "/api/registry/-/package/unpublish",
        serde_json::json!({ "ok": true, "package": "@lpm.dev/acme.kit", "version": "1.2.3" }),
    )
    .await;
    answer(
        &mock,
        "POST",
        "/api/registry/-/package/deprecate",
        serde_json::json!({
            "ok": true,
            "action": "deprecated",
            "package": "@lpm.dev/acme.kit",
            "version": "1.2.3",
            "changed": 1,
        }),
    )
    .await;
    mock.with_token_rotate(SESSION_TOKEN, SESSION_TOKEN, "2032-01-03T04:05:06Z")
        .await;

    let failures: Vec<String> = [
        &["unpublish", "acme.kit@1.2.3", "--yes", "--json"][..],
        &[
            "deprecate",
            "@lpm.dev/acme.kit@1.2.3",
            "Use 2.0.0",
            "--json",
        ][..],
        &["token-rotate", "--json"][..],
    ]
    .into_iter()
    .filter_map(|args| run(&project, &front, args).err())
    .collect();

    assert!(
        failures.is_empty(),
        "every change must reach a registry its .npmrc cafile trusts:\n{}",
        failures.join("\n")
    );
}

#[tokio::test]
async fn logout_revoke_reaches_the_registry_over_its_npmrc_cafile() {
    let project = TempProject::empty(r#"{"name":"registry-tls-logout","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let front = TlsFront::start(&mock, project.home());
    trust_only_the_front(&project, &front);
    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &front.url,
            access_token: Some(SESSION_TOKEN),
            refresh_token: Some("tls-refresh-token"),
            session_access_expires_at: Some("2030-01-01T00:00:00Z"),
        }],
    );
    mock.with_current_principal(SESSION_TOKEN, "account-1", 1)
        .await;
    mock.with_revoke_token(SESSION_TOKEN).await;

    let output = support::lpm(&project)
        .args(["--registry", &front.url, "--json", "logout", "--revoke"])
        .output()
        .expect("run lpm logout --revoke");

    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("logout prints one JSON document");
    assert_eq!(json["server_revoked"], true, "{json}");
    // The pairing revocation reaches the registry too. It then stops at the
    // vault's response signature: the test signing key is trusted only from
    // a plain-HTTP localhost registry, never from an HTTPS one.
    let errors = json["errors"].to_string();
    assert!(
        !errors.contains("UnknownIssuer") && errors.contains("signing key"),
        "{json}"
    );
}

#[tokio::test]
async fn logout_revoke_refreshes_an_expired_session_over_the_registrys_npmrc_cafile() {
    let project = TempProject::empty(r#"{"name":"registry-tls-logout-refresh","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let front = TlsFront::start(&mock, project.home());
    trust_only_the_front(&project, &front);
    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &front.url,
            access_token: Some("expired-access-token"),
            refresh_token: Some("tls-refresh-token"),
            session_access_expires_at: Some("2020-01-01T00:00:00Z"),
        }],
    );
    mock.with_refresh_expected(
        "tls-refresh-token",
        "refreshed-access-token",
        "rotated-refresh-token",
        "2032-01-01T00:00:00Z",
        1,
    )
    .await;
    mock.with_current_principal("refreshed-access-token", "account-1", 1)
        .await;
    mock.with_revoke_token("refreshed-access-token").await;

    let output = support::lpm(&project)
        .args(["--registry", &front.url, "--json", "logout", "--revoke"])
        .output()
        .expect("run lpm logout --revoke");

    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("logout prints one JSON document");
    assert_eq!(json["server_revoked"], true, "{json}");
    assert_eq!(json["local_cleared"], true, "{json}");
    assert!(!credentials_path(project.home()).exists());
}

#[tokio::test]
async fn logout_revoke_with_a_broken_npmrc_cafile_reports_it_and_still_clears_the_session() {
    let project = TempProject::empty(r#"{"name":"registry-tls-logout-broken","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    std::fs::write(
        project.home().join(".npmrc"),
        format!(
            "cafile={}\n",
            project.home().join("missing-ca.pem").display()
        ),
    )
    .unwrap();
    signed_in(&project, &mock.url());

    let output = support::lpm(&project)
        .args(["--registry", &mock.url(), "--json", "logout", "--revoke"])
        .output()
        .expect("run lpm logout --revoke");

    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("logout prints one JSON document");
    assert_eq!(output.status.code(), Some(1), "{json}");
    assert_eq!(json["server_revoked"], false, "{json}");
    assert_eq!(json["local_cleared"], true, "{json}");
    let errors = json["errors"].as_array().expect("errors array");
    assert!(
        errors.len() == 1
            && errors[0]
                .as_str()
                .is_some_and(|error| error.starts_with("session revocation")
                    && error.contains("missing-ca.pem")),
        "{json}"
    );
    assert!(!credentials_path(project.home()).exists());
    assert!(
        mock.server().received_requests().await.unwrap().is_empty(),
        "nothing may be sent without the .npmrc trust settings"
    );
}

#[tokio::test]
async fn a_browser_approval_waits_on_the_registry_over_its_npmrc_cafile() {
    let project = TempProject::empty(r#"{"name":"registry-tls-approval","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let front = TlsFront::start(&mock, project.home());
    trust_only_the_front(&project, &front);
    signed_in(&project, &front.url);
    let base = front.url.clone();
    Mock::given(method("POST"))
        .and(path("/api/registry/-/package/unpublish"))
        .respond_with(move |request: &Request| {
            if request.headers.get("x-lpm-approval").is_some() {
                return ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "ok": true,
                    "package": "@lpm.dev/acme.kit",
                    "version": "1.2.3",
                }));
            }
            ResponseTemplate::new(401).set_body_json(serde_json::json!({
                "error": "Approve this change in your browser with your passkey.",
                "code": "OTP_REQUIRED",
                "otp": false,
                "passkey": true,
                "authUrl": format!("{base}/cli/approve/approval-1"),
                "doneUrl": format!("{base}/api/auth/cli-approvals/approval-1/poll-secret"),
            }))
        })
        .mount(mock.server())
        .await;
    answer(
        &mock,
        "GET",
        "/api/auth/cli-approvals/approval-1/poll-secret",
        serde_json::json!({ "token": "approval-token" }),
    )
    .await;

    let output = run(&project, &front, &["unpublish", "acme.kit@1.2.3", "--yes"]);

    assert!(
        output.is_ok(),
        "the approval's polling must trust the registry's .npmrc cafile:\n{}",
        output.unwrap_or_else(|failure| failure)
    );
}

#[tokio::test]
async fn publish_reaches_lpm_dev_and_an_npm_registry_over_their_npmrc_cafiles() {
    let project = TempProject::empty(
        r#"{"name":"@lpm.dev/testuser.tls-publish","version":"1.0.0","main":"index.js","license":"MIT"}"#,
    );
    project.write_file("index.js", "module.exports = {}");
    let mock = MockRegistry::start().await;
    let front = TlsFront::start(&mock, project.home());
    project.write_file(
        "lpm.json",
        &format!(
            r#"{{"publish":{{"npm":{{"name":"tls-publish","registry":"{}","access":"public"}}}}}}"#,
            front.url
        ),
    );
    trust_only_the_front(&project, &front);
    answer(
        &mock,
        "GET",
        "/api/registry/-/whoami",
        serde_json::json!({
            "username": "test@example.com",
            "profile_username": "testuser",
            "mfa_enabled": false,
        }),
    )
    .await;
    answer(
        &mock,
        "GET",
        "/api/registry/-/package/publish-preflight",
        serde_json::json!({
            "success": true,
            "name": "@lpm.dev/testuser.tls-publish",
            "version": "1.0.0",
            "packageExists": false,
        }),
    )
    .await;
    mount_tarball_uploads(mock.server()).await;
    Mock::given(method("PUT"))
        .and(path_regex("^/(api/registry/|tls-publish)"))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "success": true,
        })))
        .mount(mock.server())
        .await;
    let login = support::lpm(&project)
        .args([
            "--json",
            "login",
            "--login-registry",
            &front.url,
            "--token",
            "npm-token",
        ])
        .output()
        .expect("store the npm registry's token");
    assert!(login.status.success(), "{login:?}");

    let output = run(
        &project,
        &front,
        &[
            "--json",
            "publish",
            "--yes",
            "--token",
            "lpm-token",
            "--lpm",
            "--npm",
        ],
    );

    let rendered = output.unwrap_or_else(|failure| panic!("{failure}"));
    let puts: Vec<String> = mock
        .server()
        .received_requests()
        .await
        .expect("record requests")
        .into_iter()
        .filter(|request| request.method.as_str() == "PUT")
        .map(|request| request.url.path().to_string())
        .collect();
    assert!(
        puts.iter().any(|route| route.starts_with("/api/registry/"))
            && puts.iter().any(|route| route.starts_with("/tls-publish")),
        "both targets must publish through the trusted front: {puts:?}\n{rendered}"
    );
}

#[tokio::test]
async fn stage_publish_reaches_the_npm_registry_over_its_npmrc_cafile() {
    let project = TempProject::empty(
        r#"{"name":"@lpm.dev/testuser.tls-staged","version":"1.0.0","main":"index.js","license":"MIT"}"#,
    );
    project.write_file("index.js", "module.exports = {}");
    project.write_file("lpm.json", r#"{"publish":{"npm":{"name":"tls-staged"}}}"#);
    let mock = MockRegistry::start().await;
    let front = TlsFront::start(&mock, project.home());
    trust_only_the_front(&project, &front);
    answer(
        &mock,
        "GET",
        "/tls-staged",
        serde_json::json!({ "name": "tls-staged", "versions": { "0.9.0": {} } }),
    )
    .await;
    answer(
        &mock,
        "POST",
        "/-/stage/package/tls-staged",
        serde_json::json!({ "stageId": "11111111-1111-4111-8111-111111111111" }),
    )
    .await;

    let output = support::lpm(&project)
        .env("NPM_TOKEN", "stage-token")
        .args([
            "--json",
            "stage",
            "publish",
            "--yes",
            "--npm-registry",
            &front.url,
        ])
        .output()
        .expect("run lpm stage publish");

    assert!(
        output.status.success(),
        "stage publish must trust the npm registry's .npmrc cafile\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[tokio::test]
async fn an_npm_publish_redirect_trusts_the_npmrc_cafile_of_the_registry_it_reaches() {
    let project = TempProject::empty(
        r#"{"name":"@lpm.dev/testuser.tls-redirect","version":"1.0.0","main":"index.js","license":"MIT"}"#,
    );
    project.write_file("index.js", "module.exports = {}");
    let mock = MockRegistry::start().await;
    let ca_dirs = [project.home().join("ca-a"), project.home().join("ca-b")];
    for dir in &ca_dirs {
        std::fs::create_dir_all(dir).unwrap();
    }
    // Two registries, each signed by a CA of its own that only its own
    // per-origin cafile trusts.
    let publishing = TlsFront::start(&mock, &ca_dirs[0]);
    let redirected = TlsFront::start(&mock, &ca_dirs[1]);
    std::fs::write(
        project.home().join(".npmrc"),
        format!(
            "{}{}",
            publishing.per_origin_cafile_line(),
            redirected.per_origin_cafile_line()
        ),
    )
    .unwrap();
    project.write_file(
        "lpm.json",
        &format!(
            r#"{{"publish":{{"npm":{{"name":"tls-redirect","registry":"{}","access":"public"}}}}}}"#,
            publishing.url
        ),
    );
    Mock::given(method("GET"))
        .and(path("/tls-redirect"))
        .respond_with(ResponseTemplate::new(404))
        .mount(mock.server())
        .await;
    Mock::given(method("PUT"))
        .and(path("/tls-redirect"))
        .respond_with(ResponseTemplate::new(303).insert_header(
            "location",
            format!("{}/-/published/tls-redirect", redirected.url),
        ))
        .mount(mock.server())
        .await;
    answer(
        &mock,
        "GET",
        "/-/published/tls-redirect",
        serde_json::json!({ "ok": true }),
    )
    .await;
    let login = support::lpm(&project)
        .args([
            "--json",
            "login",
            "--login-registry",
            &publishing.url,
            "--token",
            "npm-token",
        ])
        .output()
        .expect("store the npm registry's token");
    assert!(login.status.success(), "{login:?}");

    let output = support::lpm(&project)
        .args(["--json", "publish", "--yes", "--npm"])
        .output()
        .expect("run lpm publish");

    assert!(
        output.status.success() && redirected.connections() > 0,
        "the redirect must reach its registry over that registry's own cafile\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[tokio::test]
async fn an_expired_session_refreshes_over_the_registrys_npmrc_cafile() {
    let project = TempProject::empty(r#"{"name":"registry-tls-refresh","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let front = TlsFront::start(&mock, project.home());
    trust_only_the_front(&project, &front);
    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &front.url,
            access_token: Some("expired-access-token"),
            refresh_token: Some("tls-refresh-token"),
            session_access_expires_at: Some("2020-01-01T00:00:00Z"),
        }],
    );
    mock.with_refresh(
        "tls-refresh-token",
        "refreshed-access-token",
        "rotated-refresh-token",
        "2032-01-01T00:00:00Z",
    )
    .await;
    mock.with_whoami("tls-user", "tls-user@example.com").await;

    let output = run(&project, &front, &["--json", "whoami"]);

    let refreshes = mock
        .server()
        .received_requests()
        .await
        .expect("record requests")
        .iter()
        .filter(|request| request.url.path() == "/api/cli/refresh")
        .count();
    assert!(
        output.is_ok() && refreshes == 1,
        "the refresh must trust the registry's .npmrc cafile ({refreshes} refresh requests reached it):\n{}",
        output.unwrap_or_else(|failure| failure)
    );
}

#[tokio::test]
async fn commands_that_send_nothing_ignore_a_broken_npmrc_tls_setting() {
    let project = TempProject::empty(
        r#"{"name":"@lpm.dev/testuser.tls-check","version":"1.0.0","main":"index.js","license":"MIT"}"#,
    );
    project.write_file("index.js", "module.exports = {}");
    project.write_file("lpm.json", r#"{"publish":{"npm":{"name":"tls-check"}}}"#);
    std::fs::write(
        project.home().join(".npmrc"),
        format!(
            "cafile={}\n",
            project.home().join("missing-ca.pem").display()
        ),
    )
    .unwrap();

    let failures: Vec<String> = [
        &["publish", "--check", "--npm"][..],
        &["--json", "logout", "--revoke"][..],
    ]
    .into_iter()
    .filter_map(|args| {
        let output = support::lpm(&project).args(args).output().expect("run lpm");
        (!output.status.success()).then(|| {
            format!(
                "lpm {args:?}\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            )
        })
    })
    .collect();
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[tokio::test]
async fn a_stage_download_redirect_trusts_the_npmrc_cafile_of_the_host_it_reaches() {
    let project = TempProject::empty(r#"{"name":"registry-tls-stage-download","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let ca_dirs = [project.home().join("ca-a"), project.home().join("ca-b")];
    for dir in &ca_dirs {
        std::fs::create_dir_all(dir).unwrap();
    }
    let registry = TlsFront::start(&mock, &ca_dirs[0]);
    let storage = TlsFront::start(&mock, &ca_dirs[1]);
    std::fs::write(
        project.home().join(".npmrc"),
        format!(
            "{}{}",
            registry.per_origin_cafile_line(),
            storage.per_origin_cafile_line()
        ),
    )
    .unwrap();
    let stage_id = "123e4567-e89b-12d3-a456-426614174000";
    Mock::given(method("GET"))
        .and(path(format!("/-/stage/{stage_id}/tarball")))
        .respond_with(
            ResponseTemplate::new(302)
                .insert_header("location", format!("{}/storage/staged.tgz", storage.url)),
        )
        .mount(mock.server())
        .await;
    Mock::given(method("GET"))
        .and(path("/storage/staged.tgz"))
        .respond_with(
            ResponseTemplate::new(200).set_body_bytes(make_tarball_from_pkg_json(
                serde_json::json!({ "name": "tls-staged", "version": "1.0.0" }),
                &[],
            )),
        )
        .mount(mock.server())
        .await;

    let output = support::lpm(&project)
        .env("NPM_TOKEN", "stage-token")
        .args([
            "--json",
            "stage",
            "download",
            stage_id,
            "--npm-registry",
            &registry.url,
        ])
        .output()
        .expect("run lpm stage download");

    assert!(
        output.status.success() && storage.connections() > 0,
        "the redirect must reach storage over its own cafile\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[tokio::test]
async fn an_unchanged_install_restores_a_recorded_skill_over_the_registrys_npmrc_cafile() {
    let project = TempProject::empty(r#"{"name":"registry-tls-skills","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let front = TlsFront::start(&mock, project.home());
    front.write_user_npmrc(project.home(), "");
    run(&project, &front, &["install"]).expect("the cold install reaches the front");
    project.write_file(
        "lpm-sources.json",
        &serde_json::json!({
            "schemaVersion": 1,
            "packages": {"@lpm.dev/owner.widget": {
                "version": "1.4.0",
                "files": {},
                "skills": "owner.widget",
            }},
        })
        .to_string(),
    );
    let content = "---\nname: widget-guide\ndescription: Use the widget\n---\nRender it.";
    mock.with_package_skills_for_version_expected(
        "owner.widget",
        "1.4.0",
        vec![serde_json::json!({
            "name": "widget-guide",
            "description": "Use the widget",
            "sizeBytes": content.len(),
            "rawContent": content,
        })],
        1,
    )
    .await;

    let output = run(&project, &front, &["--json", "install"]).expect("unchanged install");

    assert!(output.contains("\"up_to_date\": true"), "{output}");
    assert!(
        project.file_exists(".lpm/skills/owner.widget/widget-guide.md"),
        "the skill comes over the registry's .npmrc trust:\n{output}"
    );
}
