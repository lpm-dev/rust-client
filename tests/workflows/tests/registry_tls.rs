//! Workflow tests for `.npmrc` TLS settings on commands that talk to a
//! registry outside a project install, reading or sending: each one must
//! reach a registry whose certificate only `~/.npmrc`'s `cafile=` makes
//! trustworthy, without loading the TLS files of a registry it doesn't
//! contact.

mod support;

use support::TempProject;
use support::auth_state::{SessionSeed, seed_sessions};
use support::mock_registry::{MockRegistry, mount_tarball_uploads};
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
