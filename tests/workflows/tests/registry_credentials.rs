mod support;

use base64::Engine as _;
use std::process::Output;
use support::mock_registry::{MockRegistry, compute_integrity, make_tarball};
use support::{TempProject, lpm_with_registry};
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

const PACKAGE: &str = "credential-fixture";
const SECRET: &str = "disposable-registry-password";

fn project() -> TempProject {
    let project = TempProject::empty(
        r#"{"name":"credential-fixture","version":"1.0.0","main":"index.js","license":"MIT"}"#,
    );
    project.write_file("index.js", "module.exports = 42\n");
    project
}

fn command(project: &TempProject, registry: &MockRegistry) -> assert_cmd::Command {
    let mut command = lpm_with_registry(project, &registry.url());
    command
        .env_remove("LPM_NPM_ROUTE")
        .env("NPM_CONFIG_USERCONFIG", project.home().join(".npmrc"))
        .env(
            "NPM_CONFIG_GLOBALCONFIG",
            project.home().join("global.npmrc"),
        );
    command
}

fn npmrc(project: &TempProject, text: &str) {
    project.write_file(".npmrc", text);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            project.path().join(".npmrc"),
            std::fs::Permissions::from_mode(0o600),
        )
        .expect("restrict npmrc permissions");
    }
}

fn scoped_auth(registry: &MockRegistry, credential: &str) -> String {
    let url = registry.url();
    let host = url.strip_prefix("http://").unwrap();
    format!("registry={url}/a/\n//{host}/a/:{credential}\n")
}

fn assert_no_secret(output: &Output, secret: &str) {
    for bytes in [&output.stdout, &output.stderr] {
        let text = String::from_utf8_lossy(bytes);
        assert!(
            !text.contains(secret),
            "credential appeared in output: {text}"
        );
    }
}

async fn mount_package(registry: &MockRegistry) {
    let tarball = make_tarball(PACKAGE, "1.0.0");
    let metadata = serde_json::json!({
        "name": PACKAGE,
        "dist-tags": { "latest": "1.0.0" },
        "versions": { "1.0.0": {
            "name": PACKAGE,
            "version": "1.0.0",
            "dist": {
                "tarball": format!("{}/a/-/fixture.tgz", registry.url()),
                "integrity": compute_integrity(&tarball)
            }
        }}
    });
    Mock::given(method("GET"))
        .and(path(format!("/a/{PACKAGE}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(metadata))
        .mount(registry.server())
        .await;
    Mock::given(method("GET"))
        .and(path("/a/-/fixture.tgz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(tarball))
        .mount(registry.server())
        .await;
}

fn read_command(
    project: &TempProject,
    registry: &MockRegistry,
    operation: &str,
) -> assert_cmd::Command {
    let mut command = command(project, registry);
    command.args([operation, PACKAGE]);
    if operation == "add" {
        command.args([
            "--path",
            "copied",
            "--yes",
            "--no-skills",
            "--no-editor-setup",
        ]);
    }
    command
}

#[tokio::test]
async fn registry_url_password_is_refused_before_output_network_or_lockfile_changes() {
    let registry = MockRegistry::start().await;
    mount_package(&registry).await;
    let project = project();
    let manifest = project.read_file("package.json");
    let url = registry
        .url()
        .replacen("http://", &format!("http://user:{SECRET}@"), 1);
    npmrc(&project, &format!("registry={url}/a/\n"));

    let output = read_command(&project, &registry, "install")
        .args(["--json", "--verbose"])
        .output()
        .unwrap();

    assert_no_secret(&output, SECRET);
    assert!(
        !output.status.success(),
        "credential-bearing registry URL must fail"
    );
    assert!(!project.file_exists("lpm.lock"));
    assert!(!project.file_exists("lpm.lockb"));
    assert_eq!(project.read_file("package.json"), manifest);
    assert!(
        registry
            .server()
            .received_requests()
            .await
            .unwrap()
            .is_empty()
    );
    let message = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        message.contains("registry-scoped"),
        "missing repair guidance: {message}"
    );

    npmrc(
        &project,
        &scoped_auth(&registry, &format!("_authToken={SECRET}")),
    );
    let output = read_command(&project, &registry, "install")
        .arg("--json")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_no_secret(&output, SECRET);
    assert!(!project.read_file("lpm.lock").contains(SECRET));
    command(&project, &registry)
        .args(["install", "--frozen-lockfile", "--json"])
        .assert()
        .success();
}

#[tokio::test]
async fn scoped_and_explicit_registry_urls_refuse_encoded_and_username_only_credentials() {
    for userinfo in ["disposable-user", "user:p%40ssword", ":disposable-password"] {
        for source in ["default", "scope", "flag"] {
            let registry = MockRegistry::start().await;
            let project = project();
            let manifest = project.read_file("package.json");
            let url = registry
                .url()
                .replacen("http://", &format!("http://{userinfo}@"), 1);
            let mut command = command(&project, &registry);
            match source {
                "scope" => {
                    npmrc(&project, &format!("@private:registry={url}/a/\n"));
                    command.args(["install", "@private/fixture"]);
                }
                "flag" => {
                    command.args(["install", "@lpm.dev/owner.fixture", "--registry", &url]);
                }
                _ => {
                    npmrc(&project, &format!("registry={url}/a/\n"));
                    command.args(["install", PACKAGE]);
                }
            }
            let output = command.args(["--json", "--verbose"]).output().unwrap();
            assert!(
                !output.status.success(),
                "accepted {source} URL credentials"
            );
            assert_no_secret(&output, userinfo);
            assert!(
                registry
                    .server()
                    .received_requests()
                    .await
                    .unwrap()
                    .is_empty()
            );
            assert_eq!(project.read_file("package.json"), manifest);
            assert!(!project.file_exists("lpm.lock"));
        }
    }
}

#[tokio::test]
async fn read_commands_refuse_registry_url_credentials_before_redirects() {
    for operation in ["info", "add", "download", "search"] {
        let registry = MockRegistry::start().await;
        let project = project();
        let url = registry
            .url()
            .replacen("http://", &format!("http://user:{SECRET}@"), 1);
        npmrc(&project, &format!("registry={url}/a/\n"));
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(302).insert_header("location", "/b/capture"))
            .mount(registry.server())
            .await;

        let output = read_command(&project, &registry, operation)
            .arg("--json")
            .output()
            .unwrap();

        assert!(!output.status.success());
        assert_no_secret(&output, SECRET);
        assert!(
            registry
                .server()
                .received_requests()
                .await
                .unwrap()
                .is_empty(),
            "{operation} sent an implicit URL credential"
        );
    }
}

#[cfg(unix)]
#[tokio::test]
async fn readable_npmrc_cannot_supply_implicit_url_credentials() {
    use std::os::unix::fs::PermissionsExt;
    let registry = MockRegistry::start().await;
    mount_package(&registry).await;
    let project = project();
    let url = registry
        .url()
        .replacen("http://", &format!("http://user:{SECRET}@"), 1);
    npmrc(&project, &format!("registry={url}/a/\n"));
    std::fs::set_permissions(
        project.path().join(".npmrc"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();

    let output = read_command(&project, &registry, "info")
        .arg("--json")
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert_no_secret(&output, SECRET);
    assert!(
        registry
            .server()
            .received_requests()
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn read_errors_redact_reflected_bearer_credentials_in_terminal_and_json() {
    for operation in ["info", "install", "add", "download", "search"] {
        for json in [false, true] {
            let registry = MockRegistry::start().await;
            let project = project();
            npmrc(
                &project,
                &scoped_auth(&registry, &format!("_authToken={SECRET}")),
            );
            Mock::given(method("GET"))
                .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
                    "error": format!("permission denied for Bearer {SECRET}")
                })))
                .mount(registry.server())
                .await;
            let mut command = read_command(&project, &registry, operation);
            if json {
                command.arg("--json");
            }
            let output = command.output().unwrap();
            assert!(!output.status.success());
            assert_no_secret(&output, SECRET);
            let message = format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(
                message.contains("permission denied"),
                "lost useful error context: {message}"
            );
        }
    }
}

#[tokio::test]
async fn read_errors_redact_encoded_and_decoded_basic_credentials() {
    let encoded = base64::engine::general_purpose::STANDARD.encode(format!("user:{SECRET}"));
    for status in [400, 403, 404, 500] {
        let registry = MockRegistry::start().await;
        let project = project();
        npmrc(
            &project,
            &scoped_auth(&registry, &format!("_auth={encoded}")),
        );
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(status).set_body_json(serde_json::json!({
                    "error": format!("denied Basic {encoded}, user:{SECRET}, password={SECRET}")
                })),
            )
            .mount(registry.server())
            .await;
        let output = read_command(&project, &registry, "info")
            .arg("--json")
            .env("LPM_RETRY_BACKOFF_MS_OVERRIDE", "0")
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert_no_secret(&output, SECRET);
        assert_no_secret(&output, &encoded);
    }
}

fn login(project: &TempProject, registry: &MockRegistry, url: &str, token: &str) {
    command(project, registry)
        .args(["login", "--login-registry", url, "--token", token, "--json"])
        .assert()
        .success();
}

#[tokio::test]
async fn publish_redirects_keep_credentials_and_body_within_registry_path() {
    for status in [301, 302, 303, 307, 308] {
        for npm in [false, true] {
            let registry = MockRegistry::start().await;
            let project = project();
            let base = format!("{}/a/", registry.url());
            login(&project, &registry, &base, SECRET);
            login(
                &project,
                &registry,
                &format!("{}/b/", registry.url()),
                "other-registry-token",
            );
            Mock::given(method("PUT"))
                .and(path(format!("/a/{PACKAGE}")))
                .respond_with(ResponseTemplate::new(status).insert_header("location", "/b/capture"))
                .mount(registry.server())
                .await;
            Mock::given(path("/b/capture"))
                .respond_with(
                    ResponseTemplate::new(201).set_body_json(serde_json::json!({"ok": true})),
                )
                .mount(registry.server())
                .await;
            let mut command = command(&project, &registry);
            command.args(["publish", "--yes", "--ignore-scripts", "--json"]);
            if npm {
                project.write_file(
                    "lpm.json",
                    &serde_json::json!({"publish":{"npm":{"registry":base}}}).to_string(),
                );
                command.arg("--npm");
            } else {
                command.args(["--publish-registry", &base]);
            }
            let output = command.output().unwrap();
            assert_no_secret(&output, SECRET);
            let requests = registry.server().received_requests().await.unwrap();
            assert!(
                requests
                    .iter()
                    .any(|request| request.method.as_str() == "PUT"
                        && request.url.path() == format!("/a/{PACKAGE}"))
            );
            let redirected: Vec<_> = requests
                .iter()
                .filter(|request| request.url.path() == "/b/capture")
                .collect();
            if status == 303 {
                assert!(output.status.success());
                assert_eq!(redirected.len(), 1);
                assert_eq!(redirected[0].method.as_str(), "GET");
                assert!(redirected[0].headers.get("authorization").is_none());
                assert!(redirected[0].body.is_empty());
            } else {
                assert!(!output.status.success());
                assert!(
                    redirected.is_empty(),
                    "package body escaped registry path on status {status}"
                );
            }
        }
    }
}

#[tokio::test]
async fn custom_publish_reuses_login_across_equivalent_trailing_slash_spellings() {
    for (login_suffix, publish_suffix) in [("/a/", "/a"), ("/a", "/a/")] {
        let registry = MockRegistry::start().await;
        let project = project();
        login(
            &project,
            &registry,
            &format!("{}{login_suffix}", registry.url()),
            SECRET,
        );
        Mock::given(method("PUT"))
            .and(path(format!("/a/{PACKAGE}")))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({"ok": true})))
            .mount(registry.server())
            .await;

        let output = command(&project, &registry)
            .args([
                "publish",
                "--publish-registry",
                &format!("{}{publish_suffix}", registry.url()),
                "--yes",
                "--ignore-scripts",
                "--json",
            ])
            .output()
            .unwrap();

        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert_no_secret(&output, SECRET);
        let requests = registry.server().received_requests().await.unwrap();
        assert!(
            requests
                .iter()
                .any(|request| request.method.as_str() == "PUT")
        );
        for request in requests {
            assert_eq!(
                request.headers.get("authorization").unwrap(),
                &format!("Bearer {SECRET}")
            );
        }
    }
}

#[tokio::test]
async fn custom_publish_never_reuses_a_login_for_another_registry_path() {
    let registry = MockRegistry::start().await;
    let project = project();
    login(
        &project,
        &registry,
        &format!("{}/a/", registry.url()),
        SECRET,
    );
    let output = command(&project, &registry)
        .args([
            "publish",
            "--publish-registry",
            &format!("{}/a-other/", registry.url()),
            "--yes",
            "--ignore-scripts",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_no_secret(&output, SECRET);
    assert!(
        registry
            .server()
            .received_requests()
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn publish_redirect_inside_registry_path_preserves_credentials_and_package_body() {
    let registry = MockRegistry::start().await;
    let project = project();
    let base = format!("{}/a/", registry.url());
    login(&project, &registry, &base, SECRET);
    Mock::given(method("PUT"))
        .and(path(format!("/a/{PACKAGE}")))
        .respond_with(ResponseTemplate::new(307).insert_header("location", "/a/uploads/fixture"))
        .mount(registry.server())
        .await;
    Mock::given(method("PUT"))
        .and(path("/a/uploads/fixture"))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({"ok":true})))
        .mount(registry.server())
        .await;
    command(&project, &registry)
        .args([
            "publish",
            "--publish-registry",
            &base,
            "--yes",
            "--ignore-scripts",
            "--json",
        ])
        .assert()
        .success();
    let requests = registry.server().received_requests().await.unwrap();
    let uploads: Vec<_> = requests
        .iter()
        .filter(|request| request.method.as_str() == "PUT")
        .collect();
    assert_eq!(uploads.len(), 2);
    assert!(!uploads[0].body.is_empty());
    assert_eq!(uploads[0].body, uploads[1].body);
    assert_eq!(
        uploads[1].headers.get("authorization").unwrap(),
        &format!("Bearer {SECRET}")
    );
}
