use super::*;
use std::time::{Duration, Instant};

#[tokio::test]
async fn swift_registry_normalizes_a_trailing_slash() {
    let mock = MockRegistry::start().await;
    mount_swift_package(&mock).await;
    let project = swift_project();
    let mut command = lpm_with_registry(&project, &format!("{}/", mock.url()));
    configure_fake_swift(&mut command, &project, &[], 0);
    let output = command.args(["swift-registry", "--json"]).output().unwrap();
    assert!(output.status.success(), "{}", combined_output(&output));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        json["registry_url"],
        format!("{}/api/swift-registry", mock.url())
    );
}

#[tokio::test]
async fn swift_registry_uppercase_https_still_configures_authentication() {
    let mock = MockRegistry::start().await;
    let registry_url = mock.url().replacen("http://", "HTTPS://", 1);
    let project = swift_project();
    let capture = project.path().join("login.json");
    let mut command = lpm_with_registry(&project, &registry_url);
    configure_fake_swift(&mut command, &project, &[], 0);
    configure_fake_swift_login_capture(&mut command, &capture);
    let output = command
        .env("LPM_TEST_SWIFT_LOGIN_EXIT_CODE", "7")
        .args(["swift-registry", "--token", "session-token", "--json"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let args: Vec<String> =
        serde_json::from_slice(&std::fs::read(&capture).unwrap_or_else(|_| {
            panic!("authentication was skipped: {}", combined_output(&output))
        }))
        .unwrap();
    assert_eq!(
        args[0],
        format!(
            "{}/api/swift-registry",
            registry_url.replacen("HTTPS://", "https://", 1)
        )
    );
}

#[tokio::test]
async fn swift_registry_rejects_query_and_fragment_before_scope_changes() {
    let mock = MockRegistry::start().await;
    for suffix in ["?mode=registry", "#registry"] {
        let project = swift_project();
        let capture = project.path().join("commands.log");
        let mut command = lpm_with_registry(&project, &format!("{}{suffix}", mock.url()));
        configure_fake_swift(&mut command, &project, &[], 0);
        configure_fake_swift_command_log(&mut command, &capture);
        let output = command.args(["swift-registry", "--json"]).output().unwrap();
        assert!(!output.status.success(), "{}", combined_output(&output));
        assert!(!capture.exists(), "invalid base URL invoked SwiftPM");
        assert!(!project.path().join(".swiftpm").exists());
    }
}

#[tokio::test]
async fn swift_registry_json_does_not_break_a_subprocess_stderr_writer() {
    let mock = MockRegistry::start().await;
    mount_swift_package(&mock).await;
    let project = swift_project();
    let mut command = lpm_with_registry(&project, &mock.url());
    configure_fake_swift(&mut command, &project, &[], 0);
    let output = command
        .env("LPM_TEST_SWIFT_SET_STDERR", "1")
        .args(["swift-registry", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", combined_output(&output));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["success"], true);
    assert!(output.stderr.is_empty(), "{output:?}");
}

#[tokio::test]
async fn swift_registry_http_json_reports_unencrypted_transport() {
    let mock = MockRegistry::start().await;
    mount_swift_package(&mock).await;
    let project = swift_project();
    let mut command = lpm_with_registry(&project, &mock.url());
    configure_fake_swift(&mut command, &project, &[], 0);
    let output = command.args(["swift-registry", "--json"]).output().unwrap();
    assert!(output.status.success(), "{}", combined_output(&output));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["https"], false);
    assert_eq!(json["trust_anchor"], "insecure_http");
    assert_eq!(json["authentication_outcome"], "skipped_http");
    insta::assert_json_snapshot!("swift_registry_http_setup", json, {
        ".registry_url" => "[registry]/api/swift-registry"
    });
}

#[tokio::test]
async fn swift_registry_stalled_certificate_headers_fail_within_the_deadline() {
    let mock = MockRegistry::start().await;
    let cert = rcgen::generate_simple_self_signed(vec!["lpm.dev".into()])
        .unwrap()
        .cert
        .der()
        .to_vec();
    Mock::given(method("GET"))
        .and(path("/api/swift-registry/certificate"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_bytes(cert.clone())
                .set_delay(Duration::from_secs(40)),
        )
        .mount(mock.server())
        .await;
    let project = swift_project();
    configure_existing_registry(&project, &mock.url(), &cert);
    let cert_path = project
        .home()
        .join(".swiftpm/security/trusted-root-certs/lpm.der");
    let mut command = lpm_with_registry(&project, &mock.url());
    configure_fake_swift(&mut command, &project, &[], 0);
    let start = Instant::now();
    let output = command
        .timeout(Duration::from_secs(45))
        .args(["swift-registry", "--json", "--force"])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "stalled fetch unexpectedly succeeded"
    );
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["success"], false);
    assert!(
        json["error"].as_str().unwrap().contains("timed out"),
        "{json}"
    );
    assert!(start.elapsed() < Duration::from_secs(37));
    assert_eq!(std::fs::read(cert_path).unwrap(), cert);
}

#[tokio::test]
async fn swift_registry_stalled_certificate_body_fails_within_the_deadline() {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0; 4096];
        assert!(stream.read(&mut request).unwrap() > 0);
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\nx")
            .unwrap();
        let mut end = [0; 1];
        stream
            .set_read_timeout(Some(Duration::from_secs(40)))
            .unwrap();
        let _ = stream.read(&mut end);
    });
    let project = swift_project();
    let cert = rcgen::generate_simple_self_signed(vec!["lpm.dev".into()])
        .unwrap()
        .cert
        .der()
        .to_vec();
    configure_existing_registry(&project, &base_url, &cert);
    let cert_path = project
        .home()
        .join(".swiftpm/security/trusted-root-certs/lpm.der");
    let mut command = lpm_with_registry(&project, &base_url);
    configure_fake_swift(&mut command, &project, &[], 0);
    let start = Instant::now();
    let output = command
        .timeout(Duration::from_secs(45))
        .args(["swift-registry", "--json", "--force"])
        .output()
        .unwrap();
    server.join().unwrap();
    assert!(!output.status.success());
    assert!(
        start.elapsed() < Duration::from_secs(37),
        "fetch had no deadline"
    );
    assert_eq!(std::fs::read(cert_path).unwrap(), cert);
}

#[tokio::test]
async fn xcode_registry_scopes_use_the_same_normalized_url() {
    let mock = MockRegistry::start().await;
    let cert = mount_swift_package(&mock).await;
    Mock::given(wiremock::matchers::path_regex(r"^//"))
        .respond_with(|request: &wiremock::Request| {
            let mut location = format!("/{}", request.url.path().trim_start_matches('/'));
            if let Some(query) = request.url.query() {
                location.push('?');
                location.push_str(query);
            }
            ResponseTemplate::new(307).insert_header("Location", location.as_str())
        })
        .mount(mock.server())
        .await;
    let project = TempProject::empty(r#"{"name":"xcode-app","version":"1.0.0"}"#);
    write_xcode_project(&project, "", "MyApp");
    configure_existing_registry(&project, &mock.url(), &cert);
    let mut command = lpm_with_registry(&project, &format!("{}/", mock.url()));
    configure_fake_swift(&mut command, &project, &["unused"], 0);
    command
        .args(["install", "--yes", SWIFT_PACKAGE])
        .assert()
        .success();
    let global: serde_json::Value = serde_json::from_slice(
        &std::fs::read(
            project
                .home()
                .join(".swiftpm/configuration/registries.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let local: serde_json::Value = serde_json::from_str(
        &project.read_file("Packages/LPMDependencies/.swiftpm/configuration/registries.json"),
    )
    .unwrap();
    let expected = format!("{}/api/swift-registry", mock.url());
    assert_eq!(local["registries"]["lpmdev"]["url"], expected);
    assert_eq!(global["registries"]["lpmdev"]["url"], expected);
}
