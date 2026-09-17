use super::*;

#[test]
fn stage_refuses_pending_manifest_transactions_before_lifecycle() {
    for dry_run in [true, false] {
        let project = TempProject::empty(
            r#"{"name":"stage-pending","version":"1.0.0","scripts":{"prepack":"echo ran > stage-hook-ran"}}"#,
        );
        project.write_file(".lpm/release-apply/journal.json", "{}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                project.path().join(".lpm/release-apply"),
                std::fs::Permissions::from_mode(0o700),
            )
            .unwrap();
            std::fs::set_permissions(
                project.path().join(".lpm/release-apply/journal.json"),
                std::fs::Permissions::from_mode(0o600),
            )
            .unwrap();
        }
        let mut command = lpm(&project);
        command.args(["stage", "publish", "--yes", "--json"]);
        if dry_run {
            command.arg("--dry-run");
        }
        let output = command.output().unwrap();
        assert!(
            !project.path().join("stage-hook-ran").exists(),
            "pending transaction ran a lifecycle: {output:?}"
        );
        assert!(
            !output.status.success(),
            "pending transaction accepted: {output:?}"
        );
        let body = parse_json(&output.stdout);
        assert!(
            body["error"].as_str().unwrap().contains("release"),
            "{body}"
        );
    }
}

#[test]
fn stage_validates_configured_package_names() {
    let project = stage_project();
    project.write_file("lpm.json", r#"{"publish":{"npm":{"name":"Bad Name"}}}"#);
    let output = lpm(&project)
        .args([
            "stage",
            "publish",
            "--dry-run",
            "--ignore-scripts",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "invalid name accepted: {output:?}"
    );
}

#[test]
fn stage_validates_effective_tags() {
    for tag in ["", "bad tag", "1.2.3"] {
        for configured in [true, false] {
            let project = stage_project();
            let mut command = lpm(&project);
            command.args([
                "stage",
                "publish",
                "--dry-run",
                "--ignore-scripts",
                "--json",
            ]);
            if configured {
                project.write_file(
                    "lpm.json",
                    &serde_json::json!({"publish":{"npm":{"name":"@scope/staged-pkg","tag":tag}}})
                        .to_string(),
                );
            } else {
                command.args(["--tag", tag]);
            }
            let output = command.output().unwrap();
            assert!(
                !output.status.success(),
                "invalid tag {tag:?}, configured={configured}: {output:?}"
            );
        }
    }
}

#[test]
fn stage_rejects_restricted_access_for_unscoped_packages() {
    let project = TempProject::empty(r#"{"name":"stage-unscoped","version":"1.0.0"}"#);
    let output = lpm(&project)
        .args([
            "stage",
            "publish",
            "--dry-run",
            "--access",
            "restricted",
            "--ignore-scripts",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "unscoped restricted access accepted: {output:?}"
    );
}

#[test]
fn stage_management_propagates_configuration_errors() {
    for action in ["list", "view", "download", "approve", "reject"] {
        let project = stage_project();
        project.write_file("lpm.json", "{malformed");
        let mut command = lpm(&project);
        command.args(["stage", action, "--json"]);
        if action != "list" {
            command.arg(STAGE_ID);
        }
        let output = command.output().unwrap();
        assert!(!output.status.success(), "{action}: {output:?}");
        let body = parse_json(&output.stdout);
        assert!(
            body["error"].as_str().unwrap().contains("lpm.json"),
            "discarded configuration error for {action}: {body}"
        );
    }
}

#[tokio::test]
async fn stage_explicit_registry_prefers_its_stored_credential() {
    for ambient in [false, true] {
        let mock = MockRegistry::start().await;
        Mock::given(method("GET"))
            .and(path("/-/stage"))
            .and(header(
                "authorization",
                format!("Bearer {CUSTOM_STAGE_TOKEN}"),
            ))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"items":[],"total":0})),
            )
            .mount(mock.server())
            .await;
        let project = stage_project();
        let login = lpm(&project)
            .args([
                "login",
                "--login-registry",
                &mock.url(),
                "--token",
                CUSTOM_STAGE_TOKEN,
                "--json",
            ])
            .output()
            .unwrap();
        assert!(login.status.success(), "{login:?}");
        let mut command = lpm(&project);
        command.args(["stage", "list", "--npm-registry", &mock.url(), "--json"]);
        if ambient {
            command.env("NPM_TOKEN", "unrelated-token");
        }
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "exact token ignored, ambient={ambient}: {output:?}"
        );
    }
}

fn manifest_tarball(name: &str, version: &str, bom: bool) -> Vec<u8> {
    let body = format!(
        "{}{}",
        if bom { "\u{feff}" } else { "" },
        serde_json::json!({"name":name,"version":version})
    );
    let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let mut builder = tar::Builder::new(encoder);
    let mut header = tar::Header::new_gnu();
    header.set_size(body.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    builder
        .append_data(&mut header, "package/package.json", body.as_bytes())
        .unwrap();
    builder.into_inner().unwrap().finish().unwrap()
}

async fn download_fixture(name: &str, version: &str, bom: bool) {
    let mock = MockRegistry::start().await;
    let tarball = manifest_tarball(name, version, bom);
    Mock::given(method("GET"))
        .and(path(format!("/-/stage/{STAGE_ID}/tarball")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(tarball.clone()))
        .mount(mock.server())
        .await;
    let project = stage_project();
    let args = [
        "stage",
        "download",
        STAGE_ID,
        "--npm-registry",
        &mock.url(),
        "--json",
    ];
    let output = lpm(&project)
        .env("NPM_TOKEN", NPM_TOKEN)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "download failed for {name}@{version}, bom={bom}: {output:?}"
    );
    let body = parse_json(&output.stdout);
    let destination = std::path::PathBuf::from(body["path"].as_str().unwrap());
    assert!(destination.file_name().unwrap().len() <= 255);
    assert_eq!(std::fs::read(&destination).unwrap(), tarball);
    let repeated = lpm(&project)
        .env("NPM_TOKEN", NPM_TOKEN)
        .args(args)
        .output()
        .unwrap();
    assert!(!repeated.status.success(), "overwrote an existing archive");
    assert_eq!(std::fs::read(&destination).unwrap(), tarball);
}

#[tokio::test]
async fn stage_download_accepts_bom_manifests_without_rewriting_the_archive() {
    download_fixture("bom-package", "1.0.0", true).await;
}

#[tokio::test]
async fn stage_download_bounds_filenames_for_long_valid_identities() {
    download_fixture(&"a".repeat(214), "1.0.0", false).await;
    download_fixture("long-version", &format!("1.0.0-{}", "a".repeat(200)), false).await;
}

#[tokio::test]
async fn stage_preview_reports_the_final_renamed_tarball_size() {
    let mock = MockRegistry::start().await;
    let project = stage_project();
    mount_package_metadata(&mock, "@scope/staged-pkg", serde_json::json!({"0.9.0":{}})).await;
    mount_stage_publish(&mock, "@scope/staged-pkg").await;
    let preview = lpm(&project)
        .args([
            "stage",
            "publish",
            "--dry-run",
            "--ignore-scripts",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(preview.status.success(), "{preview:?}");
    let real = lpm(&project)
        .env("NPM_TOKEN", NPM_TOKEN)
        .args([
            "stage",
            "publish",
            "--npm-registry",
            &mock.url(),
            "--ignore-scripts",
            "--yes",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(real.status.success(), "{real:?}");
    let payload = recorded_stage_publish_payload(&mock).await;
    let attachment = payload["_attachments"]
        .as_object()
        .unwrap()
        .values()
        .next()
        .unwrap();
    let bytes = BASE64.decode(attachment["data"].as_str().unwrap()).unwrap();
    assert_eq!(
        parse_json(&preview.stdout)["tarball_size"]
            .as_u64()
            .unwrap(),
        bytes.len() as u64
    );
}

#[tokio::test]
async fn stage_custom_registry_unauthorized_guides_scoped_login() {
    let mock = MockRegistry::start().await;
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(401).set_body_json(serde_json::json!({"error":"expired token"})),
        )
        .mount(mock.server())
        .await;
    let project = stage_project();
    project.write_file(
        "lpm.json",
        &serde_json::json!({"publish":{"npm":{"registry":mock.url()}}}).to_string(),
    );
    let login = lpm(&project)
        .args([
            "login",
            "--login-registry",
            &mock.url(),
            "--token",
            CUSTOM_STAGE_TOKEN,
            "--json",
        ])
        .output()
        .unwrap();
    assert!(login.status.success(), "{login:?}");
    let output = lpm(&project)
        .args(["stage", "list", "--json"])
        .output()
        .unwrap();
    assert!(!output.status.success(), "{output:?}");
    assert!(
        parse_json(&output.stdout)["error"]
            .as_str()
            .unwrap()
            .contains("lpm login --login-registry"),
        "wrong credential recovery: {output:?}"
    );
}
