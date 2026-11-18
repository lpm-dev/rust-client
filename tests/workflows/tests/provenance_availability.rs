//! Workflow coverage for `[sigstore] availability = "strict"` beyond
//! install: an approval refuses a package whose provenance the registry
//! can't establish, and a standalone rebuild runs a trusted package's
//! scripts only when the lockfile holds its provenance evidence.

mod support;

use lpm_common::integrity::HashAlgorithm;
use support::mock_registry::{MockRegistry, compute_integrity, make_tarball_from_pkg_json};
use support::{TempProject, lpm_with_registry, write_signed_unlock};
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

const PACKAGE: &str = "strict-provenance-pkg";
const VERSION: &str = "1.0.0";

#[derive(Clone, Copy)]
enum Attestation {
    /// The registry serves no attestation for the version.
    Absent,
    /// The registry names an attestation that answers 503.
    Unavailable,
}

async fn mount_scripted_package(mock: &MockRegistry, attestation: Attestation) {
    let scripts = serde_json::json!({ "postinstall": "node -e \"process.exit(0)\"" });
    let tarball = make_tarball_from_pkg_json(
        serde_json::json!({
            "name": PACKAGE,
            "version": VERSION,
            "scripts": scripts,
        }),
        &[],
    );
    let mut dist = serde_json::json!({
        "tarball": mock.tarball_url(PACKAGE, VERSION),
        "integrity": compute_integrity(&tarball),
    });
    if let Attestation::Unavailable = attestation {
        let attestation_path = format!("/-/attestations/{PACKAGE}@{VERSION}");
        dist["attestations"] = serde_json::json!({
            "url": format!("{}{attestation_path}", mock.url()),
            "provenance": { "predicateType": "https://slsa.dev/provenance/v1" }
        });
        Mock::given(method("GET"))
            .and(path(attestation_path))
            .respond_with(ResponseTemplate::new(503))
            .mount(mock.server())
            .await;
    }
    let metadata = serde_json::json!({
        "name": PACKAGE,
        "dist-tags": { "latest": VERSION },
        "versions": {
            VERSION: {
                "name": PACKAGE,
                "version": VERSION,
                "scripts": scripts,
                "dist": dist,
                "dependencies": {}
            }
        },
        "time": { VERSION: "2025-01-01T00:00:00.000Z" }
    });
    for metadata_path in [format!("/{PACKAGE}"), format!("/api/registry/{PACKAGE}")] {
        Mock::given(method("GET"))
            .and(path(metadata_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(metadata.clone()))
            .mount(mock.server())
            .await;
    }
    mock.with_batch_metadata(vec![metadata]).await;
    Mock::given(method("GET"))
        .and(path(MockRegistry::tarball_path(PACKAGE, VERSION)))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_bytes(tarball)
                .insert_header("content-type", "application/octet-stream"),
        )
        .mount(mock.server())
        .await;
}

fn write_availability(project: &TempProject, availability: &str) {
    let path = project.home().join(".lpm").join("config.toml");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(
        path,
        format!("[sigstore]\navailability = \"{availability}\"\n"),
    )
    .unwrap();
}

/// A project whose install left `PACKAGE` blocked, with `availability`
/// configured from then on.
async fn installed_and_blocked(
    mock: &MockRegistry,
    attestation: Attestation,
    availability: &str,
) -> TempProject {
    mount_scripted_package(mock, attestation).await;
    let project = TempProject::empty(&format!(
        r#"{{"name":"strict-availability","version":"1.0.0","dependencies":{{"{PACKAGE}":"{VERSION}"}}}}"#
    ));
    // The registry the package comes from, which serves its attestations.
    project.write_file(".npmrc", &format!("registry={}\n", mock.url()));
    let install = lpm_with_registry(&project, &mock.url())
        .args(["install", "--no-skills", "--no-security-summary"])
        .output()
        .unwrap();
    assert!(install.status.success(), "{}", output_of(&install));
    write_availability(&project, availability);
    write_signed_unlock(&project, &["trust-bulk-approve"]);
    project
}

fn output_of(output: &std::process::Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn approve(project: &TempProject, mock: &MockRegistry) -> std::process::Output {
    lpm_with_registry(project, &mock.url())
        .args(["approve-scripts", PACKAGE])
        .output()
        .unwrap()
}

fn has_binding(project: &TempProject) -> bool {
    let manifest: serde_json::Value =
        serde_json::from_str(&project.read_file("package.json")).unwrap();
    manifest
        .pointer("/lpm/trustedDependencies")
        .and_then(serde_json::Value::as_object)
        .is_some_and(|bindings| {
            bindings
                .keys()
                .any(|key| key.starts_with(&format!("{PACKAGE}@")))
        })
}

async fn an_approval_is_refused(attestation: Attestation, reason: &str) {
    let mock = MockRegistry::start().await;
    let project = installed_and_blocked(&mock, attestation, "strict").await;
    let manifest = project.read_file("package.json");

    let approval = approve(&project, &mock);

    let output = output_of(&approval);
    assert!(!approval.status.success(), "{output}");
    assert!(output.contains(reason), "{output}");
    assert!(output.contains("Provenance unavailable"), "{output}");
    assert!(
        !output.contains("failed cryptographic"),
        "a missing attestation isn't a failed one: {output}"
    );
    assert_eq!(project.read_file("package.json"), manifest);
}

#[tokio::test]
async fn approve_scripts_refuses_a_package_without_an_attestation_under_strict_availability() {
    an_approval_is_refused(
        Attestation::Absent,
        "strict provenance availability requires an attestation for strict-provenance-pkg@1.0.0",
    )
    .await;
}

#[tokio::test]
async fn approve_scripts_refuses_a_package_whose_attestation_is_unavailable_under_strict_availability()
 {
    an_approval_is_refused(
        Attestation::Unavailable,
        "could not verify strict-provenance-pkg@1.0.0 because the attestation was unavailable",
    )
    .await;
}

#[tokio::test]
async fn approve_scripts_records_a_package_without_an_attestation_under_best_effort_availability() {
    let mock = MockRegistry::start().await;
    let project = installed_and_blocked(&mock, Attestation::Absent, "best-effort").await;

    let approval = approve(&project, &mock);

    assert!(approval.status.success(), "{}", output_of(&approval));
    assert!(has_binding(&project));
}

fn rebuild(project: &TempProject, mock: &MockRegistry) -> std::process::Output {
    lpm_with_registry(project, &mock.url())
        .args(["rebuild"])
        .output()
        .unwrap()
}

/// Records verified provenance evidence for `PACKAGE` in the project's
/// lockfile, bound to the bytes it pins.
fn record_lockfile_evidence(project: &TempProject) {
    let lockfile_path = project.path().join(lpm_lockfile::LOCKFILE_NAME);
    let mut lockfile = lpm_lockfile::Lockfile::read_from_file(&lockfile_path).unwrap();
    let package = lockfile
        .packages
        .iter()
        .find(|package| package.name == PACKAGE)
        .unwrap()
        .clone();
    let integrity = lpm_common::Integrity::parse(package.integrity.as_deref().unwrap()).unwrap();
    assert_eq!(integrity.algorithm, HashAlgorithm::Sha512);
    lockfile.set_verified_provenance(
        &package.package_key(),
        lpm_lockfile::LockedProvenance {
            snapshot: lpm_common::ProvenanceSnapshot {
                present: true,
                publisher: Some("github:example/strict-provenance-pkg".to_string()),
                workflow_path: Some(".github/workflows/publish.yml".to_string()),
                workflow_ref: Some("refs/tags/v1.0.0".to_string()),
                attestation_cert_sha256: Some(format!("sha256-{}", "11".repeat(32))),
            },
            subject_name: lpm_common::npm_package_purl(PACKAGE, VERSION),
            subject_sha512: hex::encode(integrity.hash),
            integrated_time_secs: 1_700_000_000,
            log_id: "rekor-test-log".to_string(),
            log_index: 42,
            bundle_sha256: format!("sha256-{}", "22".repeat(32)),
        },
    );
    lockfile.write_all(&lockfile_path).unwrap();
}

#[tokio::test]
async fn rebuild_refuses_an_approved_package_without_lockfile_provenance_under_strict_availability()
{
    let mock = MockRegistry::start().await;
    let project = installed_and_blocked(&mock, Attestation::Absent, "best-effort").await;
    let approval = approve(&project, &mock);
    assert!(approval.status.success(), "{}", output_of(&approval));
    write_availability(&project, "strict");

    let refused = rebuild(&project, &mock);

    let output = output_of(&refused);
    assert!(!refused.status.success(), "{output}");
    assert!(
        output.contains(
            "strict provenance availability requires lockfile evidence for strict-provenance-pkg@1.0.0"
        ),
        "{output}"
    );
    assert!(!output.contains("postinstall"), "{output}");

    record_lockfile_evidence(&project);
    let rebuilt = rebuild(&project, &mock);

    let output = output_of(&rebuilt);
    assert!(rebuilt.status.success(), "{output}");
    assert!(output.contains("strict-provenance-pkg@1.0.0"), "{output}");
}

/// A project whose approval of `PACKAGE` was recorded while its
/// attestation couldn't be fetched, so the approval holds no provenance,
/// with strict availability configured afterwards.
async fn approved_while_unavailable_then_strict(mock: &MockRegistry) -> TempProject {
    let project = installed_and_blocked(mock, Attestation::Unavailable, "best-effort").await;
    let approval = approve(&project, mock);
    assert!(approval.status.success(), "{}", output_of(&approval));
    assert!(has_binding(&project));
    write_availability(&project, "strict");
    project
}

const MISSING_EVIDENCE: &str =
    "strict provenance availability requires lockfile evidence for strict-provenance-pkg@1.0.0";

#[tokio::test]
async fn rebuild_refuses_a_package_approved_without_provenance_under_strict_availability() {
    let mock = MockRegistry::start().await;
    let project = approved_while_unavailable_then_strict(&mock).await;

    let refused = rebuild(&project, &mock);

    let output = output_of(&refused);
    assert!(!refused.status.success(), "{output}");
    assert!(output.contains(MISSING_EVIDENCE), "{output}");
}

#[tokio::test]
async fn install_refuses_a_package_approved_without_provenance_under_strict_availability() {
    let mock = MockRegistry::start().await;
    let project = approved_while_unavailable_then_strict(&mock).await;
    for installed in ["node_modules", ".lpm"] {
        std::fs::remove_dir_all(project.path().join(installed)).unwrap();
    }

    let refused = lpm_with_registry(&project, &mock.url())
        .args(["install", "--no-skills", "--no-security-summary"])
        .output()
        .unwrap();

    let output = output_of(&refused);
    assert!(!refused.status.success(), "{output}");
    assert!(output.contains(MISSING_EVIDENCE), "{output}");
}

#[tokio::test]
async fn offline_install_refuses_an_approved_package_without_lockfile_provenance_under_strict_availability()
 {
    let mock = MockRegistry::start().await;
    let project = installed_and_blocked(&mock, Attestation::Absent, "best-effort").await;
    let approval = approve(&project, &mock);
    assert!(approval.status.success(), "{}", output_of(&approval));
    write_availability(&project, "strict");
    for installed in ["node_modules", ".lpm"] {
        std::fs::remove_dir_all(project.path().join(installed)).unwrap();
    }

    let refused = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--offline",
            "--no-skills",
            "--no-security-summary",
        ])
        .output()
        .unwrap();

    let output = output_of(&refused);
    assert!(!refused.status.success(), "{output}");
    assert!(output.contains(MISSING_EVIDENCE), "{output}");
    assert!(
        !output.contains("✓ strict-provenance-pkg@1.0.0  postinstall"),
        "{output}"
    );
}

#[tokio::test]
async fn rebuild_refuses_a_package_the_script_policy_runs_without_lockfile_provenance_under_strict_availability_for_all_packages()
 {
    let mock = MockRegistry::start().await;
    let project = installed_and_blocked(&mock, Attestation::Absent, "best-effort").await;
    let mut manifest: serde_json::Value =
        serde_json::from_str(&project.read_file("package.json")).unwrap();
    manifest["lpm"] = serde_json::json!({ "scriptPolicy": "allow" });
    project.write_file("package.json", &manifest.to_string());
    std::fs::write(
        project.home().join(".lpm").join("config.toml"),
        "[sigstore]\navailability = \"strict\"\nscope = \"all\"\n",
    )
    .unwrap();
    write_signed_unlock(&project, &["trust-bulk-approve", "scripts-allow"]);

    let refused = rebuild(&project, &mock);

    let output = output_of(&refused);
    assert!(!refused.status.success(), "{output}");
    assert!(output.contains(MISSING_EVIDENCE), "{output}");
}

#[tokio::test]
async fn approve_scripts_refuses_to_run_on_a_config_it_cannot_read_rather_than_drop_strict_availability()
 {
    let mock = MockRegistry::start().await;
    let project = installed_and_blocked(&mock, Attestation::Absent, "strict").await;
    let config = project.home().join(".lpm").join("config.toml");
    let readable = std::fs::read_to_string(&config).unwrap();
    std::fs::write(&config, format!("{readable}[unterminated\n")).unwrap();
    let manifest = project.read_file("package.json");

    let approval = approve(&project, &mock);

    assert!(!approval.status.success(), "{}", output_of(&approval));
    assert_eq!(project.read_file("package.json"), manifest);
}

async fn an_approval_that_can_t_be_checked_is_refused(
    change: impl FnOnce(&TempProject),
    reason: &str,
) {
    let mock = MockRegistry::start().await;
    let project = installed_and_blocked(&mock, Attestation::Absent, "strict").await;
    change(&project);
    let manifest = project.read_file("package.json");

    let approval = approve(&project, &mock);

    let output = output_of(&approval);
    assert!(!approval.status.success(), "{output}");
    assert!(output.contains(reason), "{output}");
    assert_eq!(project.read_file("package.json"), manifest);
}

#[tokio::test]
async fn approve_scripts_refuses_under_strict_availability_when_the_lockfile_can_t_be_read() {
    an_approval_that_can_t_be_checked_is_refused(
        |project| std::fs::remove_file(project.path().join(lpm_lockfile::LOCKFILE_NAME)).unwrap(),
        "can't check this approval",
    )
    .await;
}

#[tokio::test]
async fn approve_scripts_refuses_under_strict_availability_a_package_now_routed_to_another_registry()
 {
    an_approval_that_can_t_be_checked_is_refused(
        |project| project.write_file(".npmrc", "registry=https://registry.example.test/\n"),
        "can't check strict-provenance-pkg@1.0.0",
    )
    .await;
}

#[tokio::test]
async fn waiving_provenance_drift_doesn_t_waive_strict_availability() {
    let mock = MockRegistry::start().await;
    let project = installed_and_blocked(&mock, Attestation::Absent, "best-effort").await;
    let approval = approve(&project, &mock);
    assert!(approval.status.success(), "{}", output_of(&approval));
    write_availability(&project, "strict");
    write_signed_unlock(&project, &["trust-bulk-approve", "provenance-ignore-drift"]);

    for waiver in [
        &["--ignore-provenance-drift-all"][..],
        &["--ignore-provenance-drift", PACKAGE],
    ] {
        for installed in ["node_modules", ".lpm"] {
            let _ = std::fs::remove_dir_all(project.path().join(installed));
        }

        let refused = lpm_with_registry(&project, &mock.url())
            .args(["install", "--no-skills", "--no-security-summary"])
            .args(waiver)
            .output()
            .unwrap();

        let output = output_of(&refused);
        assert!(!refused.status.success(), "{waiver:?}: {output}");
        assert!(output.contains(MISSING_EVIDENCE), "{waiver:?}: {output}");
    }
}
