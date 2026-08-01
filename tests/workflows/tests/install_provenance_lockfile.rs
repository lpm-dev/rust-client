//! Workflow coverage for artifact-bound provenance lockfile evidence and
//! opt-in verification scope/availability.

mod support;

use lpm_common::integrity::HashAlgorithm;
use support::mock_registry::{MockRegistry, compute_integrity, make_tarball};
use support::{TempProject, lpm_with_registry, write_signed_unlock};
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

const PACKAGE: &str = "provenance-history-pkg";
const LPM_PACKAGE: &str = "@lpm.dev/acme.source-identity";
const VERSION_1: &str = "1.0.0";
const VERSION_2: &str = "1.1.0";

#[derive(Clone, Copy)]
enum Attestation {
    Absent,
    InvalidBundle,
    Unavailable,
}

async fn mount_package_versions(
    mock: &MockRegistry,
    versions: &[(&str, Attestation)],
) -> Vec<(String, Vec<u8>)> {
    let mut version_docs = serde_json::Map::with_capacity(versions.len());
    let mut times = serde_json::Map::with_capacity(versions.len());
    let mut tarballs = Vec::with_capacity(versions.len());

    for (version, attestation) in versions {
        let tarball = make_tarball(PACKAGE, version);
        let tarball_url = mock.tarball_url(PACKAGE, version);
        let mut dist = serde_json::json!({
            "tarball": tarball_url,
            "integrity": compute_integrity(&tarball),
        });
        if !matches!(attestation, Attestation::Absent) {
            dist["attestations"] = serde_json::json!({
                "url": format!("{}/-/attestations/{PACKAGE}@{version}", mock.url()),
                "provenance": {
                    "predicateType": "https://slsa.dev/provenance/v1"
                }
            });
            let response = match attestation {
                Attestation::InvalidBundle => {
                    ResponseTemplate::new(200).set_body_json(serde_json::json!({
                        "mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.2",
                        "verificationMaterial": {}
                    }))
                }
                Attestation::Unavailable => ResponseTemplate::new(503),
                Attestation::Absent => unreachable!("absent attestations have no URL"),
            };
            Mock::given(method("GET"))
                .and(path(format!("/-/attestations/{PACKAGE}@{version}")))
                .respond_with(response)
                .mount(mock.server())
                .await;
        }

        version_docs.insert(
            (*version).to_string(),
            serde_json::json!({
                "name": PACKAGE,
                "version": version,
                "dist": dist,
                "dependencies": {}
            }),
        );
        times.insert(
            (*version).to_string(),
            serde_json::Value::String("2024-01-01T00:00:00.000Z".to_string()),
        );
        Mock::given(method("GET"))
            .and(path(format!(
                "/tarballs/{PACKAGE}/-/{PACKAGE}-{version}.tgz"
            )))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_bytes(tarball.clone())
                    .insert_header("content-type", "application/octet-stream"),
            )
            .mount(mock.server())
            .await;
        tarballs.push(((*version).to_string(), tarball));
    }

    let latest = versions
        .last()
        .expect("at least one version fixture")
        .0
        .to_string();
    let metadata = serde_json::json!({
        "name": PACKAGE,
        "dist-tags": { "latest": latest },
        "versions": version_docs,
        "time": times,
        "modified": "2024-01-02T00:00:00.000Z"
    });

    for metadata_path in [format!("/{PACKAGE}"), format!("/api/registry/{PACKAGE}")] {
        Mock::given(method("GET"))
            .and(path(metadata_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(metadata.clone()))
            .mount(mock.server())
            .await;
    }
    mock.with_batch_metadata(vec![metadata]).await;
    tarballs
}

fn configure_custom_registry(project: &TempProject, mock: &MockRegistry) {
    project.write_file(".npmrc", &format!("registry={}\n", mock.url()));
}

fn write_sigstore_config(
    project: &TempProject,
    scope: Option<&str>,
    availability: Option<&str>,
    trust_policy: Option<&str>,
    verify: Option<&str>,
) {
    let mut config = String::new();
    if let Some(trust_policy) = trust_policy {
        config.push_str(&format!("trust-policy = \"{trust_policy}\"\n"));
    }
    if scope.is_some() || availability.is_some() || verify.is_some() {
        config.push_str("[sigstore]\n");
    }
    if let Some(verify) = verify {
        config.push_str(&format!("verify = \"{verify}\"\n"));
    }
    if let Some(scope) = scope {
        config.push_str(&format!("scope = \"{scope}\"\n"));
    }
    if let Some(availability) = availability {
        config.push_str(&format!("availability = \"{availability}\"\n"));
    }

    let path = project.home().join(".lpm").join("config.toml");
    std::fs::create_dir_all(path.parent().expect("config parent")).expect("create config dir");
    std::fs::write(path, config).expect("write config");
}

fn project_for_version(version: &str) -> TempProject {
    TempProject::empty(&format!(
        r#"{{
            "name": "provenance-lockfile-test",
            "version": "1.0.0",
            "dependencies": {{ "{PACKAGE}": "{version}" }}
        }}"#
    ))
}

fn install(project: &TempProject, mock: &MockRegistry, extra: &[&str]) -> std::process::Output {
    let mut command = lpm_with_registry(project, &mock.url());
    command.args([
        "install",
        "--no-security-summary",
        "--no-skills",
        "--no-editor-setup",
    ]);
    command.args(extra);
    command.output().expect("run lpm install")
}

#[tokio::test]
async fn lockfile_records_configured_lpm_registry_as_the_package_source() {
    let mock = MockRegistry::start().await;
    let tarball = make_tarball(LPM_PACKAGE, VERSION_1);
    mock.with_package(LPM_PACKAGE, VERSION_1, &tarball).await;
    let project = TempProject::empty(&format!(
        r#"{{
            "name": "configured-source-test",
            "version": "1.0.0",
            "dependencies": {{ "{LPM_PACKAGE}": "{VERSION_1}" }}
        }}"#
    ));

    let output = install(&project, &mock, &[]);

    assert!(
        output.status.success(),
        "install failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let lockfile =
        lpm_lockfile::Lockfile::read_from_file(&project.path().join(lpm_lockfile::LOCKFILE_NAME))
            .expect("read installed lockfile");
    let package = lockfile
        .packages
        .iter()
        .find(|package| package.name == LPM_PACKAGE)
        .expect("configured-registry package must be locked");
    assert_eq!(
        package.source.as_deref(),
        Some(format!("registry+{}", mock.url()).as_str()),
        "the lockfile must record the exact configured registry that supplied the package"
    );
}

fn seed_verified_lockfile_evidence(project: &TempProject, version: &str) -> String {
    seed_verified_lockfile_evidence_at(&project.path().join(lpm_lockfile::LOCKFILE_NAME), version)
}

fn seed_verified_lockfile_evidence_at(lockfile_path: &std::path::Path, version: &str) -> String {
    let mut lockfile =
        lpm_lockfile::Lockfile::read_from_file(lockfile_path).expect("read installed lockfile");
    let package = lockfile
        .packages
        .iter()
        .find(|package| {
            package.name == PACKAGE && package.version == version && package.integrity.is_some()
        })
        .expect("locked registry package")
        .clone();
    let integrity = lpm_common::Integrity::parse(
        package
            .integrity
            .as_deref()
            .expect("registry package integrity"),
    )
    .expect("valid integrity");
    assert_eq!(integrity.algorithm, HashAlgorithm::Sha512);
    let subject_sha512 = hex::encode(integrity.hash);
    let key = package.package_key();
    lockfile.set_verified_provenance(
        &key,
        lpm_lockfile::LockedProvenance {
            snapshot: lpm_common::ProvenanceSnapshot {
                present: true,
                publisher: Some("github:example/provenance-history-pkg".to_string()),
                workflow_path: Some(".github/workflows/publish.yml".to_string()),
                workflow_ref: Some(format!("refs/tags/v{version}")),
                attestation_cert_sha256: Some(format!("sha256-{}", "11".repeat(32))),
            },
            subject_name: lpm_common::npm_package_purl(PACKAGE, version),
            subject_sha512: subject_sha512.clone(),
            integrated_time_secs: 1_700_000_000,
            log_id: "rekor-test-log".to_string(),
            log_index: 42,
            bundle_sha256: format!("sha256-{}", "22".repeat(32)),
        },
    );
    lockfile
        .write_all(lockfile_path)
        .expect("write lockfile with verified provenance");
    subject_sha512
}

#[tokio::test]
async fn default_scope_does_not_verify_unapproved_packages() {
    let project = project_for_version(VERSION_1);
    let mock = MockRegistry::start().await;
    configure_custom_registry(&project, &mock);
    mount_package_versions(&mock, &[(VERSION_1, Attestation::InvalidBundle)]).await;

    let output = install(&project, &mock, &[]);
    assert!(
        output.status.success(),
        "default approved-only scope must preserve existing behavior:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let requests = mock.server().received_requests().await.expect("requests");
    assert!(
        requests
            .iter()
            .all(|request| !request.url.path().starts_with("/-/attestations/")),
        "default scope must not fetch attestations for unapproved packages"
    );
}

#[tokio::test]
async fn scope_all_verifies_unapproved_packages() {
    let project = project_for_version(VERSION_1);
    let mock = MockRegistry::start().await;
    configure_custom_registry(&project, &mock);
    write_sigstore_config(&project, Some("all"), None, None, None);
    mount_package_versions(&mock, &[(VERSION_1, Attestation::InvalidBundle)]).await;

    let output = install(&project, &mock, &[]);
    assert!(
        !output.status.success(),
        "scope=all must reject an invalid bundle for an unapproved package"
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("provenance") && combined.contains("verif"),
        "failure must identify provenance verification: {combined}"
    );
}

#[tokio::test]
async fn best_effort_availability_remains_the_default() {
    let project = project_for_version(VERSION_1);
    let mock = MockRegistry::start().await;
    configure_custom_registry(&project, &mock);
    write_sigstore_config(&project, Some("all"), None, None, None);
    mount_package_versions(&mock, &[(VERSION_1, Attestation::Absent)]).await;

    let output = install(&project, &mock, &[]);
    assert!(
        output.status.success(),
        "scope=all without strict availability must keep absence fail-open:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
async fn strict_availability_requires_an_attestation_for_scope_all() {
    let project = project_for_version(VERSION_1);
    let mock = MockRegistry::start().await;
    configure_custom_registry(&project, &mock);
    write_sigstore_config(&project, Some("all"), Some("strict"), None, None);
    mount_package_versions(&mock, &[(VERSION_1, Attestation::Absent)]).await;

    let output = install(&project, &mock, &[]);
    assert!(
        !output.status.success(),
        "strict availability must fail when an in-scope package has no attestation"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("strict provenance availability requires an attestation"),
        "strict failure must be actionable: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
async fn strict_scope_all_skips_local_dependencies_without_registry_disclosure() {
    let project = TempProject::empty(
        r#"{
            "name": "local-provenance-scope-test",
            "version": "1.0.0",
            "dependencies": { "local-pkg": "file:./local-pkg" }
        }"#,
    );
    project.write_file(
        "local-pkg/package.json",
        r#"{
            "name": "local-pkg",
            "version": "1.0.0",
            "main": "index.js"
        }"#,
    );
    project.write_file("local-pkg/index.js", "module.exports = 1;\n");
    let mock = MockRegistry::start().await;
    configure_custom_registry(&project, &mock);
    write_sigstore_config(&project, Some("all"), Some("strict"), None, None);

    let fresh = install(&project, &mock, &[]);
    assert!(
        fresh.status.success(),
        "fresh strict install must ignore local provenance availability:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&fresh.stdout),
        String::from_utf8_lossy(&fresh.stderr)
    );

    let requests = mock.server().received_requests().await.expect("requests");
    assert!(
        requests
            .iter()
            .all(|request| !request.url.path().contains("local-pkg")),
        "provenance checks must not disclose local package names to a registry: {requests:#?}"
    );
}

#[tokio::test]
async fn frozen_strict_install_replays_artifact_bound_lockfile_evidence() {
    let project = project_for_version(VERSION_1);
    let mock = MockRegistry::start().await;
    configure_custom_registry(&project, &mock);
    write_sigstore_config(&project, Some("all"), None, None, None);
    mount_package_versions(&mock, &[(VERSION_1, Attestation::Absent)]).await;
    let initial = install(&project, &mock, &[]);
    assert!(initial.status.success(), "initial install must succeed");
    seed_verified_lockfile_evidence(&project, VERSION_1);
    write_sigstore_config(&project, Some("all"), Some("strict"), None, None);
    std::fs::remove_dir_all(project.path().join("node_modules")).expect("remove node_modules");

    let output = install(&project, &mock, &["--frozen-lockfile"]);
    assert!(
        output.status.success(),
        "frozen strict replay must accept matching verified evidence:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
async fn lockfile_replay_accepts_a_coexisting_unattested_version_under_no_downgrade() {
    let project = TempProject::empty(&format!(
        r#"{{
            "name": "coexisting-provenance-history",
            "version": "1.0.0",
            "dependencies": {{
                "verified-copy": "npm:{PACKAGE}@{VERSION_1}",
                "unattested-copy": "npm:{PACKAGE}@{VERSION_2}"
            }}
        }}"#,
    ));
    let mock = MockRegistry::start().await;
    configure_custom_registry(&project, &mock);
    mount_package_versions(
        &mock,
        &[
            (VERSION_1, Attestation::Absent),
            (VERSION_2, Attestation::Absent),
        ],
    )
    .await;

    let initial = install(&project, &mock, &[]);
    assert!(
        initial.status.success(),
        "initial install with coexisting versions must succeed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&initial.stdout),
        String::from_utf8_lossy(&initial.stderr)
    );
    seed_verified_lockfile_evidence(&project, VERSION_1);
    write_sigstore_config(&project, None, None, Some("no-downgrade"), None);

    let replay = install(&project, &mock, &[]);

    assert!(
        replay.status.success(),
        "a verified version must not make a coexisting locked version fail on replay:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&replay.stdout),
        String::from_utf8_lossy(&replay.stderr)
    );
}

#[tokio::test]
async fn lockfile_replay_accepts_coexisting_registry_and_local_sources_under_no_downgrade() {
    let project = TempProject::empty(&format!(
        r#"{{
            "name": "coexisting-provenance-sources",
            "version": "1.0.0",
            "dependencies": {{
                "registry-copy": "npm:{PACKAGE}@{VERSION_1}",
                "local-copy": "file:./local-copy"
            }}
        }}"#,
    ));
    project.write_file(
        "local-copy/package.json",
        &format!(
            r#"{{
                "name": "{PACKAGE}",
                "version": "{VERSION_1}",
                "main": "index.js"
            }}"#,
        ),
    );
    project.write_file("local-copy/index.js", "module.exports = 'local';\n");
    let mock = MockRegistry::start().await;
    configure_custom_registry(&project, &mock);
    mount_package_versions(&mock, &[(VERSION_1, Attestation::Absent)]).await;

    let initial = install(&project, &mock, &[]);
    assert!(
        initial.status.success(),
        "initial install with coexisting sources must succeed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&initial.stdout),
        String::from_utf8_lossy(&initial.stderr)
    );
    seed_verified_lockfile_evidence(&project, VERSION_1);
    write_sigstore_config(&project, None, None, Some("no-downgrade"), None);

    let replay = install(&project, &mock, &[]);

    assert!(
        replay.status.success(),
        "verified registry evidence must not relabel a coexisting locked local source as a substitution:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&replay.stdout),
        String::from_utf8_lossy(&replay.stderr)
    );
}

#[tokio::test]
async fn frozen_install_rejects_tampered_lockfile_evidence_binding() {
    let project = project_for_version(VERSION_1);
    let mock = MockRegistry::start().await;
    configure_custom_registry(&project, &mock);
    mount_package_versions(&mock, &[(VERSION_1, Attestation::Absent)]).await;
    let initial = install(&project, &mock, &[]);
    assert!(initial.status.success(), "initial install must succeed");
    let subject_sha512 = seed_verified_lockfile_evidence(&project, VERSION_1);
    let lockfile_path = project.path().join(lpm_lockfile::LOCKFILE_NAME);
    let tampered = std::fs::read_to_string(&lockfile_path)
        .expect("read lockfile")
        .replace(&subject_sha512, &"00".repeat(64));
    std::fs::write(&lockfile_path, tampered).expect("write tampered lockfile");

    let output = install(&project, &mock, &["--frozen-lockfile"]);
    assert!(
        !output.status.success(),
        "frozen install must reject evidence whose digest binding was edited"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("subject-sha512 does not match the locked package integrity"),
        "tamper failure must identify the broken binding: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
async fn no_downgrade_blocks_new_version_after_verified_history() {
    let project = project_for_version(VERSION_1);
    let mock = MockRegistry::start().await;
    configure_custom_registry(&project, &mock);
    mount_package_versions(
        &mock,
        &[
            (VERSION_1, Attestation::Absent),
            (VERSION_2, Attestation::Absent),
        ],
    )
    .await;
    let initial = install(&project, &mock, &[]);
    assert!(initial.status.success(), "initial install must succeed");
    seed_verified_lockfile_evidence(&project, VERSION_1);
    write_sigstore_config(&project, None, None, Some("no-downgrade"), None);
    project.write_file(
        "package.json",
        &format!(
            r#"{{
                "name": "provenance-lockfile-test",
                "version": "1.0.0",
                "dependencies": {{ "{PACKAGE}": "{VERSION_2}" }}
            }}"#
        ),
    );

    let output = install(&project, &mock, &["--force"]);
    assert!(
        !output.status.success(),
        "no-downgrade must block an attestation-free release after verified history:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("trust-policy no-downgrade")
            && combined.contains(PACKAGE)
            && combined.contains(VERSION_2),
        "failure must identify the provenance downgrade: {combined}"
    );
}

#[tokio::test]
async fn no_downgrade_blocks_registry_to_local_substitution_without_registry_lookup() {
    let project = project_for_version(VERSION_1);
    let mock = MockRegistry::start().await;
    configure_custom_registry(&project, &mock);
    mount_package_versions(&mock, &[(VERSION_1, Attestation::Absent)]).await;
    let initial = install(&project, &mock, &[]);
    assert!(initial.status.success(), "initial install must succeed");
    seed_verified_lockfile_evidence(&project, VERSION_1);
    write_sigstore_config(&project, None, None, Some("no-downgrade"), None);
    project.write_file(
        "package.json",
        &format!(
            r#"{{
                "name": "provenance-lockfile-test",
                "version": "1.0.0",
                "dependencies": {{ "{PACKAGE}": "file:./local-pkg" }}
            }}"#
        ),
    );
    project.write_file(
        "local-pkg/package.json",
        &format!(
            r#"{{
                "name": "{PACKAGE}",
                "version": "{VERSION_1}",
                "main": "index.js"
            }}"#
        ),
    );
    project.write_file("local-pkg/index.js", "module.exports = 1;\n");
    let requests_before = mock
        .server()
        .received_requests()
        .await
        .expect("requests before substitution")
        .len();
    let metadata_cache = project.cache_dir().join("metadata");
    if metadata_cache.exists() {
        std::fs::remove_dir_all(&metadata_cache).expect("clear registry metadata cache");
    }

    let output = install(&project, &mock, &["--force"]);
    assert!(
        !output.status.success(),
        "no-downgrade must reject registry-to-local source substitution"
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("trust-policy no-downgrade")
            && combined.contains(PACKAGE)
            && combined.contains("registry-to-local source substitution"),
        "failure must identify the source downgrade: {combined}"
    );
    let requests_after = mock
        .server()
        .received_requests()
        .await
        .expect("requests after substitution");
    assert_eq!(
        requests_after.len(),
        requests_before,
        "rejecting a local source substitution must not make any registry request"
    );
}

#[tokio::test]
async fn no_downgrade_blocks_unavailable_attestation_after_verified_history() {
    let project = project_for_version(VERSION_1);
    let mock = MockRegistry::start().await;
    configure_custom_registry(&project, &mock);
    mount_package_versions(
        &mock,
        &[
            (VERSION_1, Attestation::Absent),
            (VERSION_2, Attestation::Unavailable),
        ],
    )
    .await;
    let initial = install(&project, &mock, &[]);
    assert!(initial.status.success(), "initial install must succeed");
    seed_verified_lockfile_evidence(&project, VERSION_1);
    write_sigstore_config(&project, None, None, Some("no-downgrade"), None);
    project.write_file(
        "package.json",
        &format!(
            r#"{{
                "name": "provenance-lockfile-test",
                "version": "1.0.0",
                "dependencies": {{ "{PACKAGE}": "{VERSION_2}" }}
            }}"#
        ),
    );

    let output = install(&project, &mock, &["--force"]);
    assert!(
        !output.status.success(),
        "no-downgrade must block an unavailable attestation after verified history:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("trust-policy no-downgrade")
            && combined.contains(PACKAGE)
            && combined.contains(VERSION_2),
        "failure must identify the unavailable provenance downgrade: {combined}"
    );
}

#[tokio::test]
async fn no_downgrade_blocks_invalid_attestation_when_verification_warns() {
    let project = project_for_version(VERSION_1);
    let mock = MockRegistry::start().await;
    configure_custom_registry(&project, &mock);
    mount_package_versions(
        &mock,
        &[
            (VERSION_1, Attestation::Absent),
            (VERSION_2, Attestation::InvalidBundle),
        ],
    )
    .await;
    let initial = install(&project, &mock, &[]);
    assert!(initial.status.success(), "initial install must succeed");
    seed_verified_lockfile_evidence(&project, VERSION_1);
    write_sigstore_config(&project, None, None, Some("no-downgrade"), Some("warn"));
    write_signed_unlock(&project, &["provenance-unverified"]);
    project.write_file(
        "package.json",
        &format!(
            r#"{{
                "name": "provenance-lockfile-test",
                "version": "1.0.0",
                "dependencies": {{ "{PACKAGE}": "{VERSION_2}" }}
            }}"#
        ),
    );

    let output = install(&project, &mock, &["--force"]);
    assert!(
        !output.status.success(),
        "no-downgrade must block invalid provenance even when verification normally warns:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("trust-policy no-downgrade")
            && combined.contains(PACKAGE)
            && combined.contains(VERSION_2),
        "failure must identify the rejected provenance downgrade: {combined}"
    );
}

#[tokio::test]
async fn no_downgrade_blocks_disabled_verification_after_verified_history() {
    let project = project_for_version(VERSION_1);
    let mock = MockRegistry::start().await;
    configure_custom_registry(&project, &mock);
    mount_package_versions(
        &mock,
        &[
            (VERSION_1, Attestation::Absent),
            (VERSION_2, Attestation::InvalidBundle),
        ],
    )
    .await;
    let initial = install(&project, &mock, &[]);
    assert!(initial.status.success(), "initial install must succeed");
    seed_verified_lockfile_evidence(&project, VERSION_1);
    write_sigstore_config(&project, None, None, Some("no-downgrade"), Some("off"));
    write_signed_unlock(&project, &["provenance-unverified"]);
    project.write_file(
        "package.json",
        &format!(
            r#"{{
                "name": "provenance-lockfile-test",
                "version": "1.0.0",
                "dependencies": {{ "{PACKAGE}": "{VERSION_2}" }}
            }}"#
        ),
    );

    let output = install(&project, &mock, &["--force"]);
    assert!(
        !output.status.success(),
        "no-downgrade must block disabled verification after verified history:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("trust-policy no-downgrade")
            && combined.contains(PACKAGE)
            && combined.contains(VERSION_2),
        "failure must identify the disabled-verification downgrade: {combined}"
    );
}

#[tokio::test]
async fn no_downgrade_blocks_package_verification_skip_after_verified_history() {
    let project = project_for_version(VERSION_1);
    let mock = MockRegistry::start().await;
    configure_custom_registry(&project, &mock);
    mount_package_versions(
        &mock,
        &[
            (VERSION_1, Attestation::Absent),
            (VERSION_2, Attestation::InvalidBundle),
        ],
    )
    .await;
    let initial = install(&project, &mock, &[]);
    assert!(initial.status.success(), "initial install must succeed");
    seed_verified_lockfile_evidence(&project, VERSION_1);
    write_sigstore_config(&project, None, None, Some("no-downgrade"), None);
    write_signed_unlock(&project, &["provenance-unverified"]);
    project.write_file(
        "package.json",
        &format!(
            r#"{{
                "name": "provenance-lockfile-test",
                "version": "1.0.0",
                "dependencies": {{ "{PACKAGE}": "{VERSION_2}" }}
            }}"#
        ),
    );

    let output = install(
        &project,
        &mock,
        &["--force", "--unverified-provenance", PACKAGE],
    );
    assert!(
        !output.status.success(),
        "no-downgrade must block a package verification skip after verified history:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("trust-policy no-downgrade")
            && combined.contains(PACKAGE)
            && combined.contains(VERSION_2),
        "failure must identify the explicitly skipped provenance downgrade: {combined}"
    );
}
