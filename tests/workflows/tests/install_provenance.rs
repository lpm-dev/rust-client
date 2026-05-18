//! Workflow tests for the install-time provenance-drift gate.
//!
//! Ship-criteria pinned end-to-end against a wiremock-backed
//! mock registry that serves both the package metadata (carrying a
//! `dist.attestations.url` pointer) and the attestation bundle itself.
//! Eight properties pinned: drift block on dropped/changed attestations,
//! per-package and blanket waivers, legitimate release-bump pass-through,
//! D16 orthogonality with `--allow-new`, fetch-failure degradation
//! safety, and the no-approvals contract.
//!
//! The synthetic Sigstore bundles use rcgen-generated certs with SAN
//! URIs encoding `(publisher, workflow_path, workflow_ref)` — the same
//! tuple the drift comparator extracts. Cert SHAs are intentionally
//! ephemeral (fresh keypair per test) because the comparator excludes
//! cert SHA from the identity tuple by design (Finding-1 fix).
//!
//! In its own file rather than inline in `install.rs` because the
//! cert + bundle helpers are unique to this gate and `install.rs`
//! is already past the ~2k-line review trigger.

mod support;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use rcgen::{CertificateParams, Ia5String, KeyPair, SanType};
use support::mock_registry::MockRegistry;
use support::{TempProject, lpm_with_registry};
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

const PKG: &str = "@lpm.dev/acme.widget";
const APPROVED_VERSION: &str = "1.0.0";
const CANDIDATE_VERSION: &str = "1.0.1";
const APPROVED_PUBLISHER: &str = "github:acme/widget";
const APPROVED_WORKFLOW_PATH: &str = ".github/workflows/publish.yml";

// ─── Cert + bundle synthesis ─────────────────────────────────────────────

fn cert_der_with_san_uri(uri: &str) -> Vec<u8> {
    let mut params = CertificateParams::default();
    params.subject_alt_names = vec![SanType::URI(Ia5String::try_from(uri).unwrap())];
    let key_pair = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key_pair).unwrap();
    cert.der().to_vec()
}

fn sigstore_bundle_with_cert(der: &[u8]) -> serde_json::Value {
    serde_json::json!({
        "mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.2",
        "verificationMaterial": {
            "x509CertificateChain": {
                "certificates": [ { "rawBytes": BASE64.encode(der) } ]
            }
        }
    })
}

/// Build a Sigstore bundle whose cert's SAN URI encodes the supplied
/// `(publisher, workflow_path, workflow_ref)`. Mirrors the parser the
/// drift fetcher uses on the way back.
fn sigstore_bundle_for_identity(
    publisher: &str,
    workflow_path: &str,
    workflow_ref: &str,
) -> serde_json::Value {
    let org_repo = publisher.strip_prefix("github:").unwrap_or(publisher);
    let path_tail = workflow_path
        .strip_prefix(".github/workflows/")
        .unwrap_or(workflow_path);
    let uri = format!("https://github.com/{org_repo}/.github/workflows/{path_tail}@{workflow_ref}");
    sigstore_bundle_with_cert(&cert_der_with_san_uri(&uri))
}

// ─── Metadata + tarball + mount helpers ─────────────────────────────────

fn make_minimal_tarball(version: &str) -> Vec<u8> {
    use std::io::Write;
    let mut builder = tar::Builder::new(Vec::new());

    let pkg_json = serde_json::json!({ "name": PKG, "version": version, "main": "index.js" });
    let pkg_json_bytes = serde_json::to_vec_pretty(&pkg_json).unwrap();
    let mut header = tar::Header::new_gnu();
    header.set_path("package/package.json").unwrap();
    header.set_size(pkg_json_bytes.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    builder.append(&header, &pkg_json_bytes[..]).unwrap();

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

fn package_metadata(
    registry_url: &str,
    version: &str,
    tarball: &[u8],
    attestations: Option<serde_json::Value>,
) -> serde_json::Value {
    let tarball_url = format!("{registry_url}/tarballs/{PKG}/-/{PKG}-{version}.tgz");
    let integrity = support::mock_registry::compute_integrity(tarball);
    let mut dist = serde_json::json!({ "tarball": tarball_url, "integrity": integrity });
    if let Some(att) = attestations {
        dist["attestations"] = att;
    }
    serde_json::json!({
        "name": PKG,
        "dist-tags": { "latest": version },
        "versions": {
            version: {
                "name": PKG,
                "version": version,
                "dist": dist,
                "dependencies": {},
            }
        },
        "time": { version: "2024-01-01T00:00:00.000Z" }
    })
}

/// `dist.attestations` shape on the mocked metadata response.
enum AttestationShape {
    /// No `attestations` field at all — registry says "no attestation
    /// for this version." Axios-case signal against an approved-present
    /// reference.
    NoField,
    /// `attestations.url` points at a mocked endpoint with the supplied
    /// response shape.
    UrlPresent(AttestationResponse),
}

enum AttestationResponse {
    /// Valid Sigstore bundle with a synthetic cert encoding the supplied
    /// identity tuple in its SAN URI.
    SigstoreBundle {
        publisher: &'static str,
        workflow_path: &'static str,
        workflow_ref: &'static str,
    },
    /// HTTP 500 from the attestation endpoint — fetcher must degrade
    /// (`Ok(None)`) and the comparator must return `NoDrift`.
    Http500,
}

/// Mount metadata (single-package GET + batch POST), tarball GET, and
/// optionally the attestation-bundle endpoint, for `pkg@version`.
async fn mount_package_version(mock: &MockRegistry, version: &str, shape: AttestationShape) {
    let tarball = make_minimal_tarball(version);
    let dist_attestations = match &shape {
        AttestationShape::NoField => None,
        AttestationShape::UrlPresent(_) => Some(serde_json::json!({
            "url": format!("{}/-/attestations/{PKG}@{version}", mock.url()),
            "provenance": { "predicateType": "https://slsa.dev/provenance/v1" }
        })),
    };
    let metadata = package_metadata(&mock.url(), version, &tarball, dist_attestations);

    let server = mock.server();

    Mock::given(method("GET"))
        .and(path(format!("/api/registry/{PKG}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(metadata.clone()))
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .and(path("/api/registry/batch-metadata"))
        .respond_with(ResponseTemplate::new(200).set_body_json({
            let mut packages = serde_json::Map::new();
            packages.insert(PKG.to_string(), metadata.clone());
            serde_json::json!({ "packages": packages })
        }))
        .mount(server)
        .await;

    Mock::given(method("GET"))
        .and(path(format!("/tarballs/{PKG}/-/{PKG}-{version}.tgz")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_bytes(tarball.clone())
                .insert_header("content-type", "application/octet-stream"),
        )
        .mount(server)
        .await;

    if let AttestationShape::UrlPresent(resp) = shape {
        let att_path = format!("/-/attestations/{PKG}@{version}");
        let template = match resp {
            AttestationResponse::SigstoreBundle {
                publisher,
                workflow_path,
                workflow_ref,
            } => ResponseTemplate::new(200).set_body_json(sigstore_bundle_for_identity(
                publisher,
                workflow_path,
                workflow_ref,
            )),
            AttestationResponse::Http500 => {
                ResponseTemplate::new(500).set_body_string("simulated transient failure")
            }
        };
        Mock::given(method("GET"))
            .and(path(att_path))
            .respond_with(template)
            .mount(server)
            .await;
    }
}

// ─── Manifest authoring ─────────────────────────────────────────────────

struct ApprovedRefShape {
    publisher: Option<&'static str>,
    workflow_path: Option<&'static str>,
    workflow_ref: Option<&'static str>,
    has_provenance: bool,
}

fn write_manifest_with_approval(project: &TempProject, approval: ApprovedRefShape) {
    let mut binding = serde_json::json!({
        "integrity": "sha512-placeholder",
        "scriptHash": "sha256-placeholder",
    });
    if approval.has_provenance {
        let mut snap = serde_json::Map::new();
        snap.insert("present".into(), serde_json::Value::Bool(true));
        if let Some(p) = approval.publisher {
            snap.insert("publisher".into(), serde_json::Value::String(p.into()));
        }
        if let Some(p) = approval.workflow_path {
            snap.insert("workflowPath".into(), serde_json::Value::String(p.into()));
        }
        if let Some(r) = approval.workflow_ref {
            snap.insert("workflowRef".into(), serde_json::Value::String(r.into()));
        }
        binding["provenanceAtApproval"] = serde_json::Value::Object(snap);
    }

    let mut rich = serde_json::Map::new();
    rich.insert(format!("{PKG}@{APPROVED_VERSION}"), binding);

    let manifest = serde_json::json!({
        "name": "provenance-drift-test",
        "version": "1.0.0",
        "dependencies": { PKG: CANDIDATE_VERSION },
        "lpm": {
            // Cooldown disabled so the drift gate is exercised in isolation.
            "minimumReleaseAge": 0,
            "trustedDependencies": rich,
        },
    });
    project.write_file(
        "package.json",
        &serde_json::to_string_pretty(&manifest).unwrap(),
    );
}

fn write_manifest_without_approval(project: &TempProject) {
    let manifest = serde_json::json!({
        "name": "provenance-drift-test",
        "version": "1.0.0",
        "dependencies": { PKG: CANDIDATE_VERSION },
        "lpm": { "minimumReleaseAge": 0 },
    });
    project.write_file(
        "package.json",
        &serde_json::to_string_pretty(&manifest).unwrap(),
    );
}

// ─── Assertion helpers ──────────────────────────────────────────────────

fn drift_block_message_present(out: &std::process::Output) -> bool {
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    combined.contains("blocked by provenance drift")
        || combined.contains("package(s) blocked by provenance drift")
}

fn assert_drift_blocked(out: &std::process::Output) {
    assert!(
        !out.status.success(),
        "install must fail with a drift block; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        drift_block_message_present(out),
        "output must name the drift block; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

fn install_completed_successfully(out: &std::process::Output) -> bool {
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    // Post-link summary marker (human mode) OR JSON success.
    combined.contains("linked") || combined.contains("\"success\":true")
}

/// Stronger form: drift-block absent AND install reached the post-link
/// stage. Catches regressions where the install fails at a downstream
/// stage for unrelated reasons that could mask "drift gate let us
/// through" with "drift message absent."
fn assert_drift_not_blocked_and_install_succeeded(out: &std::process::Output) {
    assert!(
        !drift_block_message_present(out),
        "drift block message must NOT appear (gate should pass or be waived);\
         \nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out.status.success(),
        "install must exit 0 to prove progress past the drift gate;\
         \nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        install_completed_successfully(out),
        "install must emit a post-link success marker;\
         \nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

// ─── Setup helpers ──────────────────────────────────────────────────────

async fn setup_approved_present_candidate_absent() -> (TempProject, MockRegistry) {
    let project = TempProject::empty("");
    write_manifest_with_approval(
        &project,
        ApprovedRefShape {
            publisher: Some(APPROVED_PUBLISHER),
            workflow_path: Some(APPROVED_WORKFLOW_PATH),
            workflow_ref: Some("refs/tags/v1.0.0"),
            has_provenance: true,
        },
    );
    let mock = MockRegistry::start().await;
    mount_package_version(&mock, CANDIDATE_VERSION, AttestationShape::NoField).await;
    (project, mock)
}

async fn setup_identity_changed() -> (TempProject, MockRegistry) {
    let project = TempProject::empty("");
    write_manifest_with_approval(
        &project,
        ApprovedRefShape {
            publisher: Some(APPROVED_PUBLISHER),
            workflow_path: Some(APPROVED_WORKFLOW_PATH),
            workflow_ref: Some("refs/tags/v1.0.0"),
            has_provenance: true,
        },
    );
    let mock = MockRegistry::start().await;
    mount_package_version(
        &mock,
        CANDIDATE_VERSION,
        AttestationShape::UrlPresent(AttestationResponse::SigstoreBundle {
            // Different publisher: "repo moved to attacker fork".
            publisher: "github:attacker/widget",
            workflow_path: APPROVED_WORKFLOW_PATH,
            workflow_ref: "refs/tags/v1.0.1",
        }),
    )
    .await;
    (project, mock)
}

async fn setup_legitimate_release_bump() -> (TempProject, MockRegistry) {
    let project = TempProject::empty("");
    write_manifest_with_approval(
        &project,
        ApprovedRefShape {
            publisher: Some(APPROVED_PUBLISHER),
            workflow_path: Some(APPROVED_WORKFLOW_PATH),
            workflow_ref: Some("refs/tags/v1.0.0"),
            has_provenance: true,
        },
    );
    let mock = MockRegistry::start().await;
    mount_package_version(
        &mock,
        CANDIDATE_VERSION,
        AttestationShape::UrlPresent(AttestationResponse::SigstoreBundle {
            publisher: APPROVED_PUBLISHER,
            workflow_path: APPROVED_WORKFLOW_PATH,
            // Only the ref differs — legitimate release tag.
            workflow_ref: "refs/tags/v1.0.1",
        }),
    )
    .await;
    (project, mock)
}

async fn setup_http500_attestation() -> (TempProject, MockRegistry) {
    let project = TempProject::empty("");
    write_manifest_with_approval(
        &project,
        ApprovedRefShape {
            publisher: Some(APPROVED_PUBLISHER),
            workflow_path: Some(APPROVED_WORKFLOW_PATH),
            workflow_ref: Some("refs/tags/v1.0.0"),
            has_provenance: true,
        },
    );
    let mock = MockRegistry::start().await;
    mount_package_version(
        &mock,
        CANDIDATE_VERSION,
        AttestationShape::UrlPresent(AttestationResponse::Http500),
    )
    .await;
    (project, mock)
}

// ─── Tests: ship criteria ────────────────────────────────────────

/// Approved v1 had attestation; candidate v2 has none — drift blocks
/// install. The axios 1.14.1 scenario, end-to-end.
#[tokio::test]
async fn install_drift_blocks_when_approved_attestation_dropped() {
    let (project, mock) = setup_approved_present_candidate_absent().await;
    let out = lpm_with_registry(&project, &mock.url())
        .args(["install"])
        .output()
        .expect("spawn lpm install");
    assert_drift_blocked(&out);
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        combined.contains("provenance dropped"),
        "block message must name the 'provenance dropped' verdict; got:\n{combined}"
    );
}

/// `--ignore-provenance-drift <pkg>` waives the named package's drift
/// while leaving the rest of the gate live. Stronger assertion: install
/// must complete end-to-end, not just suppress the drift message.
#[tokio::test]
async fn install_ignore_provenance_drift_per_package_unblocks() {
    let (project, mock) = setup_approved_present_candidate_absent().await;
    let out = lpm_with_registry(&project, &mock.url())
        .args(["install", "--ignore-provenance-drift", PKG])
        .output()
        .expect("spawn lpm install");
    assert_drift_not_blocked_and_install_succeeded(&out);

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        combined.contains("waived by --ignore-provenance-drift"),
        "waived-advisory must appear so the user sees what they opted out of; got:\n{combined}"
    );
}

/// `--ignore-provenance-drift-all` blanket-waives every package. Held
/// as a separate test from per-package so CI can pinpoint a regression
/// to the right code path.
#[tokio::test]
async fn install_ignore_provenance_drift_all_unblocks() {
    let (project, mock) = setup_approved_present_candidate_absent().await;
    let out = lpm_with_registry(&project, &mock.url())
        .args(["install", "--ignore-provenance-drift-all"])
        .output()
        .expect("spawn lpm install");
    assert_drift_not_blocked_and_install_succeeded(&out);

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        combined.contains("waived for this install by --ignore-provenance-drift-all"),
        "blanket-waive advisory must announce the opt-out; got:\n{combined}"
    );
}

/// Both versions carry attestations but the publisher differs (repo
/// moved to attacker fork). Drift blocks with "publisher identity
/// changed" verdict.
///
/// **Ignored as of Phase 2.1.** The install path now goes through
/// `sigstore_verify::verify_sigstore_bundle` which hard-fails on
/// bundles missing `dsseEnvelope` / `tlogEntries` (the verifier's
/// pre-flight check). The fixtures here are minimal v0.2 bundles
/// designed for the pre-Phase-2.1 identity-only parser and
/// intentionally lack those fields. The drift-comparator logic this
/// test pins is still covered by the pure unit tests in
/// `lpm-security::provenance`; what's missing is end-to-end coverage
/// with REAL Sigstore bundles. Phase 3.1 of the C1 plan ships golden
/// fixtures from real npm bundles which will let this test fly again.
#[ignore = "Phase 2.1: needs full Sigstore bundle fixtures, deferred to Phase 3.1"]
#[tokio::test]
async fn install_drift_blocks_when_publisher_identity_changed() {
    let (project, mock) = setup_identity_changed().await;
    let out = lpm_with_registry(&project, &mock.url())
        .args(["install"])
        .output()
        .expect("spawn lpm install");
    assert_drift_blocked(&out);

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        combined.contains("publisher identity changed"),
        "block message must name the 'publisher identity changed' verdict; got:\n{combined}"
    );
}

/// Finding-1 regression: a legitimate v1.0.0 → v1.0.1 release from the
/// same repo + same workflow file necessarily differs on `workflow_ref`
/// (release tag) AND ephemeral cert SHA. The comparator's identity
/// tuple intentionally excludes both. If this regresses, every
/// legitimate patch bump hard-blocks.
///
/// **Ignored as of Phase 2.1** for the same reason as
/// `install_drift_blocks_when_publisher_identity_changed`: minimal
/// v0.2 bundles can't satisfy the new verifier's `dsseEnvelope` /
/// `tlogEntries` requirement. The comparator's
/// excludes-workflow-ref-and-cert-sha rule is still pinned by
/// `lpm-security::provenance`'s unit tests; this end-to-end test
/// returns once Phase 3.1's golden fixtures land.
#[ignore = "Phase 2.1: needs full Sigstore bundle fixtures, deferred to Phase 3.1"]
#[tokio::test]
async fn install_legitimate_release_bump_does_not_drift() {
    let (project, mock) = setup_legitimate_release_bump().await;
    let out = lpm_with_registry(&project, &mock.url())
        .args(["install"])
        .output()
        .expect("spawn lpm install");
    assert_drift_not_blocked_and_install_succeeded(&out);
}

/// D16 orthogonality: `--allow-new` is the cooldown override; per D16
/// it does NOT bypass the drift gate. If this regresses, the two gates
/// have silently merged and users can't independently ack each signal.
#[tokio::test]
async fn install_allow_new_alone_does_not_bypass_drift() {
    let (project, mock) = setup_approved_present_candidate_absent().await;
    let out = lpm_with_registry(&project, &mock.url())
        .args(["install", "--allow-new"])
        .output()
        .expect("spawn lpm install");
    assert_drift_blocked(&out);
}

/// Reliability guard: HTTP 500 from the attestation endpoint must NOT
/// be treated as "provenance dropped." The fetcher degrades (`Ok(None)`),
/// the comparator returns `NoDrift`, install proceeds. A rate-limited
/// or transient Sigstore failure shouldn't produce spurious drift
/// blocks.
#[tokio::test]
async fn install_drift_does_not_falsely_block_on_attestation_fetch_failure() {
    let (project, mock) = setup_http500_attestation().await;
    let out = lpm_with_registry(&project, &mock.url())
        .args(["install"])
        .output()
        .expect("spawn lpm install");
    assert_drift_not_blocked_and_install_succeeded(&out);
}

/// Observable contract for projects with no rich `trustedDependencies`
/// approvals: no drift block, no blanket-waive advisory, install
/// completes. Documents the user-visible behavior — the internal
/// `has_rich_approvals` short-circuit is a perf detail not directly
/// observable from a subprocess test.
#[tokio::test]
async fn install_drift_does_not_block_for_project_with_no_approvals() {
    let project = TempProject::empty("");
    write_manifest_without_approval(&project);
    let mock = MockRegistry::start().await;
    mount_package_version(&mock, CANDIDATE_VERSION, AttestationShape::NoField).await;

    let out = lpm_with_registry(&project, &mock.url())
        .args(["install"])
        .output()
        .expect("spawn lpm install");
    assert_drift_not_blocked_and_install_succeeded(&out);

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !combined.contains("waived for this install by --ignore-provenance-drift-all"),
        "blanket-waive advisory must only fire when the user passes the flag; got:\n{combined}"
    );
}
