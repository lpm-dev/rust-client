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

// ─── Phase 2.2 SILENT-DROP regression guards ──────────────────────────

/// Mount a scripted package whose `dist.attestations.url` points at an
/// unverifiable (structurally-valid v0.2 minimal) Sigstore bundle. The
/// post-Phase-2.1 verifier rejects these on the dsseEnvelope /
/// tlogEntries pre-flight, so the bundle reaches `approve-scripts`
/// only via `fetch_provenance_for_pkgs` and the verifier signal IS
/// the SILENT-DROP regression's load-bearing input.
///
/// Bypasses `MockRegistry::with_package` deliberately — that helper
/// mounts a basic metadata document WITHOUT an `attestations` URL,
/// and a second metadata mount on the same path doesn't reliably
/// take precedence (wiremock picks the first matching mock). Here
/// we mount the metadata directly on all three paths
/// (`/api/registry/{name}` LPM proxy, `/{name}` npm direct, and
/// the batch POST endpoint) with attestations included from the
/// start, plus the tarball + the unverifiable bundle endpoint.
async fn mount_scripted_pkg_with_unverifiable_bundle(
    mock: &MockRegistry,
    name: &str,
    version: &str,
) {
    use support::mock_registry::{compute_integrity, make_tarball_from_pkg_json};

    let pkg_json = serde_json::json!({
        "name": name,
        "version": version,
        "license": "MIT",
        "main": "index.js",
        "scripts": { "postinstall": "node -e \"process.exit(0)\"" },
    });
    let tarball = make_tarball_from_pkg_json(pkg_json, &[]);

    let att_url = format!("{}/-/attestations/{name}@{version}", mock.url());
    let tarball_url = format!("{}/tarballs/{name}/-/{name}-{version}.tgz", mock.url());
    let integrity = compute_integrity(&tarball);

    let metadata = serde_json::json!({
        "name": name,
        "dist-tags": { "latest": version },
        "versions": {
            version: {
                "name": name,
                "version": version,
                "scripts": { "postinstall": "node -e \"process.exit(0)\"" },
                "dist": {
                    "tarball": tarball_url,
                    "integrity": integrity,
                    "attestations": {
                        "url": att_url,
                        "provenance": { "predicateType": "https://slsa.dev/provenance/v1" }
                    },
                },
                "dependencies": {}
            }
        },
        "time": { version: "2025-01-01T00:00:00.000Z" }
    });

    let server = mock.server();

    // LPM proxy path (Proxy mode).
    Mock::given(method("GET"))
        .and(path(format!("/api/registry/{name}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(metadata.clone()))
        .mount(server)
        .await;

    // npm direct path (Direct mode). Either resolution mode hits one.
    Mock::given(method("GET"))
        .and(path(format!("/{name}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(metadata.clone()))
        .mount(server)
        .await;

    // Batch metadata POST — the resolver uses this for the install path.
    mock.with_batch_metadata(vec![metadata]).await;

    // Tarball.
    Mock::given(method("GET"))
        .and(path(format!("/tarballs/{name}/-/{name}-{version}.tgz")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_bytes(tarball)
                .insert_header("content-type", "application/octet-stream"),
        )
        .mount(server)
        .await;

    // Unverifiable bundle — structurally-valid v0.2 minimal shape.
    // Post-Phase-2.1 the verifier rejects this at the dsseEnvelope /
    // tlogEntries pre-flight, which is exactly the rejection variant
    // the SILENT-DROP fix needs.
    let bundle = sigstore_bundle_for_identity(
        "github:attacker/forged",
        ".github/workflows/build.yml",
        "refs/tags/v1.0.0",
    );
    Mock::given(method("GET"))
        .and(path(format!("/-/attestations/{name}@{version}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(bundle))
        .mount(server)
        .await;
}

/// **Phase 2.2.a SILENT-DROP regression guard — default deny path.**
///
/// Pre-fix, `fetch_provenance_for_pkgs` collapsed
/// `Err(LpmError::ProvenanceVerification)` into `None` via
/// `.ok().flatten()`. The approve-scripts capture path then recorded
/// `provenance_at_approval: None`, and every subsequent install's
/// drift comparator read that `None` and degraded to `NoDrift` —
/// permanently disarming publisher-swap detection after one
/// attack-window approval.
///
/// Post-fix, under the default `EnforceMode::Deny` posture, an
/// unverifiable bundle MUST refuse the approval rather than silently
/// blank the binding. This test pins:
/// 1. `lpm approve-scripts --yes` exits non-zero
/// 2. The error names the package + the `provenance_verification`
///    diagnostic code so the user has actionable diagnostics
/// 3. The manifest's `trustedDependencies` field stays absent or
///    empty (no `provenance_at_approval: None` smuggled in)
#[tokio::test]
async fn approve_scripts_refuses_under_deny_when_verifier_rejects_bundle() {
    let dep = "scripted-pkg-deny";
    let project = TempProject::empty(&format!(
        r#"{{"name":"silent-drop-deny","version":"1.0.0","dependencies":{{"{dep}":"^1.0.0"}}}}"#
    ));
    let mock = MockRegistry::start().await;
    mount_scripted_pkg_with_unverifiable_bundle(&mock, dep, "1.0.0").await;

    // Install succeeds: default-deny on scripts means the scripted
    // package goes to the blocked set without running its postinstall.
    let install_out = lpm_with_registry(&project, &mock.url())
        .args(["install"])
        .output()
        .expect("spawn lpm install");
    assert!(
        install_out.status.success(),
        "install with default-deny on a scripted package must succeed (scripts deferred)\n\
         stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&install_out.stdout),
        String::from_utf8_lossy(&install_out.stderr),
    );

    // Approve-scripts MUST refuse: the verifier rejects the served
    // bundle, the typed `LpmError::ProvenanceVerification` propagates,
    // and the approval is short-circuited before any trust-store
    // mutation. No env override — this is the default posture.
    //
    // Uses the per-package approval path
    // (`lpm approve-scripts <pkg>`), not `--yes`, because `--yes` has
    // a separate `enforce_tiered_yes_gate` refusal for non-green tier
    // scripts (the postinstall `node -e "process.exit(0)"` shape
    // classifies as Red under the hand-curated blocklist). The
    // per-package path skips that gate, so the only refusal it can
    // emit is the verifier rejection we're pinning here.
    let approve_out = lpm_with_registry(&project, &mock.url())
        .args(["approve-scripts", dep])
        .output()
        .expect("spawn lpm approve-scripts <pkg>");

    assert!(
        !approve_out.status.success(),
        "approve-scripts MUST refuse under default deny when the verifier rejects;\n\
         stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&approve_out.stdout),
        String::from_utf8_lossy(&approve_out.stderr),
    );

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&approve_out.stdout),
        String::from_utf8_lossy(&approve_out.stderr),
    );
    assert!(
        combined.contains(dep),
        "refusal error must name the package; got:\n{combined}",
    );
    assert!(
        combined.contains("provenance") && combined.contains("verif"),
        "refusal error must surface as a verification-class diagnostic; got:\n{combined}",
    );

    // Critical regression assertion: the manifest's
    // trustedDependencies must NOT have grown a binding with
    // `provenanceAtApproval: null`. Pre-fix, this was the SILENT-DROP
    // smuggling vector — a null provenance reference that disarmed
    // the drift gate for every future install.
    let manifest_str = project.read_file("package.json");
    let manifest: serde_json::Value = serde_json::from_str(&manifest_str).unwrap();
    let trusted = manifest
        .get("lpm")
        .and_then(|v| v.get("trustedDependencies"));
    if let Some(tdeps) = trusted {
        // If the field exists (legacy preserve key writes can land
        // even on refused approvals in some paths), the binding for
        // our package MUST NOT have a provenanceAtApproval present
        // — null is exactly what the SILENT-DROP would have written.
        if let Some(obj) = tdeps.as_object() {
            for (key, binding) in obj {
                if key.starts_with(&format!("{dep}@")) {
                    let pa = binding.get("provenanceAtApproval");
                    assert!(
                        pa.is_none(),
                        "binding for {key} must NOT carry a `provenanceAtApproval` field — \
                         that's the SILENT-DROP smuggling vector this fix closes. Got:\n\
                         {binding:#?}",
                    );
                }
            }
        }
    }
}

/// **Phase 2.2.b warn-mode regression guard.**
///
/// Under `LPM_PROVENANCE_ENFORCE=warn`, an unverifiable bundle MUST
/// emit a loud warning but allow the approval through. The binding
/// records `provenance_at_approval: None` (today's
/// transport-degrade shape), but the drift gate's load-bearing
/// behavior — the `is_some()` filter in
/// `provenance_reference_for_name` — means a later install with a
/// prior valid binding for the same package would still see that
/// prior identity as the drift reference.
///
/// This test pins the user-facing contract:
/// 1. `lpm approve-scripts --yes` exits zero under warn
/// 2. stderr/stdout contains the `provenance verification FAILED`
///    warn line naming the package + verifier reason
/// 3. The recovery hint mentions `LPM_PROVENANCE_ENFORCE=deny`
#[tokio::test]
async fn approve_scripts_under_warn_logs_and_proceeds_when_verifier_rejects() {
    let dep = "scripted-pkg-warn";
    let project = TempProject::empty(&format!(
        r#"{{"name":"silent-drop-warn","version":"1.0.0","dependencies":{{"{dep}":"^1.0.0"}}}}"#
    ));
    let mock = MockRegistry::start().await;
    mount_scripted_pkg_with_unverifiable_bundle(&mock, dep, "1.0.0").await;

    let _ = lpm_with_registry(&project, &mock.url())
        .args(["install"])
        .output()
        .expect("spawn lpm install");

    // Warn-mode opt-in. The env knob is per-invocation so the test
    // doesn't mutate process-global state. Per-package approve flow
    // for the same reason as the deny test — skip the tier-yes gate
    // so the verifier-rejection is the only refusal under test.
    let approve_out = lpm_with_registry(&project, &mock.url())
        .env("LPM_PROVENANCE_ENFORCE", "warn")
        .args(["approve-scripts", dep])
        .output()
        .expect("spawn lpm approve-scripts <pkg> under warn mode");

    assert!(
        approve_out.status.success(),
        "approve-scripts under LPM_PROVENANCE_ENFORCE=warn must succeed (non-blocking);\n\
         stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&approve_out.stdout),
        String::from_utf8_lossy(&approve_out.stderr),
    );

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&approve_out.stdout),
        String::from_utf8_lossy(&approve_out.stderr),
    );
    assert!(
        combined.contains("provenance verification FAILED")
            || combined.contains("provenance verification failed"),
        "warn mode must emit a loud rejection notice (case-insensitive); got:\n{combined}",
    );
    assert!(
        combined.contains(dep),
        "warn notice must name the package; got:\n{combined}",
    );
    assert!(
        combined.contains("LPM_PROVENANCE_ENFORCE=deny"),
        "warn notice must point at the deny re-enable knob so operators know how to tighten back \
         to fail-closed; got:\n{combined}",
    );
}

// ─── Install drift gate: warn / skip-flag composition pins ───────────

/// Setup helper: project carries a rich-form approval for `PKG`, and
/// the mock registry serves the candidate's attestation URL with an
/// unverifiable bundle (minimal v0.2 shape — the verifier hard-fails
/// on the dsseEnvelope / tlogEntries pre-flight). Mirrors the shape
/// used by `setup_identity_changed` but with a verifier-rejecting
/// bundle as the on-purpose feature.
async fn setup_install_drift_gate_with_verifier_rejecting_candidate() -> (TempProject, MockRegistry)
{
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
            workflow_ref: "refs/tags/v1.0.1",
        }),
    )
    .await;
    (project, mock)
}

/// Under default `EnforceMode::Deny`, an install-time verifier
/// rejection refuses the install — `?`-propagates the typed
/// `LpmError::ProvenanceVerification` so the user sees a real
/// diagnostic rather than silently weakening drift detection. This
/// is the load-bearing baseline that the warn-mode degrade test
/// below contrasts against.
#[tokio::test]
async fn install_drift_gate_under_deny_blocks_when_verifier_rejects_bundle() {
    let (project, mock) = setup_install_drift_gate_with_verifier_rejecting_candidate().await;
    let out = lpm_with_registry(&project, &mock.url())
        .args(["install"])
        .output()
        .expect("spawn lpm install");
    assert!(
        !out.status.success(),
        "Deny + verifier rejection MUST block the install — \
         silent acceptance would let a forged bundle through;\n\
         stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(
        combined.contains("provenance"),
        "rejection diagnostic must surface the 'provenance' subsystem so operators can \
         find the failed gate; got:\n{combined}",
    );
}

/// Under `LPM_PROVENANCE_ENFORCE=warn`, an install-time verifier
/// rejection on a rich-form-bound package MUST NOT block the
/// install. The drift gate degrades to NoDrift, emits a loud
/// `output::warn`, and the install proceeds. This is the rollout-
/// window posture: ship the verifier in warn mode for one release
/// so a bundle-shape change at the registry surfaces as a log
/// line, not a CI nuke.
///
/// Contrasts directly with the Deny baseline above: same fixture,
/// same bundle, only the env knob differs.
#[tokio::test]
async fn install_drift_gate_under_enforce_warn_does_not_block_on_verifier_rejection() {
    let (project, mock) = setup_install_drift_gate_with_verifier_rejecting_candidate().await;
    let out = lpm_with_registry(&project, &mock.url())
        .env("LPM_PROVENANCE_ENFORCE", "warn")
        .args(["install"])
        .output()
        .expect("spawn lpm install under LPM_PROVENANCE_ENFORCE=warn");

    assert!(
        out.status.success(),
        "Warn mode MUST NOT block the install on verifier rejection (rollout-window \
         contract); stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(
        !drift_block_message_present(&out),
        "drift block message must NOT appear under warn mode; got:\n{combined}",
    );
    assert!(
        combined.contains("provenance verification FAILED"),
        "warn mode MUST emit the loud `provenance verification FAILED` line so the \
         operator sees the degraded posture; got:\n{combined}",
    );
    assert!(
        combined.contains(PKG),
        "warn line must name the package whose bundle was rejected so operators can \
         track which dependency to remediate; got:\n{combined}",
    );
    assert!(
        combined.contains("LPM_PROVENANCE_ENFORCE=deny"),
        "warn line must point at the re-enable command so operators can tighten back \
         to fail-closed; got:\n{combined}",
    );
}

/// The two verification-policy axes (`EnforceMode` and
/// `SkipPolicy`) MUST compose orthogonally:
/// `LPM_PROVENANCE_ENFORCE=warn` + `--unverified-provenance <pkg>`
/// on the same invocation means "warn-mode for the rest of the
/// install, skip verification entirely for the named package."
///
/// Pinned via a side-effect contrast: the skip-listed package's
/// rejection log line is ABSENT from stderr (because the verifier
/// never ran for it) — that's the orthogonality signal. If the two
/// axes collapsed (e.g. warn-mode also short-circuited the skip-
/// list logic), the warn line would still fire and this test
/// would catch it.
///
/// Unit test `verify_policy_should_skip_verification_unifies_skip_and_off`
/// pins the policy-decision side; this is the end-to-end pin that
/// guards against the install pipeline ignoring the skip-list
/// under warn mode.
#[tokio::test]
async fn install_skip_flag_short_circuits_verifier_under_enforce_warn() {
    let (project, mock) = setup_install_drift_gate_with_verifier_rejecting_candidate().await;
    let out = lpm_with_registry(&project, &mock.url())
        .env("LPM_PROVENANCE_ENFORCE", "warn")
        .args(["install", "--unverified-provenance", PKG])
        .output()
        .expect("spawn lpm install with both env-warn and skip-flag");

    assert!(
        out.status.success(),
        "Warn + skip MUST succeed; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(
        !drift_block_message_present(&out),
        "drift block message must NOT appear; got:\n{combined}",
    );
    // The orthogonality signal: under skip-listed routing, the
    // verifier never runs, so the warn-mode rejection line MUST NOT
    // fire. If the two axes collapsed (warn-mode forces verification
    // to run regardless of skip-list), this line would appear.
    assert!(
        !combined.contains("provenance verification FAILED"),
        "skip-listed package must NOT trigger the warn-mode verifier-rejection line — \
         the skip path bypasses the verifier entirely. Presence of this line means \
         the SkipPolicy axis collapsed into the EnforceMode axis (orthogonality \
         contract broken); got:\n{combined}",
    );
}
