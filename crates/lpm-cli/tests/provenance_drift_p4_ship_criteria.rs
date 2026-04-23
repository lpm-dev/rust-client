//! Phase 46 P4 ship-criteria end-to-end tests.
//!
//! Exercises the full `lpm install` pipeline against a wiremock-backed
//! mock registry that serves BOTH the package metadata (with a
//! `dist.attestations.url` pointer) AND the attestation bundle itself,
//! to verify the §11 P4 drift gate + override flags land correctly at
//! the install-time check introduced in Chunk 3 / wired in Chunk 4.
//!
//! Covered:
//!
//! 1. Attestation deleted between approved v1 and candidate v2 →
//!    `ProvenanceDropped` block (axios 1.14.1 scenario).
//! 2. `--ignore-provenance-drift <pkg>` unblocks the specific name.
//! 3. `--ignore-provenance-drift-all` unblocks every package.
//! 4. Identity change (publisher or workflow_path) → `IdentityChanged`
//!    block.
//! 5. **Finding-1 E2E regression:** legitimate release bump (same
//!    publisher + workflow_path, different workflow_ref + cert SHA) →
//!    `NoDrift`, install proceeds.
//! 6. **D16 orthogonality guard:** `--allow-new` alone does NOT
//!    bypass drift (cooldown and provenance are orthogonal).
//! 7. **Degraded-fetch reliability guard:** attestation URL returns
//!    HTTP 500 → fetcher degrades to `Ok(None)`, comparator returns
//!    `NoDrift`, install proceeds. A network blip must never falsely
//!    claim drift.
//! 8. **No-approvals contract:** projects without any rich
//!    `trustedDependencies` entries neither block nor emit a
//!    blanket-waive advisory; install completes normally.
//!
//! ### Strong "unblocked" assertion (reviewer Finding 1 fix)
//!
//! Every "unblocked / no drift" test uses
//! `assert_drift_not_blocked_and_install_succeeded`, which checks
//! for both the absence of the drift-block message AND
//! `status.success()` AND a post-link completion marker in stdout.
//! A subprocess exiting non-zero for an unrelated reason cannot
//! masquerade as "drift gate let the install through" — the pipeline
//! must actually progress past the drift gate's downstream stages
//! (fetch + link) for the assertion to hold.
//!
//! Harness pattern lifted from `release_age_p3_ship_criteria.rs`:
//! start a `wiremock::MockServer`, spawn `lpm-rs` with
//! `LPM_REGISTRY_URL` pointed at the mock and `HOME` scoped to a
//! per-test temp dir. Two new pieces vs the P3 harness: (a) the
//! package metadata response carries `dist.attestations.url` pointing
//! at a second mock endpoint on the same server, (b) that endpoint
//! serves a synthetic Sigstore bundle with an rcgen-generated leaf
//! cert whose SAN URI encodes the desired `(publisher, workflow_path,
//! workflow_ref)`. The cert is ephemeral per test (fresh keypair) so
//! its SHA is not fixture-stable — which is fine; the drift comparator
//! explicitly excludes cert SHA from the identity tuple.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use rcgen::{CertificateParams, Ia5String, KeyPair, SanType};
use sha2::{Digest, Sha512};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const PACKAGE_NAME: &str = "@lpm.dev/acme.widget";
const APPROVED_VERSION: &str = "1.0.0";
const CANDIDATE_VERSION: &str = "1.0.1";

// Publisher + workflow_path used throughout — stable identity tuple.
const APPROVED_PUBLISHER: &str = "github:acme/widget";
const APPROVED_WORKFLOW_PATH: &str = ".github/workflows/publish.yml";

struct CommandOutput {
    status: ExitStatus,
    stdout: String,
    stderr: String,
}

struct MockRegistry {
    server: MockServer,
}

impl MockRegistry {
    async fn start() -> Self {
        Self {
            server: MockServer::start().await,
        }
    }

    fn url(&self) -> String {
        self.server.uri()
    }

    /// Attestation-bundle URL this test will embed in the metadata
    /// response. Kept on the same wiremock server for simplicity.
    fn attestation_url_for(&self, version: &str) -> String {
        format!("{}/-/attestations/{PACKAGE_NAME}@{version}", self.url())
    }

    /// Mount a single-version package. `attestation_shape` controls
    /// whether (and how) `dist.attestations` is populated — this is
    /// what the different ship-criteria tests vary.
    async fn mount_package_version(
        &self,
        version: &str,
        attestation_shape: AttestationShape,
    ) -> Vec<u8> {
        let tarball = make_minimal_tarball(version);
        let dist_attestations = match &attestation_shape {
            AttestationShape::NoField => None,
            AttestationShape::UrlPresent { .. } => Some(serde_json::json!({
                "url": self.attestation_url_for(version),
                "provenance": { "predicateType": "https://slsa.dev/provenance/v1" }
            })),
        };
        let metadata = package_metadata(&self.url(), version, &tarball, dist_attestations);

        // Single-package GET (also used by the P4 drift gate's
        // per-package metadata lookup to extract dist.attestations).
        Mock::given(method("GET"))
            .and(path(format!("/api/registry/{PACKAGE_NAME}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(metadata.clone()))
            .mount(&self.server)
            .await;

        // Batch-metadata POST (resolver's fresh-resolution path).
        Mock::given(method("POST"))
            .and(path("/api/registry/batch-metadata"))
            .respond_with(ResponseTemplate::new(200).set_body_json({
                let mut packages = serde_json::Map::new();
                packages.insert(PACKAGE_NAME.to_string(), metadata.clone());
                serde_json::json!({ "packages": packages })
            }))
            .mount(&self.server)
            .await;

        // Tarball GET.
        Mock::given(method("GET"))
            .and(path(tarball_path(version)))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_bytes(tarball.clone())
                    .insert_header("content-type", "application/octet-stream"),
            )
            .mount(&self.server)
            .await;

        // Attestation-bundle endpoint. Shape depends on what the
        // test is exercising.
        if let AttestationShape::UrlPresent { resp } = attestation_shape {
            let att_path = format!("/-/attestations/{PACKAGE_NAME}@{version}");
            let template = match resp {
                AttestationResponse::SigstoreBundle {
                    publisher,
                    workflow_path,
                    workflow_ref,
                } => {
                    // Reverse the SAN-URI parsing the drift fetcher
                    // does: `publisher = "github:<org>/<repo>"` →
                    // URI `https://github.com/<org>/<repo>/...`;
                    // `workflow_path = ".github/workflows/<file>"`
                    // → URI segment `<file>` after the
                    // `/.github/workflows/` delimiter. `workflow_ref`
                    // is appended with `@`.
                    let org_repo = publisher.strip_prefix("github:").unwrap_or(publisher);
                    let path_tail = workflow_path
                        .strip_prefix(".github/workflows/")
                        .unwrap_or(workflow_path);
                    let uri = format!(
                        "https://github.com/{org_repo}/.github/workflows/{path_tail}@{workflow_ref}",
                    );
                    let der = cert_der_with_san_uri(&uri);
                    ResponseTemplate::new(200).set_body_json(sigstore_bundle_with_cert(&der))
                }
                AttestationResponse::Http500 => {
                    ResponseTemplate::new(500).set_body_string("simulated transient failure")
                }
            };
            Mock::given(method("GET"))
                .and(path(att_path))
                .respond_with(template)
                .mount(&self.server)
                .await;
        }

        tarball
    }
}

/// How the metadata response's `dist.attestations` field is shaped.
enum AttestationShape {
    /// `dist.attestations` is absent — the registry says "no
    /// attestation for this version." This is the axios-case signal
    /// against an approved-present reference.
    NoField,
    /// `dist.attestations.url` points at a mounted endpoint; the
    /// `resp` shape controls what that endpoint returns.
    UrlPresent { resp: AttestationResponse },
}

/// What the attestation-bundle endpoint responds with.
enum AttestationResponse {
    /// A valid Sigstore bundle carrying a synthetic cert with a
    /// deterministic SAN URI.
    SigstoreBundle {
        publisher: &'static str,
        workflow_path: &'static str,
        workflow_ref: &'static str,
    },
    /// Simulated transient failure — the fetcher must degrade
    /// (`Ok(None)`) and the drift comparator must treat as
    /// `NoDrift`.
    Http500,
}

// ── Helpers: cert, bundle, metadata, tarball ─────────────────────

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

fn tarball_path(version: &str) -> String {
    let slug = PACKAGE_NAME
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '-' })
        .collect::<String>();
    format!("/tarballs/{slug}-{version}.tgz")
}

fn package_metadata(
    registry_url: &str,
    version: &str,
    tarball: &[u8],
    attestations: Option<serde_json::Value>,
) -> serde_json::Value {
    let tarball_url = format!("{registry_url}{}", tarball_path(version));
    let integrity = compute_integrity(tarball);

    let mut dist = serde_json::json!({
        "tarball": tarball_url,
        "integrity": integrity,
    });
    if let Some(att) = attestations {
        dist["attestations"] = att;
    }

    let version_obj = serde_json::json!({
        "name": PACKAGE_NAME,
        "version": version,
        "dist": dist,
        "dependencies": {},
    });

    serde_json::json!({
        "name": PACKAGE_NAME,
        "dist-tags": { "latest": version },
        "versions": { version: version_obj },
        // `time` — published far enough in the past that cooldown
        // doesn't fire. The P4 drift gate is what this file
        // exercises; leave the P3 gate as a no-op for these tests.
        "time": { version: "2024-01-01T00:00:00.000Z" },
    })
}

fn compute_integrity(data: &[u8]) -> String {
    let digest = Sha512::digest(data);
    format!("sha512-{}", BASE64.encode(digest))
}

fn make_minimal_tarball(version: &str) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());

    let package_json = serde_json::json!({
        "name": PACKAGE_NAME,
        "version": version,
        "main": "index.js",
    });
    let package_json_bytes = serde_json::to_vec_pretty(&package_json).unwrap();
    let mut header = tar::Header::new_gnu();
    header.set_path("package/package.json").unwrap();
    header.set_size(package_json_bytes.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    builder.append(&header, &package_json_bytes[..]).unwrap();

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

// ── Helpers: project fixture ─────────────────────────────────────

fn project_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir()
        .join("lpm-provenance-drift-p4-ship")
        .join(format!("{name}.{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// Parameters that shape the approved `TrustedDependencyBinding`
/// written into `package.json > lpm > trustedDependencies`.
struct ApprovedRefShape {
    approved_version: &'static str,
    publisher: Option<&'static str>,
    workflow_path: Option<&'static str>,
    workflow_ref: Option<&'static str>,
    /// If `None`, the binding carries no `provenanceAtApproval` field
    /// (pre-P4 / legacy approval — comparator returns `NoDrift`).
    has_provenance: bool,
}

fn write_manifest_with_approval(dir: &Path, approval: ApprovedRefShape) {
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
    rich.insert(
        format!("{PACKAGE_NAME}@{}", approval.approved_version),
        binding,
    );

    let manifest = serde_json::json!({
        "name": "provenance-drift-p4-test",
        "version": "1.0.0",
        "dependencies": {
            PACKAGE_NAME: CANDIDATE_VERSION,
        },
        "lpm": {
            // P3 cooldown is disabled for these tests so the
            // provenance gate is exercised in isolation.
            "minimumReleaseAge": 0,
            "trustedDependencies": rich,
        },
    });

    fs::write(
        dir.join("package.json"),
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();
}

/// Write a manifest whose `trustedDependencies` is empty — the drift
/// gate's zero-cost short-circuit should fire (no approval reference
/// exists for this package name).
fn write_manifest_without_approval(dir: &Path) {
    let manifest = serde_json::json!({
        "name": "provenance-drift-p4-test",
        "version": "1.0.0",
        "dependencies": {
            PACKAGE_NAME: CANDIDATE_VERSION,
        },
        "lpm": {
            "minimumReleaseAge": 0,
        },
    });
    fs::write(
        dir.join("package.json"),
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();
}

fn run_lpm(cwd: &Path, args: &[&str], registry_url: &str) -> CommandOutput {
    let exe = env!("CARGO_BIN_EXE_lpm-rs");
    let home = cwd.join(".home");
    fs::create_dir_all(&home).unwrap();

    let mut command = Command::new(exe);
    command
        .args(args)
        .current_dir(cwd)
        .env("HOME", &home)
        .env("NO_COLOR", "1")
        .env("LPM_NO_UPDATE_CHECK", "1")
        .env("LPM_DISABLE_TELEMETRY", "1")
        .env("LPM_FORCE_FILE_VAULT", "1")
        .env("LPM_REGISTRY_URL", registry_url)
        .env_remove("LPM_TOKEN")
        .env_remove("RUST_LOG");

    let output = command.output().expect("failed to spawn lpm-rs");
    CommandOutput {
        status: output.status,
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    }
}

/// Assertion helper: on failure, always dump exit + stdout + stderr.
fn fail_with_context(out: &CommandOutput, what_failed: &str) -> ! {
    panic!(
        "{what_failed}\n  exit: {:?}\n  stdout:\n{}\n  stderr:\n{}",
        out.status.code(),
        out.stdout,
        out.stderr,
    );
}

/// The drift block message is the install gate's user-visible signal
/// of a §7.2 block. Presence confirms the gate fired AND produced a
/// blocking verdict; absence confirms either no drift or a waiver.
fn drift_block_message_present(out: &CommandOutput) -> bool {
    let combined = format!("{}{}", out.stdout, out.stderr);
    combined.contains("blocked by provenance drift")
        || combined.contains("package(s) blocked by provenance drift")
}

fn assert_drift_blocked(out: &CommandOutput) {
    if out.status.success() {
        fail_with_context(out, "install must fail with a drift block");
    }
    if !drift_block_message_present(out) {
        fail_with_context(out, "output must name the drift block");
    }
}

/// The install pipeline emits `Installed N packages` (or the JSON
/// equivalent) ONLY after every stage past the drift gate has
/// succeeded: fetch, link, post-install bookkeeping, lockfile write.
/// Checking for the marker — in addition to exit status — gives us a
/// positive signal that the run reached the post-gate phases, not
/// merely "the drift block message was absent for some other reason."
///
/// Pre-existing P3 harness and Chunk 5's original helper both
/// checked absence only (reviewer Finding 1). This tighter form
/// asserts the unblocked tests actually prove what their names
/// claim.
fn install_completed_successfully(out: &CommandOutput) -> bool {
    let combined = format!("{}{}", out.stdout, out.stderr);
    // Post-link summary line. Format is `  N linked, M symlinked` on
    // the human path; JSON mode emits `"success": true` in the top-
    // level install report. Either proves the pipeline got past
    // link, which in turn proves it got past the drift gate (gate
    // fires BEFORE fetch/link).
    combined.contains("linked") || combined.contains("\"success\":true")
}

fn assert_drift_not_blocked(out: &CommandOutput) {
    if drift_block_message_present(out) {
        fail_with_context(
            out,
            "drift block message must NOT appear (gate should have passed or been waived)",
        );
    }
}

/// Stronger form: drift-block absent AND the install actually
/// completed end-to-end. Addresses reviewer Finding 1 — absence of
/// the drift message alone could mask an unrelated subprocess
/// failure that never reached the drift gate.
///
/// Used by every "unblocked / no drift" test so the absence
/// assertion is never interpreted as proof of forward progress on
/// its own.
fn assert_drift_not_blocked_and_install_succeeded(out: &CommandOutput) {
    assert_drift_not_blocked(out);
    if !out.status.success() {
        fail_with_context(
            out,
            "install must exit 0 to prove progress past the drift gate",
        );
    }
    if !install_completed_successfully(out) {
        fail_with_context(
            out,
            "install must emit a post-link success marker to prove the pipeline reached \
             stages after the drift gate",
        );
    }
}

// ── Shared builders for each test's shape ─────────────────────────

async fn setup_drift_scenario_approved_present_candidate_absent(
    test_name: &str,
) -> (PathBuf, MockRegistry) {
    let dir = project_dir(test_name);
    write_manifest_with_approval(
        &dir,
        ApprovedRefShape {
            approved_version: APPROVED_VERSION,
            publisher: Some(APPROVED_PUBLISHER),
            workflow_path: Some(APPROVED_WORKFLOW_PATH),
            workflow_ref: Some("refs/tags/v1.0.0"),
            has_provenance: true,
        },
    );
    let mock = MockRegistry::start().await;
    // Candidate version has NO `dist.attestations` — axios pattern.
    mock.mount_package_version(CANDIDATE_VERSION, AttestationShape::NoField)
        .await;
    (dir, mock)
}

async fn setup_drift_scenario_identity_changed(test_name: &str) -> (PathBuf, MockRegistry) {
    let dir = project_dir(test_name);
    write_manifest_with_approval(
        &dir,
        ApprovedRefShape {
            approved_version: APPROVED_VERSION,
            publisher: Some(APPROVED_PUBLISHER),
            workflow_path: Some(APPROVED_WORKFLOW_PATH),
            workflow_ref: Some("refs/tags/v1.0.0"),
            has_provenance: true,
        },
    );
    let mock = MockRegistry::start().await;
    mock.mount_package_version(
        CANDIDATE_VERSION,
        AttestationShape::UrlPresent {
            resp: AttestationResponse::SigstoreBundle {
                // DIFFERENT publisher — "repo moved to an attacker
                // fork" scenario. Same workflow_path; comparator
                // must catch the publisher change alone.
                publisher: "github:attacker/widget",
                workflow_path: APPROVED_WORKFLOW_PATH,
                workflow_ref: "refs/tags/v1.0.1",
            },
        },
    )
    .await;
    (dir, mock)
}

async fn setup_legitimate_release_bump(test_name: &str) -> (PathBuf, MockRegistry) {
    let dir = project_dir(test_name);
    write_manifest_with_approval(
        &dir,
        ApprovedRefShape {
            approved_version: APPROVED_VERSION,
            publisher: Some(APPROVED_PUBLISHER),
            workflow_path: Some(APPROVED_WORKFLOW_PATH),
            workflow_ref: Some("refs/tags/v1.0.0"),
            has_provenance: true,
        },
    );
    let mock = MockRegistry::start().await;
    mock.mount_package_version(
        CANDIDATE_VERSION,
        AttestationShape::UrlPresent {
            resp: AttestationResponse::SigstoreBundle {
                publisher: APPROVED_PUBLISHER,
                workflow_path: APPROVED_WORKFLOW_PATH,
                // Only the ref differs — legitimate release tag.
                workflow_ref: "refs/tags/v1.0.1",
            },
        },
    )
    .await;
    (dir, mock)
}

async fn setup_http500_fetch_degradation(test_name: &str) -> (PathBuf, MockRegistry) {
    let dir = project_dir(test_name);
    write_manifest_with_approval(
        &dir,
        ApprovedRefShape {
            approved_version: APPROVED_VERSION,
            publisher: Some(APPROVED_PUBLISHER),
            workflow_path: Some(APPROVED_WORKFLOW_PATH),
            workflow_ref: Some("refs/tags/v1.0.0"),
            has_provenance: true,
        },
    );
    let mock = MockRegistry::start().await;
    mock.mount_package_version(
        CANDIDATE_VERSION,
        AttestationShape::UrlPresent {
            resp: AttestationResponse::Http500,
        },
    )
    .await;
    (dir, mock)
}

// ── §11 P4 ship criteria ──────────────────────────────────────────

/// **§11 P4 primary ship criterion.** Package whose attestation is
/// manually deleted between approved v1 and candidate v2 → drift
/// blocks install. The axios 1.14.1 scenario, end-to-end.
#[tokio::test]
async fn attestation_deleted_between_approved_and_candidate_blocks() {
    let (dir, mock) =
        setup_drift_scenario_approved_present_candidate_absent("attestation_deleted").await;

    let out = run_lpm(&dir, &["install"], &mock.url());

    assert_drift_blocked(&out);
    // Verdict-specific: "provenance dropped" is the axios signal.
    let combined = format!("{}{}", out.stdout, out.stderr);
    if !combined.contains("provenance dropped") {
        fail_with_context(
            &out,
            "block message must name the 'provenance dropped' verdict",
        );
    }
}

/// **§11 P4 ship criterion.** `--ignore-provenance-drift <pkg>`
/// unblocks the specific named package while leaving the rest of
/// the drift gate live.
#[tokio::test]
async fn ignore_provenance_drift_per_package_unblocks() {
    let (dir, mock) =
        setup_drift_scenario_approved_present_candidate_absent("ignore_per_package").await;

    let out = run_lpm(
        &dir,
        &["install", "--ignore-provenance-drift", PACKAGE_NAME],
        &mock.url(),
    );

    // Per-package waiver must let the install complete end-to-end,
    // not merely suppress the drift-block message. The stronger
    // assertion catches regressions where the install fails at a
    // different stage (e.g., fetch, link) that could leave the
    // drift-block message absent for unrelated reasons.
    assert_drift_not_blocked_and_install_succeeded(&out);
    let combined = format!("{}{}", out.stdout, out.stderr);
    if !combined.contains("waived by --ignore-provenance-drift") {
        fail_with_context(
            &out,
            "waived-advisory line must appear so the user sees what they opted out of",
        );
    }
}

/// **§11 P4 ship criterion.** `--ignore-provenance-drift-all`
/// blankets every package with a single flag. Separate test from the
/// per-package variant so CI can tell which specific code path
/// regressed if one branch silently reverts.
#[tokio::test]
async fn ignore_provenance_drift_all_unblocks() {
    let (dir, mock) = setup_drift_scenario_approved_present_candidate_absent("ignore_all").await;

    let out = run_lpm(
        &dir,
        &["install", "--ignore-provenance-drift-all"],
        &mock.url(),
    );

    assert_drift_not_blocked_and_install_succeeded(&out);
    // The `-all` short-circuit advisory fires before the per-package
    // loop; it must appear even when no package would otherwise have
    // drifted (users explicitly asked for the opt-out).
    let combined = format!("{}{}", out.stdout, out.stderr);
    if !combined.contains("waived for this install by --ignore-provenance-drift-all") {
        fail_with_context(
            &out,
            "the short-circuit advisory must announce the blanket waive",
        );
    }
}

/// **§11 P4 identity-drift case.** Both versions carry attestations,
/// but the publisher differs (repo moved to an attacker fork in a
/// hypothetical SCM handoff). Drift blocks.
#[tokio::test]
async fn identity_changed_between_approved_and_candidate_blocks() {
    let (dir, mock) = setup_drift_scenario_identity_changed("identity_changed").await;

    let out = run_lpm(&dir, &["install"], &mock.url());

    assert_drift_blocked(&out);
    let combined = format!("{}{}", out.stdout, out.stderr);
    if !combined.contains("publisher identity changed") {
        fail_with_context(
            &out,
            "block message must name the 'publisher identity changed' verdict",
        );
    }
}

/// **§11 P4 Finding-1 E2E regression.** A legitimate v1.0.0 →
/// v1.0.1 release from the same repo + same workflow file
/// necessarily differs on `workflow_ref` (release tag) AND
/// `attestation_cert_sha256` (Fulcio's ephemeral leaf). The
/// comparator's identity tuple excludes both fields by design. If
/// this test ever regresses, every legitimate patch bump will hard-
/// block — catastrophic for the gate's usability. Guards the
/// comparator fix in eec6312.
#[tokio::test]
async fn legitimate_release_bump_does_not_drift() {
    let (dir, mock) = setup_legitimate_release_bump("legitimate_bump").await;

    let out = run_lpm(&dir, &["install"], &mock.url());

    // Stronger assertion: drift-block absent AND install completed.
    // Critical for this case specifically — the legitimate-bump
    // scenario is exactly when users depend on the install
    // SUCCEEDING, not just not-blocking. A regression that caused
    // the install to fail at a downstream stage (after the drift
    // gate but before completion) would have the same "drift
    // message absent" shape without delivering the install.
    assert_drift_not_blocked_and_install_succeeded(&out);
}

/// **D16 orthogonality guard.** `--allow-new` is the P3 cooldown
/// override; per D16 it does NOT bypass the P4 drift gate. A user
/// who passes only `--allow-new` on a drifted install must still be
/// blocked by drift. If this test ever fails, D16 is broken — the
/// two gates have silently merged and users can't independently
/// acknowledge each signal.
#[tokio::test]
async fn allow_new_alone_does_not_bypass_drift() {
    let (dir, mock) =
        setup_drift_scenario_approved_present_candidate_absent("allow_new_does_not_bypass").await;

    let out = run_lpm(&dir, &["install", "--allow-new"], &mock.url());

    assert_drift_blocked(&out);
}

/// **Reliability guard.** A transient network failure (HTTP 500 from
/// the attestation endpoint) must NOT be conflated with
/// "provenance dropped." The fetcher degrades to `Ok(None)`, the
/// comparator returns `NoDrift`, the install proceeds. A CI that
/// hits a rate-limited Sigstore should never produce a spurious
/// drift block. Guards the `(Some(_), None) → NoDrift` branch in
/// `lpm_security::provenance::check_provenance_drift`.
#[tokio::test]
async fn degraded_fetch_does_not_falsely_block() {
    let (dir, mock) = setup_http500_fetch_degradation("degraded_fetch").await;

    let out = run_lpm(&dir, &["install"], &mock.url());

    // Stronger form: drift-block absent AND install completed. A
    // regression where the fetcher raised instead of degrading would
    // have plausibly hidden behind "message absent" alone.
    assert_drift_not_blocked_and_install_succeeded(&out);
}

/// **Observable contract for no-approvals projects.** When the
/// project has no rich `trustedDependencies` entries, the drift
/// gate's externally-visible contract must hold: no drift-block
/// message, no blanket-waive advisory (the user did not pass
/// `--ignore-provenance-drift-all`), and the install completes
/// end-to-end.
///
/// ## Why this test was renamed (reviewer Finding 2)
///
/// The earlier name, `project_with_no_approvals_skips_drift_gate`,
/// claimed to guard the Chunk 3 `has_rich_approvals` short-circuit
/// optimization in `install.rs`. That optimization is a PURE
/// INTERNAL performance fast-path: the alternative (gate enters,
/// iterates packages, each returns `None` from
/// `provenance_reference_for_name`, no fetch fires) produces the
/// exact same external behavior. A runtime subprocess test cannot
/// distinguish "fast path taken" from "slow path with no matches"
/// without instrumentation (e.g., a `tracing` debug marker + log-
/// capturing harness) — and the reviewer was right to flag that
/// the old assertions would have passed equally under either
/// code path.
///
/// This test now describes the actual observable contract:
/// absence of the block message, absence of the blanket-waive
/// advisory, AND install completion. Proving the specific
/// short-circuit optimization is deferred to a future
/// tracing-based harness if that ever becomes load-bearing enough
/// to warrant it.
#[tokio::test]
async fn project_with_no_approvals_does_not_block_on_drift() {
    let dir = project_dir("no_approvals");
    write_manifest_without_approval(&dir);

    let mock = MockRegistry::start().await;
    mock.mount_package_version(CANDIDATE_VERSION, AttestationShape::NoField)
        .await;

    let out = run_lpm(&dir, &["install"], &mock.url());

    assert_drift_not_blocked_and_install_succeeded(&out);

    // The `-all` waive advisory must NOT fire (user didn't pass it).
    let combined = format!("{}{}", out.stdout, out.stderr);
    if combined.contains("waived for this install by --ignore-provenance-drift-all") {
        fail_with_context(
            &out,
            "blanket waive advisory must only fire when the user passes --ignore-provenance-drift-all",
        );
    }
}
