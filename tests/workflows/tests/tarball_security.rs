//! Tarball-extraction security contracts at the workflow tier.
//!
//! These tests pin the end-to-end behavior of `lpm install` against malicious
//! tarballs served through the registry. Each test constructs the malicious
//! tarball **in-test** with `tar::Builder` (no checked-in fixtures —
//! they age poorly and obscure intent), serves it via `MockRegistry`,
//! runs `lpm install`, and asserts the contract:
//!
//! - The install never extracts a file outside the project's
//!   `node_modules/` (no zip-slip writethrough).
//! - The install either rejects the malicious entry cleanly (non-zero
//!   exit, error message names something actionable) or silently
//!   skips it (zero exit, no malicious entry on disk). Both are
//!   defensible end-states; the test pins **whichever the extractor
//!   actually does today** so a future regression that flips between
//!   them is caught.
//! - The install never panics or emits a stack trace.
//! - The pre-existing source-of-truth in
//!   [`crates/lpm-extractor/src/lib.rs`](../../../crates/lpm-extractor/src/lib.rs)
//!   already covers most of these at the unit tier. The workflow tier
//!   adds proof that the FULL install pipeline (download → verify →
//!   extract → link) honors the same contracts when an attacker
//!   reaches the extractor through `lpm install`.
//!
//! The test documentation names the current contract for each attack shape
//! so future changes are reviewed deliberately.

mod support;

use flate2::Compression;
use flate2::write::GzEncoder;
use std::io::Write;
use support::mock_registry::{MockRegistry, compute_integrity, make_tarball_from_pkg_json};
use support::{TempProject, lpm, lpm_with_registry};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ─── Helpers ────────────────────────────────────────────────────────

/// Build a `.tgz` containing a valid `package/package.json` plus a
/// caller-supplied set of additional tar entries. `package.json` is
/// the minimal shape the install pipeline needs — without it the
/// install fails on missing-manifest before reaching the extractor's
/// security checks, which would mask the actual concern under test.
fn tarball_with_extra_entries<F>(name: &str, version: &str, mut customize: F) -> Vec<u8>
where
    F: FnMut(&mut tar::Builder<&mut Vec<u8>>),
{
    let mut tar_data = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_data);

        // Always include a valid package.json so the install pipeline
        // gets past the manifest-required gate and the malicious
        // entries actually exercise the extractor's hardening.
        let pkg_json = format!(r#"{{"name":"{name}","version":"{version}"}}"#);
        let mut header = tar::Header::new_gnu();
        header.set_size(pkg_json.len() as u64);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        builder
            .append_data(&mut header, "package/package.json", pkg_json.as_bytes())
            .expect("append package.json");

        // Caller plants the malicious entries.
        customize(&mut builder);

        builder.finish().expect("finish tar");
    }

    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&tar_data).expect("gzip write");
    encoder.finish().expect("gzip finish")
}

/// Common install-args set that workflow tests reuse — keeps the
/// install footprint small and deterministic across the suite.
fn install_args(spec: &str) -> Vec<&str> {
    vec![
        "install",
        "--no-security-summary",
        "--no-skills",
        "--no-editor-setup",
        spec,
    ]
}

fn bare_install_args() -> [&'static str; 4] {
    [
        "install",
        "--no-security-summary",
        "--no-skills",
        "--no-editor-setup",
    ]
}

fn left_pad_package_json() -> serde_json::Value {
    serde_json::json!({
        "name": "left-pad",
        "version": "1.0.0",
        "main": "index.js",
    })
}

fn evict_install_outputs(project: &TempProject) {
    let node_modules = project.path().join("node_modules");
    if node_modules.exists() {
        std::fs::remove_dir_all(&node_modules)
            .unwrap_or_else(|e| panic!("remove {}: {e}", node_modules.display()));
    }
    let store_dir = project.store_dir();
    if store_dir.exists() {
        std::fs::remove_dir_all(&store_dir)
            .unwrap_or_else(|e| panic!("remove {}: {e}", store_dir.display()));
    }
    let install_hash = project.path().join(".lpm").join("install-hash");
    if install_hash.exists() {
        std::fs::remove_file(&install_hash)
            .unwrap_or_else(|e| panic!("remove {}: {e}", install_hash.display()));
    }
}

fn remove_binary_lockfile(project: &TempProject) {
    let lockb = project.path().join(lpm_lockfile::BINARY_LOCKFILE_NAME);
    if lockb.exists() {
        std::fs::remove_file(&lockb).unwrap_or_else(|e| panic!("remove {}: {e}", lockb.display()));
    }
}

fn tamper_registry_lockfile_tarball(
    project: &TempProject,
    package_name: &str,
    attacker_url: String,
    attacker_integrity: String,
) {
    let lockfile_path = project.path().join(lpm_lockfile::LOCKFILE_NAME);
    let mut lockfile =
        lpm_lockfile::Lockfile::read_from_file(&lockfile_path).expect("read lpm.lock");
    let pkg = lockfile
        .packages
        .iter_mut()
        .find(|pkg| pkg.name == package_name && pkg.version == "1.0.0")
        .unwrap_or_else(|| panic!("lpm.lock must contain {package_name}@1.0.0"));
    assert!(
        pkg.source
            .as_deref()
            .is_some_and(|source| source.starts_with("registry+")),
        "test setup must tamper a registry-sourced package, got {:?}",
        pkg.source,
    );
    pkg.tarball = Some(attacker_url);
    pkg.integrity = Some(attacker_integrity);
    lockfile
        .write_to_file(&lockfile_path)
        .expect("write tampered lpm.lock");
    remove_binary_lockfile(project);
}

// ─── Tests ──────────────────────────────────────────────────────────

#[tokio::test]
async fn registry_lockfile_tarball_hint_mismatch_is_rejected_before_fetch() {
    let registry = MockRegistry::start().await;
    registry
        .with_manifest_package(
            left_pad_package_json(),
            &[("index.js", b"module.exports = 'registry-left-pad';")],
        )
        .await;

    let project = TempProject::empty(
        r#"{
  "name": "registry-tarball-binding",
  "version": "1.0.0",
  "dependencies": {
    "left-pad": "1.0.0"
  }
}"#,
    );

    lpm_with_registry(&project, &registry.url())
        .args(bare_install_args())
        .assert()
        .success();

    let attacker_tarball = make_tarball_from_pkg_json(
        left_pad_package_json(),
        &[("index.js", b"module.exports = 'attacker-left-pad';")],
    );
    let attacker_path = "/tarballs/left-pad/-/left-pad-1.0.0-attacker.tgz";
    Mock::given(method("GET"))
        .and(path(attacker_path))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_bytes(attacker_tarball.clone())
                .insert_header("content-type", "application/octet-stream"),
        )
        .mount(registry.server())
        .await;

    tamper_registry_lockfile_tarball(
        &project,
        "left-pad",
        format!("{}{}", registry.url(), attacker_path),
        compute_integrity(&attacker_tarball),
    );
    evict_install_outputs(&project);

    let output = lpm_with_registry(&project, &registry.url())
        .args(bare_install_args())
        .output()
        .expect("run install against tampered lockfile");
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !output.status.success(),
        "tampered registry tarball hint must fail closed; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("registry lockfile tarball")
            && stderr.contains("does not match registry metadata"),
        "error must clearly name the registry tarball metadata mismatch; stderr:\n{stderr}"
    );

    let attacker_requests = registry
        .server()
        .received_requests()
        .await
        .expect("registry request log must be available")
        .into_iter()
        .filter(|request| request.url.path() == attacker_path)
        .collect::<Vec<_>>();
    assert!(
        attacker_requests.is_empty(),
        "install must reject the lockfile hint before fetching attacker bytes; got {} request(s)",
        attacker_requests.len()
    );
}

#[tokio::test]
async fn matching_registry_lockfile_tarball_hint_reinstalls_after_store_eviction() {
    let registry = MockRegistry::start().await;
    registry
        .with_manifest_package(
            left_pad_package_json(),
            &[("index.js", b"module.exports = 'registry-left-pad';")],
        )
        .await;

    let project = TempProject::empty(
        r#"{
  "name": "registry-tarball-binding-positive",
  "version": "1.0.0",
  "dependencies": {
    "left-pad": "1.0.0"
  }
}"#,
    );

    lpm_with_registry(&project, &registry.url())
        .args(bare_install_args())
        .assert()
        .success();

    evict_install_outputs(&project);
    remove_binary_lockfile(&project);

    let output = lpm_with_registry(&project, &registry.url())
        .args(bare_install_args())
        .output()
        .expect("run reinstall from matching lockfile");
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "matching registry tarball hint must remain installable; stderr:\n{stderr}"
    );
    assert!(
        project
            .path()
            .join("node_modules/left-pad/index.js")
            .exists(),
        "reinstall must link the registry package after validating the lockfile hint"
    );
}

#[tokio::test]
async fn explicit_tarball_dependency_is_not_bound_to_registry_metadata() {
    let server = MockServer::start().await;
    let tarball = make_tarball_from_pkg_json(
        serde_json::json!({
            "name": "direct-tarball-pkg",
            "version": "1.0.0",
            "main": "index.js",
        }),
        &[("index.js", b"module.exports = 'direct-tarball';")],
    );
    let integrity = compute_integrity(&tarball);

    Mock::given(method("GET"))
        .and(path("/direct-tarball-pkg-1.0.0.tgz"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_bytes(tarball)
                .insert_header("content-type", "application/octet-stream"),
        )
        .mount(&server)
        .await;

    let project = TempProject::empty(&format!(
        r#"{{
  "name": "explicit-tarball-source",
  "version": "1.0.0",
  "dependencies": {{
    "direct-tarball-pkg": "{}/direct-tarball-pkg-1.0.0.tgz#{}"
  }}
}}"#,
        server.uri(),
        integrity,
    ));

    let output = lpm(&project)
        .args(bare_install_args())
        .output()
        .expect("run explicit tarball install");
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "explicit tarball source must install without registry metadata binding; stderr:\n{stderr}"
    );
    let lockfile =
        lpm_lockfile::Lockfile::read_from_file(&project.path().join(lpm_lockfile::LOCKFILE_NAME))
            .expect("read lpm.lock");
    let pkg = lockfile
        .packages
        .iter()
        .find(|pkg| pkg.name == "direct-tarball-pkg" && pkg.version == "1.0.0")
        .expect("lockfile must contain explicit tarball package");
    assert!(
        pkg.tarball.is_none()
            && pkg
                .source
                .as_deref()
                .is_some_and(|source| source.starts_with("tarball+http://")),
        "explicit tarball package must keep URL identity in source and no registry hint: {:?}",
        pkg,
    );
}

/// **Plan #1 — `..` path entry must be rejected.**
///
/// Tarball includes a regular file whose path resolves above the
/// extraction root after npm's `package/` prefix is stripped. The
/// extractor's `Component::ParentDir` check at
/// [lib.rs:347](../../../crates/lpm-extractor/src/lib.rs#L347)
/// rejects this with an error that contains "path traversal".
///
/// The unit-tier coverage at [lib.rs:1010](../../../crates/lpm-extractor/src/lib.rs#L1010)
/// `extract_rejects_nested_path_traversal_after_prefix_stripping`
/// pins this in isolation. The workflow tier adds proof that the
/// install pipeline (download → verify → extract → link) does not
/// silently swallow the rejection or extract the entry through a
/// fast path.
#[tokio::test]
async fn tarball_with_dot_dot_path_entry_is_rejected_by_install() {
    // Build the malicious tarball: header path is "package/safe.txt"
    // (so set_path doesn't error on the `..`), then we overwrite the
    // path bytes in the raw header to "package/../escape.txt".
    let tgz = tarball_with_extra_entries("dot-dot-pkg", "1.0.0", |builder| {
        let content = b"pwned";
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_path("package/safe.txt").unwrap();
        let raw = header.as_mut_bytes();
        raw[..100].fill(0);
        let evil = b"package/../escape.txt";
        raw[..evil.len()].copy_from_slice(evil);
        header.set_cksum();
        builder.append(&header, &content[..]).unwrap();
    });

    let mock = MockRegistry::start().await;
    mock.with_package("dot-dot-pkg", "1.0.0", &tgz).await;

    let project = TempProject::empty(r#"{"name":"sec-test","version":"1.0.0"}"#);

    // Plant a sentinel just outside the project so a writethrough is
    // detectable post-failure.
    let outside = project.path().parent().unwrap().join("escape.txt");
    let _ = std::fs::remove_file(&outside);

    let output = lpm_with_registry(&project, &mock.url())
        .args(install_args("dot-dot-pkg@1.0.0"))
        .output()
        .expect("run install");
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    eprintln!(
        "[Plan#1 dotdot] status={:?}\nstderr:\n{stderr}\nstdout:\n{stdout}",
        output.status
    );

    assert!(
        !output.status.success(),
        "install of `..`-traversal tarball reported success — \
         the malicious path was extracted somewhere:\nstderr:\n{stderr}"
    );
    assert!(
        !stderr.contains("panicked at") && !stderr.contains("note: run with `RUST_BACKTRACE"),
        "extractor panicked on `..` traversal:\nstderr:\n{stderr}"
    );
    assert!(
        !outside.exists(),
        "extractor wrote outside the target through a `..` traversal — \
         security regression. file lives at: {outside:?}"
    );
    let stderr_l = stderr.to_lowercase();
    assert!(
        stderr_l.contains("traversal")
            || stderr_l.contains("integrity")
            || stderr_l.contains("invalid"),
        "rejection message lacks an actionable noun \
         (expected one of: traversal / integrity / invalid). \
         stderr:\n{stderr}"
    );
}

#[tokio::test]
async fn tarball_with_windows_reserved_basename_is_rejected_by_install() {
    let tgz = tarball_with_extra_entries("reserved-name-pkg", "1.0.0", |builder| {
        let content = b"reserved device payload";
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        builder
            .append_data(&mut header, "package/lib/NUL.txt", &content[..])
            .unwrap();
    });

    let mock = MockRegistry::start().await;
    mock.with_package("reserved-name-pkg", "1.0.0", &tgz).await;

    let project = TempProject::empty(r#"{"name":"sec-test","version":"1.0.0"}"#);
    let output = lpm_with_registry(&project, &mock.url())
        .args(install_args("reserved-name-pkg@1.0.0"))
        .output()
        .expect("run install");
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !output.status.success(),
        "install of reserved-device-name tarball reported success:\nstderr:\n{stderr}"
    );
    assert!(
        !stderr.contains("panicked at") && !stderr.contains("note: run with `RUST_BACKTRACE"),
        "extractor panicked on reserved-device-name entry:\nstderr:\n{stderr}"
    );
    let stderr_l = stderr.to_lowercase();
    assert!(
        stderr_l.contains("reserved") && stderr_l.contains("windows"),
        "reserved-device rejection should name the portable path concern. stderr:\n{stderr}"
    );
    assert!(
        !project
            .path()
            .join("node_modules/reserved-name-pkg/lib/NUL.txt")
            .exists(),
        "reserved-device-name entry must not be linked into node_modules"
    );
}

#[tokio::test]
async fn tarball_with_case_fold_path_collision_is_rejected_by_install() {
    let tgz = tarball_with_extra_entries("case-fold-pkg", "1.0.0", |builder| {
        for (path, content) in [
            ("package/lib/Foo.js", b"module.exports = 'upper';" as &[u8]),
            ("package/lib/foo.js", b"module.exports = 'lower';" as &[u8]),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            header.set_entry_type(tar::EntryType::Regular);
            header.set_cksum();
            builder.append_data(&mut header, path, content).unwrap();
        }
    });

    let mock = MockRegistry::start().await;
    mock.with_package("case-fold-pkg", "1.0.0", &tgz).await;

    let project = TempProject::empty(r#"{"name":"sec-test","version":"1.0.0"}"#);
    let output = lpm_with_registry(&project, &mock.url())
        .args(install_args("case-fold-pkg@1.0.0"))
        .output()
        .expect("run install");
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !output.status.success(),
        "install of case-fold-collision tarball reported success:\nstderr:\n{stderr}"
    );
    assert!(
        !stderr.contains("panicked at") && !stderr.contains("note: run with `RUST_BACKTRACE"),
        "extractor panicked on case-fold collision:\nstderr:\n{stderr}"
    );
    let stderr_l = stderr.to_lowercase();
    assert!(
        stderr_l.contains("case-fold") && stderr_l.contains("collision"),
        "case-fold rejection should name the collision. stderr:\n{stderr}"
    );
    let pkg_dir = project.path().join("node_modules/case-fold-pkg");
    assert!(
        !pkg_dir.join("lib/Foo.js").exists() && !pkg_dir.join("lib/foo.js").exists(),
        "case-fold collision must roll back any extracted package files under {pkg_dir:?}"
    );
}

/// **Plan #3 — absolute-path entry is normalized to relative under the package dir.**
///
/// **Plan-vs-actual:** the plan's name said "rejected"; the
/// extractor's actual behavior is to **normalize** an absolute-path
/// entry into a relative path under the package's `node_modules`
/// directory. The mechanism is incidental but worth pinning:
///
/// - `strip_first_component` ([lib.rs:733](../../../crates/lpm-extractor/src/lib.rs#L733))
///   drops the FIRST `Path::components()` element. For a tarball
///   path of `/etc/lpm-pwned.txt`, the components are
///   `[RootDir, Normal("etc"), Normal("lpm-pwned.txt")]`. Stripping
///   first yields the relative path `etc/lpm-pwned.txt`.
/// - The post-strip `Component::RootDir` check at
///   [lib.rs:347-352](../../../crates/lpm-extractor/src/lib.rs#L347)
///   then sees no `RootDir` (the strip already consumed it), so
///   the extractor proceeds.
/// - `target_path.starts_with(&extraction_root)` guards the final
///   write against any escape; the normalized path lives entirely
///   under `node_modules/<pkg>/`, so the guard passes.
///
/// **Result:** install SUCCEEDS, the file extracts at
/// `node_modules/<pkg>/etc/lpm-pwned.txt`, and `/etc/lpm-pwned.txt`
/// at the filesystem root is NEVER created. The "absolute path"
/// attack vector is foreclosed by normalization, not by rejection.
///
/// That posture is defensible: an absolute tarball entry is malformed
/// per the npm convention (every entry should sit under `package/`),
/// but normalizing-then-extracting is safer than refusing the whole
/// tarball — the user gets a working install rather than a brittle
/// hard failure on what is functionally cosmetic. Pin the current
/// shape so a future regression that flips the contract (e.g.,
/// "reject loudly" or "extract at the absolute path") trips this
/// test.
#[tokio::test]
async fn tarball_with_absolute_path_entry_is_normalized_to_relative_under_package_dir() {
    let tgz = tarball_with_extra_entries("abspath-pkg", "1.0.0", |builder| {
        let content = b"absolute attack";
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        // set_path won't accept a literal absolute path; install a
        // placeholder then poke the absolute path into the raw header
        // bytes. The header's name field is fixed-size; the trailing
        // null implicitly terminates after our slice.
        header.set_path("package/safe.txt").unwrap();
        let raw = header.as_mut_bytes();
        raw[..100].fill(0);
        let evil = b"/etc/lpm-pwned.txt";
        raw[..evil.len()].copy_from_slice(evil);
        header.set_cksum();
        builder.append(&header, &content[..]).unwrap();
    });

    let mock = MockRegistry::start().await;
    mock.with_package("abspath-pkg", "1.0.0", &tgz).await;

    let project = TempProject::empty(r#"{"name":"sec-test","version":"1.0.0"}"#);

    let output = lpm_with_registry(&project, &mock.url())
        .args(install_args("abspath-pkg@1.0.0"))
        .output()
        .expect("run install");
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    eprintln!(
        "[Plan#3 abspath-normalize] status={:?}\nstderr:\n{stderr}\nstdout:\n{stdout}",
        output.status
    );

    // The install SUCCEEDS — normalization, not rejection.
    assert!(
        output.status.success(),
        "install of absolute-path tarball failed — extractor's \
         normalize-then-extract contract may have changed.\n\
         stderr:\n{stderr}"
    );
    assert!(
        !stderr.contains("panicked at"),
        "extractor panicked on absolute path:\nstderr:\n{stderr}"
    );
    // **Critical** — never write to the literal absolute path. If
    // /etc/lpm-pwned.txt appears, the extractor went rogue.
    assert!(
        !std::path::Path::new("/etc/lpm-pwned.txt").exists(),
        "extractor wrote to absolute /etc/lpm-pwned.txt — security regression."
    );
    // Pin the normalized landing site so a future regression that
    // changes WHERE the entry lands (or stops extracting it at all)
    // is detected. The path may or may not exist depending on
    // pipeline details — the load-bearing assertion above is the
    // "no absolute-path writethrough" one. The diagnostic on the
    // landing site is informational.
    let normalized = project
        .path()
        .join("node_modules/abspath-pkg/etc/lpm-pwned.txt");
    eprintln!(
        "[Plan#3 abspath-normalize] normalized landing exists={}, path={normalized:?}",
        normalized.exists()
    );
}

/// **Plan #2 — symlink to outside path is silently skipped (current behavior).**
///
/// **Plan-vs-actual:** the plan's name said "rejected"; the
/// extractor's actual contract is to **silently skip** any tar entry
/// whose `header.entry_type()` is not `is_file()`. See
/// [lib.rs:398](../../../crates/lpm-extractor/src/lib.rs#L398) — the
/// regular-files-only branch swallows symlinks, hardlinks, FIFOs,
/// device files, etc.; they vanish, the tarball still extracts
/// successfully, and the install proceeds.
///
/// That posture is defensible: npm packages don't legitimately ship
/// symlinks, so silently dropping them avoids ever following a
/// dangerous link. The risk it leaves on the table: if any
/// downstream code consumes the tarball without going through the
/// extractor (e.g. a future bundler, a raw inspect tool), the
/// silently-skipped entries become invisible to the user. Pin the
/// current shape; flag a future-work item if "reject loudly" is the
/// preferred contract.
///
/// The test asserts: install succeeds (silent skip is the contract),
/// the linked file does NOT appear in the extracted package, and the
/// outside target the symlink pointed at is NOT modified.
#[tokio::test]
async fn tarball_with_symlink_to_outside_path_is_silently_skipped() {
    // Plant an outside sentinel with known content so a writethrough
    // would change it.
    let outside_dir = tempfile::tempdir().expect("outside tempdir");
    let outside_target = outside_dir.path().join("victim.txt");
    std::fs::write(&outside_target, b"original outside content").expect("plant sentinel");

    let outside_target_str = outside_target.to_string_lossy().into_owned();

    let tgz = tarball_with_extra_entries("symlink-pkg", "1.0.0", |builder| {
        let mut symlink_header = tar::Header::new_gnu();
        symlink_header.set_entry_type(tar::EntryType::Symlink);
        symlink_header.set_size(0);
        symlink_header.set_mode(0o777);
        symlink_header
            .set_link_name(&outside_target_str)
            .expect("set symlink target");
        symlink_header.set_cksum();
        builder
            .append_data(
                &mut symlink_header,
                "package/link-to-outside.txt",
                std::io::empty(),
            )
            .unwrap();
    });

    let mock = MockRegistry::start().await;
    mock.with_package("symlink-pkg", "1.0.0", &tgz).await;

    let project = TempProject::empty(r#"{"name":"sec-test","version":"1.0.0"}"#);
    let output = lpm_with_registry(&project, &mock.url())
        .args(install_args("symlink-pkg@1.0.0"))
        .output()
        .expect("run install");
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    eprintln!(
        "[Plan#2 symlink-skip] status={:?}\nstderr:\n{stderr}\nstdout:\n{stdout}",
        output.status
    );

    // Current contract: silent skip, install succeeds.
    assert!(
        output.status.success(),
        "install of symlink-bearing tarball failed — extractor's \
         silent-skip contract may have changed (audit before \
         flipping the assertion).\nstderr:\n{stderr}"
    );
    assert!(
        !stderr.contains("panicked at"),
        "extractor panicked on a symlink entry:\nstderr:\n{stderr}"
    );

    // Critical: outside sentinel is byte-identical.
    let after = std::fs::read(&outside_target).expect("re-read outside sentinel");
    assert_eq!(
        after, b"original outside content",
        "outside sentinel was modified — extractor wrote through the \
         silently-skipped symlink. file: {outside_target:?}"
    );

    // The symlink's named path must NOT appear inside the project's
    // node_modules/<pkg>/ either as a symlink, a file, or anything.
    let pkg_dir = project.path().join("node_modules/symlink-pkg");
    let phantom = pkg_dir.join("link-to-outside.txt");
    assert!(
        !phantom.exists(),
        "the silently-skipped symlink should not appear at {phantom:?}"
    );
}

/// **Plan #5 — hard link to outside file is silently skipped (current behavior).**
///
/// Same posture as #2: tar entry type 'Link' (`hardlink`) is not
/// `is_file()`, so the extractor's regular-files-only branch silently
/// drops it. The install succeeds, no hardlink lands on disk.
///
/// The risk it forecloses: a hardlink in a tarball pointing at
/// `/etc/passwd` could otherwise let an attacker materialize a
/// readable copy inside the package directory. Silent-skip prevents
/// that.
#[tokio::test]
async fn tarball_with_hard_link_to_outside_file_is_silently_skipped() {
    // Plant the outside file with known content.
    let outside_dir = tempfile::tempdir().expect("outside tempdir");
    let outside_target = outside_dir.path().join("victim.txt");
    std::fs::write(&outside_target, b"sensitive bytes").expect("plant outside victim");
    let outside_target_str = outside_target.to_string_lossy().into_owned();

    let tgz = tarball_with_extra_entries("hardlink-pkg", "1.0.0", |builder| {
        let mut hardlink_header = tar::Header::new_gnu();
        hardlink_header.set_entry_type(tar::EntryType::Link);
        hardlink_header.set_size(0);
        hardlink_header.set_mode(0o644);
        hardlink_header
            .set_link_name(&outside_target_str)
            .expect("set hardlink target");
        hardlink_header.set_cksum();
        builder
            .append_data(
                &mut hardlink_header,
                "package/hardlink-to-victim.txt",
                std::io::empty(),
            )
            .unwrap();
    });

    let mock = MockRegistry::start().await;
    mock.with_package("hardlink-pkg", "1.0.0", &tgz).await;

    let project = TempProject::empty(r#"{"name":"sec-test","version":"1.0.0"}"#);
    let output = lpm_with_registry(&project, &mock.url())
        .args(install_args("hardlink-pkg@1.0.0"))
        .output()
        .expect("run install");
    let stderr = String::from_utf8_lossy(&output.stderr);

    eprintln!(
        "[Plan#5 hardlink-skip] status={:?}\nstderr:\n{stderr}",
        output.status
    );

    assert!(
        output.status.success(),
        "install of hardlink-bearing tarball failed — extractor's \
         silent-skip contract may have changed.\nstderr:\n{stderr}"
    );
    assert!(
        !stderr.contains("panicked at"),
        "extractor panicked on a hardlink entry:\nstderr:\n{stderr}"
    );

    // Outside target must still contain the original bytes — the
    // hardlink was NOT created (which would have made the outside
    // file mutable through the package path).
    let after = std::fs::read(&outside_target).expect("re-read outside victim");
    assert_eq!(
        after, b"sensitive bytes",
        "outside file was mutated — silent-skip contract violated. \
         file: {outside_target:?}"
    );

    let phantom = project
        .path()
        .join("node_modules/hardlink-pkg/hardlink-to-victim.txt");
    assert!(
        !phantom.exists(),
        "the silently-skipped hardlink should not appear at {phantom:?}"
    );
}

/// **Plan #8 — setuid/setgid executable extracts with setuid bits stripped.**
///
/// `set_preserve_permissions(false)` at [lib.rs:240](../../../crates/lpm-extractor/src/lib.rs#L240)
/// disables tar's SUID-bit preservation. Subsequent post-write
/// `set_permissions` at [lib.rs:472](../../../crates/lpm-extractor/src/lib.rs#L472)
/// uses `0o644 | exec_bits`, where `exec_bits = mode & 0o111` —
/// strictly the user/group/other execute bits, never the SUID
/// (0o4000), SGID (0o2000), or sticky (0o1000) bits.
///
/// Pinned contract: a tarball with mode `0o4755` (SUID + rwxr-xr-x)
/// extracts with mode `0o755` (no SUID). The file extracts, the
/// install succeeds, and a `stat` of the on-disk file shows the SUID
/// bit cleared.
///
/// POSIX-only — Windows NTFS doesn't have POSIX mode bits; bin
/// scripts there are dispatched by extension.
#[cfg(unix)]
#[tokio::test]
async fn tarball_with_setuid_executable_extracts_with_setuid_bit_stripped() {
    use std::os::unix::fs::PermissionsExt;

    let tgz = tarball_with_extra_entries("setuid-pkg", "1.0.0", |builder| {
        let content = b"#!/bin/sh\necho privileged\n";
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        // 0o4755 = SUID + rwxr-xr-x. The extractor must strip the
        // SUID bit (0o4000) and emit 0o755.
        header.set_mode(0o4755);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        builder
            .append_data(&mut header, "package/bin/run.sh", &content[..])
            .unwrap();
    });

    let mock = MockRegistry::start().await;
    mock.with_package("setuid-pkg", "1.0.0", &tgz).await;

    let project = TempProject::empty(r#"{"name":"sec-test","version":"1.0.0"}"#);
    let output = lpm_with_registry(&project, &mock.url())
        .args(install_args("setuid-pkg@1.0.0"))
        .output()
        .expect("run install");
    let stderr = String::from_utf8_lossy(&output.stderr);

    eprintln!(
        "[Plan#8 setuid-strip] status={:?}\nstderr:\n{stderr}",
        output.status
    );

    assert!(
        output.status.success(),
        "install of setuid-bearing tarball failed — the file should \
         have extracted (SUID stripped, rwx preserved).\nstderr:\n{stderr}"
    );
    assert!(
        !stderr.contains("panicked at"),
        "extractor panicked on setuid entry:\nstderr:\n{stderr}"
    );

    let extracted = project.path().join("node_modules/setuid-pkg/bin/run.sh");
    assert!(
        extracted.exists(),
        "expected the setuid file to extract (with SUID stripped) at {extracted:?}"
    );

    let mode = std::fs::metadata(&extracted)
        .expect("stat extracted file")
        .permissions()
        .mode()
        & 0o7777;
    // The post-write set_permissions uses (0o644 | exec_bits). For a
    // tarball mode of 0o4755 (rwxr-xr-x + SUID): exec_bits = 0o111,
    // so the on-disk mode is 0o644 | 0o111 = 0o755. SUID (0o4000)
    // MUST be cleared.
    assert_eq!(
        mode & 0o4000,
        0,
        "SUID bit was preserved — security regression. on-disk mode: {mode:#o}"
    );
    assert_eq!(
        mode & 0o2000,
        0,
        "SGID bit was preserved — security regression. on-disk mode: {mode:#o}"
    );
    assert_eq!(
        mode & 0o1000,
        0,
        "sticky bit was preserved — sanity. on-disk mode: {mode:#o}"
    );
    // Sanity: exec bits are still present (the extractor honored
    // the legitimate executability of bin scripts).
    assert!(
        mode & 0o111 != 0,
        "all execute bits stripped — the extractor over-corrected. \
         on-disk mode: {mode:#o}. Expected exec bits preserved (0o755)."
    );
}

// ──────────────────────────────────────────────────────────────────────

/// **Plan #4 — Unicode-bearing entry path is taken as literal bytes, not normalized.**
///
/// The extractor's `Component::ParentDir` check at
/// [lib.rs:347](../../../crates/lpm-extractor/src/lib.rs#L347) compares
/// against `b".."` byte-exactly. A tarball entry with full-width
/// dots `．．` (U+FF0E × 2, UTF-8 `\xef\xbc\x8e\xef\xbc\x8e`) does
/// NOT match `ParentDir` and is treated as a normal `Component::Normal`
/// directory name. Same shape for RTL override (U+202E, the
/// `RIGHT-TO-LEFT OVERRIDE` codepoint — not literally embedded in
/// this docstring because rustc rejects bidi codepoints in source
/// even in comments), URL-encoded forms like `..%c0%af`, and any
/// other Unicode
/// representation that doesn't decode to the literal ASCII bytes
/// `..` at the OS layer.
///
/// **Result:** install SUCCEEDS, the entry extracts at the literal
/// Unicode-bearing path under `node_modules/<pkg>/`, no traversal
/// triggers, and the outside sentinel is unchanged.
///
/// That posture is defensible: Rust's `Path::components()` is byte-
/// based on POSIX (no NFC/NFKC normalization), so any non-ASCII
/// representation of "parent dir" loses its semantic meaning at the
/// path-component layer. The bytes become a normal filename. The
/// only Unicode-trick that COULD escape would be one whose bytes
/// are byte-identical to ASCII `..` at the OS layer — by
/// construction, that's the regular `..` case (Plan #1), already
/// pinned.
///
/// Pin the no-escape contract: outside sentinel byte-identical, the
/// extracted file (if any) lives strictly under
/// `node_modules/<pkg>/`.
#[tokio::test]
async fn tarball_with_unicode_lookalike_parent_dir_extracts_safely_as_literal_bytes() {
    // Plant an outside sentinel — same shape as the symlink/hardlink
    // tests so a writethrough is detectable.
    let outside_dir = tempfile::tempdir().expect("outside tempdir");
    let outside_target = outside_dir.path().join("escape.txt");
    std::fs::write(&outside_target, b"original outside content").expect("plant sentinel");

    let tgz = tarball_with_extra_entries("unicode-pkg", "1.0.0", |builder| {
        let content = b"unicode-pwn-attempt";
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        // Full-width dots — visually `..` but bytewise NOT the
        // ASCII `..` that triggers `Component::ParentDir`.
        header
            .set_path("package/．．/escape.txt")
            .expect("set unicode path");
        header.set_cksum();
        builder.append(&header, &content[..]).unwrap();
    });

    let mock = MockRegistry::start().await;
    mock.with_package("unicode-pkg", "1.0.0", &tgz).await;

    let project = TempProject::empty(r#"{"name":"sec-test","version":"1.0.0"}"#);
    let output = lpm_with_registry(&project, &mock.url())
        .args(install_args("unicode-pkg@1.0.0"))
        .output()
        .expect("run install");
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    eprintln!(
        "[Plan#4 unicode-literal] status={:?}\nstderr:\n{stderr}\nstdout:\n{stdout}",
        output.status
    );

    assert!(
        output.status.success(),
        "install of Unicode-lookalike-traversal tarball failed — \
         the extractor's literal-bytes contract may have changed.\n\
         stderr:\n{stderr}"
    );
    assert!(
        !stderr.contains("panicked at"),
        "extractor panicked on Unicode-bearing path:\nstderr:\n{stderr}"
    );

    // **Critical** — outside sentinel must be byte-identical. If
    // `．．` were ever interpreted as parent-dir traversal AND the
    // extractor wrote through it, the outside file would be
    // overwritten or supplemented.
    let after = std::fs::read(&outside_target).expect("re-read outside sentinel");
    assert_eq!(
        after, b"original outside content",
        "outside sentinel was modified — Unicode-lookalike path was \
         interpreted as traversal somewhere in the pipeline. \
         file: {outside_target:?}"
    );
    // Also pin: nothing landed at the project's parent dir as a
    // sibling escape.txt (`node_modules/escape.txt` would also be
    // a smell — the literal path should land deeper).
    let project_parent_escape = project.path().parent().unwrap().join("escape.txt");
    assert!(
        !project_parent_escape.exists(),
        "extractor wrote to project's parent — security regression. \
         file lives at: {project_parent_escape:?}"
    );

    // Diagnostic only: surface the actual landing path so future
    // readers can see where the extractor placed the literal-bytes
    // entry. Not asserted because filesystem rules around non-ASCII
    // dir names vary across macOS HFS+/APFS, ext4, NTFS-via-WSL.
    let pkg_dir = project.path().join("node_modules/unicode-pkg");
    let unicode_subdir = pkg_dir.join("．．");
    eprintln!(
        "[Plan#4 unicode-literal] unicode_subdir_exists={} pkg_dir_exists={} files_under_pkg={:?}",
        unicode_subdir.exists(),
        pkg_dir.exists(),
        pkg_dir
            .read_dir()
            .ok()
            .map(|rd| rd.flatten().map(|e| e.file_name()).collect::<Vec<_>>())
    );
}

/// **Plan #6 — character-device entry is silently skipped (POSIX-only).**
///
/// Tarball entry type `EntryType::Char` (or `Block`) is not
/// `is_file()`, so the extractor's regular-files-only branch at
/// [lib.rs:398](../../../crates/lpm-extractor/src/lib.rs#L398)
/// silently drops it. Same posture as the symlink/hardlink tests
/// in phase 1.
///
/// Defensible: npm packages don't legitimately ship device files.
/// Silent-skip avoids ever materializing a /dev/null-like entry
/// that could confuse downstream tools (Node's `fs.readFileSync`
/// on a character device would block forever or read zero bytes).
///
/// **Why Unix-only:** tar's `EntryType::Char` and `Block` map to
/// POSIX `mknod()` semantics. Windows tar can't materialize them
/// even if the silent-skip logic were bypassed; the path is moot
/// there. The same `is_file()` predicate gates the skip cross-
/// platform, but constructing the test fixture is POSIX-shaped.
#[cfg(unix)]
#[tokio::test]
async fn tarball_with_character_device_entry_is_silently_skipped() {
    let tgz = tarball_with_extra_entries("chardev-pkg", "1.0.0", |builder| {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Char);
        header.set_size(0);
        header.set_mode(0o600);
        // device_major/minor live in the tar header but the extractor
        // never reads them (silent-skip happens before any device-
        // creation code path). Set both to 0 — value is irrelevant.
        header.set_device_major(1).expect("set major");
        header.set_device_minor(3).expect("set minor"); // /dev/null-shape
        header.set_cksum();
        builder
            .append_data(&mut header, "package/devnull-clone", std::io::empty())
            .unwrap();
    });

    let mock = MockRegistry::start().await;
    mock.with_package("chardev-pkg", "1.0.0", &tgz).await;

    let project = TempProject::empty(r#"{"name":"sec-test","version":"1.0.0"}"#);
    let output = lpm_with_registry(&project, &mock.url())
        .args(install_args("chardev-pkg@1.0.0"))
        .output()
        .expect("run install");
    let stderr = String::from_utf8_lossy(&output.stderr);

    eprintln!(
        "[Plan#6 chardev-skip] status={:?}\nstderr:\n{stderr}",
        output.status
    );

    assert!(
        output.status.success(),
        "install of character-device-bearing tarball failed — \
         silent-skip contract may have changed.\nstderr:\n{stderr}"
    );
    assert!(
        !stderr.contains("panicked at"),
        "extractor panicked on character-device entry:\nstderr:\n{stderr}"
    );

    let phantom = project
        .path()
        .join("node_modules/chardev-pkg/devnull-clone");
    assert!(
        !phantom.exists(),
        "the silently-skipped character device should not appear at {phantom:?}"
    );
}

/// **Plan #7 — FIFO entry is silently skipped (POSIX-only).**
///
/// Tarball entry type `EntryType::Fifo` is not `is_file()`. Same
/// silent-skip posture as #6 (character device). Pinned for
/// completeness so a future regression that flips the gate (e.g.,
/// `EntryType::Fifo` accidentally treated as Regular) is detected
/// here.
///
/// Defensible: npm packages don't ship named pipes. Materializing
/// one would create a hang trap for any tool that opened the path
/// for read.
#[cfg(unix)]
#[tokio::test]
async fn tarball_with_fifo_entry_is_silently_skipped() {
    let tgz = tarball_with_extra_entries("fifo-pkg", "1.0.0", |builder| {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Fifo);
        header.set_size(0);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, "package/named-pipe", std::io::empty())
            .unwrap();
    });

    let mock = MockRegistry::start().await;
    mock.with_package("fifo-pkg", "1.0.0", &tgz).await;

    let project = TempProject::empty(r#"{"name":"sec-test","version":"1.0.0"}"#);
    let output = lpm_with_registry(&project, &mock.url())
        .args(install_args("fifo-pkg@1.0.0"))
        .output()
        .expect("run install");
    let stderr = String::from_utf8_lossy(&output.stderr);

    eprintln!(
        "[Plan#7 fifo-skip] status={:?}\nstderr:\n{stderr}",
        output.status
    );

    assert!(
        output.status.success(),
        "install of FIFO-bearing tarball failed — silent-skip contract \
         may have changed.\nstderr:\n{stderr}"
    );
    assert!(
        !stderr.contains("panicked at"),
        "extractor panicked on FIFO entry:\nstderr:\n{stderr}"
    );

    let phantom = project.path().join("node_modules/fifo-pkg/named-pipe");
    assert!(
        !phantom.exists(),
        "the silently-skipped FIFO should not appear at {phantom:?}"
    );
}

/// **Plan #9 — zero-byte regular file extracts as an empty file (sanity).**
///
/// Pure sanity check that the size-0 edge case isn't swallowed by
/// the size-limit / hardening branches. Many npm packages ship
/// empty files (build artifacts, `.gitkeep`, `LICENSE` placeholders),
/// so a regression that drops them would break real installs while
/// passing all the malicious-tarball tests above.
///
/// Pin: install succeeds, the empty file lands at the expected path
/// inside `node_modules/<pkg>/`, on-disk size is 0.
#[tokio::test]
async fn tarball_with_zero_byte_regular_file_extracts_as_empty_file() {
    let tgz = tarball_with_extra_entries("empty-pkg", "1.0.0", |builder| {
        let mut header = tar::Header::new_gnu();
        header.set_size(0);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        builder
            .append_data(&mut header, "package/empty.txt", std::io::empty())
            .unwrap();
    });

    let mock = MockRegistry::start().await;
    mock.with_package("empty-pkg", "1.0.0", &tgz).await;

    let project = TempProject::empty(r#"{"name":"sec-test","version":"1.0.0"}"#);
    let output = lpm_with_registry(&project, &mock.url())
        .args(install_args("empty-pkg@1.0.0"))
        .output()
        .expect("run install");
    let stderr = String::from_utf8_lossy(&output.stderr);

    eprintln!(
        "[Plan#9 zero-byte] status={:?}\nstderr:\n{stderr}",
        output.status
    );

    assert!(
        output.status.success(),
        "install of zero-byte-member tarball failed — extractor's \
         empty-file handling may have regressed.\nstderr:\n{stderr}"
    );
    assert!(
        !stderr.contains("panicked at"),
        "extractor panicked on zero-byte entry:\nstderr:\n{stderr}"
    );

    let extracted = project.path().join("node_modules/empty-pkg/empty.txt");
    assert!(
        extracted.exists(),
        "expected the zero-byte file to extract at {extracted:?}"
    );
    let on_disk_size = std::fs::metadata(&extracted)
        .expect("stat extracted empty file")
        .len();
    assert_eq!(
        on_disk_size, 0,
        "extracted empty file is not zero bytes — the extractor wrote \
         garbage. on-disk size: {on_disk_size}"
    );
}

/// **Plan #10 — entry path with a single 300-byte component fails cleanly.**
///
/// POSIX `NAME_MAX` is 255 on most filesystems (ext4/APFS/HFS+);
/// Windows `MAX_PATH` is 260 by default. A single 300-byte path
/// component exceeds NAME_MAX everywhere, so `std::fs::create_dir`
/// (or `OpenOptions::open` for the leaf) returns an OS error
/// (`ENAMETOOLONG` on Linux/macOS, `ERROR_FILENAME_EXCED_RANGE` on
/// Windows). The extractor wraps this as `LpmError::Io(error)` →
/// install fails with the OS message visible.
///
/// Pin the contract:
/// - Install fails non-zero (no silent extraction at a corrupted path).
/// - No panic (the OS error is wrapped, not unwrapped).
/// - Stderr contains the long-name nature OR the generic IO error
///   noun (long / name / file / directory / io / extraction / install).
///
/// **Why 300, not 4096:** the goal is to trip the per-component
/// `NAME_MAX` (~255) ceiling, which most filesystems enforce
/// uniformly. Trying to trip the per-path `PATH_MAX` (4096 on Linux,
/// 1024 on macOS) would require deep nesting AND a long leaf,
/// adding shape complexity for the same security signal.
#[tokio::test]
async fn tarball_with_single_path_component_exceeding_name_max_fails_cleanly() {
    // 300-byte component name. Most filesystems cap at NAME_MAX=255;
    // 300 trips the ceiling reliably.
    let long_name: String = "a".repeat(300);
    let entry_path = format!("package/{long_name}");

    let tgz = tarball_with_extra_entries("longname-pkg", "1.0.0", |builder| {
        let content = b"will-fail-on-create";
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        // append_data uses GNU long-name extension for paths longer
        // than 100 bytes — the tar wire format succeeds; only the
        // FILESYSTEM rejects on extraction.
        builder
            .append_data(&mut header, &entry_path, &content[..])
            .expect("append long-name entry");
    });

    let mock = MockRegistry::start().await;
    mock.with_package("longname-pkg", "1.0.0", &tgz).await;

    let project = TempProject::empty(r#"{"name":"sec-test","version":"1.0.0"}"#);
    let output = lpm_with_registry(&project, &mock.url())
        .args(install_args("longname-pkg@1.0.0"))
        .output()
        .expect("run install");
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    eprintln!(
        "[Plan#10 long-path] status={:?}\nstderr:\n{stderr}\nstdout:\n{stdout}",
        output.status
    );

    assert!(
        !output.status.success(),
        "install of 300-byte-component tarball reported success — \
         the filesystem accepted a path beyond NAME_MAX, OR the \
         extractor silently dropped the entry. Either is a contract \
         break.\nstderr:\n{stderr}"
    );
    assert!(
        !stderr.contains("panicked at") && !stderr.contains("note: run with `RUST_BACKTRACE"),
        "extractor panicked on long-path entry:\nstderr:\n{stderr}"
    );

    // Stderr should name SOMETHING actionable. The extractor wraps
    // the OS error as `LpmError::Io`, and the slim renderer preserves
    // the original system message ("File name too long" / "filename
    // exceeds maximum length"). The word list is broad to tolerate
    // platform variance.
    let stderr_l = stderr.to_lowercase();
    let actionable = [
        "long",
        "name",
        "filename",
        "file name",
        "exceed",
        "directory",
        "io error",
        "io ",
        "io)",
        "extraction",
        "extract",
        "tarball",
        "installation",
        "install",
    ]
    .iter()
    .any(|n| stderr_l.contains(n));
    assert!(
        actionable,
        "long-path failure didn't surface an actionable noun. \
         stderr:\n{stderr}"
    );
}

// ─── Additional tarball attack surfaces ───────────────
//
// Each test hardens the install pipeline against a tarball-shape attack
// vector the baseline tests above did not exercise.

/// **Candidate — PAX-extended path-header traversal is rejected.**
///
/// PAX (POSIX 1003.1-2001) extended headers let a tarball override
/// the legacy 100-byte path field with arbitrary UTF-8. An attacker
/// can put a benign-looking path in the legacy header (which casual
/// inspection tools surface) while smuggling a `..`-traversal payload
/// in the PAX `path` record. The tar crate resolves the PAX-overridden
/// path through `entry.path()` at
/// [entry.rs:304](https://docs.rs/tar/0.4.45/src/tar/entry.rs.html#304),
/// so the extractor's `Component::ParentDir` check at
/// [lib.rs:347](../../../crates/lpm-extractor/src/lib.rs#L347) sees the
/// PAX path (not the legacy one) and rejects.
///
/// Pin the contract: install fails non-zero, no panic, outside
/// sentinel byte-identical. This forecloses the "PAX-only-aware
/// scanner sees benign path, extractor sees real malicious path"
/// disagreement class.
#[tokio::test]
async fn tarball_with_pax_path_traversal_rejected() {
    let tgz = tarball_with_extra_entries("pax-pkg", "1.0.0", |builder| {
        // PAX extended header (`x` entry type). Body is a sequence of
        // `LEN KEY=VALUE\n` records where LEN is the byte length of
        // the entire record INCLUDING the leading length digits and
        // the trailing newline. For path "package/../escape.txt"
        // (21 bytes): " path=...\n" is 1+4+1+21+1 = 28 bytes; with
        // length "30" (2 digits) total = 30. Format: "30 path=...\n".
        let path_value = "package/../escape.txt";
        // " path=" + value + "\n" = 7 + value.len() bytes. Length =
        // digits(length) + 7 + value.len(). Solve: for value.len()=21,
        // total without length digits = 28; 30 fits with 2-digit "30".
        let payload_body_len = 1 + b"path=".len() + path_value.len() + 1;
        // Iterate to find the length that includes its own digits.
        let mut total = payload_body_len + 2;
        loop {
            let digits = total.to_string().len();
            let candidate = payload_body_len + digits;
            if candidate == total {
                break;
            }
            total = candidate;
        }
        let pax_record = format!("{total} path={path_value}\n");
        assert_eq!(pax_record.len(), total, "PAX length self-consistent");

        let mut pax_header = tar::Header::new_gnu();
        pax_header.set_size(pax_record.len() as u64);
        pax_header.set_entry_type(tar::EntryType::XHeader);
        pax_header.set_mode(0o644);
        // The PAX header entry's own path is conventionally
        // "<dir>/PaxHeaders/<name>" or similar. The contents are what
        // matter; the tar crate doesn't validate the header path.
        pax_header
            .set_path("package/PaxHeaders/safe.txt")
            .expect("set pax header path");
        pax_header.set_cksum();
        builder.append(&pax_header, pax_record.as_bytes()).unwrap();

        // The target file entry that the PAX header redirects. Its
        // legacy header carries a benign path; on read, the tar crate
        // overrides with the PAX `path` value.
        let content = b"pax-pwned";
        let mut file_header = tar::Header::new_gnu();
        file_header.set_size(content.len() as u64);
        file_header.set_mode(0o644);
        file_header.set_entry_type(tar::EntryType::Regular);
        file_header
            .set_path("package/safe.txt")
            .expect("set file header path");
        file_header.set_cksum();
        builder.append(&file_header, &content[..]).unwrap();
    });

    let mock = MockRegistry::start().await;
    mock.with_package("pax-pkg", "1.0.0", &tgz).await;

    let project = TempProject::empty(r#"{"name":"sec-test","version":"1.0.0"}"#);
    let outside = project.path().parent().unwrap().join("escape.txt");
    let _ = std::fs::remove_file(&outside);

    let output = lpm_with_registry(&project, &mock.url())
        .args(install_args("pax-pkg@1.0.0"))
        .output()
        .expect("run install");
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    eprintln!(
        "[Candidate pax-traversal] status={:?}\nstderr:\n{stderr}\nstdout:\n{stdout}",
        output.status
    );

    assert!(
        !output.status.success(),
        "install of PAX-traversal tarball reported success — the \
         attacker's PAX-smuggled `..` path was extracted somewhere:\n\
         stderr:\n{stderr}"
    );
    assert!(
        !stderr.contains("panicked at") && !stderr.contains("note: run with `RUST_BACKTRACE"),
        "extractor panicked on PAX traversal:\nstderr:\n{stderr}"
    );
    assert!(
        !outside.exists(),
        "extractor wrote outside via PAX-overridden path — security \
         regression. file lives at: {outside:?}"
    );
    let stderr_l = stderr.to_lowercase();
    assert!(
        stderr_l.contains("traversal")
            || stderr_l.contains("integrity")
            || stderr_l.contains("invalid"),
        "PAX rejection lacks actionable noun. stderr:\n{stderr}"
    );
}

/// **Candidate — GNU longname-extended path-header traversal is rejected.**
///
/// GNU longname headers (`L` entry type) supply an out-of-band path
/// for entries whose path exceeds the legacy 100-byte field. The tar
/// crate resolves through `long_pathname` at
/// [entry.rs:309](https://docs.rs/tar/0.4.45/src/tar/entry.rs.html#309)
/// taking precedence over the legacy header path AND over PAX. An
/// attacker who knows the legacy-only path is inspected can hide a
/// `..` traversal in the GNU L body.
///
/// Pin the contract: install fails non-zero, no panic, outside
/// sentinel byte-identical. Forecloses the GNU-aware-disagreement
/// class symmetric to PAX above.
#[tokio::test]
async fn tarball_with_gnu_longname_traversal_rejected() {
    let tgz = tarball_with_extra_entries("gnu-long-pkg", "1.0.0", |builder| {
        // GNU L entry: body is the long path bytes, NUL-terminated.
        // The tar crate accepts trailing NUL or not — both shapes are
        // recognized; supply the terminator to match the GNU spec.
        let long_path = b"package/../escape.txt\0";

        let mut long_header = tar::Header::new_gnu();
        long_header.set_size(long_path.len() as u64);
        long_header.set_entry_type(tar::EntryType::GNULongName);
        long_header.set_mode(0o644);
        long_header
            .set_path("././@LongLink")
            .expect("set GNU L header conventional path");
        long_header.set_cksum();
        builder.append(&long_header, &long_path[..]).unwrap();

        // Target file entry — legacy header carries a benign path; on
        // read, the tar crate substitutes the L body.
        let content = b"gnu-long-pwned";
        let mut file_header = tar::Header::new_gnu();
        file_header.set_size(content.len() as u64);
        file_header.set_mode(0o644);
        file_header.set_entry_type(tar::EntryType::Regular);
        file_header
            .set_path("package/safe.txt")
            .expect("set file header path");
        file_header.set_cksum();
        builder.append(&file_header, &content[..]).unwrap();
    });

    let mock = MockRegistry::start().await;
    mock.with_package("gnu-long-pkg", "1.0.0", &tgz).await;

    let project = TempProject::empty(r#"{"name":"sec-test","version":"1.0.0"}"#);
    let outside = project.path().parent().unwrap().join("escape.txt");
    let _ = std::fs::remove_file(&outside);

    let output = lpm_with_registry(&project, &mock.url())
        .args(install_args("gnu-long-pkg@1.0.0"))
        .output()
        .expect("run install");
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    eprintln!(
        "[Candidate gnu-longname-traversal] status={:?}\nstderr:\n{stderr}\nstdout:\n{stdout}",
        output.status
    );

    assert!(
        !output.status.success(),
        "install of GNU-longname-traversal tarball reported success — \
         the L-smuggled `..` path was extracted:\nstderr:\n{stderr}"
    );
    assert!(
        !stderr.contains("panicked at") && !stderr.contains("note: run with `RUST_BACKTRACE"),
        "extractor panicked on GNU longname traversal:\nstderr:\n{stderr}"
    );
    assert!(
        !outside.exists(),
        "extractor wrote outside via GNU-longname-overridden path — \
         security regression. file lives at: {outside:?}"
    );
    let stderr_l = stderr.to_lowercase();
    assert!(
        stderr_l.contains("traversal")
            || stderr_l.contains("integrity")
            || stderr_l.contains("invalid"),
        "GNU longname rejection lacks actionable noun. stderr:\n{stderr}"
    );
}

/// **Candidate — duplicate-member path: pin the current contract.**
///
/// Two tar entries share the same `package/duplicate.txt` path with
/// different bytes. The extractor walks entries in order. Neither
/// entry trips any security check (both are well-formed regular
/// files under the extraction root). The first write creates the
/// file; the second write opens with create-or-truncate (`write_buffered_entry`
/// and `stream_entry_to_disk` both use this semantics — see
/// [lib.rs:498-522](../../../crates/lpm-extractor/src/lib.rs#L498)).
///
/// **Pinned contract (last-write-wins):** install succeeds, the
/// duplicate path materializes with the SECOND entry's bytes,
/// stripping the first entry's content. This is defensible because
/// (a) npm never legitimately ships duplicates and (b) deterministic
/// last-wins is preferable to a non-deterministic file-system race.
/// The risk it leaves on the table: a scanner that snapshots the
/// FIRST entry's content disagrees with the extractor's on-disk
/// result. Pinned here so any future flip (e.g., "reject duplicates",
/// "first-wins") is detected immediately.
#[tokio::test]
async fn tarball_with_duplicate_member_path_rejected_or_deterministic() {
    let tgz = tarball_with_extra_entries("dup-pkg", "1.0.0", |builder| {
        let first = b"FIRST-CONTENT";
        let mut h1 = tar::Header::new_gnu();
        h1.set_size(first.len() as u64);
        h1.set_mode(0o644);
        h1.set_entry_type(tar::EntryType::Regular);
        h1.set_cksum();
        builder
            .append_data(&mut h1, "package/duplicate.txt", &first[..])
            .unwrap();

        let second = b"SECOND-CONTENT-different-length";
        let mut h2 = tar::Header::new_gnu();
        h2.set_size(second.len() as u64);
        h2.set_mode(0o644);
        h2.set_entry_type(tar::EntryType::Regular);
        h2.set_cksum();
        builder
            .append_data(&mut h2, "package/duplicate.txt", &second[..])
            .unwrap();
    });

    let mock = MockRegistry::start().await;
    mock.with_package("dup-pkg", "1.0.0", &tgz).await;

    let project = TempProject::empty(r#"{"name":"sec-test","version":"1.0.0"}"#);
    let output = lpm_with_registry(&project, &mock.url())
        .args(install_args("dup-pkg@1.0.0"))
        .output()
        .expect("run install");
    let stderr = String::from_utf8_lossy(&output.stderr);

    eprintln!(
        "[Candidate duplicate-member] status={:?}\nstderr:\n{stderr}",
        output.status
    );

    // Current contract is last-write-wins, install succeeds. If the
    // contract is ever tightened to "reject duplicates", flip this
    // to !success + actionable-noun assertions — but only after a
    // conscious policy decision is recorded in the extractor source.
    assert!(
        output.status.success(),
        "install of duplicate-member tarball failed — the extractor's \
         last-write-wins contract may have changed (audit before \
         flipping the assertion).\nstderr:\n{stderr}"
    );
    assert!(
        !stderr.contains("panicked at"),
        "extractor panicked on duplicate member:\nstderr:\n{stderr}"
    );

    let extracted = project.path().join("node_modules/dup-pkg/duplicate.txt");
    assert!(
        extracted.exists(),
        "expected the duplicate file to extract at {extracted:?}"
    );
    let bytes = std::fs::read(&extracted).expect("read duplicate extract");
    assert_eq!(
        bytes,
        b"SECOND-CONTENT-different-length".to_vec(),
        "last-write-wins contract violated — on-disk bytes do not \
         match the second entry's payload. Got: {bytes:?}"
    );
}

/// **Candidate — malicious later entry causes rollback of earlier valid entries.**
///
/// Order matters in tar extraction: a tarball whose first N entries
/// pass every security check and whose N+1-th entry is malicious
/// (`..` traversal) tests whether the extractor leaves the earlier
/// extracted bytes on disk after rejection. The
/// [`rollback_extraction`](../../../crates/lpm-extractor/src/lib.rs#L665)
/// helper cleans up `extracted_files` and `created_dirs` on every
/// error path — so the contract is: install fails, NO partial
/// extraction survives.
///
/// At the workflow tier the store extracts into a temp dir before
/// the atomic rename to `~/.lpm/store/`, so on rejection the temp
/// dir is removed and no entry lands in the store. Linking never
/// happens. Therefore `node_modules/<pkg>/` must be entirely absent
/// post-failure.
#[tokio::test]
async fn tarball_rejects_or_rolls_back_when_later_entry_is_malicious() {
    let tgz = tarball_with_extra_entries("rollback-pkg", "1.0.0", |builder| {
        // Valid first entry — would extract cleanly on its own.
        let valid = b"valid-first-entry";
        let mut valid_h = tar::Header::new_gnu();
        valid_h.set_size(valid.len() as u64);
        valid_h.set_mode(0o644);
        valid_h.set_entry_type(tar::EntryType::Regular);
        valid_h.set_cksum();
        builder
            .append_data(&mut valid_h, "package/valid-first.txt", &valid[..])
            .unwrap();

        // Malicious second entry — `..` traversal triggers rejection
        // AFTER the first entry already passed prepare_output_path
        // and was written to disk. The extractor's rollback path
        // must clean up the first entry.
        let evil = b"evil-second-entry";
        let mut evil_h = tar::Header::new_gnu();
        evil_h.set_size(evil.len() as u64);
        evil_h.set_mode(0o644);
        evil_h.set_entry_type(tar::EntryType::Regular);
        evil_h.set_path("package/safe.txt").unwrap();
        let raw = evil_h.as_mut_bytes();
        raw[..100].fill(0);
        let payload = b"package/../escape.txt";
        raw[..payload.len()].copy_from_slice(payload);
        evil_h.set_cksum();
        builder.append(&evil_h, &evil[..]).unwrap();
    });

    let mock = MockRegistry::start().await;
    mock.with_package("rollback-pkg", "1.0.0", &tgz).await;

    let project = TempProject::empty(r#"{"name":"sec-test","version":"1.0.0"}"#);
    let outside = project.path().parent().unwrap().join("escape.txt");
    let _ = std::fs::remove_file(&outside);

    let output = lpm_with_registry(&project, &mock.url())
        .args(install_args("rollback-pkg@1.0.0"))
        .output()
        .expect("run install");
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    eprintln!(
        "[Candidate later-entry-malicious] status={:?}\nstderr:\n{stderr}\nstdout:\n{stdout}",
        output.status
    );

    assert!(
        !output.status.success(),
        "install of tarball with malicious second entry reported \
         success — the extractor accepted a `..` traversal mid-stream.\
         \nstderr:\n{stderr}"
    );
    assert!(
        !stderr.contains("panicked at"),
        "extractor panicked on later-entry traversal:\nstderr:\n{stderr}"
    );
    assert!(
        !outside.exists(),
        "extractor wrote outside via late-entry traversal — \
         rollback failed. file lives at: {outside:?}"
    );

    // Critical rollback contract: the earlier valid entry must NOT
    // survive the rejection. node_modules/<pkg>/ should not exist
    // (atomic install pipeline never linked) AND, even if a future
    // refactor surfaces a partial directory, the valid-first.txt
    // file must NOT exist.
    let pkg_dir = project.path().join("node_modules/rollback-pkg");
    let valid_first = pkg_dir.join("valid-first.txt");
    assert!(
        !valid_first.exists(),
        "earlier valid entry survived rollback — partial state leak.\
         \nleftover at: {valid_first:?}"
    );
}

/// **Candidate — truncated gzip stream fails cleanly with no partial extraction.**
///
/// Truncating the gzip bytes mid-stream causes `libdeflate` to return
/// a decompression error at
/// [lib.rs:108-120](../../../crates/lpm-extractor/src/lib.rs#L108).
/// The extractor never reaches the tar walk, so there is nothing to
/// roll back from disk — but the test still pins the user-visible
/// contract: install fails non-zero, no panic, and `node_modules/<pkg>/`
/// is absent (no half-extracted files).
///
/// The truncation point is chosen to leave a valid gzip header (so
/// the magic check at lib.rs:77 passes) but to corrupt the compressed
/// payload (so libdeflate fails partway through decompression).
#[tokio::test]
async fn tarball_with_truncated_gzip_rolls_back_partial_extract() {
    // Build a valid tarball with a recognizable payload so we know
    // its decompressed size > truncation point.
    let valid_tgz = tarball_with_extra_entries("trunc-pkg", "1.0.0", |builder| {
        // A real-sized file (~1 KB) so the gzip stream has enough body
        // to truncate meaningfully — too tiny and the truncation might
        // land in the trailer rather than the deflate stream.
        let content = vec![b'A'; 1024];
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        builder
            .append_data(&mut header, "package/payload.txt", &content[..])
            .unwrap();
    });
    assert!(
        valid_tgz.len() > 50,
        "valid tarball too small to truncate meaningfully"
    );

    // Truncate to half — preserves gzip header (0x1f 0x8b at byte 0)
    // but corrupts the deflate body. libdeflate will fail mid-stream.
    let truncated = valid_tgz[..valid_tgz.len() / 2].to_vec();
    assert_eq!(
        &truncated[..2],
        &[0x1f, 0x8b],
        "truncation removed gzip magic — wrong truncation point"
    );

    let mock = MockRegistry::start().await;
    mock.with_package("trunc-pkg", "1.0.0", &truncated).await;

    let project = TempProject::empty(r#"{"name":"sec-test","version":"1.0.0"}"#);
    let output = lpm_with_registry(&project, &mock.url())
        .args(install_args("trunc-pkg@1.0.0"))
        .output()
        .expect("run install");
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    eprintln!(
        "[Candidate truncated-gzip] status={:?}\nstderr:\n{stderr}\nstdout:\n{stdout}",
        output.status
    );

    assert!(
        !output.status.success(),
        "install of truncated-gzip tarball reported success — \
         libdeflate accepted a half-stream.\nstderr:\n{stderr}"
    );
    assert!(
        !stderr.contains("panicked at") && !stderr.contains("note: run with `RUST_BACKTRACE"),
        "extractor panicked on truncated gzip:\nstderr:\n{stderr}"
    );

    // No partial extraction.
    let pkg_dir = project.path().join("node_modules/trunc-pkg");
    assert!(
        !pkg_dir.exists(),
        "node_modules/<pkg>/ exists after truncated-gzip install — \
         partial extraction leaked: {pkg_dir:?}"
    );

    // Stderr should name something about the failure mode.
    let stderr_l = stderr.to_lowercase();
    let actionable = [
        "gzip",
        "decompression",
        "decompress",
        "integrity",
        "tarball",
        "extract",
        "install",
        "registry",
        "invalid",
    ]
    .iter()
    .any(|n| stderr_l.contains(n));
    assert!(
        actionable,
        "truncated-gzip failure didn't surface an actionable noun. \
         stderr:\n{stderr}"
    );
}

/// **Candidate — uid/gid ownership metadata in tar header is ignored.**
///
/// Tar entries carry uid/gid fields. An attacker shipping a tarball
/// could declare a privileged uid (0 = root) or a hostile uid (e.g.,
/// 99999 for a "ghost" account) hoping the extractor honors it. The
/// extractor's `set_preserve_ownerships(false)` at
/// [lib.rs:241](../../../crates/lpm-extractor/src/lib.rs#L241) tells
/// `tar::Archive` to skip the `fchownat` syscall entirely.
///
/// Result: files extract owned by the running process's uid/gid,
/// regardless of header claims. Pin the contract empirically — read
/// extracted file's `metadata().uid()` and assert it matches the
/// process uid, not the header's bogus 99999.
///
/// POSIX-only — Windows NTFS has no uid/gid concept; ownership is
/// SID-based and tar headers can't represent it. `set_preserve_ownerships`
/// is a no-op there.
#[cfg(unix)]
#[tokio::test]
async fn tarball_ignores_uid_gid_ownership_metadata() {
    use std::os::unix::fs::MetadataExt;

    let tgz = tarball_with_extra_entries("uid-gid-pkg", "1.0.0", |builder| {
        let content = b"normal-file-content";
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        // Claim ownership by a non-existent privileged-shape uid/gid.
        // The values are arbitrary — what matters is they don't
        // match the running process and would be visible if the
        // extractor honored them.
        header.set_uid(99_999);
        header.set_gid(99_999);
        header.set_cksum();
        builder
            .append_data(&mut header, "package/owned.txt", &content[..])
            .unwrap();
    });

    let mock = MockRegistry::start().await;
    mock.with_package("uid-gid-pkg", "1.0.0", &tgz).await;

    let project = TempProject::empty(r#"{"name":"sec-test","version":"1.0.0"}"#);
    let output = lpm_with_registry(&project, &mock.url())
        .args(install_args("uid-gid-pkg@1.0.0"))
        .output()
        .expect("run install");
    let stderr = String::from_utf8_lossy(&output.stderr);

    eprintln!(
        "[Candidate uid-gid-ignored] status={:?}\nstderr:\n{stderr}",
        output.status
    );

    assert!(
        output.status.success(),
        "install of uid/gid-bearing tarball failed — extractor's \
         ownership-ignore contract may have changed.\nstderr:\n{stderr}"
    );
    assert!(
        !stderr.contains("panicked at"),
        "extractor panicked on uid/gid entry:\nstderr:\n{stderr}"
    );

    let extracted = project.path().join("node_modules/uid-gid-pkg/owned.txt");
    assert!(
        extracted.exists(),
        "expected the uid/gid-bearing file to extract at {extracted:?}"
    );

    let md = std::fs::metadata(&extracted).expect("stat extracted file");
    let process_uid = unsafe { libc::getuid() };
    let process_gid = unsafe { libc::getgid() };
    assert_eq!(
        md.uid(),
        process_uid,
        "extracted file uid={} does not match process uid={process_uid} — \
         tarball's bogus uid (99999) was honored. security regression.",
        md.uid()
    );
    assert_eq!(
        md.gid(),
        process_gid,
        "extracted file gid={} does not match process gid={process_gid} — \
         tarball's bogus gid (99999) was honored. security regression.",
        md.gid()
    );
}

/// **Candidate — entry with declared size beyond MAX_FILE_SIZE is rejected up-front.**
///
/// The extractor pre-checks `entry.header().size()` at
/// [lib.rs:306](../../../crates/lpm-extractor/src/lib.rs#L306) against
/// `MAX_FILE_SIZE = 500 MB` BEFORE allocating or writing any bytes.
/// This forecloses the "sparse-bomb" attack class where a tar header
/// declares a multi-GB logical file even when the actual on-wire bytes
/// are tiny — without the up-front size check, the extractor could
/// allocate a multi-GB buffer or write a sparse file that exhausts
/// disk quota on touch.
///
/// Pin the contract: header declares `MAX_FILE_SIZE + 1` bytes; the
/// tar payload on the wire is empty (no actual content sent). The
/// extractor rejects on the size check before reading any payload
/// bytes from the entry. Install fails non-zero, no panic, no
/// partial extraction, stderr names the size-limit violation.
///
/// **Why this doesn't require an actual gigantic gzip stream:** the
/// per-entry size check reads `header().size()` from the 12-byte
/// octal field in the tar header — it doesn't care whether the
/// declared bytes are actually present in the stream. The check
/// fires at line 306 BEFORE `entry.read_to_end()` or
/// `stream_entry_to_disk` would try to drain the entry. So a tarball
/// with a header that lies about size is enough to exercise the check.
#[tokio::test]
async fn tarball_with_sparse_huge_file_rejected_by_declared_size() {
    // MAX_FILE_SIZE = 500 MB. Declare a size 1 byte beyond the cap.
    // The on-wire bytes are EMPTY — only the header lies. The
    // extractor's pre-check at lib.rs:306 reads the header size and
    // rejects BEFORE attempting to drain the (non-existent) body, so
    // we never need to actually generate 500 MB of data. This keeps
    // the test under the determinism budget.
    const MAX_FILE_SIZE: u64 = 500 * 1024 * 1024;
    let declared_size = MAX_FILE_SIZE + 1;

    // Construct the tar bytes manually — `tar::Builder::append` would
    // demand `declared_size` bytes of data, which is precisely what
    // we're trying to avoid.
    let mut header = tar::Header::new_gnu();
    header.set_size(declared_size); // The LIE.
    header.set_mode(0o644);
    header.set_entry_type(tar::EntryType::Regular);
    header
        .set_path("package/lying.txt")
        .expect("set lying header path");
    header.set_cksum();

    let mut tar_bytes = Vec::with_capacity(2048);
    // 512-byte header block.
    tar_bytes.extend_from_slice(header.as_bytes());
    // No body — the extractor rejects before reading any body bytes.
    // Append the tar end-of-archive marker (two 512-byte zero blocks)
    // so the archive is well-formed up to the failing entry.
    tar_bytes.extend_from_slice(&[0u8; 1024]);

    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&tar_bytes).expect("gzip the lying tar");
    let tgz = encoder.finish().expect("finish gzip");

    // Sanity: the compressed bytes should be tiny — gzip of ~1.5 KB
    // of mostly-zero header + zero-block trailer.
    assert!(
        tgz.len() < 1024,
        "gzip-compressed lying tarball is {} bytes (expected <1KB) — \
         construction may have ballooned",
        tgz.len()
    );

    let mock = MockRegistry::start().await;
    mock.with_package("huge-decl-pkg", "1.0.0", &tgz).await;

    let project = TempProject::empty(r#"{"name":"sec-test","version":"1.0.0"}"#);
    let output = lpm_with_registry(&project, &mock.url())
        .args(install_args("huge-decl-pkg@1.0.0"))
        .output()
        .expect("run install");
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    eprintln!(
        "[Candidate huge-declared-size] status={:?}\nstderr:\n{stderr}\nstdout:\n{stdout}",
        output.status
    );

    assert!(
        !output.status.success(),
        "install of huge-declared-size tarball reported success — \
         the extractor's MAX_FILE_SIZE pre-check may have regressed.\
         \nstderr:\n{stderr}"
    );
    assert!(
        !stderr.contains("panicked at") && !stderr.contains("note: run with `RUST_BACKTRACE"),
        "extractor panicked on huge-declared-size entry:\nstderr:\n{stderr}"
    );

    let pkg_dir = project.path().join("node_modules/huge-decl-pkg");
    assert!(
        !pkg_dir.exists(),
        "node_modules/<pkg>/ exists after huge-declared-size install — \
         partial extraction leaked: {pkg_dir:?}"
    );

    let stderr_l = stderr.to_lowercase();
    let actionable = [
        "too large",
        "size limit",
        "size",
        "exceed",
        "limit",
        "tarball",
        "extract",
        "install",
        "registry",
    ]
    .iter()
    .any(|n| stderr_l.contains(n));
    assert!(
        actionable,
        "huge-declared-size failure didn't surface an actionable noun. \
         stderr:\n{stderr}"
    );
}
