//! Real-registry smoke test for `lpm install` using a local Verdaccio.
//!
//! This is the first phase-65.1 slice: publish a package to a real npm
//! registry process, install it through a project `.npmrc`, and assert the
//! lockfile records the actual registry mirror URL rather than npmjs.org.

mod support;

use std::process::Output;

use support::verdaccio::VerdaccioRegistry;
use support::verdaccio_proxy::{MetadataBehavior, TarballBehavior, VerdaccioProxyRegistry};
use support::{TempProject, lpm};
use tempfile::TempDir;

fn run_install(project: &TempProject) -> Output {
    lpm(project)
        .env_remove("LPM_NPM_ROUTE")
        .env_remove("LPM_TOKEN")
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run lpm install against verdaccio")
}

fn package_install_path(project: &TempProject, package_name: &str) -> std::path::PathBuf {
    package_name
        .split('/')
        .fold(project.path().join("node_modules"), |path, segment| {
            path.join(segment)
        })
}

fn assert_package_installed(project: &TempProject, package_name: &str) {
    assert!(
        package_install_path(project, package_name).exists(),
        "expected {} to exist after install",
        package_install_path(project, package_name).display()
    );
}

fn assert_lockfile_source(project: &TempProject, package_name: &str, registry_url: &str) {
    let lockfile = lpm_lockfile::Lockfile::read_fast(&project.path().join("lpm.lock"))
        .expect("failed to read lpm.lock");
    let pkg = lockfile
        .find_package(package_name)
        .unwrap_or_else(|| panic!("lockfile must contain {package_name}"));
    let registry_source = format!("registry+{registry_url}");

    assert_eq!(
        pkg.source.as_deref(),
        Some(registry_source.as_str()),
        "lockfile source should record the actual verdaccio mirror URL"
    );
}

#[tokio::test]
async fn install_from_verdaccio_records_real_registry_source_in_lockfile() {
    let registry = VerdaccioRegistry::start().await;
    registry.publish_package("verdaccio-smoke-pkg", "1.0.0");

    let project = TempProject::empty(
        r#"{
            "name": "verdaccio-install-smoke",
            "version": "1.0.0",
            "dependencies": {
                "verdaccio-smoke-pkg": "1.0.0"
            }
        }"#,
    );
    registry.write_project_npmrc(project.path());

    let output = run_install(&project);

    assert!(
        output.status.success(),
        "install against verdaccio failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    assert_package_installed(&project, "verdaccio-smoke-pkg");
    assert_lockfile_source(&project, "verdaccio-smoke-pkg", registry.url());
}

#[tokio::test]
async fn install_scoped_package_from_verdaccio_preserves_real_registry_source() {
    let registry = VerdaccioRegistry::start().await;
    registry.publish_package("@verdaccio/smoke-scoped", "1.0.0");

    let project = TempProject::empty(
        r#"{
            "name": "verdaccio-install-scoped",
            "version": "1.0.0",
            "dependencies": {
                "@verdaccio/smoke-scoped": "1.0.0"
            }
        }"#,
    );
    registry.write_project_npmrc(project.path());

    let output = run_install(&project);

    assert!(
        output.status.success(),
        "scoped install against verdaccio failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    assert_package_installed(&project, "@verdaccio/smoke-scoped");
    assert_lockfile_source(&project, "@verdaccio/smoke-scoped", registry.url());
}

#[tokio::test]
async fn install_with_invalid_verdaccio_token_fails_without_creating_install_state() {
    let registry = VerdaccioRegistry::start().await;
    registry.publish_package("verdaccio-auth-pkg", "1.0.0");

    let project = TempProject::empty(
        r#"{
            "name": "verdaccio-auth-failure",
            "version": "1.0.0",
            "dependencies": {
                "verdaccio-auth-pkg": "1.0.0"
            }
        }"#,
    );
    registry.write_project_npmrc_with_token(project.path(), "PHASE65-INVALID-TOKEN");

    let output = run_install(&project);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stderr_lower = stderr.to_ascii_lowercase();

    assert!(
        !output.status.success(),
        "install with invalid verdaccio token must fail; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        stderr,
    );
    assert!(
        stderr_lower.contains("401")
            || stderr_lower.contains("unauthorized")
            || stderr_lower.contains("authorization")
            || stderr_lower.contains("authentication"),
        "stderr should mention auth failure for an invalid verdaccio token; got:\n{}",
        stderr,
    );
    assert!(
        !project.file_exists("lpm.lock"),
        "failed auth must not leave a lockfile behind"
    );
    assert!(
        !project
            .path()
            .join("node_modules")
            .join("verdaccio-auth-pkg")
            .exists(),
        "failed auth must not materialize node_modules/verdaccio-auth-pkg"
    );
}

#[tokio::test]
async fn install_missing_version_from_verdaccio_fails_without_creating_install_state() {
    let registry = VerdaccioRegistry::start().await;
    registry.publish_package("verdaccio-version-pkg", "1.0.0");

    let project = TempProject::empty(
        r#"{
            "name": "verdaccio-version-failure",
            "version": "1.0.0",
            "dependencies": {
                "verdaccio-version-pkg": "9.9.9"
            }
        }"#,
    );
    registry.write_project_npmrc(project.path());

    let output = run_install(&project);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !output.status.success(),
        "install with a missing verdaccio version must fail; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        stderr,
    );
    assert!(
        stderr.contains("verdaccio-version-pkg") && stderr.contains("9.9.9"),
        "stderr should identify the missing registry package version; got:\n{}",
        stderr,
    );
    assert!(
        !project.file_exists("lpm.lock"),
        "missing version must not leave a lockfile behind"
    );
    assert!(
        !project
            .path()
            .join("node_modules")
            .join("verdaccio-version-pkg")
            .exists(),
        "missing version must not materialize node_modules/verdaccio-version-pkg"
    );
}

#[tokio::test]
async fn install_fails_on_verdaccio_integrity_mismatch_without_creating_install_state() {
    let registry = VerdaccioRegistry::start().await;
    let package_name = "verdaccio-integrity-pkg";
    let version = "1.0.0";
    registry.publish_package(package_name, version);
    registry.rewrite_dist(package_name, version, None, Some("sha512-AAAAAAAAAA=="));

    let project = TempProject::empty(
        r#"{
            "name": "verdaccio-integrity-failure",
            "version": "1.0.0",
            "dependencies": {
                "verdaccio-integrity-pkg": "1.0.0"
            }
        }"#,
    );
    registry.write_project_npmrc(project.path());

    let output = run_install(&project);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stderr_lower = stderr.to_ascii_lowercase();

    assert!(
        !output.status.success(),
        "install with mismatched verdaccio integrity must fail; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        stderr,
    );
    assert!(
        stderr_lower.contains("integrity") || stderr_lower.contains("checksum"),
        "stderr should mention integrity mismatch; got:\n{}",
        stderr,
    );
    assert!(
        !project.file_exists("lpm.lock"),
        "integrity mismatch must not leave a lockfile behind"
    );
    assert!(
        !package_install_path(&project, package_name).exists(),
        "integrity mismatch must not materialize the installed package"
    );
}

#[tokio::test]
async fn install_fails_when_verdaccio_tarball_is_missing_after_publish() {
    let registry = VerdaccioRegistry::start().await;
    let package_name = "verdaccio-missing-tarball-pkg";
    let version = "1.0.0";
    registry.publish_package(package_name, version);
    registry.delete_tarball(package_name, version);

    let project = TempProject::empty(
        r#"{
            "name": "verdaccio-missing-tarball",
            "version": "1.0.0",
            "dependencies": {
                "verdaccio-missing-tarball-pkg": "1.0.0"
            }
        }"#,
    );
    registry.write_project_npmrc(project.path());

    let output = run_install(&project);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stderr_lower = stderr.to_ascii_lowercase();

    assert!(
        !output.status.success(),
        "install with a deleted verdaccio tarball must fail; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        stderr,
    );
    assert!(
        stderr_lower.contains("tarball") || stderr_lower.contains("unpublished"),
        "stderr should mention the missing tarball; got:\n{}",
        stderr,
    );
    assert!(
        !project.file_exists("lpm.lock"),
        "missing tarball must not leave a lockfile behind"
    );
    assert!(
        !package_install_path(&project, package_name).exists(),
        "missing tarball must not materialize the installed package"
    );
}

#[tokio::test]
async fn install_fails_when_verdaccio_tarball_bytes_are_tampered_after_publish() {
    let registry = VerdaccioRegistry::start().await;
    let package_name = "verdaccio-tampered-bytes-pkg";
    let version = "1.0.0";
    registry.publish_package(package_name, version);
    registry.publish_package_with_files(
        "verdaccio-tamper-source",
        version,
        &[("index.js", "module.exports = 'tampered';\n")],
    );
    let tampered_bytes = registry.read_tarball_bytes("verdaccio-tamper-source", version);
    registry.overwrite_tarball_bytes(package_name, version, &tampered_bytes);

    let project = TempProject::empty(
        r#"{
            "name": "verdaccio-tampered-bytes",
            "version": "1.0.0",
            "dependencies": {
                "verdaccio-tampered-bytes-pkg": "1.0.0"
            }
        }"#,
    );
    registry.write_project_npmrc(project.path());

    let output = run_install(&project);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stderr_lower = stderr.to_ascii_lowercase();

    assert!(
        !output.status.success(),
        "install with tampered verdaccio tarball bytes must fail; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        stderr,
    );
    assert!(
        stderr_lower.contains("integrity") || stderr_lower.contains("checksum"),
        "stderr should mention integrity mismatch for tampered tarball bytes; got:\n{}",
        stderr,
    );
    assert!(
        !project.file_exists("lpm.lock"),
        "tampered tarball bytes must not leave a lockfile behind"
    );
    assert!(
        !package_install_path(&project, package_name).exists(),
        "tampered tarball bytes must not materialize the installed package"
    );
}

#[tokio::test]
async fn install_follows_same_origin_redirect_tarball_proxy() {
    let registry = VerdaccioRegistry::start().await;
    let package_name = "verdaccio-redirect-pkg";
    let version = "1.0.0";
    registry.publish_package(package_name, version);
    let proxy =
        VerdaccioProxyRegistry::start(&registry, package_name, version, TarballBehavior::Redirect)
            .await;

    let project = TempProject::empty(
        r#"{
            "name": "verdaccio-redirect-success",
            "version": "1.0.0",
            "dependencies": {
                "verdaccio-redirect-pkg": "1.0.0"
            }
        }"#,
    );
    proxy.write_project_npmrc(project.path());

    let output = run_install(&project);

    assert!(
        output.status.success(),
        "install through same-origin redirect proxy must succeed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert_package_installed(&project, package_name);
    assert_lockfile_source(&project, package_name, proxy.url());

    let received_paths = proxy.received_paths().await;
    assert!(
        received_paths
            .iter()
            .any(|path| path == proxy.metadata_path()),
        "proxy must receive the metadata request; got {received_paths:?}"
    );
    assert!(
        received_paths
            .iter()
            .any(|path| path == proxy.tarball_path()),
        "proxy must receive the initial tarball request; got {received_paths:?}"
    );
    assert!(
        received_paths
            .iter()
            .any(|path| Some(path.as_str()) == proxy.redirect_target_path()),
        "proxy must receive the redirected tarball request; got {received_paths:?}"
    );
}

#[tokio::test]
async fn install_accepts_http_gzip_wrapped_tarball_from_same_origin_proxy() {
    let registry = VerdaccioRegistry::start().await;
    let package_name = "verdaccio-http-gzip-pkg";
    let version = "1.0.0";
    registry.publish_package(package_name, version);
    let proxy =
        VerdaccioProxyRegistry::start(&registry, package_name, version, TarballBehavior::HttpGzip)
            .await;

    let project = TempProject::empty(
        r#"{
            "name": "verdaccio-http-gzip-success",
            "version": "1.0.0",
            "dependencies": {
                "verdaccio-http-gzip-pkg": "1.0.0"
            }
        }"#,
    );
    proxy.write_project_npmrc(project.path());

    let output = run_install(&project);

    assert!(
        output.status.success(),
        "install through same-origin HTTP-gzip proxy must succeed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert_package_installed(&project, package_name);
    assert_lockfile_source(&project, package_name, proxy.url());

    let received_paths = proxy.received_paths().await;
    let tarball_hits = received_paths
        .iter()
        .filter(|path| path.as_str() == proxy.tarball_path())
        .count();
    assert_eq!(tarball_hits, 1, "HTTP-gzip tarball should be fetched once");
}

#[tokio::test]
async fn install_retries_same_origin_tarball_after_429_from_proxy() {
    let registry = VerdaccioRegistry::start().await;
    let package_name = "verdaccio-retry-429-pkg";
    let version = "1.0.0";
    registry.publish_package(package_name, version);
    let proxy = VerdaccioProxyRegistry::start(
        &registry,
        package_name,
        version,
        TarballBehavior::Retry429ThenSuccess,
    )
    .await;

    let project = TempProject::empty(
        r#"{
            "name": "verdaccio-retry-429-success",
            "version": "1.0.0",
            "dependencies": {
                "verdaccio-retry-429-pkg": "1.0.0"
            }
        }"#,
    );
    proxy.write_project_npmrc(project.path());

    let output = run_install(&project);

    assert!(
        output.status.success(),
        "install through 429 proxy retry path must succeed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert_package_installed(&project, package_name);
    assert_lockfile_source(&project, package_name, proxy.url());

    let received_paths = proxy.received_paths().await;
    let tarball_hits = received_paths
        .iter()
        .filter(|path| path.as_str() == proxy.tarball_path())
        .count();
    assert_eq!(
        tarball_hits, 2,
        "429 tarball response should trigger exactly one retry; got {received_paths:?}"
    );
}

#[tokio::test]
async fn install_does_not_repeat_authorized_tarball_request_after_speculative_proxy_401() {
    let registry = VerdaccioRegistry::start().await;
    let package_name = "verdaccio-tarball-401-pkg";
    let version = "1.0.0";
    registry.publish_package(package_name, version);
    let proxy = VerdaccioProxyRegistry::start(
        &registry,
        package_name,
        version,
        TarballBehavior::Unauthorized,
    )
    .await;

    let project = TempProject::empty(
        r#"{
            "name": "verdaccio-tarball-401-failure",
            "version": "1.0.0",
            "dependencies": {
                "verdaccio-tarball-401-pkg": "1.0.0"
            }
        }"#,
    );
    proxy.write_project_npmrc(project.path());

    let output = run_install(&project);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stderr_lower = stderr.to_ascii_lowercase();

    assert!(
        !output.status.success(),
        "static-auth 401 on the tarball path must fail:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        stderr,
    );
    assert!(
        stderr_lower.contains("401")
            || stderr_lower.contains("unauthorized")
            || stderr_lower.contains("authorization")
            || stderr_lower.contains("authentication"),
        "stderr should mention auth failure for a tarball 401; got:\n{}",
        stderr,
    );
    assert!(
        !project.file_exists("lpm.lock"),
        "tarball 401 must not leave a lockfile behind"
    );
    assert!(
        !package_install_path(&project, package_name).exists(),
        "tarball 401 must not materialize the installed package"
    );

    let request_summaries = proxy.received_request_summaries().await;
    let tarball_requests: Vec<_> = request_summaries
        .iter()
        .filter(|(_, path, _)| path.as_str() == proxy.tarball_path())
        .collect();
    assert_eq!(
        tarball_requests.len(),
        1,
        "a speculative proxy tarball 401 should not be reissued by the real fetch loop; requests={request_summaries:?}"
    );
    assert!(
        tarball_requests
            .iter()
            .all(|(_, _, authorization)| authorization.is_some()),
        "the failing speculative tarball request must carry the static auth header; requests={request_summaries:?}"
    );
}

#[tokio::test]
async fn install_fails_when_proxy_metadata_omits_tarball_field() {
    let registry = VerdaccioRegistry::start().await;
    let package_name = "verdaccio-missing-tarball-field-pkg";
    let version = "1.0.0";
    registry.publish_package(package_name, version);
    let proxy = VerdaccioProxyRegistry::start_with_metadata_behavior(
        &registry,
        package_name,
        version,
        MetadataBehavior::MissingTarballField,
        TarballBehavior::Direct,
    )
    .await;

    let project = TempProject::empty(
        r#"{
            "name": "verdaccio-missing-tarball-field",
            "version": "1.0.0",
            "dependencies": {
                "verdaccio-missing-tarball-field-pkg": "1.0.0"
            }
        }"#,
    );
    proxy.write_project_npmrc(project.path());

    let output = run_install(&project);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stderr_lower = stderr.to_ascii_lowercase();

    assert!(
        !output.status.success(),
        "metadata without dist.tarball must fail install:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        stderr,
    );
    assert!(
        stderr_lower.contains("no tarball url") || stderr_lower.contains("tarball"),
        "stderr should mention the missing tarball field; got:\n{}",
        stderr,
    );
    assert!(
        !project.file_exists("lpm.lock"),
        "missing dist.tarball field must not leave a lockfile behind"
    );
    assert!(
        !package_install_path(&project, package_name).exists(),
        "missing dist.tarball field must not materialize the installed package"
    );

    let received_paths = proxy.received_paths().await;
    assert!(
        !received_paths.is_empty()
            && received_paths
                .iter()
                .all(|path| path == &proxy.metadata_path().to_string()),
        "missing dist.tarball should fail before any tarball request; got {received_paths:?}"
    );
}

#[tokio::test]
async fn install_ignores_extra_packument_fields_from_proxy_metadata() {
    let registry = VerdaccioRegistry::start().await;
    let package_name = "verdaccio-extra-fields-pkg";
    let version = "1.0.0";
    registry.publish_package(package_name, version);
    let proxy = VerdaccioProxyRegistry::start_with_metadata_behavior(
        &registry,
        package_name,
        version,
        MetadataBehavior::ExtraFields,
        TarballBehavior::Direct,
    )
    .await;

    let project = TempProject::empty(
        r#"{
            "name": "verdaccio-extra-fields-success",
            "version": "1.0.0",
            "dependencies": {
                "verdaccio-extra-fields-pkg": "1.0.0"
            }
        }"#,
    );
    proxy.write_project_npmrc(project.path());

    let output = run_install(&project);

    assert!(
        output.status.success(),
        "extra packument fields should be ignored during install:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert_package_installed(&project, package_name);
    assert_lockfile_source(&project, package_name, proxy.url());

    let received_paths = proxy.received_paths().await;
    assert_eq!(
        received_paths
            .iter()
            .filter(|path| path.as_str() == proxy.tarball_path())
            .count(),
        1,
        "extra-field metadata should still fetch exactly one tarball; got {received_paths:?}"
    );
}

#[tokio::test]
async fn install_accepts_abbreviated_npm_install_v1_packument_from_proxy() {
    let registry = VerdaccioRegistry::start().await;
    let package_name = "verdaccio-install-v1-pkg";
    let version = "1.0.0";
    registry.publish_package(package_name, version);
    let proxy = VerdaccioProxyRegistry::start_with_metadata_behavior(
        &registry,
        package_name,
        version,
        MetadataBehavior::NpmInstallV1Abbreviated,
        TarballBehavior::Direct,
    )
    .await;

    let project = TempProject::empty(
        r#"{
            "name": "verdaccio-install-v1-success",
            "version": "1.0.0",
            "dependencies": {
                "verdaccio-install-v1-pkg": "1.0.0"
            }
        }"#,
    );
    proxy.write_project_npmrc(project.path());

    let output = run_install(&project);

    assert!(
        output.status.success(),
        "abbreviated npm install-v1 packument should install successfully:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert_package_installed(&project, package_name);
    assert_lockfile_source(&project, package_name, proxy.url());

    let received_paths = proxy.received_paths().await;
    assert_eq!(
        received_paths
            .iter()
            .filter(|path| path.as_str() == proxy.tarball_path())
            .count(),
        1,
        "abbreviated npm install-v1 metadata should still resolve one tarball fetch; got {received_paths:?}"
    );
}

/// Pin the contract that `lpm install <real-package>` produces a
/// `node_modules/<pkg>/package.json` byte-equivalent to `npm install`'s
/// output, modulo a documented allowlist of npm-only internal fields.
///
/// A regression that drops a load-bearing published field (e.g., `main`,
/// `exports`, `bin`) from the extractor's output, or that starts mutating
/// the package.json bytes after extraction, trips this test.
///
/// One shared Verdaccio process proxies `lodash@4.17.21` from the npmjs
/// upstream so both clients consume the same tarball bytes. lpm runs first
/// (system under test → cleaner failure diagnostic); npm reads from the
/// already-warmed cache.
///
/// Skip-and-warn rather than fail when `npm` is missing — the Verdaccio
/// harness already needs `npx`, so `npm` is almost always available too,
/// but a CI runner with `npx` and no `npm` should still get a clean run.
#[tokio::test]
async fn flow_lpm_vs_npm_install_lodash_diff_within_documented_tolerance() {
    if !npm_is_available() {
        eprintln!(
            "SKIP flow_lpm_vs_npm_install_lodash_diff_within_documented_tolerance: \
             `npm --version` failed (npm not on PATH?)"
        );
        return;
    }

    let registry = VerdaccioRegistry::start().await;

    let lpm_project = TempProject::empty(
        r#"{
            "name": "lpm-diff-probe",
            "version": "1.0.0",
            "dependencies": {
                "lodash": "4.17.21"
            }
        }"#,
    );
    registry.write_project_npmrc(lpm_project.path());

    let lpm_output = run_install(&lpm_project);
    assert!(
        lpm_output.status.success(),
        "lpm install lodash through verdaccio failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&lpm_output.stdout),
        String::from_utf8_lossy(&lpm_output.stderr),
    );
    let lpm_pkg_json_path = lpm_project
        .path()
        .join("node_modules")
        .join("lodash")
        .join("package.json");
    assert!(
        lpm_pkg_json_path.exists(),
        "lpm install must materialize node_modules/lodash/package.json at {}",
        lpm_pkg_json_path.display(),
    );

    let npm_project = TempProject::empty(
        r#"{
            "name": "npm-diff-probe",
            "version": "1.0.0",
            "dependencies": {
                "lodash": "4.17.21"
            }
        }"#,
    );
    registry.write_project_npmrc(npm_project.path());
    run_npm_install(&npm_project, registry.url());
    let npm_pkg_json_path = npm_project
        .path()
        .join("node_modules")
        .join("lodash")
        .join("package.json");
    assert!(
        npm_pkg_json_path.exists(),
        "npm install must materialize node_modules/lodash/package.json at {}",
        npm_pkg_json_path.display(),
    );

    let mut lpm_pkg: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&lpm_pkg_json_path).expect("read lpm lodash package.json"),
    )
    .expect("lpm-installed lodash package.json must parse as JSON");
    let mut npm_pkg: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&npm_pkg_json_path).expect("read npm lodash package.json"),
    )
    .expect("npm-installed lodash package.json must parse as JSON");

    // Symmetric strip: lpm-rs is not expected to write any of these,
    // but stripping both sides keeps the diff focused on the package's
    // user-facing contract even when an older npm in CI injects them.
    strip_npm_internal_fields(&mut lpm_pkg);
    strip_npm_internal_fields(&mut npm_pkg);

    assert_eq!(
        lpm_pkg,
        npm_pkg,
        "lpm install lodash@4.17.21 produced a node_modules package.json that \
         differs from npm install's output (after stripping documented npm-internal \
         fields). If a NEW field diverges intentionally, extend \
         strip_npm_internal_fields with a justification.\n\
         --- lpm side ---\n{}\n--- npm side ---\n{}",
        serde_json::to_string_pretty(&lpm_pkg).unwrap(),
        serde_json::to_string_pretty(&npm_pkg).unwrap(),
    );
}

fn npm_is_available() -> bool {
    std::process::Command::new("npm")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn run_npm_install(project: &TempProject, registry_url: &str) {
    let npm_home = TempDir::new().expect("failed to create npm HOME temp dir");
    let output = std::process::Command::new("npm")
        .arg("install")
        .arg("--registry")
        .arg(registry_url)
        .arg("--no-audit")
        .arg("--no-fund")
        .arg("--no-update-notifier")
        .arg("--loglevel=error")
        .current_dir(project.path())
        .env("HOME", npm_home.path())
        // Force npm to read the test's project-local .npmrc as user config
        // too, so the auth token + always-auth=true take effect even on hosts
        // where a real ~/.npmrc exists.
        .env("NPM_CONFIG_USERCONFIG", project.path().join(".npmrc"))
        .env("NO_COLOR", "1")
        .env_remove("NPM_TOKEN")
        .output()
        .expect("failed to spawn npm install");

    assert!(
        output.status.success(),
        "npm install lodash through verdaccio failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

/// Strip npm-internal metadata that historical npm versions injected into
/// `node_modules/<pkg>/package.json` (vs. the published `package.json`).
///
/// npm@10 stopped writing these entirely, but older npm versions in CI
/// runners still emit them; stripping keeps the diff focused on the
/// package's user-facing contract (`name`, `version`, `main`, `exports`,
/// `bin`, `dependencies`, `peerDependencies`, `license`, `engines`, ...).
fn strip_npm_internal_fields(value: &mut serde_json::Value) {
    if let Some(obj) = value.as_object_mut() {
        // Every `_*` key is npm-internal (`_resolved`, `_integrity`,
        // `_from`, `_id`, `_shasum`, `_npmVersion`, `_nodeVersion`,
        // `_npmUser`, `_npmOperationalInternal`, `_hasShrinkwrap`,
        // `_inBundle`, `_requested`, `_spec`, `_where`, `_args`,
        // `_phantomChildren`, `_optional`, `_development`, ...). Strip
        // by prefix so future npm-internal keys don't break the test.
        obj.retain(|k, _| !k.starts_with('_'));

        // Non-prefixed npm-internal fields that some npm versions inject:
        //   * `dist` — registry-packument metadata (tarball URL, integrity)
        //   * `gitHead` — publisher's git HEAD at publish time
        //   * `readme` / `readmeFilename` — npm sometimes inlines README
        for k in ["dist", "gitHead", "readme", "readmeFilename"] {
            obj.remove(k);
        }
    }
}

/// Verdaccio-npm parity for a real package that ships a `bin` entry —
/// pins the contract that `lpm install which@4.0.0` produces a
/// `node_modules` layout congruent with `npm install`'s output across
/// (a) the published `node_modules/<pkg>/package.json` (modulo the
/// same npm-internal allowlist as the lodash diff test) AND (b) the
/// `node_modules/.bin/<bin-name>` shim that links the executable.
///
/// **Why this complements the lodash test.** Lodash has no `bin`
/// field, so `flow_lpm_vs_npm_install_lodash_diff_within_documented_tolerance`
/// only exercises the metadata-equivalence half of the contract.
/// `which@4.0.0` ships exactly one bin (`node-which → ./bin/which.js`),
/// which makes it the smallest interesting target to compare:
///
/// - lpm's bin-shim writer ([crates/lpm-linker/src/v2.rs](../../../crates/lpm-linker/src/v2.rs)::`create_bin_links_v2`)
///   creates `.bin/<name>` as a symlink (isolated linker) or a
///   `cmd-shim` script (hoisted/cross-platform). npm produces a
///   similar shape but with its own shebang convention.
/// - The test pins the user-visible contract: `.bin/<name>` exists
///   AND its resolution lands on the bin target inside `node_modules/<pkg>/`.
///   The exact shim format (symlink vs. script body) is deliberately
///   NOT pinned — those are manager-internal details and would lock
///   us into npm-specific shim shapes we don't want to copy.
///
/// **Why `which@4.0.0` specifically:**
/// - Published 2022-08, no foreseeable churn.
/// - Single, named bin (`node-which`), easy to assert against.
/// - Tiny package surface: 1 transitive dep (`isexe`) that we
///   don't need to assert on but proves the install handled
///   sub-resolution correctly.
/// - The bin target path (`./bin/which.js`) is a relative path
///   under the package dir, which is the common case the linker
///   handles.
///
/// Skip-and-warn rather than fail when `npm` is missing — same posture
/// as the lodash test, so a CI runner with `npx` but no `npm` produces
/// a clean run.
#[tokio::test]
async fn verdaccio_npm_parity_for_bin_package_pins_metadata_and_shim_presence() {
    if !npm_is_available() {
        eprintln!(
            "SKIP verdaccio_npm_parity_for_bin_package_pins_metadata_and_shim_presence: \
             `npm --version` failed (npm not on PATH?)"
        );
        return;
    }

    let registry = VerdaccioRegistry::start().await;

    let lpm_project = TempProject::empty(
        r#"{
            "name": "lpm-bin-diff-probe",
            "version": "1.0.0",
            "dependencies": {
                "which": "4.0.0"
            }
        }"#,
    );
    registry.write_project_npmrc(lpm_project.path());

    let lpm_output = run_install(&lpm_project);
    assert!(
        lpm_output.status.success(),
        "lpm install which@4.0.0 through verdaccio failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&lpm_output.stdout),
        String::from_utf8_lossy(&lpm_output.stderr),
    );

    let lpm_pkg_json_path = lpm_project
        .path()
        .join("node_modules")
        .join("which")
        .join("package.json");
    assert!(
        lpm_pkg_json_path.exists(),
        "lpm install must materialize node_modules/which/package.json at {}",
        lpm_pkg_json_path.display(),
    );

    let npm_project = TempProject::empty(
        r#"{
            "name": "npm-bin-diff-probe",
            "version": "1.0.0",
            "dependencies": {
                "which": "4.0.0"
            }
        }"#,
    );
    registry.write_project_npmrc(npm_project.path());
    run_npm_install(&npm_project, registry.url());

    let npm_pkg_json_path = npm_project
        .path()
        .join("node_modules")
        .join("which")
        .join("package.json");
    assert!(
        npm_pkg_json_path.exists(),
        "npm install must materialize node_modules/which/package.json at {}",
        npm_pkg_json_path.display(),
    );

    // (a) Metadata parity — same allowlist as the lodash test, so the
    // same npm-internal `_*` + `dist`/`gitHead`/`readme*` fields are
    // stripped symmetrically before comparison.
    let mut lpm_pkg: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&lpm_pkg_json_path).expect("read lpm which package.json"),
    )
    .expect("lpm-installed which package.json must parse as JSON");
    let mut npm_pkg: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&npm_pkg_json_path).expect("read npm which package.json"),
    )
    .expect("npm-installed which package.json must parse as JSON");

    strip_npm_internal_fields(&mut lpm_pkg);
    strip_npm_internal_fields(&mut npm_pkg);

    assert_eq!(
        lpm_pkg,
        npm_pkg,
        "lpm install which@4.0.0 produced a node_modules package.json that \
         differs from npm install's output (after stripping documented npm-internal \
         fields). If a NEW field diverges intentionally, extend \
         strip_npm_internal_fields with a justification.\n\
         --- lpm side ---\n{}\n--- npm side ---\n{}",
        serde_json::to_string_pretty(&lpm_pkg).unwrap(),
        serde_json::to_string_pretty(&npm_pkg).unwrap(),
    );

    // Pre-flight on the published `bin` field — `which@4.0.0` ships
    // `bin: { "node-which": "./bin/which.js" }`. If a future npm
    // republish changes the bin shape, the lpm side would still match
    // npm (the test pins parity, not absolute values), but the
    // assertions below assume a specific bin name. Surface that
    // assumption explicitly so a republish breakage gives a clear
    // diagnostic rather than a confused symlink-target assertion.
    let lpm_bin_decl = lpm_pkg
        .get("bin")
        .and_then(|v| v.as_object())
        .and_then(|m| m.get("node-which"))
        .and_then(|v| v.as_str());
    assert_eq!(
        lpm_bin_decl,
        Some("./bin/which.js"),
        "which@4.0.0's `bin.node-which` no longer points to `./bin/which.js` — \
         the published package shape changed. Update this test's bin-target \
         assertion to match. Current bin map: {:?}",
        lpm_pkg.get("bin")
    );

    // (b) Shim presence + target resolution. The .bin/<name> entry
    // must exist on BOTH sides and the target file must exist inside
    // node_modules/which/.
    let bin_name = "node-which";
    let bin_target_rel = "node_modules/which/bin/which.js";

    let lpm_shim = lpm_project.path().join("node_modules/.bin").join(bin_name);
    let npm_shim = npm_project.path().join("node_modules/.bin").join(bin_name);

    assert!(
        lpm_shim.symlink_metadata().is_ok(),
        "lpm install must create node_modules/.bin/{bin_name} for which@4.0.0; \
         path checked: {lpm_shim:?}"
    );
    assert!(
        npm_shim.symlink_metadata().is_ok(),
        "npm install must create node_modules/.bin/{bin_name} for which@4.0.0; \
         path checked: {npm_shim:?}"
    );

    // The bin target file inside node_modules/which/ must be present.
    // This proves the linker materialized the actual executable, not
    // just a dangling shim.
    let lpm_target = lpm_project.path().join(bin_target_rel);
    let npm_target = npm_project.path().join(bin_target_rel);
    assert!(
        lpm_target.exists(),
        "lpm install must materialize the bin target at {lpm_target:?}"
    );
    assert!(
        npm_target.exists(),
        "npm install must materialize the bin target at {npm_target:?}"
    );

    // On Unix, also pin executability. NTFS dispatches bin scripts by
    // extension instead of mode bits, so this assertion is POSIX-only.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let lpm_target_mode = std::fs::metadata(&lpm_target)
            .expect("stat lpm bin target")
            .permissions()
            .mode()
            & 0o111;
        assert!(
            lpm_target_mode != 0,
            "lpm bin target {lpm_target:?} is not executable (no exec bits in mode); \
             the linker dropped the published exec bits during extraction"
        );
        let npm_target_mode = std::fs::metadata(&npm_target)
            .expect("stat npm bin target")
            .permissions()
            .mode()
            & 0o111;
        assert!(
            npm_target_mode != 0,
            "npm bin target {npm_target:?} is not executable — unexpected; \
             this is npm-internal but the assertion symmetry catches a \
             tooling regression on the npm side too"
        );
    }
}
