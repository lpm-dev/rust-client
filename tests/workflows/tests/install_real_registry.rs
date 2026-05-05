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

fn run_install(project: &TempProject) -> Output {
    lpm(project)
        .env_remove("LPM_NPM_ROUTE")
        .env_remove("LPM_TOKEN")
        .args([
            "install",
            "--allow-new",
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
    assert_eq!(
        received_paths,
        vec![proxy.metadata_path().to_string()],
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
