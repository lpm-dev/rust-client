use super::*;
use std::sync::{Mutex, OnceLock};

mod fetch;
mod gitignore;
mod lifecycle;
mod lockfile;
mod manifest;
mod package;
mod peer;
mod source_resolution;
mod state;
mod swift;
mod workspace;

fn confirm_prompt_test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
}

#[cfg(unix)]
struct StdinSwapGuard {
    original_stdin_fd: std::os::fd::RawFd,
}

#[cfg(unix)]
impl StdinSwapGuard {
    fn replace_with(new_stdin_fd: std::os::fd::RawFd) -> Self {
        let original_stdin_fd = unsafe { libc::dup(libc::STDIN_FILENO) };
        assert!(
            original_stdin_fd >= 0,
            "failed to duplicate stdin before PTY swap"
        );

        let swap_result = unsafe { libc::dup2(new_stdin_fd, libc::STDIN_FILENO) };
        assert!(swap_result >= 0, "failed to swap stdin to PTY slave");

        Self { original_stdin_fd }
    }
}

#[cfg(unix)]
impl Drop for StdinSwapGuard {
    fn drop(&mut self) {
        let _ = unsafe { libc::dup2(self.original_stdin_fd, libc::STDIN_FILENO) };
        let _ = unsafe { libc::close(self.original_stdin_fd) };
    }
}

#[cfg(unix)]
fn with_tty_stdin_input<F, R>(input: &str, action: F) -> R
where
    F: FnOnce() -> R,
{
    use std::fs::File;
    use std::io::Write;
    use std::os::fd::FromRawFd;

    let _lock = confirm_prompt_test_lock();

    let mut master_fd = -1;
    let mut slave_fd = -1;
    let open_result = unsafe {
        libc::openpty(
            &mut master_fd,
            &mut slave_fd,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(open_result, 0, "failed to create PTY pair for prompt test");

    let stdin_guard = StdinSwapGuard::replace_with(slave_fd);
    let _ = unsafe { libc::close(slave_fd) };

    let mut master = unsafe { File::from_raw_fd(master_fd) };
    master
        .write_all(input.as_bytes())
        .expect("failed to feed PTY input");
    master.flush().expect("failed to flush PTY input");

    let result = action();

    drop(master);
    drop(stdin_guard);

    result
}

fn registry_metadata(value: serde_json::Value) -> lpm_registry::PackageMetadata {
    serde_json::from_value(value).expect("valid registry metadata")
}

/// Build a PackageMetadata with the given version strings and latest tag.
fn make_metadata(versions: &[&str], latest: &str) -> lpm_registry::PackageMetadata {
    let mut version_map = std::collections::HashMap::new();
    for &v in versions {
        version_map.insert(
            v.to_string(),
            lpm_registry::VersionMetadata {
                name: "@lpm.dev/acme.swift-logger".to_string(),
                version: v.to_string(),
                description: None,
                dependencies: Default::default(),
                dev_dependencies: Default::default(),
                peer_dependencies: Default::default(),
                peer_dependencies_meta: Default::default(),
                bundle_dependencies: Default::default(),
                optional_dependencies: Default::default(),
                os: vec![],
                cpu: vec![],
                libc: vec![],
                dist: None,
                readme: None,
                lpm_config: None,
                ecosystem: Some("swift".to_string()),
                swift_meta: None,
                npm_user: None,
                behavioral_tags: None,
                lifecycle_scripts: None,
                security_findings: None,
                quality_score: None,
                vulnerabilities: None,
            },
        );
    }

    let mut dist_tags = std::collections::HashMap::new();
    dist_tags.insert("latest".to_string(), latest.to_string());

    lpm_registry::PackageMetadata {
        name: "@lpm.dev/acme.swift-logger".to_string(),
        description: None,
        dist_tags,
        versions: version_map,
        time: Default::default(),
        modified: None,
        downloads: None,
        distribution_mode: None,
        package_type: None,
        latest_version: Some(latest.to_string()),
        ecosystem: Some("swift".to_string()),
    }
}

fn write_manifest(path: &Path, value: &serde_json::Value) {
    std::fs::write(path, serde_json::to_string_pretty(value).unwrap()).unwrap();
}

fn read_manifest(path: &Path) -> serde_json::Value {
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

/// Helper to construct an `InstallPackage` with the fields the
/// `collect_direct_versions` helper actually reads. Other fields are
/// stubbed because they don't affect the result.
fn fake_pkg(name: &str, version: &str, is_direct: bool) -> InstallPackage {
    InstallPackage {
        name: name.to_string(),
        version: version.to_string(),
        source: "registry+https://registry.npmjs.org".to_string(),
        dependencies: Vec::new(),
        aliases: HashMap::new(),
        root_link_names: None,
        is_direct,
        is_lpm: false,
        peers: Vec::new(),
        integrity: None,
        registry_signatures: Vec::new(),
        registry_published_at: None,
        platform: None,
        optional: false,
        tarball_url: None,
        metadata_checked_for_tarball: false,
    }
}

#[test]
fn publish_ages_from_resolved_metadata_uses_registry_published_at() {
    let mut old = fake_pkg("old-pkg", "1.0.0", false);
    old.registry_published_at = Some("2020-01-01T00:00:00Z".to_string());
    let mut invalid = fake_pkg("invalid-pkg", "1.0.0", false);
    invalid.registry_published_at = Some("not-a-date".to_string());
    let missing = fake_pkg("missing-pkg", "1.0.0", false);

    let ages = publish_ages_from_resolved_metadata(&[old, invalid, missing]);

    assert_eq!(ages.len(), 1);
    assert!(ages.contains_key(&("old-pkg".to_string(), "1.0.0".to_string())));
}

#[test]
fn direct_release_age_canonicals_use_alias_targets() {
    let deps = HashMap::from_iter([
        ("plain".to_string(), "^1.0.0".to_string()),
        (
            "alias-local".to_string(),
            "npm:@scope/real@^2.0.0".to_string(),
        ),
        (
            "lpm".to_string(),
            "npm:@lpm.dev/acme.widget@^3.0.0".to_string(),
        ),
    ]);

    let canonicals = direct_release_age_canonicals(&deps);

    assert_eq!(
        canonicals,
        vec![
            CanonicalKey::lpm("acme", "widget"),
            CanonicalKey::npm("@scope/real"),
            CanonicalKey::npm("plain"),
        ]
    );
}

/// Helper: real on-disk workspace fixture so resolve_install_targets can
/// actually discover it.
fn write_workspace_for_install_tests(root: &Path, members: &[(&str, &str)]) {
    let workspace_globs: Vec<String> = members.iter().map(|(_, p)| (*p).to_string()).collect();
    let root_pkg = serde_json::json!({
        "name": "monorepo",
        "private": true,
        "workspaces": workspace_globs,
    });
    std::fs::write(
        root.join("package.json"),
        serde_json::to_string_pretty(&root_pkg).unwrap(),
    )
    .unwrap();
    for (name, path) in members {
        let dir = root.join(path);
        std::fs::create_dir_all(&dir).unwrap();
        let pkg = serde_json::json!({"name": name, "version": "0.0.0"});
        std::fs::write(
            dir.join("package.json"),
            serde_json::to_string_pretty(&pkg).unwrap(),
        )
        .unwrap();
    }
}

fn build_test_tarball() -> Vec<u8> {
    // Minimal valid npm tarball: package/package.json with a name+version,
    // gzip-wrapped. Mirrors the lpm-store test helper.
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;
    let mut tar_data = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_data);
        let body = br#"{"name":"test-tarball-pkg","version":"1.0.0"}"#;
        let mut header = tar::Header::new_gnu();
        header.set_size(body.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, "package/package.json", &body[..])
            .unwrap();
        builder.finish().unwrap();
    }
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&tar_data).unwrap();
    encoder.finish().unwrap()
}

fn install_package_for_tarball(url: &str, integrity: Option<&str>) -> InstallPackage {
    InstallPackage {
        name: "test-tarball-pkg".to_string(),
        version: "1.0.0".to_string(),
        source: format!("tarball+{url}"),
        dependencies: vec![],
        aliases: HashMap::new(),
        root_link_names: None,
        is_direct: true,
        is_lpm: false,
        peers: Vec::new(),
        integrity: integrity.map(|s| s.to_string()),
        registry_signatures: Vec::new(),
        registry_published_at: None,
        platform: None,
        optional: false,
        tarball_url: Some(url.to_string()),
        metadata_checked_for_tarball: false,
    }
}

fn install_pkg_acquire_permit() -> tokio::sync::OwnedSemaphorePermit {
    Arc::new(tokio::sync::Semaphore::new(1))
        .try_acquire_owned()
        .expect("permit must be available in test setup")
}
