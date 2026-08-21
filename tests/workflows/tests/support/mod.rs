#![allow(dead_code)]

//! Test harness for the workflow tier — the **default** location for any
//! new end-to-end test that exercises a CLI command surface.
//!
//! Provides `TempProject` (fixture copying + environment isolation) and
//! `lpm()` (pre-configured `assert_cmd::Command` for the real binary),
//! plus `MockRegistry` (wiremock-backed) under `mock_registry`.
//!
//! # Where new tests go (test tier discipline)
//!
//! - **Default — workflow tier** (`tests/workflows/tests/<feature>.rs`):
//!   any test that exercises a multi-step user flow through the CLI.
//!   Use [`TempProject`] + [`lpm`] + `MockRegistry` from this module.
//!   Test names must be falsifiable behavior claims — never phase
//!   numbers, audit round IDs, or ticket codes.
//!
//! - **Cli-binary** (`crates/lpm-cli/tests/`): only for cases that
//!   genuinely cannot live here — TTY/stdin interactive paths,
//!   global-install state mutation (`~/.lpm/global/`), parser/schema
//!   corpora, intentionally minimal binary-surface repros. Every
//!   file in that tier must justify its placement in a header
//!   docstring. If you're tempted to drop a test there because
//!   "it's just easier to copy `CommandOutput`," it belongs here
//!   instead.
//!
//! - **Integration** (`tests/integration/tests/`): cross-crate local
//!   pipelines that don't need a binary or HOME isolation.
//!
//! - **Unit** (inline `#[cfg(test)]`): private helpers, pure logic,
//!   internal invariants. **Not** command-behavior or CLI-contract
//!   regressions — those go here in the workflow tier.
//!
//! # JSON contracts
//!
//! Every `--json` command surface gets an `insta::assert_json_snapshot!`
//! envelope test (with redactions for temp paths, mock URLs, timestamps).
//! Where the contract is more than shape (stable doctor codes, error
//! code strings), keep semantic field assertions alongside the snapshot.

pub mod assertions;
pub mod auth_state;
pub mod build_state;
pub mod fault_registry;
pub mod mock_registry;
pub mod verdaccio;
pub mod verdaccio_proxy;

use std::ffi::OsStr;
use std::io::Write;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

type HmacSha256 = hmac::Hmac<sha2::Sha256>;

pub const LOCK_CONTENTION_MARKER_ENV: &str = "LPM_TEST_LOCK_CONTENTION_MARKER";
pub const VALID_TEST_INTEGRITY: &str = "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";

pub fn finalize_exact_lockfile_fixture(
    lockfile: &mut lpm_lockfile::Lockfile,
    roots: &[(&str, &str, &str)],
) {
    for (index, package) in lockfile.packages.iter_mut().enumerate() {
        let source = package.source.as_deref().unwrap_or("registry+unknown");
        let context = format!("fixture/{index}/{}/{}", package.name, package.version);
        package.instance_id = Some(lpm_common::PackageInstanceId::derive(
            &package.name,
            &package.version,
            source,
            &context,
        ));
        package.dependency_targets.clear();
        package.peer_targets.clear();
    }

    let package_snapshot = lockfile.packages.clone();
    for package in &mut lockfile.packages {
        for dependency in &package.dependencies {
            let separator = dependency
                .rfind('@')
                .unwrap_or_else(|| panic!("malformed fixture dependency {dependency:?}"));
            let local_name = &dependency[..separator];
            let target_value = &dependency[separator + 1..];
            let target_name = package
                .alias_dependencies
                .iter()
                .find_map(|alias| (alias[0] == local_name).then_some(alias[1].as_str()))
                .unwrap_or(local_name);
            let target = unique_fixture_target(&package_snapshot, target_name, target_value);
            package
                .dependency_targets
                .insert(local_name.to_string(), target);
        }
        for peer in &package.peer_edges {
            let target = unique_fixture_target(
                &package_snapshot,
                &peer.target_name,
                peer.target_wrapper_id
                    .as_deref()
                    .unwrap_or(&peer.target_version),
            );
            package.peer_targets.insert(peer.local_name.clone(), target);
        }
    }

    lockfile.root_resolutions.clear();
    for &(local_name, package_name, version) in roots {
        let matches = lockfile
            .packages
            .iter()
            .filter(|package| package.name == package_name && package.version == version)
            .collect::<Vec<_>>();
        let [package] = matches.as_slice() else {
            panic!(
                "fixture root {local_name:?} must select one {package_name}@{version}; found {}",
                matches.len(),
            );
        };
        lockfile.root_resolutions.insert(
            local_name.to_string(),
            lpm_lockfile::LockedRootResolution {
                instance_id: package.instance_id,
                package: package.name.clone(),
                version: package.version.clone(),
                source: package.source.clone(),
            },
        );
    }

    lockfile.packages.sort_unstable_by(|left, right| {
        let left_key = left.package_key();
        let right_key = right.package_key();
        left_key
            .name
            .cmp(&right_key.name)
            .then_with(|| left_key.version.cmp(&right_key.version))
            .then_with(|| left_key.source_id.cmp(&right_key.source_id))
            .then_with(|| left.instance_id.cmp(&right.instance_id))
    });
}

fn unique_fixture_target(
    packages: &[lpm_lockfile::LockedPackage],
    target_name: &str,
    target_value: &str,
) -> lpm_common::PackageInstanceId {
    let matches = packages
        .iter()
        .filter(|candidate| {
            if candidate.name != target_name {
                return false;
            }
            match candidate.source_kind() {
                Some(Ok(lpm_lockfile::Source::Registry { .. })) | None => {
                    candidate.version == target_value
                }
                Some(Ok(source)) => source.source_id() == target_value,
                Some(Err(_)) => false,
            }
        })
        .collect::<Vec<_>>();
    let [target] = matches.as_slice() else {
        panic!(
            "fixture edge must select one {target_name}@{target_value}; found {}",
            matches.len(),
        );
    };
    target
        .instance_id
        .expect("fixture package instance assigned")
}

/// A temporary project directory copied from a fixture, with fully isolated
/// HOME, store, cache, and config directories.
///
/// All environment variables that could leak the developer's global state
/// are overridden. The project is deleted on drop.
pub struct TempProject {
    /// The project directory (contains package.json, etc.)
    dir: TempDir,
    /// Isolated HOME directory
    home: TempDir,
}

impl TempProject {
    /// Create a new TempProject by copying a fixture directory.
    ///
    /// Fixture name maps to `tests/fixtures/{name}/` relative to the
    /// workspace root.
    pub fn from_fixture(fixture_name: &str) -> Self {
        let fixture_src = fixture_path(fixture_name);
        assert!(
            fixture_src.exists(),
            "fixture not found: {}",
            fixture_src.display()
        );

        let dir = TempDir::new().expect("failed to create temp project dir");
        let home = TempDir::new().expect("failed to create temp home dir");

        // Recursively copy the fixture into the temp directory
        copy_dir_recursive(&fixture_src, dir.path());

        TempProject { dir, home }
    }

    /// Create an empty project with just a package.json.
    pub fn empty(package_json: &str) -> Self {
        let dir = TempDir::new().expect("failed to create temp project dir");
        let home = TempDir::new().expect("failed to create temp home dir");

        std::fs::write(dir.path().join("package.json"), package_json)
            .expect("failed to write package.json");

        TempProject { dir, home }
    }

    /// Path to the project directory.
    pub fn path(&self) -> &Path {
        self.dir.path()
    }

    /// Path to the isolated HOME directory.
    pub fn home(&self) -> &Path {
        self.home.path()
    }

    /// Path to the isolated LPM store directory (inside HOME).
    pub fn store_dir(&self) -> PathBuf {
        self.home.path().join(".lpm").join("store")
    }

    /// Path to the isolated LPM cache directory (inside HOME).
    pub fn cache_dir(&self) -> PathBuf {
        self.home.path().join(".lpm").join("cache")
    }

    /// Read a file from the project directory.
    pub fn read_file(&self, rel_path: &str) -> String {
        let path = self.dir.path().join(rel_path);
        std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()))
    }

    /// Check if a file exists in the project directory.
    pub fn file_exists(&self, rel_path: &str) -> bool {
        self.dir.path().join(rel_path).exists()
    }

    /// Write a file into the project directory.
    pub fn write_file(&self, rel_path: &str, content: &str) {
        let path = self.dir.path().join(rel_path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        std::fs::write(&path, content)
            .unwrap_or_else(|e| panic!("failed to write {}: {e}", path.display()));
    }

    /// Write a credential-bearing file with owner-only permissions on Unix.
    pub fn write_private_file(&self, rel_path: &str, content: &str) {
        let path = self.dir.path().join(rel_path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        write_private_file(&path, content);
    }
}

fn write_private_file(path: &Path, content: impl AsRef<[u8]>) {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options
        .open(path)
        .unwrap_or_else(|e| panic!("failed to open {}: {e}", path.display()));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .unwrap_or_else(|e| panic!("failed to restrict {}: {e}", path.display()));
    }

    file.write_all(content.as_ref())
        .unwrap_or_else(|e| panic!("failed to write {}: {e}", path.display()));
}

/// Build a two-member workspace whose root lockfile stores disjoint importer
/// projections. Both package manifests are also present below the selected
/// member's node_modules directory so command tests prove isolation comes from
/// the lockfile projection rather than missing local metadata.
pub fn workspace_projection_project() -> TempProject {
    const VALID_TEST_INTEGRITY: &str = "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";
    let project = TempProject::empty(
        r#"{
            "name": "projection-workspace",
            "version": "1.0.0",
            "private": true,
            "workspaces": ["packages/*"]
        }"#,
    );
    project.write_file(
        "packages/app/package.json",
        r#"{
            "name": "projection-app",
            "version": "1.0.0",
            "license": "MIT",
            "dependencies": { "app-only": "1.0.0" }
        }"#,
    );
    project.write_file(
        "packages/sibling/package.json",
        r#"{
            "name": "projection-sibling",
            "version": "1.0.0",
            "dependencies": { "sibling-only": "1.0.0" }
        }"#,
    );

    let source = "registry+https://registry.npmjs.org";
    let package = |name: &str, importer: &str| {
        let instance_id = lpm_common::PackageInstanceId::derive(name, "1.0.0", source, importer);
        (
            lpm_lockfile::LockedPackage {
                instance_id: Some(instance_id),
                name: name.to_string(),
                version: "1.0.0".to_string(),
                source: Some(source.to_string()),
                integrity: Some(VALID_TEST_INTEGRITY.to_string()),
                ..Default::default()
            },
            lpm_lockfile::LockedRootResolution {
                instance_id: Some(instance_id),
                package: name.to_string(),
                version: "1.0.0".to_string(),
                source: Some(source.to_string()),
            },
        )
    };
    let (app_package, app_root) = package("app-only", "packages/app/app-only");
    let mut app = lpm_lockfile::Lockfile::new();
    app.add_package(app_package);
    app.importers.insert(
        ".".to_string(),
        lpm_lockfile::ImporterSnapshot {
            dependencies: std::collections::BTreeMap::from([(
                "app-only".to_string(),
                "1.0.0".to_string(),
            )]),
            ..Default::default()
        },
    );
    app.root_resolutions
        .insert("app-only".to_string(), app_root);
    let (sibling_package, sibling_root) = package("sibling-only", "packages/sibling/sibling-only");
    let mut sibling = lpm_lockfile::Lockfile::new();
    sibling.add_package(sibling_package);
    sibling.importers.insert(
        ".".to_string(),
        lpm_lockfile::ImporterSnapshot {
            dependencies: std::collections::BTreeMap::from([(
                "sibling-only".to_string(),
                "1.0.0".to_string(),
            )]),
            ..Default::default()
        },
    );
    sibling
        .root_resolutions
        .insert("sibling-only".to_string(), sibling_root);

    let mut root = lpm_lockfile::Lockfile::new();
    root.absorb_importer("packages/app", app)
        .expect("absorb app importer");
    root.absorb_importer("packages/sibling", sibling)
        .expect("absorb sibling importer");
    root.write_all(&project.path().join(lpm_lockfile::LOCKFILE_NAME))
        .expect("write root workspace lockfile");

    for (name, license) in [("app-only", "MIT"), ("sibling-only", "Apache-2.0")] {
        project.write_file(
            &format!("packages/app/node_modules/{name}/package.json"),
            &format!(
                r#"{{
                    "name": "{name}",
                    "version": "1.0.0",
                    "license": "{license}"
                }}"#
            ),
        );
    }

    project
}

pub async fn installed_manifest_dependency_graph(linker: &str) -> TempProject {
    use mock_registry::{MockRegistry, make_tarball_from_pkg_json};

    let registry = MockRegistry::start().await;
    for manifest in [
        serde_json::json!({
            "name": "manifest-parent",
            "version": "1.0.0",
            "license": "MIT",
            "dependencies": {
                "copyleft-leaf": "1.0.0",
                "multi-license": "1.0.0"
            },
            "optionalDependencies": {
                "platform-only-leaf": "1.0.0"
            }
        }),
        serde_json::json!({
            "name": "version-parent",
            "version": "1.0.0",
            "license": "MIT",
            "dependencies": {
                "missing-license-leaf": "1.0.0",
                "multi-license": "2.0.0"
            }
        }),
        serde_json::json!({
            "name": "copyleft-leaf",
            "version": "1.0.0",
            "license": "GPL-3.0-only"
        }),
        serde_json::json!({
            "name": "missing-license-leaf",
            "version": "1.0.0"
        }),
        serde_json::json!({
            "name": "platform-only-leaf",
            "version": "1.0.0",
            "license": "GPL-3.0-only",
            "cpu": ["wasm32"],
            "dependencies": {
                "optional-platform-runtime": "1.0.0"
            }
        }),
        serde_json::json!({
            "name": "optional-platform-runtime",
            "version": "1.0.0",
            "license": "GPL-3.0-only"
        }),
    ] {
        registry.with_manifest_package(manifest, &[]).await;
    }
    let multi_one = make_tarball_from_pkg_json(
        serde_json::json!({
            "name": "multi-license",
            "version": "1.0.0",
            "license": "Apache-2.0"
        }),
        &[],
    );
    let multi_two = make_tarball_from_pkg_json(
        serde_json::json!({
            "name": "multi-license",
            "version": "2.0.0",
            "license": "BSD-3-Clause"
        }),
        &[],
    );
    registry
        .with_full_package_metadata(
            "multi-license",
            "2.0.0",
            &[
                ("1.0.0", serde_json::json!({}), Some(multi_one)),
                ("2.0.0", serde_json::json!({}), Some(multi_two)),
            ],
        )
        .await;

    let project = TempProject::empty(
        r#"{
            "name": "installed-manifest-graph",
            "version": "1.0.0",
            "license": "MIT",
            "dependencies": {
                "manifest-parent": "1.0.0",
                "version-parent": "1.0.0"
            }
        }"#,
    );
    let output = lpm_with_registry(&project, &registry.url())
        .args([
            "install",
            "--strict-peer-dependencies",
            "--linker",
            linker,
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("run manifest dependency graph install");
    assert!(
        output.status.success(),
        "{linker} manifest dependency graph install must succeed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        project.file_exists("node_modules/manifest-parent/package.json"),
        "direct dependency must be linked at project node_modules"
    );
    assert!(
        !project.file_exists("node_modules/copyleft-leaf/package.json"),
        "transitive dependency must remain inside the linker graph"
    );
    assert!(
        !project.file_exists("node_modules/platform-only-leaf/package.json"),
        "platform-incompatible optional dependency must not be materialized"
    );
    let lockfile = lpm_lockfile::Lockfile::read_for_project(project.path())
        .expect("read installed manifest graph lockfile")
        .lockfile;
    for name in ["platform-only-leaf", "optional-platform-runtime"] {
        let package = lockfile
            .packages
            .iter()
            .find(|package| package.name == name)
            .unwrap_or_else(|| panic!("{name} must remain represented in the lockfile"));
        assert!(
            package.optional,
            "{name} must retain optional-only reachability in the lockfile"
        );
    }
    project
}

pub fn project_bin_path(project: &TempProject, name: &str) -> PathBuf {
    let bin_dir = project.path().join("node_modules").join(".bin");
    #[cfg(windows)]
    {
        bin_dir.join(format!("{name}.cmd"))
    }
    #[cfg(not(windows))]
    {
        bin_dir.join(name)
    }
}

/// Write a short-lived signed project unlock for workflow scenarios that
/// intentionally need to cross the security-approval boundary.
pub fn write_signed_unlock(project: &TempProject, scopes: &[&str]) {
    write_signed_unlock_for(project, project.path(), scopes);
}

/// Write a short-lived signed unlock for a workspace member or another
/// project directory that shares the fixture's isolated LPM home.
pub fn write_signed_unlock_for(project: &TempProject, project_dir: &Path, scopes: &[&str]) {
    use hmac::Mac;

    let now = chrono::Utc::now();
    let project_root = std::fs::canonicalize(project_dir)
        .expect("canonicalize temp project")
        .to_string_lossy()
        .to_string();
    let payload = serde_json::json!({
        "schema_version": 1,
        "id": format!("unl_{}", now.timestamp_nanos_opt().unwrap_or_default()),
        "target": "project",
        "project_root": project_root,
        "scopes": scopes,
        "limits": {},
        "issued_at": now.to_rfc3339(),
        "expires_at": (now + chrono::Duration::minutes(10)).to_rfc3339(),
        "issuer": "user-presence",
    });

    let secret = [42u8; 32];
    let security_dir = project.home().join(".lpm/security");
    std::fs::create_dir_all(security_dir.join("unlocks")).expect("create security unlocks dir");
    std::fs::write(security_dir.join("signing-secret.hex"), hex::encode(secret))
        .expect("write security signing secret");

    let mut mac = HmacSha256::new_from_slice(&secret).expect("valid hmac secret");
    mac.update(&serde_json::to_vec(&payload).expect("serialize unlock payload"));
    let signature = hex::encode(mac.finalize().into_bytes());
    let envelope = serde_json::json!({
        "payload": payload,
        "signature": signature,
    });
    let unlock_id = envelope["payload"]["id"].as_str().unwrap();
    std::fs::write(
        security_dir
            .join("unlocks")
            .join(format!("{unlock_id}.json")),
        serde_json::to_string_pretty(&envelope).expect("serialize unlock envelope"),
    )
    .expect("write signed unlock");
}

pub fn write_npm_firewall_global_config(project: &TempProject, mode: &str) {
    let lpm_dir = project.home().join(".lpm");
    std::fs::create_dir_all(&lpm_dir).expect("create isolated lpm home");
    std::fs::write(
        lpm_dir.join("config.toml"),
        format!("[firewall]\nmode = \"{mode}\"\n"),
    )
    .expect("write isolated npm firewall config");
}

pub fn write_lpm_proxy_npmrc(project: &TempProject, registry_url: &str) {
    let registry_url = registry_url.trim_end_matches('/');
    project.write_file(
        ".npmrc",
        &format!("registry={registry_url}/api/registry/\n"),
    );
}

/// Write a signed approved machine posture with a specific typosquat
/// guard floor for workflow scenarios that intentionally exercise an
/// approved machine-wide typosquat setting.
pub fn write_signed_typosquat_guard_posture(project: &TempProject, typosquat_guard: &str) {
    use hmac::Mac;

    let security_dir = project.home().join(".lpm/security");
    std::fs::create_dir_all(&security_dir).expect("create security dir");
    let secret = [42u8; 32];
    std::fs::write(security_dir.join("signing-secret.hex"), hex::encode(secret))
        .expect("write security signing secret");

    let payload = serde_json::json!({
        "schema_version": 1,
        "updated_at": chrono::Utc::now().to_rfc3339(),
        "script_policy": "deny",
        "minimum_release_age_secs": 86400,
        "release_age_policy": "direct",
        "sandbox_mode": "default",
        "sandbox_allow_degraded": false,
        "sigstore_verify": "deny",
        "typosquat_guard": typosquat_guard,
    });
    let mut mac = HmacSha256::new_from_slice(&secret).expect("valid hmac secret");
    mac.update(&serde_json::to_vec(&payload).expect("serialize posture payload"));
    let envelope = serde_json::json!({
        "payload": payload,
        "signature": hex::encode(mac.finalize().into_bytes()),
    });
    std::fs::write(
        security_dir.join("approved-posture.json"),
        serde_json::to_string_pretty(&envelope).expect("serialize posture envelope"),
    )
    .expect("write signed approved posture");
}

/// Common interface for `assert_cmd::Command` and `std::process::Command`
/// so the workflow-tier env-isolation set can be applied uniformly to both.
///
/// Workflow tests default to `assert_cmd::Command` (via [`lpm`]) because
/// it's wait-only and ergonomic. Concurrency tests in
/// `install_concurrency.rs` need `Child::kill()`, which only
/// `std::process::Command::spawn()` exposes — they use [`lpm_spawnable`]
/// instead. Both helpers MUST apply identical env isolation; this trait
/// is what enforces that.
pub trait LpmEnvSink {
    fn set_env(&mut self, key: &str, value: &OsStr);
    fn remove_env(&mut self, key: &str);
}

impl LpmEnvSink for assert_cmd::Command {
    fn set_env(&mut self, key: &str, value: &OsStr) {
        self.env(key, value);
    }
    fn remove_env(&mut self, key: &str) {
        self.env_remove(key);
    }
}

impl LpmEnvSink for std::process::Command {
    fn set_env(&mut self, key: &str, value: &OsStr) {
        self.env(key, value);
    }
    fn remove_env(&mut self, key: &str) {
        self.env_remove(key);
    }
}

/// Apply the full workflow-tier env-isolation set to a command builder.
///
/// Shared by [`lpm`] and [`lpm_spawnable`] so the two helpers can't
/// drift. Every env knob below was added to fix a specific test-isolation
/// hole — keep the comments when editing this function.
fn apply_lpm_env<S: LpmEnvSink>(cmd: &mut S, project: &TempProject) {
    // Isolate HOME so keyring, config, store, cache all land in temp dir.
    // POSIX hosts route through `$HOME` for `dirs::home_dir()`; Windows
    // does NOT (it calls `SHGetKnownFolderPath(FOLDERID_Profile)`, which
    // ignores every env var and returns the real user profile from the
    // registry). The `LPM_HOME` override below is what actually isolates
    // lpm-rs on Windows — `LpmRoot::from_env` consults it first, before
    // any `dirs::home_dir()` fallback fires. Keep both: `HOME` keeps
    // POSIX paths working without forcing every test to opt into
    // `LPM_HOME`, and `LPM_HOME` is the cross-platform canonical knob.
    cmd.set_env("HOME", project.home().as_os_str());
    let lpm_home = project.home().join(".lpm");
    cmd.set_env("LPM_HOME", lpm_home.as_os_str());

    // Isolate XDG dirs to prevent leaking desktop state
    cmd.set_env(
        "XDG_CONFIG_HOME",
        project.home().join(".config").as_os_str(),
    );
    cmd.set_env(
        "XDG_DATA_HOME",
        project.home().join(".local/share").as_os_str(),
    );
    cmd.set_env("XDG_CACHE_HOME", project.home().join(".cache").as_os_str());

    // Isolate LPM-specific paths. Note: production lpm-rs only reads
    // `LPM_HOME` (above) — these two are kept for documentation / future
    // override hooks but are currently dead env on the binary side.
    cmd.set_env("LPM_STORE_DIR", project.store_dir().as_os_str());
    cmd.set_env("LPM_CACHE_DIR", project.cache_dir().as_os_str());

    // Debug/test binaries allow this override so workflow tests don't
    // inherit a host-wide `/etc/lpm/security-policy.toml`.
    cmd.set_env(
        "LPM_SECURITY_POLICY_PATH",
        project.home().join(".lpm/security-policy.toml").as_os_str(),
    );

    // Clear auth tokens to prevent accidental network calls with real creds
    cmd.remove_env("LPM_TOKEN");
    cmd.remove_env("LPM_REMOTE_CACHE");
    cmd.remove_env("LPM_REMOTE_CACHE_TOKEN");
    cmd.remove_env("LPM_REMOTE_CACHE_URL");
    cmd.remove_env("LPM_REMOTE_CACHE_TEAM");
    cmd.remove_env("LPM_REMOTE_CACHE_SIGNATURE_KEY");
    cmd.remove_env("LPM_REMOTE_CACHE_READ_ONLY");
    cmd.remove_env("NPM_TOKEN");
    cmd.remove_env("GITHUB_TOKEN");
    cmd.remove_env("GITLAB_TOKEN");
    cmd.remove_env("CI_JOB_TOKEN");
    cmd.remove_env("LPM_TEST_VAULT_WRAPPING_KEY_ERROR");
    cmd.remove_env("LPM_VAULT_ID");
    cmd.remove_env("LPM_OIDC_POLICY_ID");
    cmd.remove_env("LPM_TEST_ASSUME_EUID_ROOT");
    cmd.remove_env(LOCK_CONTENTION_MARKER_ENV);
    cmd.remove_env("SUDO_USER");

    // Clear CI-environment vars that GitHub Actions / GitLab inject into
    // every job. Without this, OIDC tests running ON GitHub Actions pick the
    // runner's CI provider (because `GITHUB_ACTIONS=true` is always set) and
    // exchange against the real provider instead of the mock the test set up.
    // Generic `CI=true` also carries install semantics: tests opt into it
    // explicitly when they want auto-frozen installs.
    //
    // The full list mirrors every env var read by `get_ci_oidc_token`
    // and `oidc::detect_ci_environment` so the tests exercise only the
    // explicit `LPM_OIDC_TOKEN` / per-test-set surfaces. Tests that
    // intentionally exercise a CI provider re-set the relevant vars
    // themselves on their command builder (later `cmd.env(...)` calls
    // override these `env_remove`s).
    cmd.remove_env("CI");
    cmd.remove_env("GITHUB_ACTIONS");
    cmd.remove_env("ACTIONS_ID_TOKEN_REQUEST_URL");
    cmd.remove_env("ACTIONS_ID_TOKEN_REQUEST_TOKEN");
    cmd.remove_env("GITLAB_CI");
    cmd.remove_env("LPM_OIDC_TOKEN");
    cmd.remove_env("LPM_GITLAB_OIDC_TOKEN");
    cmd.remove_env("NPM_ID_TOKEN");
    cmd.remove_env("SIGSTORE_ID_TOKEN");
    cmd.remove_env("CI_JOB_JWT");
    cmd.remove_env("CI_JOB_JWT_V2");

    // Force file-backed auth storage so workflow tests never touch the OS keychain.
    cmd.set_env("LPM_FORCE_FILE_AUTH", OsStr::new("1"));
    cmd.set_env("LPM_TEST_FAST_SCRYPT", OsStr::new("1"));
    cmd.set_env("LPM_FORCE_FILE_VAULT", OsStr::new("1"));
    cmd.set_env("LPM_DISABLE_HOST_CLI_AUTH", OsStr::new("1"));

    // Clear `LPM_LINKER` so a developer's exported value (or a prior test
    // process) can't override the package.json + config.toml linker chain
    // we're trying to exercise. Tests that intentionally probe the env-var
    // surface re-set it on their own command builder.
    cmd.remove_env("LPM_LINKER");
    cmd.remove_env("LPM_CONCURRENT_DOWNLOADS");

    // Exercise the shipped store default and prevent a developer's shell
    // override from changing workflow behavior. Rollback-layout tests opt
    // into v1 through the dedicated helpers below.
    cmd.remove_env("LPM_STORE_VERSION");

    // Disable color for deterministic output in assertions
    cmd.set_env("NO_COLOR", OsStr::new("1"));

    // Disable update check (would make network calls)
    cmd.set_env("LPM_NO_UPDATE_CHECK", OsStr::new("1"));

    // The shipped Direct route defaults hit `registry.npmjs.org`
    // for npm packages. Workflow tests use a single mock server at the
    // `--registry` base URL that serves `/api/registry/{name}` (LPM
    // proxy path) and don't have a separate npm mock. Force Proxy mode
    // so the mock's proxy-tier mounts serve all metadata fetches.
    // Individual tests that want to exercise Direct routing can
    // override this env.
    cmd.set_env("LPM_NPM_ROUTE", OsStr::new("proxy"));

    // on Windows, the install pipeline's sandbox
    // factory probes `current_exe().parent()` for
    // `lpm-sandbox-helper.exe`. `assert_cmd::cargo_bin("lpm-rs")`
    // returns the binary from `target/<profile>/`, where cargo also
    // places the helper bin — so the sibling probe would succeed on
    // production-shaped distributions. On test runners the helper
    // build may or may not have happened (e.g.
    // `cargo test -p lpm-workflows` without a prior workspace build).
    // Set `LPM_SANDBOX_HELPER` explicitly when the helper exists so
    // workflow tests exercise the AppContainer backend whenever the
    // binary is actually built; tests that intentionally want the
    // Low IL fallback can override or unset.
    #[cfg(target_os = "windows")]
    if let Some(helper) = locate_test_sandbox_helper() {
        cmd.set_env("LPM_SANDBOX_HELPER", helper.as_os_str());
    }
}

/// Build an `assert_cmd::Command` for the `lpm-rs` binary, pre-configured
/// with full environment isolation pointing at the given `TempProject`.
///
/// This ensures the binary never touches the developer's real HOME, store,
/// auth tokens, or cache.
pub fn lpm(project: &TempProject) -> assert_cmd::Command {
    let binary = assert_cmd::cargo::cargo_bin("lpm-rs");
    lpm_from_path(project, &binary)
}

pub fn lpm_from_path(project: &TempProject, binary: &Path) -> assert_cmd::Command {
    let mut cmd = assert_cmd::Command::new(binary);
    cmd.current_dir(project.path());
    apply_lpm_env(&mut cmd, project);
    cmd.env("LPM_TEST_SELF_UPDATE_ACCOUNT_HOME", project.home());
    cmd
}

/// Build an isolated command that explicitly exercises the store-v1 rollback
/// writer and its paired linker.
pub fn lpm_v1(project: &TempProject) -> assert_cmd::Command {
    let mut cmd = lpm(project);
    cmd.env("LPM_STORE_VERSION", "v1");
    cmd
}

/// Build a store-v1 rollback command pre-configured to use a mock registry.
pub fn lpm_v1_with_registry(project: &TempProject, registry_url: &str) -> assert_cmd::Command {
    let mut cmd = lpm_v1(project);
    cmd.args(["--registry", registry_url, "--insecure"]);
    cmd
}

/// `std::process::Command` variant of [`lpm`] for tests that need
/// `Child::kill()` or `Child::wait_with_output()` mid-pipeline —
/// `assert_cmd::Command` is wait-only and can't be killed before it
/// finishes.
///
/// Used by `install_concurrency.rs` for the SIGKILL-mid-install
/// recovery tests and two-process race tests. Shares the env-isolation
/// set with [`lpm`] via [`apply_lpm_env`] so the two helpers can't
/// silently drift.
///
/// Defaults `stdout` and `stderr` to `Stdio::piped()` so callers can
/// capture output after a `kill()` — `inherit` would lose it.
pub fn lpm_spawnable(project: &TempProject) -> std::process::Command {
    let bin = assert_cmd::cargo::cargo_bin("lpm-rs");
    lpm_spawnable_from_path(project, &bin)
}

pub fn lpm_spawnable_from_path(project: &TempProject, binary: &Path) -> std::process::Command {
    let mut cmd = std::process::Command::new(binary);
    cmd.current_dir(project.path());
    apply_lpm_env(&mut cmd, project);
    cmd.env("LPM_TEST_SELF_UPDATE_ACCOUNT_HOME", project.home());
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());
    cmd
}

pub fn wait_for_lock_contention(
    child: &mut std::process::Child,
    marker_path: &Path,
    expected_lock_path: &Path,
) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        match std::fs::read_to_string(marker_path) {
            Ok(actual_lock_path) => {
                let actual_lock_path = std::fs::canonicalize(&actual_lock_path)
                    .expect("canonicalize the contended lock path");
                let expected_lock_path = std::fs::canonicalize(expected_lock_path)
                    .expect("canonicalize the expected lock path");
                assert_eq!(
                    actual_lock_path, expected_lock_path,
                    "child contended on an unexpected lock"
                );
                assert!(
                    child.try_wait().expect("inspect lock waiter").is_none(),
                    "child exited after reporting lock contention"
                );
                return;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!(
                "failed to read lock contention marker {}: {error}",
                marker_path.display()
            ),
        }

        if let Some(status) = child.try_wait().expect("inspect lock waiter") {
            panic!("child exited with {status} before reporting lock contention");
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            let mut stdout = String::new();
            let mut stderr = String::new();
            if let Some(mut pipe) = child.stdout.take() {
                let _ = std::io::Read::read_to_string(&mut pipe, &mut stdout);
            }
            if let Some(mut pipe) = child.stderr.take() {
                let _ = std::io::Read::read_to_string(&mut pipe, &mut stderr);
            }
            panic!(
                "child did not report contention on {} within 10 seconds\nstdout:\n{stdout}\nstderr:\n{stderr}",
                expected_lock_path.display(),
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

/// Resolve the absolute path of `lpm-sandbox-helper.exe` if cargo
/// has placed it next to the workspace's other release/debug bins.
/// `cargo_bin`'s discovery for non-owning crates falls back to
/// `target/<profile>/<name>` derived from `current_exe()`'s
/// grandparent — we use the same shape here.
#[cfg(target_os = "windows")]
fn locate_test_sandbox_helper() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    // current_exe = target/<profile>/deps/<test-binary>.exe
    // parent      = target/<profile>/deps/
    // grandparent = target/<profile>/
    let target_profile = exe.parent()?.parent()?;
    let candidate = target_profile.join("lpm-sandbox-helper.exe");
    candidate.exists().then_some(candidate)
}

/// Build an `lpm` command pre-configured to use a mock registry.
pub fn lpm_with_registry(project: &TempProject, registry_url: &str) -> assert_cmd::Command {
    let mut cmd = lpm(project);
    cmd.args(["--registry", registry_url, "--insecure"]);
    cmd.env("LPM_INTERNAL_TEST_NPM_REGISTRY_URL", registry_url);
    cmd
}

/// Put a deterministic fake `node --version` at the front of `PATH`.
pub fn configure_fake_node(
    command: &mut assert_cmd::Command,
    project: &TempProject,
    version: &str,
) {
    let bin_dir = project.home().join("fake-node-bin");
    std::fs::create_dir_all(&bin_dir).expect("create fake Node bin directory");
    let node_path = if cfg!(windows) {
        bin_dir.join("node.cmd")
    } else {
        bin_dir.join("node")
    };
    let script = if cfg!(windows) {
        format!(
            "@echo off\r\nif not \"%LPM_FAKE_NODE_MARKER%\"==\"\" type nul > \"%LPM_FAKE_NODE_MARKER%\"\r\necho v{version}\r\n"
        )
    } else {
        format!(
            "#!/bin/sh\nif [ -n \"${{LPM_FAKE_NODE_MARKER:-}}\" ]; then : > \"$LPM_FAKE_NODE_MARKER\"; fi\necho v{version}\n"
        )
    };
    std::fs::write(&node_path, script).expect("write fake Node binary");
    set_test_binary_executable(&node_path);

    let existing_path = std::env::var_os("PATH").unwrap_or_default();
    let paths = std::iter::once(bin_dir).chain(std::env::split_paths(&existing_path));
    command.env(
        "PATH",
        std::env::join_paths(paths).expect("construct PATH with fake Node"),
    );
}

#[cfg(unix)]
fn set_test_binary_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = std::fs::metadata(path)
        .expect("test binary must exist")
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(path, permissions).expect("mark test binary executable");
}

#[cfg(not(unix))]
fn set_test_binary_executable(_path: &Path) {}

pub fn write_repeated_file(
    path: &Path,
    prefix: &[u8],
    repeated_byte: u8,
    total_len: u64,
    suffix: &[u8],
) {
    use std::io::{Read, Write};

    let fixed_len = u64::try_from(prefix.len() + suffix.len()).expect("fixture length fits u64");
    assert!(
        total_len >= fixed_len,
        "fixture length must fit prefix and suffix"
    );
    let file = std::fs::File::create(path)
        .unwrap_or_else(|error| panic!("create {}: {error}", path.display()));
    let mut writer = std::io::BufWriter::new(file);
    writer.write_all(prefix).expect("write fixture prefix");
    std::io::copy(
        &mut std::io::repeat(repeated_byte).take(total_len - fixed_len),
        &mut writer,
    )
    .expect("write repeated fixture bytes");
    writer.write_all(suffix).expect("write fixture suffix");
    writer.flush().expect("flush repeated fixture");
}

/// Spawnable variant of [`lpm_with_registry`] for tests that need
/// `Child::kill()` or two-process races. Shares env isolation with
/// [`lpm_with_registry`] via [`apply_lpm_env`].
pub fn lpm_spawnable_with_registry(
    project: &TempProject,
    registry_url: &str,
) -> std::process::Command {
    let mut cmd = lpm_spawnable(project);
    cmd.args(["--registry", registry_url, "--insecure"]);
    cmd
}

/// Resolve the path to a fixture directory.
fn fixture_path(name: &str) -> PathBuf {
    // CARGO_MANIFEST_DIR points to tests/workflows/
    // Fixtures are at tests/fixtures/
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("fixtures")
        .join(name)
}

/// Recursively copy a directory tree.
fn copy_dir_recursive(src: &Path, dst: &Path) {
    for entry in std::fs::read_dir(src).expect("failed to read fixture dir") {
        let entry = entry.expect("failed to read entry");
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());

        if src_path.is_dir() {
            std::fs::create_dir_all(&dst_path).expect("failed to create dir");
            copy_dir_recursive(&src_path, &dst_path);
        } else {
            std::fs::copy(&src_path, &dst_path).expect("failed to copy file");
        }
    }
}
