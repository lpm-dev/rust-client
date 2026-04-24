#![allow(dead_code)]

//! Test harness for binary-level workflow tests.
//!
//! Provides `TempProject` (fixture copying + environment isolation) and
//! `lpm()` (pre-configured `assert_cmd::Command` for the real binary).

pub mod assertions;
pub mod auth_state;
pub mod mock_registry;

use std::path::{Path, PathBuf};
use tempfile::TempDir;

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
}

/// Build an `assert_cmd::Command` for the `lpm-rs` binary, pre-configured
/// with full environment isolation pointing at the given `TempProject`.
///
/// This ensures the binary never touches the developer's real HOME, store,
/// auth tokens, or cache.
pub fn lpm(project: &TempProject) -> assert_cmd::Command {
    let mut cmd = assert_cmd::Command::cargo_bin("lpm-rs").expect("lpm-rs binary not found");
    cmd.current_dir(project.path());

    // Isolate HOME so keyring, config, store, cache all land in temp dir
    cmd.env("HOME", project.home());

    // Isolate XDG dirs to prevent leaking desktop state
    cmd.env("XDG_CONFIG_HOME", project.home().join(".config"));
    cmd.env("XDG_DATA_HOME", project.home().join(".local/share"));
    cmd.env("XDG_CACHE_HOME", project.home().join(".cache"));

    // Isolate LPM-specific paths
    cmd.env("LPM_STORE_DIR", project.store_dir());
    cmd.env("LPM_CACHE_DIR", project.cache_dir());

    // Clear auth tokens to prevent accidental network calls with real creds
    cmd.env_remove("LPM_TOKEN");
    cmd.env_remove("NPM_TOKEN");

    // Clear CI-environment OIDC vars that GitHub Actions / GitLab inject
    // into every job. Without this, OIDC tests running ON GitHub Actions
    // pick the runner's CI provider (because `GITHUB_ACTIONS=true` is
    // always set) and exchange against the real provider instead of the
    // mock the test set up — failure looks like "ACTIONS_ID_TOKEN_REQUEST_TOKEN
    // not set" because we strip the inner token vars but not the
    // *gating* `GITHUB_ACTIONS` flag.
    //
    // The full list mirrors every env var read by `get_ci_oidc_token`
    // and `oidc::detect_ci_environment` so the tests exercise only the
    // explicit `LPM_OIDC_TOKEN` / per-test-set surfaces. Tests that
    // intentionally exercise a CI provider re-set the relevant vars
    // themselves on their command builder (later `cmd.env(...)` calls
    // override these `env_remove`s).
    cmd.env_remove("GITHUB_ACTIONS");
    cmd.env_remove("ACTIONS_ID_TOKEN_REQUEST_URL");
    cmd.env_remove("ACTIONS_ID_TOKEN_REQUEST_TOKEN");
    cmd.env_remove("GITLAB_CI");
    cmd.env_remove("LPM_GITLAB_OIDC_TOKEN");
    cmd.env_remove("CI_JOB_JWT");
    cmd.env_remove("CI_JOB_JWT_V2");

    // Force file-backed auth storage so workflow tests never touch the OS keychain.
    cmd.env("LPM_FORCE_FILE_AUTH", "1");
    cmd.env("LPM_TEST_FAST_SCRYPT", "1");
    cmd.env("LPM_FORCE_FILE_VAULT", "1");

    // Disable color for deterministic output in assertions
    cmd.env("NO_COLOR", "1");

    // Disable update check (would make network calls)
    cmd.env("LPM_NO_UPDATE_CHECK", "1");

    // Phase 49: the shipped Direct route defaults hit `registry.npmjs.org`
    // for npm packages. Workflow tests use a single mock server at the
    // `--registry` base URL that serves `/api/registry/{name}` (LPM
    // proxy path) and don't have a separate npm mock. Force Proxy mode
    // so the mock's proxy-tier mounts serve all metadata fetches.
    // Individual tests that want to exercise Direct routing can
    // override this env.
    cmd.env("LPM_NPM_ROUTE", "proxy");

    cmd
}

/// Build an `lpm` command pre-configured to use a mock registry.
pub fn lpm_with_registry(project: &TempProject, registry_url: &str) -> assert_cmd::Command {
    let mut cmd = lpm(project);
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
