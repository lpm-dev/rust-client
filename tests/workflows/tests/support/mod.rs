#![allow(dead_code)]

//! Test harness for the workflow tier — the **default** location for any
//! new end-to-end test that exercises a CLI command surface.
//!
//! Provides `TempProject` (fixture copying + environment isolation) and
//! `lpm()` (pre-configured `assert_cmd::Command` for the real binary),
//! plus `MockRegistry` (wiremock-backed) under `mock_registry`.
//!
//! # Where new tests go (Phase 65 tier discipline)
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
//!
//! Full rules: see `# Testing Tier Discipline` in the rust-client
//! `CLAUDE.md` at the workspace root.

pub mod assertions;
pub mod auth_state;
pub mod build_state;
pub mod mock_registry;
pub mod verdaccio;
pub mod verdaccio_proxy;

use std::ffi::OsStr;
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

    // Clear auth tokens to prevent accidental network calls with real creds
    cmd.remove_env("LPM_TOKEN");
    cmd.remove_env("NPM_TOKEN");

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
    cmd.remove_env("GITHUB_ACTIONS");
    cmd.remove_env("ACTIONS_ID_TOKEN_REQUEST_URL");
    cmd.remove_env("ACTIONS_ID_TOKEN_REQUEST_TOKEN");
    cmd.remove_env("GITLAB_CI");
    cmd.remove_env("LPM_GITLAB_OIDC_TOKEN");
    cmd.remove_env("CI_JOB_JWT");
    cmd.remove_env("CI_JOB_JWT_V2");

    // Force file-backed auth storage so workflow tests never touch the OS keychain.
    cmd.set_env("LPM_FORCE_FILE_AUTH", OsStr::new("1"));
    cmd.set_env("LPM_TEST_FAST_SCRYPT", OsStr::new("1"));
    cmd.set_env("LPM_FORCE_FILE_VAULT", OsStr::new("1"));

    // Clear `LPM_LINKER` so a developer's exported value (or a prior test
    // process) can't override the package.json + config.toml linker chain
    // we're trying to exercise. Tests that intentionally probe the env-var
    // surface re-set it on their own command builder.
    cmd.remove_env("LPM_LINKER");
    cmd.remove_env("LPM_CONCURRENT_DOWNLOADS");

    // Phase 66 Phase 4d — workflow tests assert on v1 layout shape
    // (e.g., `<project>/.lpm/wrappers/<seg>/`, hoisted-flat
    // `node_modules/<dep>` real dirs, hardlink-detach behavior). The
    // Phase-4d default flip to v2 changes these to symlinks-into-the-
    // global-store, which would break shape assertions wholesale.
    //
    // Pin every workflow test to v1 explicitly. v2's regression
    // coverage lives in the audit-fixture CI matrix (see
    // `bench/audit-fixtures/run-all.sh` + `.github/workflows/ci.yml`),
    // which runs the same 18-fixture suite under both `LPM_STORE_VERSION`
    // values and gates on no-asymmetric-outcomes. Tests that
    // intentionally exercise the v2 shape re-set this on their own
    // command builder.
    cmd.set_env("LPM_STORE_VERSION", OsStr::new("v1"));

    // Disable color for deterministic output in assertions
    cmd.set_env("NO_COLOR", OsStr::new("1"));

    // Disable update check (would make network calls)
    cmd.set_env("LPM_NO_UPDATE_CHECK", OsStr::new("1"));

    // Phase 49: the shipped Direct route defaults hit `registry.npmjs.org`
    // for npm packages. Workflow tests use a single mock server at the
    // `--registry` base URL that serves `/api/registry/{name}` (LPM
    // proxy path) and don't have a separate npm mock. Force Proxy mode
    // so the mock's proxy-tier mounts serve all metadata fetches.
    // Individual tests that want to exercise Direct routing can
    // override this env.
    cmd.set_env("LPM_NPM_ROUTE", OsStr::new("proxy"));

    // Phase 46.3 PR-2: on Windows, the install pipeline's sandbox
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
    let mut cmd = assert_cmd::Command::cargo_bin("lpm-rs").expect("lpm-rs binary not found");
    cmd.current_dir(project.path());
    apply_lpm_env(&mut cmd, project);
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
    let mut cmd = std::process::Command::new(bin);
    cmd.current_dir(project.path());
    apply_lpm_env(&mut cmd, project);
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());
    cmd
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
    cmd
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
