//! Shared test harness for the Chunk 5 corpora — escape, compat
//! greens, (Chunk 5b: compat ambers). Keeps the per-test files
//! focused on WHAT they assert, not on fixture plumbing.
//!
//! Every helper is platform-aware: callers can check
//! [`sandbox_supported`] up front and skip (rather than fail) when
//! the host doesn't have a working backend — e.g. CI runners
//! without landlock enabled, or non-Linux-non-macOS dev machines.

#![allow(dead_code)] // each integration-test binary uses a different subset

use lpm_sandbox::{
    Sandbox, SandboxError, SandboxMode, SandboxSpec, SandboxStdio, SandboxedCommand,
    new_for_platform,
};
use std::path::{Path, PathBuf};
use tempfile::TempDir;

/// Bundles a realistic [`SandboxSpec`] together with the backing
/// tempdirs so drop order is correct (spec can reference live
/// directories; dropping the Bundle drops the tempdirs).
pub struct SandboxFixture {
    pub spec: SandboxSpec,
    pub pkg_dir: PathBuf,
    pub project_dir: PathBuf,
    _tmp: TempDir,
}

impl SandboxFixture {
    /// Build a realistic fixture rooted in a tempdir: `{tmp}/store/{pkg}@{ver}`
    /// for the package, `{tmp}/proj` for the project. `home_dir` uses the real
    /// host home so platform backends can test against `~/.cache` etc.
    ///
    /// Calls [`lpm_sandbox::prepare_writable_dirs`] before returning so
    /// the `.husky` / `.lpm` / `node_modules` / cache subpaths exist —
    /// mirrors what the production build.rs path does. Fixtures
    /// therefore model "scripts modify a prepared environment," which
    /// IS the real lifecycle-script contract.
    pub fn new(pkg_name: &str, pkg_version: &str) -> Self {
        let tmp = tempfile::tempdir().expect("tempdir");
        let pkg_dir = tmp
            .path()
            .join("store")
            .join(format!("{pkg_name}@{pkg_version}"));
        std::fs::create_dir_all(&pkg_dir).expect("mkdir pkg_dir");
        let project_dir = tmp.path().join("proj");
        std::fs::create_dir_all(&project_dir).expect("mkdir project_dir");

        let home = dirs::home_dir().expect("home dir for test");
        let spec = SandboxSpec {
            package_dir: pkg_dir.clone(),
            project_dir: project_dir.clone(),
            package_name: pkg_name.to_string(),
            package_version: pkg_version.to_string(),
            store_root: tmp.path().join("store"),
            home_dir: home,
            tmpdir: PathBuf::from("/tmp"),
            extra_write_dirs: Vec::new(),
        };
        lpm_sandbox::prepare_writable_dirs(&spec).expect("prepare_writable_dirs");
        Self {
            spec,
            pkg_dir,
            project_dir,
            _tmp: tmp,
        }
    }

    pub fn with_extra_write_dirs(mut self, dirs: Vec<PathBuf>) -> Self {
        self.spec.extra_write_dirs = dirs;
        self
    }

    /// Root of the fixture's tempdir. Useful for creating siblings
    /// of `pkg_dir` / `project_dir` that intentionally fall OUTSIDE
    /// the spec's allow list (e.g. escape-corpus probe files).
    pub fn tmp_path(&self) -> &Path {
        self._tmp.path()
    }
}

/// Returns `Some(sandbox)` if [`new_for_platform`] succeeds in the
/// requested mode, or `None` if the platform/kernel lacks support.
/// Caller-driven skip avoids coupling the test harness to a specific
/// environment (handy for cross-distro CI runners).
pub fn try_build_sandbox(spec: SandboxSpec, mode: SandboxMode) -> Option<Box<dyn Sandbox>> {
    match new_for_platform(spec, mode) {
        Ok(sb) => Some(sb),
        Err(
            SandboxError::KernelTooOld { .. }
            | SandboxError::UnsupportedPlatform { .. }
            | SandboxError::ModeNotSupportedOnPlatform { .. },
        ) => None,
        Err(other) => panic!("unexpected sandbox init error: {other:?}"),
    }
}

/// True if the host has a working sandbox for the mode. Use as a
/// test-skip guard at the top of each `#[test]`.
pub fn sandbox_supported(mode: SandboxMode) -> bool {
    // Cheap synthetic probe — matches the build.rs pre-probe shape.
    let home = match dirs::home_dir() {
        Some(h) => h,
        None => return false,
    };
    let probe = SandboxSpec {
        package_dir: home.clone(),
        project_dir: home.clone(),
        package_name: "__probe".into(),
        package_version: "0.0.0".into(),
        store_root: home.clone(),
        home_dir: home.clone(),
        tmpdir: PathBuf::from("/tmp"),
        extra_write_dirs: Vec::new(),
    };
    new_for_platform(probe, mode).is_ok()
}

/// Run `sh -c <script>` inside the sandbox with stdio suppressed.
/// Returns the exit status. Environment is cleared except for:
/// - `PATH=/usr/bin:/bin` (coreutils).
/// - `HOME=<real host home>` (scripts often expand `$HOME/.cache`,
///   `$HOME/.node-gyp`, etc. — matches the real build.rs env which
///   preserves HOME after env sanitization).
/// - `TMPDIR=<real host tmpdir>` (same rationale).
///
/// Working directory defaults to [`SandboxFixture::pkg_dir`].
pub fn run_script(sandbox: &dyn Sandbox, cwd: &Path, script: &str) -> std::process::ExitStatus {
    let home = dirs::home_dir()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tmpdir = std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".into());
    let mut cmd = SandboxedCommand::new("/bin/sh")
        .arg("-c")
        .arg(script)
        .current_dir(cwd)
        .envs_cleared([
            ("PATH", "/usr/bin:/bin"),
            ("HOME", home.as_str()),
            ("TMPDIR", tmpdir.as_str()),
        ]);
    cmd.stdout = SandboxStdio::Null;
    cmd.stderr = SandboxStdio::Null;
    let mut child = sandbox.spawn(cmd).expect("spawn under sandbox");
    child.wait().expect("wait for sandboxed child")
}
