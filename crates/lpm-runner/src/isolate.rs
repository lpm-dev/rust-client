//! Phase 37 — `IsolatedInstall`: one engine, two storage policies.
//!
//! Both `lpm dlx <spec>` (ephemeral) and `lpm install -g <spec>`
//! (persistent) need the same five things from a per-package install
//! root: write a synthetic `package.json`, run the project install
//! pipeline against it, mark completeness, refresh use-time, optionally
//! expose binaries on PATH. M2 introduces this primitive as the
//! abstraction shared by both call sites; M3 wires the persistent
//! policy fully (commit transactions, bin shim emission, manifest
//! updates).
//!
//! ## Why a primitive (and not just two parallel pipelines)
//!
//! Without the primitive, `lpm dlx` and `lpm install -g` would each
//! reinvent: cache freshness, install-root creation, security perms,
//! mtime semantics, manifest-text generation, and (eventually)
//! bin-target selection. Phase 32's audit history is the cautionary
//! tale — every divergence between two "very similar" code paths
//! eventually grew its own bug. One engine, two policies, one source
//! of truth.
//!
//! ## Scope of M2
//!
//! M2 ships:
//! - `IsolatedInstall::ephemeral` — used by `commands::run::dlx` after
//!   the M2.3 migration; behavior is byte-for-byte identical to the
//!   pre-M2 dlx path.
//! - `IsolatedInstall::persistent` — constructible, exposes the API
//!   surface, but `is_ready()` and `should_sweep()` return values
//!   appropriate for "no TTL, never auto-expire". The bin-exposure
//!   side (`BinExposure` list, shim emission) is data-only in M2 —
//!   the actual writer lives in M3 alongside the global manifest tx
//!   and the WAL.
//!
//! `lpm install -g` does not yet construct a persistent
//! `IsolatedInstall` — that wiring is M3's first task.

use crate::dlx;
use lpm_common::{INSTALL_READY_MARKER, LpmError};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// One declared command exposed by a persistent install. M3 consumes
/// this list when emitting `~/.lpm/bin/<command_name>` shims (Unix
/// symlink + Windows `.cmd`/`.ps1`/bash triple per the plan §M3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BinExposure {
    /// The name to expose on PATH. Equals the package's declared bin
    /// name unless the user asked for an alias.
    pub command_name: String,
    /// Absolute path of the script the shim should invoke. Lives
    /// inside the install root.
    pub target_path: PathBuf,
}

/// Storage policy for an [`IsolatedInstall`].
///
/// `Ephemeral` is what `lpm dlx` uses: the install root sits under
/// `~/.lpm/cache/dlx/` and ages out via the
/// [`dlx::sweep_stale_dlx_entries`] sweep when the user hasn't run the
/// spec in `ttl`. `Persistent` is what `lpm install -g` will use in
/// M3: the install root sits under `~/.lpm/global/installs/` and never
/// ages out — uninstalls happen via explicit `lpm uninstall -g`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoragePolicy {
    Ephemeral {
        /// How long the install can sit unused before the dlx sweep
        /// reaps it. Refreshed by [`IsolatedInstall::touch`] on every
        /// successful invocation (install or hit).
        ttl: Duration,
    },
    Persistent {
        /// Commands this install will own on PATH. M3 emits one shim
        /// triple per entry under `~/.lpm/bin/`.
        exposed: Vec<BinExposure>,
    },
}

/// One isolated install root, plus the policy that governs its
/// lifetime and exposure. Constructed by the dlx and install-g call
/// sites, consumed by their respective install/exec flows.
#[derive(Debug, Clone)]
pub struct IsolatedInstall {
    spec: String,
    root: PathBuf,
    policy: StoragePolicy,
}

impl IsolatedInstall {
    /// Build an ephemeral install (dlx).
    pub fn ephemeral(spec: impl Into<String>, root: impl Into<PathBuf>, ttl: Duration) -> Self {
        IsolatedInstall {
            spec: spec.into(),
            root: root.into(),
            policy: StoragePolicy::Ephemeral { ttl },
        }
    }

    /// Build a persistent install (`install -g`). M3 consumes the
    /// `exposed` list when emitting bin shims and manifest entries.
    pub fn persistent(
        spec: impl Into<String>,
        root: impl Into<PathBuf>,
        exposed: Vec<BinExposure>,
    ) -> Self {
        IsolatedInstall {
            spec: spec.into(),
            root: root.into(),
            policy: StoragePolicy::Persistent { exposed },
        }
    }

    pub fn spec(&self) -> &str {
        &self.spec
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn policy(&self) -> &StoragePolicy {
        &self.policy
    }

    /// True when this install root is bootable.
    ///
    /// **Ephemeral (dlx)**: requires the cheap completeness markers
    /// `{package.json, node_modules/.bin/}` AND the entry must be
    /// within its TTL. Outside the TTL the entry is treated as "needs
    /// reinstall."
    ///
    /// **Persistent (install -g)**: requires the durable
    /// [`INSTALL_READY_MARKER`] file. The marker is written by M3 only
    /// after extract + link + lockfile + bin-targets are all present,
    /// so its presence is the load-bearing signal of a complete install.
    /// The `{package.json, node_modules/.bin/}` markers are necessary
    /// but not sufficient for global installs — a process killed
    /// between linking `node_modules/.bin/` and writing the marker
    /// would otherwise be classified as ready while still missing
    /// the global manifest's commit step. M3 will additionally call
    /// the recovery-time `validate_install_root()` helper to re-check
    /// bin-target executability before flipping the manifest.
    ///
    /// This is the single source of truth `commands::run::dlx` queries
    /// (and M3's install commit step will query) to decide hit vs install.
    pub fn is_ready(&self) -> bool {
        match &self.policy {
            StoragePolicy::Ephemeral { ttl } => {
                if !markers_present(&self.root) {
                    return false;
                }
                dlx::is_cache_fresh(&self.root, ttl.as_secs())
            }
            StoragePolicy::Persistent { .. } => self.root.join(INSTALL_READY_MARKER).is_file(),
        }
    }

    /// True when an ephemeral install is past its TTL, i.e. the
    /// `dlx` sweep should reap it. Always false for persistent
    /// installs (they only get removed by explicit `lpm uninstall -g`).
    /// This mirrors the predicate used by [`dlx::sweep_stale_dlx_entries`]
    /// so a future refactor can eventually drive the sweep through this
    /// primitive too.
    pub fn should_sweep(&self) -> bool {
        let StoragePolicy::Ephemeral { ttl } = &self.policy else {
            return false;
        };
        let pkg_json = self.root.join("package.json");
        let Ok(meta) = std::fs::metadata(&pkg_json) else {
            return false; // no marker → not a recognized entry
        };
        let Ok(mtime) = meta.modified() else {
            return false;
        };
        let Ok(age) = SystemTime::now().duration_since(mtime) else {
            return false; // clock skew, mtime in the future
        };
        age >= *ttl
    }

    /// Generate the `package.json` text that the install pipeline
    /// should write into the install root. Single dependency on the
    /// spec, marked private so npm/yarn/pnpm wouldn't try to publish
    /// it. Same shape as the pre-M2 dlx writer at
    /// `commands::run::dlx`.
    pub fn manifest_text(&self) -> String {
        let (pkg_name, version_spec) = dlx::parse_package_spec(&self.spec);
        format!(r#"{{"private":true,"dependencies":{{"{pkg_name}":"{version_spec}"}}}}"#)
    }

    /// Create the install root with restricted permissions. On Unix
    /// the directory is `chmod 0o700` so other users on shared hosts
    /// can't read cached package contents (which can include private
    /// tokens via dotenv files, etc.). On Windows the inherited ACLs
    /// are sufficient — dlx has done it this way since day one.
    pub fn prepare(&self) -> Result<(), LpmError> {
        dlx::create_cache_dir(&self.root)
    }

    /// Refresh the install's "last used" mtime. Called on every
    /// successful invocation, hit or install — see
    /// [`crate::dlx::touch_cache`] for the use-time semantics rationale.
    /// No-op for persistent installs (they don't care about TTL).
    pub fn touch(&self) {
        if matches!(self.policy, StoragePolicy::Ephemeral { .. }) {
            dlx::touch_cache(&self.root);
        }
    }
}

/// Check that the install-root completeness markers
/// `{package.json, node_modules/.bin}` are both present. Same predicate
/// used by `dlx_entry_appears_complete` in the dlx module (the
/// migration audit fixed the collision branch to use it). Kept here
/// as a private helper because the predicate is the contract this
/// primitive enforces, not a public concept.
fn markers_present(root: &Path) -> bool {
    root.join("package.json").is_file() && root.join("node_modules").join(".bin").is_dir()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_complete_install_root(root: &Path) {
        std::fs::create_dir_all(root.join("node_modules").join(".bin")).unwrap();
        std::fs::write(root.join("package.json"), "{}").unwrap();
    }

    #[test]
    fn ephemeral_constructor_sets_policy() {
        let i = IsolatedInstall::ephemeral("cowsay", "/tmp/foo", Duration::from_secs(60));
        assert_eq!(i.spec(), "cowsay");
        assert_eq!(i.root(), Path::new("/tmp/foo"));
        assert!(matches!(i.policy(), StoragePolicy::Ephemeral { .. }));
    }

    #[test]
    fn persistent_constructor_sets_policy() {
        let bins = vec![BinExposure {
            command_name: "eslint".into(),
            target_path: PathBuf::from("/usr/local/lib/eslint/bin/eslint.js"),
        }];
        let i = IsolatedInstall::persistent("eslint@^9", "/tmp/global/eslint@9.24.0", bins.clone());
        assert_eq!(i.spec(), "eslint@^9");
        match i.policy() {
            StoragePolicy::Persistent { exposed } => assert_eq!(exposed, &bins),
            _ => panic!("expected persistent"),
        }
    }

    #[test]
    fn is_ready_false_when_markers_missing() {
        let tmp = TempDir::new().unwrap();
        let i = IsolatedInstall::ephemeral("x", tmp.path(), Duration::from_secs(60));
        assert!(!i.is_ready());
    }

    #[test]
    fn is_ready_false_for_persistent_when_only_markers_present() {
        // Markers (package.json + node_modules/.bin) are necessary but
        // not sufficient for global installs. Without the durable
        // .lpm-install-ready marker, recovery must NOT classify the
        // install as bootable — M3 has not yet flipped the manifest /
        // emitted shims for it.
        let tmp = TempDir::new().unwrap();
        make_complete_install_root(tmp.path());
        let i = IsolatedInstall::persistent("x@1", tmp.path(), vec![]);
        assert!(!i.is_ready(), "persistent must require ready marker");
    }

    #[test]
    fn is_ready_true_for_persistent_when_install_ready_marker_present() {
        let tmp = TempDir::new().unwrap();
        make_complete_install_root(tmp.path());
        // The marker is what M3 writes after the full install commit.
        std::fs::write(
            tmp.path().join(lpm_common::INSTALL_READY_MARKER),
            r#"{"schema_version":1,"commands":["x"],"written_at":"2026-04-15T00:00:00Z"}"#,
        )
        .unwrap();
        let i = IsolatedInstall::persistent("x@1", tmp.path(), vec![]);
        assert!(i.is_ready());
    }

    #[test]
    fn is_ready_false_for_persistent_when_marker_absent_even_with_partial_state() {
        // Partial install case: extract finished, link wrote some files,
        // but the M3 commit step never wrote the marker. The pre-audit
        // implementation would have called this "ready"; we now
        // correctly call it not-ready.
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path().join("node_modules").join(".bin")).unwrap();
        std::fs::write(tmp.path().join("package.json"), "{}").unwrap();
        // Plant a fake lpm.lock to make the install root look "almost done"
        std::fs::write(tmp.path().join("lpm.lock"), "").unwrap();
        let i = IsolatedInstall::persistent("x@1", tmp.path(), vec![]);
        assert!(!i.is_ready(), "missing marker must defeat partial state");
    }

    #[test]
    fn is_ready_for_ephemeral_respects_ttl() {
        let tmp = TempDir::new().unwrap();
        make_complete_install_root(tmp.path());

        // Fresh entry within TTL.
        let fresh = IsolatedInstall::ephemeral("x", tmp.path(), Duration::from_secs(3600));
        assert!(fresh.is_ready());

        // Same entry with zero TTL — never fresh.
        let stale_ttl = IsolatedInstall::ephemeral("x", tmp.path(), Duration::from_secs(0));
        assert!(!stale_ttl.is_ready());
    }

    #[test]
    fn should_sweep_false_for_persistent() {
        let tmp = TempDir::new().unwrap();
        make_complete_install_root(tmp.path());
        let i = IsolatedInstall::persistent("x", tmp.path(), vec![]);
        assert!(!i.should_sweep());
    }

    #[test]
    fn should_sweep_false_when_root_absent() {
        let tmp = TempDir::new().unwrap();
        let i = IsolatedInstall::ephemeral("x", tmp.path().join("nope"), Duration::from_secs(0));
        // No package.json → not a recognized entry → don't sweep.
        assert!(!i.should_sweep());
    }

    #[test]
    fn should_sweep_true_for_ephemeral_past_ttl() {
        let tmp = TempDir::new().unwrap();
        make_complete_install_root(tmp.path());
        // Backdate the package.json mtime far enough that any reasonable
        // TTL classifies the entry as stale.
        let pkg_json = tmp.path().join("package.json");
        let f = std::fs::OpenOptions::new()
            .write(true)
            .open(&pkg_json)
            .unwrap();
        let when = SystemTime::now() - Duration::from_secs(48 * 3600);
        f.set_modified(when).unwrap();

        let i = IsolatedInstall::ephemeral("x", tmp.path(), Duration::from_secs(3600));
        assert!(i.should_sweep());
    }

    #[test]
    fn manifest_text_unscoped_spec() {
        let i = IsolatedInstall::ephemeral("cowsay", "/tmp", Duration::from_secs(60));
        let text = i.manifest_text();
        assert!(text.contains(r#""private":true"#));
        assert!(text.contains(r#""cowsay":"*""#));
    }

    #[test]
    fn manifest_text_scoped_spec_with_version() {
        let i = IsolatedInstall::ephemeral("@scope/foo@^1.2", "/tmp", Duration::from_secs(60));
        let text = i.manifest_text();
        assert!(text.contains(r#""@scope/foo":"^1.2""#));
    }

    #[test]
    fn prepare_creates_root_with_restricted_perms_on_unix() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("install-root");
        let i = IsolatedInstall::ephemeral("x", &root, Duration::from_secs(60));
        i.prepare().unwrap();
        assert!(root.is_dir());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&root).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700);
        }
    }

    #[test]
    fn touch_refreshes_mtime_for_ephemeral() {
        let tmp = TempDir::new().unwrap();
        make_complete_install_root(tmp.path());
        let pkg_json = tmp.path().join("package.json");
        let f = std::fs::OpenOptions::new()
            .write(true)
            .open(&pkg_json)
            .unwrap();
        f.set_modified(SystemTime::now() - Duration::from_secs(3600))
            .unwrap();

        let before = std::fs::metadata(&pkg_json).unwrap().modified().unwrap();
        let i = IsolatedInstall::ephemeral("x", tmp.path(), Duration::from_secs(60));
        i.touch();
        let after = std::fs::metadata(&pkg_json).unwrap().modified().unwrap();
        assert!(after > before, "touch should advance mtime");
    }

    #[test]
    fn touch_is_no_op_for_persistent() {
        let tmp = TempDir::new().unwrap();
        make_complete_install_root(tmp.path());
        let pkg_json = tmp.path().join("package.json");
        let f = std::fs::OpenOptions::new()
            .write(true)
            .open(&pkg_json)
            .unwrap();
        let baseline = SystemTime::now() - Duration::from_secs(3600);
        f.set_modified(baseline).unwrap();

        let i = IsolatedInstall::persistent("x", tmp.path(), vec![]);
        i.touch();
        let after = std::fs::metadata(&pkg_json).unwrap().modified().unwrap();
        assert_eq!(after, baseline, "persistent touch must not advance mtime");
    }
}
