//! Phase 37 — `IsolatedInstall`: per-spec install root for `lpm dlx`.
//!
//! M2 introduced this primitive as the abstraction shared between
//! `lpm dlx` and `lpm install -g`, with the ambition of "one engine,
//! two policies." In practice, M3 wired `lpm install -g` through
//! `commands::install::run_with_options` directly (with a synthetic
//! `package.json`) — the resolver / store / extractor sharing that
//! the abstraction was meant to provide is achieved through the inner
//! pipeline call, not through this struct.
//!
//! We deleted the `Persistent` policy variant rather than carry a
//! second code path that was never reached in production. If a future
//! refactor needs the dual-policy abstraction back, it can be
//! reintroduced when there is a real second caller.
//!
//! Today this primitive serves one job: encapsulate the per-spec
//! install-root lifecycle for `lpm dlx` (cache freshness, completeness
//! markers, TTL sweep, mtime touch, restricted-perms create).
//! `commands::run::dlx` is the only call site; future audit-driven
//! changes to that flow happen here.

use crate::dlx;
use lpm_common::LpmError;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// One isolated install root for `lpm dlx`. Holds the spec it was
/// constructed for, the absolute root path, and the TTL after which
/// the cache sweep should reap it.
#[derive(Debug, Clone)]
pub struct IsolatedInstall {
    spec: String,
    root: PathBuf,
    /// How long the install can sit unused before [`should_sweep`]
    /// classifies it as stale. Refreshed by [`touch`] on every
    /// successful invocation (install or hit).
    ttl: Duration,
}

impl IsolatedInstall {
    /// Build an ephemeral install (`lpm dlx`).
    pub fn ephemeral(spec: impl Into<String>, root: impl Into<PathBuf>, ttl: Duration) -> Self {
        IsolatedInstall {
            spec: spec.into(),
            root: root.into(),
            ttl,
        }
    }

    pub fn spec(&self) -> &str {
        &self.spec
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// True when this install root is bootable: the cheap completeness
    /// markers `{package.json, node_modules/.bin/}` are both present
    /// AND the entry is within its TTL. Outside the TTL the entry is
    /// treated as "needs reinstall."
    pub fn is_ready(&self) -> bool {
        if !markers_present(&self.root) {
            return false;
        }
        dlx::is_cache_fresh(&self.root, self.ttl.as_secs())
    }

    /// True when this install is past its TTL — i.e. the dlx sweep
    /// should reap it. Mirrors the predicate used by
    /// [`dlx::sweep_stale_dlx_entries`] so a future refactor can
    /// drive the sweep through this primitive.
    pub fn should_sweep(&self) -> bool {
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
        age >= self.ttl
    }

    /// Generate the `package.json` text the install pipeline writes
    /// into the install root: single dependency on `spec`, marked
    /// private so npm/yarn/pnpm wouldn't try to publish it. Same
    /// shape as the pre-M2 dlx writer at `commands::run::dlx`.
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
    pub fn touch(&self) {
        dlx::touch_cache(&self.root);
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
    fn ephemeral_constructor_round_trips() {
        let i = IsolatedInstall::ephemeral("cowsay", "/tmp/foo", Duration::from_secs(60));
        assert_eq!(i.spec(), "cowsay");
        assert_eq!(i.root(), Path::new("/tmp/foo"));
        assert_eq!(i.ttl(), Duration::from_secs(60));
    }

    #[test]
    fn is_ready_false_when_markers_missing() {
        let tmp = TempDir::new().unwrap();
        let i = IsolatedInstall::ephemeral("x", tmp.path(), Duration::from_secs(60));
        assert!(!i.is_ready());
    }

    #[test]
    fn is_ready_respects_ttl() {
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
    fn should_sweep_false_when_root_absent() {
        let tmp = TempDir::new().unwrap();
        let i = IsolatedInstall::ephemeral("x", tmp.path().join("nope"), Duration::from_secs(0));
        // No package.json → not a recognized entry → don't sweep.
        assert!(!i.should_sweep());
    }

    #[test]
    fn should_sweep_true_past_ttl() {
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
    fn touch_refreshes_mtime() {
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
}
