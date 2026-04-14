//! Phase 37 — centralized `~/.lpm` path layer.
//!
//! Before this module, every crate that needed a machine-global path computed
//! it independently by reading `HOME` / `USERPROFILE` or calling
//! `dirs::home_dir()`, then joining `.lpm` + a crate-specific subpath. That
//! pattern made testing hard (no single injection point for a fake root) and
//! it let the global layout drift silently as new crates were added.
//!
//! Everything downstream now goes through [`LpmRoot`]. Paths are computed
//! once at startup (respecting `$LPM_HOME` for test / power-user overrides)
//! and passed around as a typed value.
//!
//! ## Layout
//!
//! ```text
//! <root>/
//!   bin/                          ← unix symlinks / Windows shim triples (on PATH)
//!   cache/
//!     metadata/                   ← registry metadata cache (lpm-registry)
//!     tasks/                      ← task cache (lpm-task)
//!     dlx/                        ← ephemeral dlx installs (lpm-runner) — was ~/.lpm/dlx-cache/
//!     .clean.lock                 ← serializes concurrent `cache clean` ops
//!   store/
//!     v1/                         ← content-addressable package store (lpm-store)
//!     .gc.lock                    ← serializes `store gc`
//!   global/
//!     manifest.toml               ← [packages.*] active + [pending.*] in-flight + [aliases] + [tombstones]
//!     build-state.json            ← pending blocked scripts (reuses lpm-cli BuildState shape)
//!     trusted-dependencies.json   ← GlobalTrustFile; parallel to project `package.json`'s lpm.trustedDependencies
//!     wal.jsonl                   ← framed write-ahead log for crash recovery
//!     .tx.lock                    ← fs2 advisory lock for install tx critical sections
//!     .tx.lock.pid                ← best-effort PID of current holder (unlinked on clean exit)
//!     installs/
//!       <name>@<ver>/             ← per-package isolated install root
//!         .lpm-install-ready      ← durable completeness marker (see phase37 plan)
//!         lpm.lock
//!         node_modules/
//!         .lpm/
//! ```
//!
//! ## Testing
//!
//! Tests use [`LpmRoot::from_dir`] to inject a `tempfile::TempDir` as the
//! root. [`LpmRoot::from_env`] is strictly for production startup and is
//! the single canonical entry point for deciding where machine-global state
//! lives on a real user's machine.

use crate::LpmError;
use std::path::{Path, PathBuf};

/// Typed handle for the `~/.lpm/` directory tree.
///
/// Prefer passing `&LpmRoot` between crates over raw `PathBuf`s — it makes
/// call sites self-documenting and lets tests inject a fake home without
/// touching `$HOME` or `$LPM_HOME`.
#[derive(Debug, Clone)]
pub struct LpmRoot {
    home: PathBuf,
}

impl LpmRoot {
    /// Resolve the LPM root from the environment.
    ///
    /// Precedence:
    /// 1. `$LPM_HOME` if set (used by tests and power users)
    /// 2. `$HOME/.lpm` on Unix
    /// 3. `$USERPROFILE\.lpm` on Windows (via `dirs::home_dir`)
    ///
    /// Returns an error only when no home directory can be resolved, which
    /// on a sanely configured system is essentially never. This function
    /// performs **no** filesystem I/O and is safe to call from any command
    /// path, including read-only ones like `--help`.
    pub fn from_env() -> Result<Self, LpmError> {
        if let Ok(explicit) = std::env::var("LPM_HOME")
            && !explicit.is_empty()
        {
            return Ok(LpmRoot {
                home: PathBuf::from(explicit),
            });
        }

        let home = dirs::home_dir().ok_or_else(|| {
            LpmError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "could not determine home directory (neither $LPM_HOME nor $HOME / $USERPROFILE is set)",
            ))
        })?;

        Ok(LpmRoot {
            home: home.join(".lpm"),
        })
    }

    /// Build an `LpmRoot` pointing at an explicit directory. For tests and
    /// internal migration helpers only.
    pub fn from_dir(home: impl Into<PathBuf>) -> Self {
        LpmRoot { home: home.into() }
    }

    // ─── Core accessors ─────────────────────────────────────────────

    pub fn root(&self) -> &Path {
        &self.home
    }

    // ─── Store ──────────────────────────────────────────────────────

    pub fn store_root(&self) -> PathBuf {
        self.home.join("store")
    }

    pub fn store_v1(&self) -> PathBuf {
        self.store_root().join("v1")
    }

    pub fn store_gc_lock(&self) -> PathBuf {
        self.store_root().join(".gc.lock")
    }

    // ─── Cache ──────────────────────────────────────────────────────

    pub fn cache_root(&self) -> PathBuf {
        self.home.join("cache")
    }

    pub fn cache_metadata(&self) -> PathBuf {
        self.cache_root().join("metadata")
    }

    pub fn cache_tasks(&self) -> PathBuf {
        self.cache_root().join("tasks")
    }

    pub fn cache_dlx(&self) -> PathBuf {
        self.cache_root().join("dlx")
    }

    pub fn cache_clean_lock(&self) -> PathBuf {
        self.cache_root().join(".clean.lock")
    }

    /// Legacy pre-phase37 dlx cache location. Used only by the one-shot
    /// migration; do not read or write through this path in new code.
    pub fn legacy_dlx_cache(&self) -> PathBuf {
        self.home.join("dlx-cache")
    }

    // ─── Bin (PATH-exposed shims) ──────────────────────────────────

    pub fn bin_dir(&self) -> PathBuf {
        self.home.join("bin")
    }

    // ─── Global install tree ────────────────────────────────────────

    pub fn global_root(&self) -> PathBuf {
        self.home.join("global")
    }

    pub fn global_manifest(&self) -> PathBuf {
        self.global_root().join("manifest.toml")
    }

    pub fn global_installs(&self) -> PathBuf {
        self.global_root().join("installs")
    }

    pub fn global_build_state(&self) -> PathBuf {
        self.global_root().join("build-state.json")
    }

    pub fn global_trusted_deps(&self) -> PathBuf {
        self.global_root().join("trusted-dependencies.json")
    }

    pub fn global_wal(&self) -> PathBuf {
        self.global_root().join("wal.jsonl")
    }

    pub fn global_tx_lock(&self) -> PathBuf {
        self.global_root().join(".tx.lock")
    }

    pub fn global_tx_lock_pid(&self) -> PathBuf {
        self.global_root().join(".tx.lock.pid")
    }

    /// The install root for a specific `(name, version)` pair, under
    /// `global/installs/`. Name is sanitized: `@scope/pkg` becomes
    /// `@scope+pkg`, matching existing `lpm-store` conventions.
    pub fn install_root_for(&self, name: &str, version: &str) -> PathBuf {
        let safe_name = name.replace('/', "+");
        self.global_installs()
            .join(format!("{safe_name}@{version}"))
    }

    // ─── Onboarding / notice markers ────────────────────────────────

    /// Sentinel file created after the first successful `install -g` on a
    /// host, used to suppress the PATH-onboarding banner on subsequent runs.
    pub fn path_hint_marker(&self) -> PathBuf {
        self.home.join(".path-hint-shown")
    }

    /// Sentinel file created after the one-time "cache clean semantics
    /// changed" banner fires, used to suppress it on subsequent runs.
    pub fn cache_clean_notice_marker(&self) -> PathBuf {
        self.home.join(".cache-clean-notice-shown")
    }

    /// Sentinel file created after the one-time network-filesystem warning
    /// fires, used to suppress it on subsequent runs.
    pub fn network_fs_notice_marker(&self) -> PathBuf {
        self.home.join(".network-fs-notice-shown")
    }
}

// ─── Windows long-path helper ─────────────────────────────────────────

/// Return a path safe for filesystem APIs that would otherwise hit the
/// Win32 MAX_PATH (260-char) ceiling.
///
/// On Windows, absolute paths longer than 259 characters are truncated by
/// the legacy API unless they carry the `\\?\` extended-length prefix.
/// This helper is a no-op on other platforms and on paths that are already
/// prefixed, relative, or short enough to be safe.
///
/// Call this for every filesystem operation under `~/.lpm/global/installs/`
/// — the combination of `$LPM_HOME` + scope + `@ver` + nested `node_modules`
/// chains routinely pushes paths past the ceiling.
pub fn as_extended_path(path: &Path) -> PathBuf {
    #[cfg(windows)]
    {
        let s = path.to_string_lossy();
        // Skip if already prefixed with \\?\ or \\.\ (device namespace)
        if s.starts_with(r"\\?\") || s.starts_with(r"\\.\") {
            return path.to_path_buf();
        }
        // Skip relative paths — the prefix is only meaningful on absolute ones
        if !path.is_absolute() {
            return path.to_path_buf();
        }
        // UNC paths use \\?\UNC\server\share form
        if s.starts_with(r"\\") {
            return PathBuf::from(format!(r"\\?\UNC\{}", &s[2..]));
        }
        return PathBuf::from(format!(r"\\?\{s}"));
    }
    #[cfg(not(windows))]
    {
        path.to_path_buf()
    }
}

// ─── Network-filesystem detection ─────────────────────────────────────

/// Classification of the filesystem backing a given path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsKind {
    /// Local storage — advisory locks are reliable.
    Local,
    /// Known unreliable networked filesystem (NFS / SMB / CIFS / AFP).
    /// Advisory locks are lying-or-incomplete; emit a warning at bootstrap.
    Network,
    /// Unknown (statfs failed, unfamiliar filesystem type). Treat as local
    /// to avoid false-positive warnings for legitimate FUSE mounts, tmpfs
    /// on Linux, APFS snapshots, etc.
    Unknown,
}

/// Best-effort detection of whether `path` lives on a local filesystem.
///
/// The detection is used only to emit a one-time diagnostic warning when
/// `$LPM_HOME` sits on NFS/SMB. We intentionally default to treating
/// unknown filesystems as local — false positives on obscure-but-reliable
/// mounts (FUSE, tmpfs, loopback) would be more annoying than the rare
/// missed NFS warning.
pub fn is_local_fs(path: &Path) -> FsKind {
    #[cfg(target_os = "linux")]
    {
        // /proc/self/mountinfo parsing would be more robust, but statfs with
        // f_type matching is simpler and good enough for the warning use case.
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let Ok(c_path) = CString::new(path.as_os_str().as_bytes()) else {
            return FsKind::Unknown;
        };
        let mut buf: libc::statfs = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::statfs(c_path.as_ptr(), &mut buf) };
        if rc != 0 {
            return FsKind::Unknown;
        }
        // Magic numbers from linux/magic.h — spelled out here to avoid
        // pulling in a filesystem-types crate for five constants.
        const NFS_SUPER_MAGIC: libc::__fsword_t = 0x6969;
        const SMB_SUPER_MAGIC: libc::__fsword_t = 0x517B;
        const SMB2_MAGIC_NUMBER: libc::__fsword_t = 0xFE534D42u32 as libc::__fsword_t;
        const CIFS_MAGIC_NUMBER: libc::__fsword_t = 0xFF534D42u32 as libc::__fsword_t;
        const CODA_SUPER_MAGIC: libc::__fsword_t = 0x73757245;

        match buf.f_type {
            NFS_SUPER_MAGIC | SMB_SUPER_MAGIC | SMB2_MAGIC_NUMBER | CIFS_MAGIC_NUMBER
            | CODA_SUPER_MAGIC => FsKind::Network,
            _ => FsKind::Local,
        }
    }
    #[cfg(target_os = "macos")]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let Ok(c_path) = CString::new(path.as_os_str().as_bytes()) else {
            return FsKind::Unknown;
        };
        let mut buf: libc::statfs = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::statfs(c_path.as_ptr(), &mut buf) };
        if rc != 0 {
            return FsKind::Unknown;
        }
        // f_fstypename is a null-terminated [c_char; MFSTYPENAMELEN]. Convert
        // to &str for comparison; any non-UTF8 implies an exotic FS we
        // should not try to classify.
        let raw: Vec<u8> = buf
            .f_fstypename
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c as u8)
            .collect();
        let Ok(fstype) = std::str::from_utf8(&raw) else {
            return FsKind::Unknown;
        };
        match fstype {
            "nfs" | "smbfs" | "cifs" | "afpfs" | "webdav" => FsKind::Network,
            _ => FsKind::Local,
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::{DRIVE_REMOTE, GetDriveTypeW};

        // GetDriveTypeW takes a root path like "C:\\". Extract the root
        // component of the input; if we can't, default to Unknown.
        let Some(root) = path.ancestors().last() else {
            return FsKind::Unknown;
        };
        let wide: Vec<u16> = root
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let drive_type = unsafe { GetDriveTypeW(wide.as_ptr()) };
        if drive_type == DRIVE_REMOTE {
            FsKind::Network
        } else {
            FsKind::Local
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        let _ = path;
        FsKind::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn from_env_respects_lpm_home_override() {
        let tmp = TempDir::new().unwrap();
        // Use set_var under a mutex in a real project; for one-shot tests the
        // env is process-local and we're not racing with other threads that
        // read LPM_HOME.
        unsafe {
            std::env::set_var("LPM_HOME", tmp.path());
        }
        let root = LpmRoot::from_env().unwrap();
        assert_eq!(root.root(), tmp.path());
        unsafe {
            std::env::remove_var("LPM_HOME");
        }
    }

    #[test]
    fn from_env_falls_back_to_home_dot_lpm() {
        unsafe {
            std::env::remove_var("LPM_HOME");
        }
        let root = LpmRoot::from_env().unwrap();
        assert_eq!(root.root().file_name().unwrap(), ".lpm");
    }

    #[test]
    fn from_dir_injects_explicit_home() {
        let tmp = TempDir::new().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        assert_eq!(root.root(), tmp.path());
    }

    #[test]
    fn accessors_all_compose_under_home() {
        let tmp = TempDir::new().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        for p in [
            root.store_root(),
            root.store_v1(),
            root.store_gc_lock(),
            root.cache_root(),
            root.cache_metadata(),
            root.cache_tasks(),
            root.cache_dlx(),
            root.cache_clean_lock(),
            root.legacy_dlx_cache(),
            root.bin_dir(),
            root.global_root(),
            root.global_manifest(),
            root.global_installs(),
            root.global_build_state(),
            root.global_trusted_deps(),
            root.global_wal(),
            root.global_tx_lock(),
            root.global_tx_lock_pid(),
            root.install_root_for("eslint", "9.24.0"),
            root.install_root_for("@lpm.dev/owner.tool", "1.2.0"),
            root.path_hint_marker(),
            root.cache_clean_notice_marker(),
            root.network_fs_notice_marker(),
        ] {
            assert!(
                p.starts_with(tmp.path()),
                "accessor produced {p:?} outside root"
            );
        }
    }

    #[test]
    fn install_root_for_sanitizes_scoped_names() {
        let root = LpmRoot::from_dir("/tmp/lpm-test");
        let p = root.install_root_for("@lpm.dev/owner.tool", "1.2.0");
        let tail = p.file_name().unwrap().to_string_lossy();
        assert_eq!(tail, "@lpm.dev+owner.tool@1.2.0");
        assert!(!tail.contains('/'));
    }

    #[test]
    fn as_extended_path_is_noop_on_unix() {
        #[cfg(not(windows))]
        {
            let p = Path::new("/some/long/path");
            assert_eq!(as_extended_path(p), p);
        }
    }

    #[test]
    #[cfg(windows)]
    fn as_extended_path_prefixes_absolute_windows_paths() {
        let p = Path::new(r"C:\Users\test\AppData\Local\.lpm\global\installs\pkg@1.0.0");
        let got = as_extended_path(p);
        assert!(got.to_string_lossy().starts_with(r"\\?\"));
    }

    #[test]
    #[cfg(windows)]
    fn as_extended_path_skips_already_prefixed() {
        let p = Path::new(r"\\?\C:\already\prefixed");
        assert_eq!(as_extended_path(p), p);
    }

    #[test]
    #[cfg(windows)]
    fn as_extended_path_skips_relative() {
        let p = Path::new(r"some\relative\path");
        assert_eq!(as_extended_path(p), p);
    }

    #[test]
    fn is_local_fs_returns_sane_value_for_tempdir() {
        let tmp = TempDir::new().unwrap();
        // Temp dirs are always local on supported platforms; on everything
        // else we expect Unknown, which we still treat as non-Network.
        let kind = is_local_fs(tmp.path());
        assert_ne!(kind, FsKind::Network, "tempdir classified as Network");
    }
}
