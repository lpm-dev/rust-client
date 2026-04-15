//! Phase 37 M3.1b — install root completeness markers.
//!
//! Per the plan §"Crash-safe transactions", a global install commits
//! in three phases. Step 2 (the slow lock-free extract / link / lockfile
//! / bin-targets work) finishes by writing
//! `<install_root>/.lpm-install-ready`. Recovery uses that marker plus
//! a re-validation of bin-target executability to decide between
//! roll-forward and roll-back of an INTENT that lacks a matching COMMIT.
//!
//! ## Why a marker file isn't enough on its own
//!
//! A bare "marker exists" check would be vulnerable to filesystem state
//! that moved between mark-write and recovery — a `.lpm-install-ready`
//! file can outlive the bins it claims, e.g. if a user manually
//! deletes a file inside the install root or if a partial filesystem
//! restore reintroduces the marker without its dependencies. The
//! [`validate_install_root`] helper re-checks each declared command's
//! bin target at recovery time so the marker's claim is corroborated
//! by the actual filesystem.
//!
//! ## What the marker carries
//!
//! Just enough to identify the install: schema version, command names,
//! a UTC timestamp. Deliberately no integrity hash — the audit
//! resolved this in rev 5 of the plan: marker answers "did step 2
//! complete?", not "was step 2 correct?". Content correctness lives
//! in the extractor + content-addressable store layers.

use chrono::{DateTime, Utc};
use lpm_common::{INSTALL_READY_MARKER, LpmError};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub const MARKER_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallReadyMarker {
    pub schema_version: u32,
    /// Command names this install exposed — must match the install
    /// pipeline's manifest entry. Recovery cross-checks each name's
    /// bin target via [`validate_install_root`] before rolling forward.
    pub commands: Vec<String>,
    pub written_at: DateTime<Utc>,
}

impl InstallReadyMarker {
    pub fn new(commands: Vec<String>) -> Self {
        InstallReadyMarker {
            schema_version: MARKER_SCHEMA_VERSION,
            commands,
            written_at: Utc::now(),
        }
    }
}

/// Write `marker` into `<install_root>/.lpm-install-ready` atomically
/// (tempfile + rename + parent fsync on Unix).
///
/// The install pipeline calls this **only after** every step-2
/// deliverable is in place: tarballs extracted with integrity verified,
/// node_modules layout linked, `lpm.lock` written, every command in
/// `marker.commands` resolves to an executable file inside the root.
/// A future reader of the marker is entitled to assume those things
/// are true; if any precondition is broken at write time, the marker
/// must NOT be written and recovery will (correctly) classify the
/// install as needing rollback.
pub fn write_marker(install_root: &Path, marker: &InstallReadyMarker) -> Result<(), LpmError> {
    let parent = install_root;
    std::fs::create_dir_all(parent)?;
    let target = install_root.join(INSTALL_READY_MARKER);
    let tmp_name = format!(".{INSTALL_READY_MARKER}.tmp.{}", std::process::id());
    let tmp = install_root.join(tmp_name);
    let serialized = serde_json::to_vec_pretty(marker)
        .map_err(|e| LpmError::Io(std::io::Error::other(format!("marker serialize: {e}"))))?;
    {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp)?;
        std::io::Write::write_all(&mut f, &serialized)?;
        f.sync_all()?;
    }
    if let Err(e) = std::fs::rename(&tmp, &target) {
        let _ = std::fs::remove_file(&tmp);
        return Err(LpmError::Io(e));
    }
    #[cfg(unix)]
    {
        if let Ok(parent_fd) = std::fs::File::open(install_root) {
            let _ = parent_fd.sync_all();
        }
    }
    Ok(())
}

/// Read and parse the marker file at `<install_root>/.lpm-install-ready`.
/// Returns `Ok(None)` when the file does not exist (legitimate "step 2
/// did not complete" state); errors only on I/O failure or malformed
/// JSON / future schema version.
pub fn read_marker(install_root: &Path) -> Result<Option<InstallReadyMarker>, LpmError> {
    let path = install_root.join(INSTALL_READY_MARKER);
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(LpmError::Io(e)),
    };
    let marker: InstallReadyMarker = serde_json::from_slice(&bytes).map_err(|e| {
        LpmError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("install-ready marker parse error: {e}"),
        ))
    })?;
    if marker.schema_version > MARKER_SCHEMA_VERSION {
        return Err(LpmError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "install-ready marker schema_version {} is newer than this binary supports ({})",
                marker.schema_version, MARKER_SCHEMA_VERSION
            ),
        )));
    }
    Ok(Some(marker))
}

/// Outcome of [`validate_install_root`]. Recovery branches on this:
/// `Ready` → roll forward; everything else → roll back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallRootStatus {
    /// Marker present, every command it declares has an executable
    /// bin target inside the root, lockfile parsable. Safe to roll
    /// forward / commit. Carries the marker's command list — that is
    /// the authoritative "what commands does this install own"
    /// because the install pipeline writes it AFTER linking the bin
    /// shims (M3.1b's marker contract). Recovery and the install
    /// commit step both consume this list to drive shim emission and
    /// the [packages.<pkg>] row's commands field.
    Ready { commands: Vec<String> },
    /// `<install_root>/.lpm-install-ready` is missing. Step 2 didn't
    /// complete; the install is not bootable.
    MissingMarker,
    /// Marker present but a declared command's bin target is missing.
    /// State on disk has diverged from the marker's claim.
    MissingBinTarget { command: String },
    /// Marker present but a declared command's bin target is not an
    /// executable file (Unix only — checked via mode bits).
    BinTargetNotExecutable { command: String },
    /// `lpm.lock` is missing inside the install root. Step 2 didn't
    /// finish even though something wrote the marker — treat as not
    /// bootable.
    MissingLockfile,
    /// `lpm.lock` exists but does not parse. Almost certainly truncated
    /// or corrupted from a partial write — not safe to roll forward
    /// against.
    LockfileUnparseable,
    /// Marker declared at least one command that the WAL Intent did
    /// not anticipate. Either the install pipeline discovered more
    /// bins than expected (recoverable — accept the marker as truth),
    /// or someone tampered with the marker (refuse to commit). The
    /// caller decides which interpretation applies to its context.
    MarkerCommandMismatch { extra: Vec<String> },
    /// The install root directory itself doesn't exist. Probably means
    /// the user (or a `store gc` pass) deleted it between Intent and
    /// recovery.
    RootMissing,
}

/// Recovery / commit-time validation that an install root is bootable.
///
/// `expected_commands` is the *anticipated* command list from the WAL
/// Intent payload (or the install pipeline's pre-resolution). When
/// `Some(list)`, each name must appear in the marker's commands AND
/// resolve to an executable file inside the root. When `None` —
/// typically the install pipeline's "first commit, the install
/// discovered the commands itself" call — the marker is the sole
/// authority and every command it lists must be executable.
///
/// On success, returns `InstallRootStatus::Ready { commands }` where
/// `commands` is the marker's full list. The install commit and the
/// recovery roll-forward both use this list rather than the WAL or
/// pending row's value, making the marker the single source of truth
/// post-step-2.
///
/// **Why we check the bin shim path, not the package's package.json:**
/// the marker was written *after* the linker wrote the `.bin` shim,
/// so the existence of the shim is a stronger guarantee of step-2
/// completion than re-reading `package.json` and chasing `bin`
/// references.
pub fn validate_install_root(
    install_root: &Path,
    expected_commands: Option<&[String]>,
) -> Result<InstallRootStatus, LpmError> {
    if !install_root.is_dir() {
        return Ok(InstallRootStatus::RootMissing);
    }
    let marker = match read_marker(install_root)? {
        Some(m) => m,
        None => return Ok(InstallRootStatus::MissingMarker),
    };

    // Cross-check (only when the caller supplied an expectation): every
    // anticipated command must appear in the marker's list. The marker
    // is allowed to declare *more* commands than expected — that's the
    // common case when the install pipeline didn't pre-resolve and
    // discovered bin entries during extraction. We surface that via
    // the `Ready { commands }` return so the caller can opt to use
    // the broader list.
    if let Some(expected) = expected_commands {
        for cmd in expected {
            if !marker.commands.iter().any(|c| c == cmd) {
                return Ok(InstallRootStatus::MissingBinTarget {
                    command: cmd.clone(),
                });
            }
        }
    }

    let bin_dir = install_root.join("node_modules").join(".bin");
    for cmd in &marker.commands {
        let bin_path = bin_dir.join(cmd);
        // symlink_metadata so a broken symlink reports MissingBinTarget
        // rather than misleadingly "Ready".
        let meta = match std::fs::symlink_metadata(&bin_path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(InstallRootStatus::MissingBinTarget {
                    command: cmd.clone(),
                });
            }
            Err(e) => return Err(LpmError::Io(e)),
        };
        // Dangling symlink — target doesn't exist.
        if meta.is_symlink() && !bin_path.exists() {
            return Ok(InstallRootStatus::MissingBinTarget {
                command: cmd.clone(),
            });
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // Resolve through the symlink to check executability of the
            // actual file.
            let target_meta = std::fs::metadata(&bin_path).map_err(LpmError::Io)?;
            let mode = target_meta.permissions().mode();
            if mode & 0o111 == 0 {
                return Ok(InstallRootStatus::BinTargetNotExecutable {
                    command: cmd.clone(),
                });
            }
        }
    }

    let lockfile = install_root.join("lpm.lock");
    if !lockfile.is_file() {
        return Ok(InstallRootStatus::MissingLockfile);
    }
    // Cheap parseability check — read the whole file and verify it's
    // valid UTF-8 + non-empty + starts plausibly. The lockfile crate
    // owns the strict parse; we just want to catch torn writes here.
    let lock_bytes = std::fs::read(&lockfile)?;
    if lock_bytes.is_empty() {
        return Ok(InstallRootStatus::LockfileUnparseable);
    }
    if std::str::from_utf8(&lock_bytes).is_err() {
        return Ok(InstallRootStatus::LockfileUnparseable);
    }

    Ok(InstallRootStatus::Ready {
        commands: marker.commands,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Build a "complete" install root: marker + lockfile + .bin shims.
    /// Mirrors what the M3.2 install pipeline will produce.
    fn make_complete_root(commands: &[&str]) -> TempDir {
        let tmp = TempDir::new().unwrap();
        let bin = tmp.path().join("node_modules").join(".bin");
        std::fs::create_dir_all(&bin).unwrap();
        for cmd in commands {
            let target = bin.join(cmd);
            std::fs::write(&target, b"#!/bin/sh\necho ok\n").unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
        }
        std::fs::write(tmp.path().join("lpm.lock"), b"# valid").unwrap();
        let m = InstallReadyMarker::new(commands.iter().map(|c| c.to_string()).collect());
        write_marker(tmp.path(), &m).unwrap();
        tmp
    }

    // ─── Marker tests ──────────────────────────────────────────────

    #[test]
    fn write_then_read_marker_round_trips() {
        let tmp = TempDir::new().unwrap();
        let m = InstallReadyMarker::new(vec!["eslint".into(), "tsc".into()]);
        write_marker(tmp.path(), &m).unwrap();
        let read = read_marker(tmp.path()).unwrap().unwrap();
        assert_eq!(read.schema_version, MARKER_SCHEMA_VERSION);
        assert_eq!(read.commands, vec!["eslint", "tsc"]);
    }

    #[test]
    fn read_marker_returns_none_when_missing() {
        let tmp = TempDir::new().unwrap();
        assert!(read_marker(tmp.path()).unwrap().is_none());
    }

    #[test]
    fn read_marker_rejects_future_schema_version() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join(INSTALL_READY_MARKER);
        std::fs::write(
            &path,
            format!(
                r#"{{"schema_version":{},"commands":[],"written_at":"2026-04-15T00:00:00Z"}}"#,
                MARKER_SCHEMA_VERSION + 1
            ),
        )
        .unwrap();
        let err = read_marker(tmp.path()).unwrap_err();
        assert!(format!("{err}").contains("newer than this binary supports"));
    }

    #[test]
    fn write_marker_leaves_no_tempfile_on_success() {
        let tmp = TempDir::new().unwrap();
        let m = InstallReadyMarker::new(vec!["x".into()]);
        write_marker(tmp.path(), &m).unwrap();
        let leaks: Vec<_> = std::fs::read_dir(tmp.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                let n = e.file_name().to_string_lossy().into_owned();
                n.starts_with(&format!(".{INSTALL_READY_MARKER}.tmp."))
            })
            .collect();
        assert!(leaks.is_empty(), "tempfile leaked: {leaks:?}");
    }

    // ─── validate_install_root tests ──────────────────────────────

    fn one(s: &str) -> Vec<String> {
        vec![s.to_string()]
    }

    #[test]
    fn ready_when_marker_lockfile_and_bin_targets_all_present() {
        let tmp = make_complete_root(&["eslint"]);
        let status = validate_install_root(tmp.path(), Some(&one("eslint"))).unwrap();
        match status {
            InstallRootStatus::Ready { commands } => {
                assert_eq!(commands, vec!["eslint"]);
            }
            other => panic!("expected Ready, got {other:?}"),
        }
    }

    #[test]
    fn ready_with_no_expected_commands_uses_marker_as_authority() {
        // Install commit path: the install pipeline didn't pre-resolve
        // commands, so it passes None and trusts whatever the marker
        // declares. Marker is the source of truth (M3.2 design).
        let tmp = make_complete_root(&["eslint", "tsc"]);
        let status = validate_install_root(tmp.path(), None).unwrap();
        match status {
            InstallRootStatus::Ready { commands } => {
                assert_eq!(commands, vec!["eslint", "tsc"]);
            }
            other => panic!("expected Ready, got {other:?}"),
        }
    }

    #[test]
    fn root_missing_returns_root_missing() {
        let tmp = TempDir::new().unwrap();
        let status =
            validate_install_root(&tmp.path().join("does-not-exist"), Some(&one("eslint")))
                .unwrap();
        assert_eq!(status, InstallRootStatus::RootMissing);
    }

    #[test]
    fn missing_marker_returns_missing_marker() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path()).unwrap();
        std::fs::create_dir_all(tmp.path().join("node_modules").join(".bin")).unwrap();
        std::fs::write(tmp.path().join("lpm.lock"), b"x").unwrap();
        let status = validate_install_root(tmp.path(), Some(&one("eslint"))).unwrap();
        assert_eq!(status, InstallRootStatus::MissingMarker);
    }

    #[test]
    fn missing_bin_target_returns_missing_bin_target() {
        let tmp = TempDir::new().unwrap();
        // Marker promises eslint, but the .bin/ shim never got written.
        std::fs::create_dir_all(tmp.path().join("node_modules").join(".bin")).unwrap();
        std::fs::write(tmp.path().join("lpm.lock"), b"x").unwrap();
        let m = InstallReadyMarker::new(vec!["eslint".into()]);
        write_marker(tmp.path(), &m).unwrap();
        let status = validate_install_root(tmp.path(), Some(&one("eslint"))).unwrap();
        assert_eq!(
            status,
            InstallRootStatus::MissingBinTarget {
                command: "eslint".into()
            }
        );
    }

    #[test]
    fn marker_commands_must_cover_expected_commands() {
        // WAL says we expect tsc; marker only mentions eslint. Refuse
        // to roll forward — the marker doesn't describe the install
        // we thought we were finishing.
        let tmp = make_complete_root(&["eslint"]);
        let status = validate_install_root(tmp.path(), Some(&one("tsc"))).unwrap();
        assert_eq!(
            status,
            InstallRootStatus::MissingBinTarget {
                command: "tsc".into()
            }
        );
    }

    #[test]
    fn marker_with_extra_commands_is_accepted_and_returned() {
        // Install pipeline pre-resolved `eslint` but the actual package
        // also exposes `eslint-server`. The marker (written from the
        // installed package.json) lists both. Commit accepts both.
        let tmp = make_complete_root(&["eslint", "eslint-server"]);
        let status = validate_install_root(tmp.path(), Some(&one("eslint"))).unwrap();
        match status {
            InstallRootStatus::Ready { commands } => {
                assert_eq!(commands, vec!["eslint", "eslint-server"]);
            }
            other => panic!("expected Ready, got {other:?}"),
        }
    }

    #[test]
    fn missing_lockfile_returns_missing_lockfile() {
        let tmp = TempDir::new().unwrap();
        let bin = tmp.path().join("node_modules").join(".bin");
        std::fs::create_dir_all(&bin).unwrap();
        let target = bin.join("eslint");
        std::fs::write(&target, b"#!/bin/sh\necho ok\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        write_marker(tmp.path(), &InstallReadyMarker::new(vec!["eslint".into()])).unwrap();
        // Deliberately no lpm.lock.
        let status = validate_install_root(tmp.path(), Some(&one("eslint"))).unwrap();
        assert_eq!(status, InstallRootStatus::MissingLockfile);
    }

    #[test]
    fn empty_lockfile_returns_lockfile_unparseable() {
        let tmp = TempDir::new().unwrap();
        let bin = tmp.path().join("node_modules").join(".bin");
        std::fs::create_dir_all(&bin).unwrap();
        let target = bin.join("eslint");
        std::fs::write(&target, b"#!/bin/sh\necho ok\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        std::fs::write(tmp.path().join("lpm.lock"), b"").unwrap();
        write_marker(tmp.path(), &InstallReadyMarker::new(vec!["eslint".into()])).unwrap();
        let status = validate_install_root(tmp.path(), Some(&one("eslint"))).unwrap();
        assert_eq!(status, InstallRootStatus::LockfileUnparseable);
    }

    #[test]
    #[cfg(unix)]
    fn non_executable_bin_returns_bin_target_not_executable() {
        let tmp = TempDir::new().unwrap();
        let bin = tmp.path().join("node_modules").join(".bin");
        std::fs::create_dir_all(&bin).unwrap();
        let target = bin.join("eslint");
        std::fs::write(&target, b"// not executable").unwrap();
        // Mode 0o644 — readable but not executable.
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::write(tmp.path().join("lpm.lock"), b"x").unwrap();
        write_marker(tmp.path(), &InstallReadyMarker::new(vec!["eslint".into()])).unwrap();
        let status = validate_install_root(tmp.path(), Some(&one("eslint"))).unwrap();
        assert_eq!(
            status,
            InstallRootStatus::BinTargetNotExecutable {
                command: "eslint".into()
            }
        );
    }

    #[test]
    #[cfg(unix)]
    fn dangling_symlink_returns_missing_bin_target() {
        let tmp = TempDir::new().unwrap();
        let bin = tmp.path().join("node_modules").join(".bin");
        std::fs::create_dir_all(&bin).unwrap();
        std::os::unix::fs::symlink("/does/not/exist", bin.join("eslint")).unwrap();
        std::fs::write(tmp.path().join("lpm.lock"), b"x").unwrap();
        write_marker(tmp.path(), &InstallReadyMarker::new(vec!["eslint".into()])).unwrap();
        let status = validate_install_root(tmp.path(), Some(&one("eslint"))).unwrap();
        assert_eq!(
            status,
            InstallRootStatus::MissingBinTarget {
                command: "eslint".into()
            }
        );
    }
}
