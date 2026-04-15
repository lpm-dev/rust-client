//! Phase 37 M3.1a — bin shim emission for `~/.lpm/bin/`.
//!
//! Both M3.2 (install --global) and the recovery roll-forward path
//! produce shims through this module. M3.3 (uninstall) removes them
//! through it too. Single source of truth for what a shim looks like
//! on each platform, and how it's swapped atomically when a collision
//! resolution / upgrade rewrites it.
//!
//! ## Per-platform layout
//!
//! - **Unix**: one relative-path-tolerant absolute symlink at
//!   `<bin_dir>/<command_name>` pointing at the bin entry inside the
//!   install root. `chmod +x` is implicit on the target file inside
//!   the install root (the linker already enforces it during install).
//!
//! - **Windows**: a *triple* of artifacts at
//!   `<bin_dir>/<command_name>{.cmd, .ps1, ""}`. All three are written
//!   so the same `<command_name>` resolves correctly under cmd.exe,
//!   PowerShell, and Git Bash / Cygwin / MSYS2 / WSL. The "three-
//!   artifact invariant" is a product choice documented in the plan
//!   §"Three-artifact invariant": a partial triple is treated as
//!   uncommitted, and recovery re-emits the missing files.
//!
//! ## Atomicity
//!
//! Every artifact is written via tempfile-then-rename so a concurrent
//! reader (a shell about to fork into the binary) sees either the old
//! content or the new content, never a partial. On Windows, transient
//! `ERROR_SHARING_VIOLATION` / `ERROR_ACCESS_DENIED` from antivirus or
//! Explorer preview gets retry-with-backoff (50/150/450/1350/4050ms);
//! on the final attempt failure becomes an error so the caller can
//! abort the transaction cleanly rather than leave a half-swapped triple.
//!
//! ## Security
//!
//! Command names go through [`validate_command_name`] before any
//! filesystem call to defend against `..`, path separators, shell
//! metachars in shim names, and absurd lengths. On Windows the target
//! path additionally goes through [`validate_windows_target_path`] to
//! reject characters that have meaning inside `.cmd` files.

use lpm_common::LpmError;
use std::io;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ShimError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("invalid command name '{name}': {reason}")]
    InvalidCommandName { name: String, reason: &'static str },
    #[error("invalid Windows target path '{path}': {reason}")]
    InvalidWindowsTargetPath { path: String, reason: &'static str },
    #[error("could not swap shim at {path:?} after {attempts} attempts: {source}")]
    SwapTimeout {
        path: PathBuf,
        attempts: u32,
        source: io::Error,
    },
}

impl From<ShimError> for LpmError {
    fn from(e: ShimError) -> Self {
        LpmError::Io(io::Error::other(e.to_string()))
    }
}

/// One shim to be (re)emitted into a bin directory.
#[derive(Debug, Clone)]
pub struct Shim {
    /// The name to expose on PATH. Goes through [`validate_command_name`]
    /// before any filesystem call.
    pub command_name: String,
    /// Absolute path of the file the shim should invoke. Must live
    /// inside the install root the shim is associated with — but this
    /// invariant is enforced by the M3 install pipeline, not by the
    /// shim writer (which only does platform-correct file emission).
    pub target: PathBuf,
}

/// Inventory of files actually written by [`emit_shim`]. The install
/// pipeline records this so it can verify the three-artifact invariant
/// on Windows and so uninstall can reverse the same set of writes
/// without guessing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmittedShim {
    pub command_name: String,
    pub artifacts: Vec<PathBuf>,
}

// Retry-with-backoff steps for Windows shim swaps. AV scanners and
// Explorer preview can briefly hold a handle on a `.cmd` / `.ps1`
// right when we're trying to overwrite it; the schedule matches the
// plan §"Windows" spec. Unused on Unix where rename is atomic and not
// subject to transient sharing violations.
#[cfg(windows)]
const MAX_BACKOFF_RETRIES: u32 = 5;
#[cfg(windows)]
const BACKOFF_STEPS_MS: [u64; MAX_BACKOFF_RETRIES as usize] = [50, 150, 450, 1350, 4050];

// ─── Validation ───────────────────────────────────────────────────────

/// Reject command names that would produce unsafe filesystem paths or
/// crash the shell at exec time. Conservative on purpose — package
/// authors rarely need exotic characters in their bin names.
pub fn validate_command_name(name: &str) -> Result<(), ShimError> {
    if name.is_empty() {
        return Err(ShimError::InvalidCommandName {
            name: name.to_string(),
            reason: "empty command name",
        });
    }
    if name.len() > 255 {
        return Err(ShimError::InvalidCommandName {
            name: name.to_string(),
            reason: "command name longer than 255 chars",
        });
    }
    if name.contains('/') || name.contains('\\') {
        return Err(ShimError::InvalidCommandName {
            name: name.to_string(),
            reason: "command name contains path separator",
        });
    }
    if name.contains("..") {
        return Err(ShimError::InvalidCommandName {
            name: name.to_string(),
            reason: "command name contains '..'",
        });
    }
    if name.contains('\0') {
        return Err(ShimError::InvalidCommandName {
            name: name.to_string(),
            reason: "command name contains NUL byte",
        });
    }
    // Note on leading `-`: pre-fix this rejected `--help`-style names.
    // The audit (Answer #3) flagged it as UX policy rather than a real
    // safety boundary — accepting them now to match what npm/pnpm/bun
    // accept. Real bin entries with leading dashes are rare but exist.
    Ok(())
}

/// Windows-specific defense: the target path is interpolated literally
/// into a `.cmd` file. cmd.exe gives meaning to `&`, `|`, `<`, `>`,
/// `^`, `%`, `"`, and the line-ending bytes — any of those in the
/// target would either break the script or open a real injection
/// channel (think `&calc.exe&`). The Unix shim never interpolates the
/// path into a shell-evaluated context (it's an exec(2) argv), so this
/// check is Windows-only.
pub fn validate_windows_target_path(path: &str) -> Result<(), ShimError> {
    const DANGEROUS: &[char] = &['"', '&', '|', '<', '>', '^', '%', '\n', '\r'];
    for ch in DANGEROUS {
        if path.contains(*ch) {
            return Err(ShimError::InvalidWindowsTargetPath {
                path: path.to_string(),
                reason: match *ch {
                    '"' => "contains double-quote",
                    '&' => "contains ampersand",
                    '|' => "contains pipe",
                    '<' => "contains '<'",
                    '>' => "contains '>'",
                    '^' => "contains caret",
                    '%' => "contains percent",
                    '\n' | '\r' => "contains newline",
                    _ => unreachable!(),
                },
            });
        }
    }
    Ok(())
}

// ─── Emission ─────────────────────────────────────────────────────────

/// Emit `shim` into `bin_dir`, replacing any existing artifact at the
/// same name. Returns the inventory of files actually written.
///
/// `bin_dir` is created if missing. The shim's `command_name` and (on
/// Windows) `target` are validated before any filesystem work.
pub fn emit_shim(bin_dir: &Path, shim: &Shim) -> Result<EmittedShim, ShimError> {
    validate_command_name(&shim.command_name)?;
    std::fs::create_dir_all(bin_dir)?;

    #[cfg(unix)]
    {
        let link_path = bin_dir.join(&shim.command_name);
        atomic_replace_symlink_unix(&link_path, &shim.target)?;
        Ok(EmittedShim {
            command_name: shim.command_name.clone(),
            artifacts: vec![link_path],
        })
    }

    #[cfg(windows)]
    {
        let target_str = shim.target.to_string_lossy();
        validate_windows_target_path(&target_str)?;
        let cmd_path = bin_dir.join(format!("{}.cmd", shim.command_name));
        let ps1_path = bin_dir.join(format!("{}.ps1", shim.command_name));
        let bash_path = bin_dir.join(&shim.command_name);

        atomic_replace_file_windows(&cmd_path, &cmd_template(&target_str).into_bytes())?;
        atomic_replace_file_windows(&ps1_path, &ps1_template(&target_str).into_bytes())?;
        atomic_replace_file_windows(&bash_path, &bash_template(&target_str).into_bytes())?;

        Ok(EmittedShim {
            command_name: shim.command_name.clone(),
            artifacts: vec![cmd_path, ps1_path, bash_path],
        })
    }
}

/// Remove every artifact for `command_name` from `bin_dir`. Idempotent:
/// missing files are not an error. Returns the inventory of files that
/// were actually removed (useful for tests and tracing).
///
/// On Windows each artifact's removal is retried-with-backoff on
/// transient `ERROR_SHARING_VIOLATION` / `ERROR_ACCESS_DENIED` (AV
/// scanners, Explorer preview), mirroring [`emit_shim`]'s atomic
/// swap. Without retry, uninstall would commit even when a shim
/// briefly couldn't be unlinked, leaving a stale command on PATH
/// (audit Medium from M3.3 round).
pub fn remove_shim(bin_dir: &Path, command_name: &str) -> Result<Vec<PathBuf>, ShimError> {
    validate_command_name(command_name)?;
    let mut removed = Vec::new();

    #[cfg(unix)]
    {
        let link_path = bin_dir.join(command_name);
        // symlink_metadata so a dangling symlink still gets cleaned up.
        if std::fs::symlink_metadata(&link_path).is_ok() {
            std::fs::remove_file(&link_path)?;
            removed.push(link_path);
        }
    }

    #[cfg(windows)]
    {
        for suffix in [".cmd", ".ps1", ""] {
            let path = bin_dir.join(format!("{command_name}{suffix}"));
            if std::fs::symlink_metadata(&path).is_ok() {
                remove_file_with_retry_windows(&path)?;
                removed.push(path);
            }
        }
    }

    Ok(removed)
}

#[cfg(windows)]
fn remove_file_with_retry_windows(path: &Path) -> Result<(), ShimError> {
    use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_SHARING_VIOLATION};
    let mut last_err = None;
    let mut attempts = 0u32;
    for sleep_ms in BACKOFF_STEPS_MS {
        match std::fs::remove_file(path) {
            Ok(()) => return Ok(()),
            Err(e) => {
                attempts += 1;
                let raw = e.raw_os_error().map(|c| c as u32);
                let is_transient = matches!(
                    raw,
                    Some(ERROR_SHARING_VIOLATION) | Some(ERROR_ACCESS_DENIED)
                );
                last_err = Some(e);
                if !is_transient {
                    let e = last_err.take().unwrap();
                    return Err(ShimError::Io(e));
                }
                std::thread::sleep(std::time::Duration::from_millis(sleep_ms));
            }
        }
    }
    Err(ShimError::SwapTimeout {
        path: path.to_path_buf(),
        attempts,
        source: last_err.unwrap_or_else(|| io::Error::other("no source error captured")),
    })
}

/// Return the set of artifact paths that **would** be emitted for
/// `command_name` in `bin_dir`. Used by recovery to verify the
/// three-artifact invariant on Windows without having to re-emit
/// everything to discover what's missing.
pub fn expected_artifacts(bin_dir: &Path, command_name: &str) -> Vec<PathBuf> {
    #[cfg(unix)]
    {
        vec![bin_dir.join(command_name)]
    }
    #[cfg(windows)]
    {
        vec![
            bin_dir.join(format!("{command_name}.cmd")),
            bin_dir.join(format!("{command_name}.ps1")),
            bin_dir.join(command_name),
        ]
    }
}

/// True when every file in [`expected_artifacts`] for `command_name`
/// exists under `bin_dir`. False on the first missing file. Used by
/// recovery's three-artifact-invariant check.
pub fn artifacts_complete(bin_dir: &Path, command_name: &str) -> bool {
    expected_artifacts(bin_dir, command_name)
        .iter()
        .all(|p| p.exists())
}

// ─── Unix internals ───────────────────────────────────────────────────

#[cfg(unix)]
fn atomic_replace_symlink_unix(link_path: &Path, target: &Path) -> Result<(), ShimError> {
    // Write a fresh symlink alongside the existing one and rename over it.
    // POSIX rename across the same dir is atomic; observers see either the
    // old link or the new link, never neither.
    let parent = link_path.parent().ok_or_else(|| {
        ShimError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "bin path has no parent directory",
        ))
    })?;
    let tmp_name = format!(
        ".{}.{}.tmp",
        link_path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "shim".to_string()),
        std::process::id()
    );
    let tmp_path = parent.join(tmp_name);
    // Defensive: if a previous run left a tempfile (PID reused), nuke it.
    let _ = std::fs::remove_file(&tmp_path);
    std::os::unix::fs::symlink(target, &tmp_path)?;
    if let Err(e) = std::fs::rename(&tmp_path, link_path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(ShimError::Io(e));
    }
    Ok(())
}

// ─── Windows internals ────────────────────────────────────────────────

#[cfg(windows)]
fn cmd_template(target: &str) -> String {
    // Mirrors lpm-linker's existing .cmd template at lib.rs:1080-1085 so
    // global shims behave the same as project node_modules/.bin shims:
    // prefer a co-located node.exe, fall back to PATH.
    format!(
        "@IF EXIST \"%~dp0\\node.exe\" (\n  \"%~dp0\\node.exe\" \"{target}\" %*\n) ELSE (\n  node \"{target}\" %*\n)",
    )
}

#[cfg(windows)]
fn ps1_template(target: &str) -> String {
    // PowerShell mirror of the .cmd template. `$env:PATH` covers the
    // PATH-fallback branch since PowerShell's `&` operator resolves
    // through PATH the same way cmd.exe does.
    format!(
        "#!/usr/bin/env pwsh\n\
         $basedir = Split-Path $MyInvocation.MyCommand.Definition -Parent\n\
         $exe = Join-Path $basedir 'node.exe'\n\
         if (Test-Path $exe) {{ & $exe \"{target}\" $args }}\n\
         else {{ & node \"{target}\" $args }}\n"
    )
}

#[cfg(windows)]
fn bash_template(target: &str) -> String {
    // Mirrors npm's no-extension bash shim. Path-fallback model matches
    // the .cmd/.ps1 templates so all three artifacts behave the same.
    format!(
        "#!/bin/sh\n\
         basedir=$(dirname \"$(echo \"$0\" | sed -e 's,\\\\,/,g')\")\n\
         case `uname` in\n\
             *CYGWIN*|*MINGW*|*MSYS*) basedir=`cygpath -w \"$basedir\"` ;;\n\
         esac\n\
         if [ -x \"$basedir/node\" ]; then\n\
             exec \"$basedir/node\"  \"{target}\" \"$@\"\n\
         else\n\
             exec node  \"{target}\" \"$@\"\n\
         fi\n"
    )
}

#[cfg(windows)]
fn atomic_replace_file_windows(path: &Path, contents: &[u8]) -> Result<(), ShimError> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_SHARING_VIOLATION};

    let parent = path.parent().ok_or_else(|| {
        ShimError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "shim path has no parent directory",
        ))
    })?;
    let tmp_name = format!(
        ".{}.{}.tmp",
        path.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "shim".to_string()),
        std::process::id()
    );
    let tmp_path = parent.join(tmp_name);
    {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .share_mode(0)
            .open(&tmp_path)?;
        std::io::Write::write_all(&mut f, contents)?;
        f.sync_all()?;
    }

    // Retry the rename on transient EBUSY: AV scanners and Explorer
    // preview can briefly hold a handle on a .cmd / .ps1 right when
    // we're trying to overwrite it. Backoff matches the plan's spec.
    let mut last_err = None;
    let mut attempts = 0u32;
    for sleep_ms in BACKOFF_STEPS_MS {
        match std::fs::rename(&tmp_path, path) {
            Ok(()) => {
                return Ok(());
            }
            Err(e) => {
                attempts += 1;
                let raw = e.raw_os_error().map(|c| c as u32);
                let is_transient = matches!(
                    raw,
                    Some(ERROR_SHARING_VIOLATION) | Some(ERROR_ACCESS_DENIED)
                );
                last_err = Some(e);
                if !is_transient {
                    let e = last_err.take().unwrap();
                    let _ = std::fs::remove_file(&tmp_path);
                    return Err(ShimError::Io(e));
                }
                std::thread::sleep(std::time::Duration::from_millis(sleep_ms));
            }
        }
    }
    let _ = std::fs::remove_file(&tmp_path);
    Err(ShimError::SwapTimeout {
        path: path.to_path_buf(),
        attempts,
        source: last_err.unwrap_or_else(|| io::Error::other("no source error captured")),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn shim(name: &str, target: &str) -> Shim {
        Shim {
            command_name: name.to_string(),
            target: PathBuf::from(target),
        }
    }

    // ─── Validation tests ───────────────────────────────────────────

    #[test]
    fn validate_command_name_rejects_empty() {
        assert!(validate_command_name("").is_err());
    }

    #[test]
    fn validate_command_name_rejects_path_separators() {
        for bad in ["foo/bar", "foo\\bar", "../etc/passwd"] {
            assert!(
                validate_command_name(bad).is_err(),
                "expected error for {bad:?}"
            );
        }
    }

    #[test]
    fn validate_command_name_rejects_dotdot() {
        assert!(validate_command_name("..").is_err());
        assert!(validate_command_name("foo..bar").is_err());
    }

    #[test]
    fn validate_command_name_rejects_null_byte() {
        assert!(validate_command_name("foo\0bar").is_err());
    }

    #[test]
    fn validate_command_name_accepts_leading_dash() {
        // Pre-M3.1-audit this was rejected as UX policy. Now matches
        // npm/pnpm/bun behavior: leading dashes are uncommon but valid
        // bin names. Audit Answer #3.
        assert!(validate_command_name("-rf").is_ok());
        assert!(validate_command_name("--help").is_ok());
    }

    #[test]
    fn validate_command_name_rejects_long_names() {
        let long = "a".repeat(256);
        assert!(validate_command_name(&long).is_err());
    }

    #[test]
    fn validate_command_name_accepts_normal_names() {
        for ok in [
            "eslint",
            "tsc",
            "create-next-app",
            "neo",
            "_internal",
            "x86_64",
        ] {
            assert!(validate_command_name(ok).is_ok(), "expected ok for {ok:?}");
        }
    }

    #[test]
    fn validate_windows_target_path_rejects_metachars() {
        let bad_paths: [&str; 5] = [
            r#"C:\path"with"quotes"#,
            r"C:\path&injection",
            r"C:\path|pipe",
            "C:\\path\nwith\nlf",
            "C:\\path\rwith\rcr",
        ];
        for bad in bad_paths {
            assert!(
                validate_windows_target_path(bad).is_err(),
                "expected error for {bad:?}"
            );
        }
    }

    #[test]
    fn validate_windows_target_path_accepts_normal_paths() {
        for ok in [
            r"C:\Users\me\AppData\Local\.lpm\global\installs\eslint@9\node_modules\eslint\bin\eslint.js",
            r"D:\src\node_modules\.bin\foo",
        ] {
            assert!(
                validate_windows_target_path(ok).is_ok(),
                "expected ok for {ok:?}"
            );
        }
    }

    // ─── Emission / removal — Unix ──────────────────────────────────

    #[test]
    #[cfg(unix)]
    fn emit_creates_symlink_at_command_name_pointing_at_target() {
        let tmp = TempDir::new().unwrap();
        let bin = tmp.path().join("bin");
        let target = tmp.path().join("install/eslint/bin/eslint.js");
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::fs::write(&target, "// fake bin").unwrap();

        let emitted = emit_shim(
            &bin,
            &Shim {
                command_name: "eslint".into(),
                target: target.clone(),
            },
        )
        .unwrap();

        let link = bin.join("eslint");
        assert_eq!(emitted.artifacts, vec![link.clone()]);
        let resolved = std::fs::read_link(&link).unwrap();
        assert_eq!(resolved, target);
    }

    #[test]
    #[cfg(unix)]
    fn emit_replaces_existing_symlink_atomically() {
        let tmp = TempDir::new().unwrap();
        let bin = tmp.path().join("bin");
        let old_target = tmp.path().join("old/eslint.js");
        let new_target = tmp.path().join("new/eslint.js");
        std::fs::create_dir_all(old_target.parent().unwrap()).unwrap();
        std::fs::create_dir_all(new_target.parent().unwrap()).unwrap();
        std::fs::write(&old_target, "old").unwrap();
        std::fs::write(&new_target, "new").unwrap();

        emit_shim(
            &bin,
            &Shim {
                command_name: "eslint".into(),
                target: old_target.clone(),
            },
        )
        .unwrap();
        emit_shim(
            &bin,
            &Shim {
                command_name: "eslint".into(),
                target: new_target.clone(),
            },
        )
        .unwrap();

        let link = bin.join("eslint");
        let resolved = std::fs::read_link(&link).unwrap();
        assert_eq!(resolved, new_target, "symlink must point at new target");
    }

    #[test]
    #[cfg(unix)]
    fn emit_creates_bin_dir_if_missing() {
        let tmp = TempDir::new().unwrap();
        let bin = tmp.path().join("nested/bin");
        let target = tmp.path().join("eslint.js");
        std::fs::write(&target, "").unwrap();

        emit_shim(&bin, &shim("eslint", target.to_str().unwrap())).unwrap();
        assert!(bin.is_dir());
    }

    #[test]
    #[cfg(unix)]
    fn emit_leaves_no_tempfile_on_success() {
        let tmp = TempDir::new().unwrap();
        let bin = tmp.path().join("bin");
        let target = tmp.path().join("eslint.js");
        std::fs::write(&target, "").unwrap();

        emit_shim(&bin, &shim("eslint", target.to_str().unwrap())).unwrap();

        let leaks: Vec<_> = std::fs::read_dir(&bin)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                let n = e.file_name().to_string_lossy().into_owned();
                n.starts_with(".eslint.") && n.ends_with(".tmp")
            })
            .collect();
        assert!(leaks.is_empty(), "tempfile leaked: {leaks:?}");
    }

    #[test]
    #[cfg(unix)]
    fn remove_shim_cleans_up_symlink() {
        let tmp = TempDir::new().unwrap();
        let bin = tmp.path().join("bin");
        let target = tmp.path().join("eslint.js");
        std::fs::write(&target, "").unwrap();
        emit_shim(&bin, &shim("eslint", target.to_str().unwrap())).unwrap();

        let removed = remove_shim(&bin, "eslint").unwrap();
        assert_eq!(removed, vec![bin.join("eslint")]);
        assert!(!bin.join("eslint").exists());
    }

    #[test]
    #[cfg(unix)]
    fn remove_shim_is_idempotent() {
        let tmp = TempDir::new().unwrap();
        let bin = tmp.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        // No shim exists; removal is a no-op success.
        let removed = remove_shim(&bin, "missing").unwrap();
        assert!(removed.is_empty());
    }

    #[test]
    #[cfg(unix)]
    fn remove_shim_handles_dangling_symlink() {
        let tmp = TempDir::new().unwrap();
        let bin = tmp.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        std::os::unix::fs::symlink("/does/not/exist", bin.join("ghost")).unwrap();
        let removed = remove_shim(&bin, "ghost").unwrap();
        assert_eq!(removed, vec![bin.join("ghost")]);
    }

    // ─── Emission / removal — Windows ───────────────────────────────

    #[test]
    #[cfg(windows)]
    fn emit_creates_three_artifact_triple() {
        let tmp = TempDir::new().unwrap();
        let bin = tmp.path().join("bin");
        let target = tmp.path().join("eslint.js");
        std::fs::write(&target, "").unwrap();

        let emitted = emit_shim(&bin, &shim("eslint", target.to_str().unwrap())).unwrap();
        assert_eq!(emitted.artifacts.len(), 3);
        assert!(bin.join("eslint.cmd").exists());
        assert!(bin.join("eslint.ps1").exists());
        assert!(bin.join("eslint").exists());
    }

    #[test]
    #[cfg(windows)]
    fn emit_cmd_template_has_path_fallback() {
        let tmp = TempDir::new().unwrap();
        let bin = tmp.path().join("bin");
        let target = tmp.path().join("eslint.js");
        std::fs::write(&target, "").unwrap();
        emit_shim(&bin, &shim("eslint", target.to_str().unwrap())).unwrap();

        let cmd = std::fs::read_to_string(bin.join("eslint.cmd")).unwrap();
        assert!(cmd.contains("@IF EXIST"));
        assert!(cmd.contains("ELSE"));
        assert!(cmd.contains("node"));
    }

    #[test]
    #[cfg(windows)]
    fn emit_rejects_target_path_with_cmd_metachars() {
        let tmp = TempDir::new().unwrap();
        let bin = tmp.path().join("bin");
        let bad_target = "C:\\path&injection\\eslint.js";
        let err = emit_shim(&bin, &shim("eslint", bad_target)).unwrap_err();
        assert!(matches!(err, ShimError::InvalidWindowsTargetPath { .. }));
    }

    #[test]
    #[cfg(windows)]
    fn remove_shim_cleans_up_all_three_artifacts() {
        let tmp = TempDir::new().unwrap();
        let bin = tmp.path().join("bin");
        let target = tmp.path().join("eslint.js");
        std::fs::write(&target, "").unwrap();
        emit_shim(&bin, &shim("eslint", target.to_str().unwrap())).unwrap();

        let removed = remove_shim(&bin, "eslint").unwrap();
        assert_eq!(removed.len(), 3);
        assert!(!bin.join("eslint.cmd").exists());
        assert!(!bin.join("eslint.ps1").exists());
        assert!(!bin.join("eslint").exists());
    }

    // ─── Inventory / completeness ───────────────────────────────────

    #[test]
    fn expected_artifacts_returns_one_path_on_unix_three_on_windows() {
        let bin = Path::new("/tmp/bin");
        let paths = expected_artifacts(bin, "eslint");
        #[cfg(unix)]
        assert_eq!(paths.len(), 1);
        #[cfg(windows)]
        assert_eq!(paths.len(), 3);
    }

    #[test]
    #[cfg(unix)]
    fn artifacts_complete_true_after_emit_false_after_remove() {
        let tmp = TempDir::new().unwrap();
        let bin = tmp.path().join("bin");
        let target = tmp.path().join("eslint.js");
        std::fs::write(&target, "").unwrap();
        emit_shim(&bin, &shim("eslint", target.to_str().unwrap())).unwrap();
        assert!(artifacts_complete(&bin, "eslint"));
        remove_shim(&bin, "eslint").unwrap();
        assert!(!artifacts_complete(&bin, "eslint"));
    }

    #[test]
    #[cfg(windows)]
    fn artifacts_complete_false_when_partial_triple_present() {
        // The three-artifact invariant: a partial triple counts as
        // not-committed. Recovery uses this predicate to detect
        // crashes mid-emission.
        let tmp = TempDir::new().unwrap();
        let bin = tmp.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::write(bin.join("eslint.cmd"), "x").unwrap();
        std::fs::write(bin.join("eslint.ps1"), "y").unwrap();
        // bash shim deliberately missing
        assert!(!artifacts_complete(&bin, "eslint"));
    }

    #[test]
    fn invalid_command_name_returns_error_before_any_filesystem_call() {
        let tmp = TempDir::new().unwrap();
        let bin = tmp.path().join("bin");
        let err = emit_shim(&bin, &shim("../escape", "/tmp/x")).unwrap_err();
        assert!(matches!(err, ShimError::InvalidCommandName { .. }));
        // bin dir must NOT have been created.
        assert!(!bin.exists());
    }
}
