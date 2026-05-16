//! Linux secret-file overlay: bind-mounts `/dev/null` over
//! well-known secret file paths under `project_dir` so lifecycle
//! scripts get zero bytes when they try to read `.env`, `.npmrc`,
//! `.aws/credentials`, `*.pem`, etc.
//!
//! # Why bind-mount?
//!
//! landlock V4 is *additive* — a `Read` rule grants read on a
//! subpath and you can't subtract specific files from it. The
//! macOS Seatbelt profile uses last-match-wins `(deny ...)` rules
//! after the broad `(allow ...)` for the same effect; Linux has no
//! equivalent at the LSM layer. Bind-mounting `/dev/null` over a
//! target file is the canonical Unix trick: every `read(2)` returns
//! 0 bytes (`/dev/null`'s contract), every `stat(2)` reports a
//! character-device file. The script can `open` the path but reads
//! see no data.
//!
//! # Why the user namespace dance?
//!
//! `mount(2)` requires `CAP_SYS_ADMIN`. Unprivileged users can get
//! that capability inside a user namespace they own. The sequence
//! is:
//!
//! 1. `unshare(CLONE_NEWUSER | CLONE_NEWNS)` — enter a new user
//!    namespace AND a new mount namespace owned by it.
//! 2. Write `deny` to `/proc/self/setgroups` (required before any
//!    GID map for unprivileged user-ns).
//! 3. Write `0 <uid> 1\n` to `/proc/self/uid_map` and the same
//!    shape to `gid_map`. After this the child appears as root
//!    inside the new namespace with `CAP_SYS_ADMIN` over its own
//!    mount table.
//! 4. `mount("/dev/null", <target>, "none", MS_BIND, NULL)` per
//!    enumerated path.
//!
//! All mounts apply only to the new namespace — the host's mount
//! table is unchanged. When the lifecycle script exits, the
//! namespace is destroyed and the mounts vanish.
//!
//! # Failure mode
//!
//! Hardened distros (Debian/Ubuntu's `kernel.unprivileged_userns_clone=0`,
//! some AppArmor profiles, SELinux confinement, containers without
//! `--privileged`) block step 1. When `unshare` returns `EPERM` or
//! `EACCES`, this layer silently no-ops: the script gets the same
//! access it would have had without the overlay, which is the
//! Linux baseline before this commit. Failure is transparent
//! rather than fatal because the broader sandbox (landlock + env
//! scrub + script policy) still applies.
//!
//! # Limitations
//!
//! - Files created AFTER enumeration are not covered. A script
//!   chain that creates `.env.runtime` mid-install can read it
//!   from a sibling script.
//! - Symlinks are NOT followed at enumeration time — a symlink
//!   `proj/.ssh/id_rsa -> ~/.ssh/id_rsa` is skipped (the resolved
//!   target is outside `project_dir`; bind-mounting it would alter
//!   the script's view of the host's real file).
//! - The mount is per-file, not per-dir. Dir bind-mounts require a
//!   directory source; we use file-on-file because `/dev/null` is
//!   a character device. Subpath dirs (`.ssh/`, `.aws/`, …) are
//!   handled by walking inside and overlaying each regular file.
//!
//! # Async-signal safety
//!
//! The child-side entry point [`apply_secret_overlay_in_child`] is
//! AS-safe by construction: no heap allocation, no lock acquisition,
//! direct `libc::*` syscalls only. All allocating work
//! (`enumerate_project_secrets`, `SecretOverlaySpec::build`,
//! `CString` allocation, `uid_map` formatting) happens in the
//! parent before fork.

use crate::secret_paths::{SECRET_FILE_EXTENSIONS, SECRET_LITERAL_PATHS, SECRET_SUBPATH_DIRS};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// Directory names to prune during the project walk. These hold
/// large amounts of upstream code (`node_modules`, `target`, `.git`)
/// or generated artifacts (`dist`, `build`, `.next`, `coverage`) —
/// none of which we expect to host project secrets, and walking
/// them would slow install start meaningfully. Pruning is by
/// basename, not full path, so a deeply nested `node_modules/`
/// inside a workspace member is also skipped.
const WALK_PRUNED_DIRS: &[&str] = &[
    "node_modules",
    ".git",
    "target",
    "dist",
    "build",
    ".next",
    "coverage",
    ".pnpm",
    ".pnpm-store",
    ".yarn",
];

/// Maximum walk depth (root counts as depth 0). 4 covers
/// `project/subdir1/subdir2/subdir3/subdir4` which is enough for
/// the common cases (`infra/prod/secrets/x.tfstate`, `services/api/.env`).
/// Deeper-nested secrets escape this layer; document the limitation
/// in the module preamble.
const WALK_MAX_DEPTH: usize = 4;

/// Parent-side helper: enumerate the set of files under
/// `project_dir` whose `file-read*` should be denied. Returns
/// canonical absolute paths suitable for `mount(2)` calls.
///
/// `allow_list` carries the user's per-project / per-user
/// `script-read-allow` entries (resolved to absolute project-rooted
/// paths). Matching entries are excluded from the result.
///
/// Existence is checked: only paths that resolve to a regular file
/// at enumeration time are returned. Symlinks are skipped — a
/// project-rooted symlink can point anywhere and we don't want to
/// bind-mount over a host-system path via symlink resolution.
///
/// Performance: pruned + depth-capped walk. O(visible-files) under
/// the project tree minus `node_modules/.git/target/...`.
pub(crate) fn enumerate_project_secrets(
    project_dir: &Path,
    allow_list: &[PathBuf],
) -> Vec<PathBuf> {
    let allow_set: HashSet<&Path> = allow_list.iter().map(|p| p.as_path()).collect();
    let mut out: Vec<PathBuf> = Vec::new();

    // Literal paths — direct symlink_metadata + regular-file check.
    for rel in SECRET_LITERAL_PATHS {
        let abs = project_dir.join(rel);
        if allow_set.contains(abs.as_path()) {
            continue;
        }
        if let Ok(meta) = std::fs::symlink_metadata(&abs)
            && meta.file_type().is_file()
        {
            out.push(abs);
        }
    }

    // Subpath dirs — walk inside and overlay every regular file.
    for rel in SECRET_SUBPATH_DIRS {
        let abs = project_dir.join(rel);
        if let Ok(meta) = std::fs::symlink_metadata(&abs)
            && meta.file_type().is_dir()
        {
            collect_files_recursive(&abs, &mut out, &allow_set, WALK_MAX_DEPTH);
        }
    }

    // File-extension matches — bounded walk from project root.
    walk_for_extensions(project_dir, &mut out, &allow_set);

    // Sort for deterministic output (tests + reproducible mount
    // ordering).
    out.sort();
    out.dedup();
    out
}

/// Recursive walk that adds every regular file under `dir` to
/// `out`, honoring the allow set. Used for `SECRET_SUBPATH_DIRS`
/// entries (`.ssh`, `.aws`, etc.) where the contract is "deny
/// reads on every file in the subtree".
fn collect_files_recursive(
    dir: &Path,
    out: &mut Vec<PathBuf>,
    allow_set: &HashSet<&Path>,
    remaining_depth: usize,
) {
    if remaining_depth == 0 {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let Ok(ft) = entry.file_type() else {
            continue;
        };
        let path = entry.path();
        if ft.is_dir() {
            collect_files_recursive(&path, out, allow_set, remaining_depth - 1);
        } else if ft.is_file() && !allow_set.contains(path.as_path()) {
            out.push(path);
        }
        // Symlinks intentionally skipped.
    }
}

/// Bounded walk from `root` that pushes any regular file whose
/// basename ends with one of `SECRET_FILE_EXTENSIONS`. Prunes
/// `WALK_PRUNED_DIRS` and caps depth at `WALK_MAX_DEPTH`.
fn walk_for_extensions(root: &Path, out: &mut Vec<PathBuf>, allow_set: &HashSet<&Path>) {
    let mut stack: Vec<(PathBuf, usize)> = vec![(root.to_path_buf(), 0)];
    while let Some((dir, depth)) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(ft) = entry.file_type() else {
                continue;
            };
            let path = entry.path();
            if ft.is_dir() {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                if WALK_PRUNED_DIRS.iter().any(|p| *p == name_str.as_ref()) {
                    continue;
                }
                if depth + 1 < WALK_MAX_DEPTH {
                    stack.push((path, depth + 1));
                }
            } else if ft.is_file() {
                if allow_set.contains(path.as_path()) {
                    continue;
                }
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                if SECRET_FILE_EXTENSIONS
                    .iter()
                    .any(|ext| name_str.ends_with(ext))
                {
                    out.push(path);
                }
            }
        }
    }
}

/// Parent-side spec describing the bind-mount overlay to apply in
/// the child. All allocating work (CString construction, uid_map
/// formatting) happens here so the child's pre_exec body stays
/// AS-safe. Returns `None` when the enumerator finds no secrets
/// (project has no .env / .pem / etc.) — caller skips the whole
/// unshare dance in that case.
///
/// Linux-only: the only consumer is `linux::LandlockSandbox::spawn`
/// which is itself `#[cfg(target_os = "linux")]`. Gating the struct
/// matches CLAUDE.md's cross-platform hygiene rule (no dead-code
/// surfaces on macOS / Windows CI).
#[cfg(target_os = "linux")]
pub(crate) struct SecretOverlaySpec {
    /// CString-wrapped absolute paths the child will `mount(2)`
    /// `/dev/null` over. Allocated parent-side; the child only
    /// reads the `.as_ptr()` and never frees (see ManuallyDrop
    /// wrapping in the install site).
    pub paths: Vec<std::ffi::CString>,
    /// Pre-formatted `"0 <uid> 1\n"` bytes for `/proc/self/uid_map`.
    pub uid_map_bytes: Vec<u8>,
    /// Pre-formatted `"0 <gid> 1\n"` bytes for `/proc/self/gid_map`.
    pub gid_map_bytes: Vec<u8>,
}

#[cfg(target_os = "linux")]
impl SecretOverlaySpec {
    /// Build the overlay spec for `project_dir`. Returns `None`
    /// when there are no secret files to mount over — caller
    /// skips the `unshare` dance entirely in that case.
    pub(crate) fn build(project_dir: &Path, allow_list: &[PathBuf]) -> Option<Self> {
        let paths_pb = enumerate_project_secrets(project_dir, allow_list);
        if paths_pb.is_empty() {
            return None;
        }
        let mut paths = Vec::with_capacity(paths_pb.len());
        for p in paths_pb {
            // Skip non-UTF-8 paths and paths containing interior NUL
            // bytes (the latter is impossible on Linux but defended
            // against). Both are extreme edge cases — losing them
            // means those specific files stay readable; not a
            // regression versus the no-overlay baseline.
            let Some(s) = p.to_str() else {
                continue;
            };
            let Ok(cs) = std::ffi::CString::new(s) else {
                continue;
            };
            paths.push(cs);
        }
        if paths.is_empty() {
            return None;
        }
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };
        // ITOA-style formatting — no allocation beyond the Vec
        // capacity needed for the final byte string. `format!` in
        // the child would NOT be AS-safe; doing the format here
        // (parent-side) is cheap.
        let uid_map_bytes = format!("0 {uid} 1\n").into_bytes();
        let gid_map_bytes = format!("0 {gid} 1\n").into_bytes();
        Some(Self {
            paths,
            uid_map_bytes,
            gid_map_bytes,
        })
    }
}

/// AS-safe child-side hook: install the secret-file overlay.
/// Called from the landlock backend's `pre_exec` closure BEFORE
/// seccomp + landlock are installed (neither restricts `mount(2)`,
/// but doing overlay first keeps ordering simple).
///
/// Best-effort: any failure (`unshare` blocked by sysctl, write to
/// uid_map fails, mount EACCES because the target is on a
/// no-exec filesystem) silently no-ops. The broader sandbox
/// still applies — degradation is "same as no overlay", not
/// "weaker than baseline".
///
/// # Safety
///
/// Caller must guarantee:
/// - This runs in a forked child between `fork` and `execve`.
/// - `spec` is the only owner of its `paths` / `uid_map_bytes` /
///   `gid_map_bytes`. The wrapping `ManuallyDrop` at the call
///   site suppresses Drop in the child so the Vec/CString
///   allocations are NOT freed here (free() is not AS-safe).
#[cfg(target_os = "linux")]
pub(crate) unsafe fn apply_secret_overlay_in_child(spec: &SecretOverlaySpec) {
    // Step 1: enter a new user + mount namespace. Failure here is
    // common on hardened distros (Debian's
    // `kernel.unprivileged_userns_clone=0`, AppArmor confinement,
    // containers without --privileged). The lifecycle script will
    // still see the macOS-equivalent of the deny — sorry, scratch
    // that, this is Linux: it'll see the same access it had
    // before this layer existed.
    if unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS) } != 0 {
        return;
    }

    // Step 2: write `deny` to /proc/self/setgroups. Required by
    // the kernel before writing gid_map for unprivileged user-ns
    // (otherwise setgroups(2) inside the namespace would be a
    // privilege escalation primitive). The `deny` is permanent
    // for the namespace.
    const SETGROUPS_DENY: &[u8] = b"deny";
    const SETGROUPS_PATH: &[u8] = b"/proc/self/setgroups\0";
    if !unsafe {
        write_proc_file_assafe(
            SETGROUPS_PATH.as_ptr() as *const libc::c_char,
            SETGROUPS_DENY,
        )
    } {
        return;
    }

    // Step 3: map our real uid to 0 inside the namespace so we
    // get CAP_SYS_ADMIN there. gid_map mirrors. The pre-formatted
    // bytes were built parent-side.
    const UID_MAP_PATH: &[u8] = b"/proc/self/uid_map\0";
    const GID_MAP_PATH: &[u8] = b"/proc/self/gid_map\0";
    if !unsafe {
        write_proc_file_assafe(
            UID_MAP_PATH.as_ptr() as *const libc::c_char,
            &spec.uid_map_bytes,
        )
    } {
        return;
    }
    if !unsafe {
        write_proc_file_assafe(
            GID_MAP_PATH.as_ptr() as *const libc::c_char,
            &spec.gid_map_bytes,
        )
    } {
        return;
    }

    // Step 4: bind-mount /dev/null over each target. Per-path
    // failures are tolerated (file gone since enumeration, race
    // with another tool, target on a no-bind filesystem).
    const DEV_NULL_SRC: &[u8] = b"/dev/null\0";
    const FS_NONE: &[u8] = b"none\0";
    for cs in &spec.paths {
        unsafe {
            libc::mount(
                DEV_NULL_SRC.as_ptr() as *const libc::c_char,
                cs.as_ptr(),
                FS_NONE.as_ptr() as *const libc::c_char,
                libc::MS_BIND,
                std::ptr::null(),
            );
        }
    }
}

/// AS-safe `write_all`-style helper for `/proc/self/*` files.
/// Returns `true` on full write, `false` on any error.
///
/// # Safety
///
/// `path` must point to a NUL-terminated absolute path. `bytes`
/// must outlive the call. No allocations performed.
#[cfg(target_os = "linux")]
unsafe fn write_proc_file_assafe(path: *const libc::c_char, bytes: &[u8]) -> bool {
    let fd = unsafe { libc::open(path, libc::O_WRONLY) };
    if fd < 0 {
        return false;
    }
    let mut written: usize = 0;
    while written < bytes.len() {
        let remaining = bytes.len() - written;
        let n = unsafe {
            libc::write(
                fd,
                bytes[written..].as_ptr() as *const libc::c_void,
                remaining,
            )
        };
        if n <= 0 {
            unsafe { libc::close(fd) };
            return false;
        }
        written += n as usize;
    }
    unsafe { libc::close(fd) };
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// Build a fixture project tree under a fresh tempdir. The
    /// closure receives the project root and seeds whatever files
    /// the test needs.
    fn with_project<F: FnOnce(&Path)>(seed: F) -> tempfile::TempDir {
        let tmp = tempfile::tempdir().expect("tempdir");
        seed(tmp.path());
        tmp
    }

    /// `.env` at project root is enumerated.
    #[test]
    fn enumerates_dotenv_at_project_root() {
        let tmp = with_project(|root| {
            fs::write(root.join(".env"), "API_KEY=secret").unwrap();
        });
        let v = enumerate_project_secrets(tmp.path(), &[]);
        assert!(
            v.contains(&tmp.path().join(".env")),
            "expected .env in {v:?}"
        );
    }

    /// `.env.local` and friends are enumerated; arbitrary
    /// `.env.<custom>` is NOT (the const list is explicit).
    #[test]
    fn enumerates_known_env_variants_only() {
        let tmp = with_project(|root| {
            fs::write(root.join(".env"), "").unwrap();
            fs::write(root.join(".env.local"), "").unwrap();
            fs::write(root.join(".env.production"), "").unwrap();
            fs::write(root.join(".env.custom-suffix"), "").unwrap();
        });
        let v = enumerate_project_secrets(tmp.path(), &[]);
        assert!(v.contains(&tmp.path().join(".env")));
        assert!(v.contains(&tmp.path().join(".env.local")));
        assert!(v.contains(&tmp.path().join(".env.production")));
        // `.env.custom-suffix` not in const list — left alone.
        assert!(!v.contains(&tmp.path().join(".env.custom-suffix")));
    }

    /// Files inside `.ssh/` are enumerated by the subpath walk.
    #[test]
    fn enumerates_files_inside_subpath_secret_dirs() {
        let tmp = with_project(|root| {
            fs::create_dir(root.join(".ssh")).unwrap();
            fs::write(root.join(".ssh/id_rsa"), "").unwrap();
            fs::write(root.join(".ssh/config"), "").unwrap();
            fs::create_dir(root.join(".aws")).unwrap();
            fs::write(root.join(".aws/credentials"), "").unwrap();
        });
        let v = enumerate_project_secrets(tmp.path(), &[]);
        assert!(v.contains(&tmp.path().join(".ssh/id_rsa")));
        assert!(v.contains(&tmp.path().join(".ssh/config")));
        assert!(v.contains(&tmp.path().join(".aws/credentials")));
    }

    /// `*.pem` files at any depth (up to WALK_MAX_DEPTH) are
    /// enumerated via the extension walker.
    #[test]
    fn enumerates_pem_files_at_any_depth() {
        let tmp = with_project(|root| {
            fs::write(root.join("server.pem"), "").unwrap();
            fs::create_dir(root.join("infra")).unwrap();
            fs::write(root.join("infra/prod.pem"), "").unwrap();
            fs::create_dir_all(root.join("certs/ca/sub")).unwrap();
            fs::write(root.join("certs/ca/sub/leaf.pem"), "").unwrap();
        });
        let v = enumerate_project_secrets(tmp.path(), &[]);
        assert!(v.contains(&tmp.path().join("server.pem")));
        assert!(v.contains(&tmp.path().join("infra/prod.pem")));
        assert!(v.contains(&tmp.path().join("certs/ca/sub/leaf.pem")));
    }

    /// Terraform state and tfvars get caught by the suffix walker.
    #[test]
    fn enumerates_terraform_state_and_vars() {
        let tmp = with_project(|root| {
            fs::write(root.join("prod.tfstate"), "").unwrap();
            fs::write(root.join("secrets.tfvars"), "").unwrap();
            fs::write(root.join("secrets.tfvars.json"), "").unwrap();
        });
        let v = enumerate_project_secrets(tmp.path(), &[]);
        assert!(v.contains(&tmp.path().join("prod.tfstate")));
        assert!(v.contains(&tmp.path().join("secrets.tfvars")));
        assert!(v.contains(&tmp.path().join("secrets.tfvars.json")));
    }

    /// `node_modules/`, `.git/`, `target/` are pruned — even a
    /// `node_modules/foo/secret.pem` is NOT enumerated. The walker
    /// would slow install start meaningfully otherwise (npm projects
    /// can have tens of thousands of files under node_modules).
    #[test]
    fn pruned_dirs_are_skipped_during_walk() {
        let tmp = with_project(|root| {
            fs::create_dir_all(root.join("node_modules/foo")).unwrap();
            fs::write(root.join("node_modules/foo/bundled.pem"), "").unwrap();
            fs::create_dir_all(root.join(".git/objects")).unwrap();
            fs::write(root.join(".git/objects/pack.pem"), "").unwrap();
            fs::create_dir_all(root.join("target/release")).unwrap();
            fs::write(root.join("target/release/build.pem"), "").unwrap();
        });
        let v = enumerate_project_secrets(tmp.path(), &[]);
        for p in &v {
            let s = p.to_string_lossy();
            assert!(
                !s.contains("/node_modules/"),
                "node_modules must be pruned: {s}"
            );
            assert!(
                !s.contains("/.git/"),
                ".git must be pruned (except .git/config, .git/credentials handled by the LITERAL list): {s}"
            );
            assert!(!s.contains("/target/"), "target must be pruned: {s}");
        }
    }

    /// `.git/config` and `.git/credentials` are caught by the
    /// LITERAL list even though `.git/` is pruned from the
    /// suffix walk. They get there via the explicit literal
    /// enumeration loop, not the walker.
    #[test]
    fn git_config_and_credentials_still_caught_despite_git_prune() {
        let tmp = with_project(|root| {
            fs::create_dir(root.join(".git")).unwrap();
            fs::write(root.join(".git/config"), "[user]\n").unwrap();
            fs::write(root.join(".git/credentials"), "https://...").unwrap();
        });
        let v = enumerate_project_secrets(tmp.path(), &[]);
        assert!(v.contains(&tmp.path().join(".git/config")));
        assert!(v.contains(&tmp.path().join(".git/credentials")));
    }

    /// Symlinks pointing outside the project are skipped — we don't
    /// bind-mount over a path that resolves to a host-system file.
    #[test]
    #[cfg(unix)]
    fn symlinks_at_project_root_are_skipped() {
        let tmp = with_project(|root| {
            // Create a target outside the project.
            let outside = tempfile::tempdir().unwrap();
            fs::write(outside.path().join("real.env"), "secret").unwrap();
            // Symlink `.env` -> outside file.
            std::os::unix::fs::symlink(outside.path().join("real.env"), root.join(".env")).unwrap();
            // Leak the outside tempdir so the symlink stays valid
            // for the test (the assertion runs before this fn
            // returns, but the symlink target's existence is
            // independent).
            std::mem::forget(outside);
        });
        let v = enumerate_project_secrets(tmp.path(), &[]);
        // `.env` was a symlink, not a regular file — skipped.
        assert!(
            !v.contains(&tmp.path().join(".env")),
            "symlink at project root must not be enumerated: {v:?}"
        );
    }

    /// Allow-list excludes named paths from the enumeration.
    /// Sets up `.env` + `cert.pem` and exempts `.env` only;
    /// expects `cert.pem` enumerated, `.env` skipped.
    #[test]
    fn allow_list_excludes_named_paths() {
        let tmp = with_project(|root| {
            fs::write(root.join(".env"), "").unwrap();
            fs::write(root.join("cert.pem"), "").unwrap();
        });
        let allow = vec![tmp.path().join(".env")];
        let v = enumerate_project_secrets(tmp.path(), &allow);
        assert!(
            !v.contains(&tmp.path().join(".env")),
            "allow-listed .env must be excluded"
        );
        assert!(
            v.contains(&tmp.path().join("cert.pem")),
            "non-allowlisted cert.pem still enumerated"
        );
    }

    /// Allow-list with a path NOT present in the project doesn't
    /// affect anything (no error, no spurious add).
    #[test]
    fn allow_list_irrelevant_entries_are_ignored() {
        let tmp = with_project(|root| {
            fs::write(root.join(".env"), "").unwrap();
        });
        let allow = vec![tmp.path().join("does/not/exist")];
        let v = enumerate_project_secrets(tmp.path(), &allow);
        assert!(v.contains(&tmp.path().join(".env")));
        assert_eq!(v.len(), 1);
    }

    /// Empty project — empty result.
    #[test]
    fn empty_project_yields_empty_enumeration() {
        let tmp = with_project(|_| {});
        let v = enumerate_project_secrets(tmp.path(), &[]);
        assert!(v.is_empty());
    }

    /// Project without secrets — empty result. Validates that
    /// regular code files don't get caught by the walker.
    #[test]
    fn project_with_only_source_files_yields_empty_enumeration() {
        let tmp = with_project(|root| {
            fs::create_dir(root.join("src")).unwrap();
            fs::write(root.join("src/index.ts"), "export const x = 1").unwrap();
            fs::write(root.join("src/lib.ts"), "").unwrap();
            fs::write(root.join("package.json"), "{}").unwrap();
            fs::write(root.join("tsconfig.json"), "{}").unwrap();
        });
        let v = enumerate_project_secrets(tmp.path(), &[]);
        assert!(v.is_empty(), "no secret-like files: {v:?}");
    }

    /// Walk depth cap — files deeper than WALK_MAX_DEPTH are not
    /// reached by the extension walker. Pin the contract.
    #[test]
    fn walk_max_depth_is_respected() {
        let tmp = with_project(|root| {
            // root, /a, /a/b, /a/b/c, /a/b/c/d — depth 4 reachable.
            let mut p = root.to_path_buf();
            for d in ["a", "b", "c", "d"] {
                p = p.join(d);
                fs::create_dir(&p).unwrap();
                fs::write(p.join("at-depth.pem"), "").unwrap();
            }
            // /a/b/c/d/e — depth 5, not reachable.
            let too_deep = p.join("e");
            fs::create_dir(&too_deep).unwrap();
            fs::write(too_deep.join("at-depth.pem"), "").unwrap();
        });
        let v = enumerate_project_secrets(tmp.path(), &[]);
        // The walker enters directories at depths 1-3 (capped by
        // `WALK_MAX_DEPTH = 4` via the `depth + 1 < WALK_MAX_DEPTH`
        // push gate) and enumerates files inside them — so files
        // up to path-component-depth 4 are reachable.
        assert!(v.contains(&tmp.path().join("a/at-depth.pem")));
        assert!(v.contains(&tmp.path().join("a/b/at-depth.pem")));
        assert!(v.contains(&tmp.path().join("a/b/c/at-depth.pem")));
        // Asserting BOTH boundary-misses below pins the cap from
        // both sides — a future `<=` off-by-one in the push gate
        // would let `d/at-depth.pem` slip through; a future
        // depth-bump (e.g. `WALK_MAX_DEPTH = 5`) would let
        // `d/e/at-depth.pem` slip through. Either regression
        // fails one of these assertions.
        assert!(!v.contains(&tmp.path().join("a/b/c/d/at-depth.pem")));
        assert!(!v.contains(&tmp.path().join("a/b/c/d/e/at-depth.pem")));
    }

    /// Determinism — repeated calls return the same sorted list.
    /// The bind-mount loop runs in this order, so deterministic
    /// output matters for reproducible diagnostics.
    #[test]
    fn output_is_sorted_and_deterministic() {
        let tmp = with_project(|root| {
            fs::write(root.join(".env"), "").unwrap();
            fs::write(root.join(".npmrc"), "").unwrap();
            fs::write(root.join("server.pem"), "").unwrap();
        });
        let a = enumerate_project_secrets(tmp.path(), &[]);
        let b = enumerate_project_secrets(tmp.path(), &[]);
        assert_eq!(a, b);
        let mut sorted = a.clone();
        sorted.sort();
        assert_eq!(a, sorted, "output must be pre-sorted");
    }

    /// SecretOverlaySpec::build returns None when no secrets exist.
    /// Linux-only because the constructor is gated.
    #[test]
    #[cfg(target_os = "linux")]
    fn overlay_spec_build_returns_none_for_clean_project() {
        let tmp = with_project(|root| {
            fs::write(root.join("package.json"), "{}").unwrap();
        });
        assert!(SecretOverlaySpec::build(tmp.path(), &[]).is_none());
    }

    /// SecretOverlaySpec::build returns Some with CStrings + maps
    /// when secrets exist. Pins the uid_map shape.
    #[test]
    #[cfg(target_os = "linux")]
    fn overlay_spec_build_populates_paths_and_uid_map() {
        let tmp = with_project(|root| {
            fs::write(root.join(".env"), "").unwrap();
        });
        let spec = SecretOverlaySpec::build(tmp.path(), &[]).expect("must have spec");
        assert!(!spec.paths.is_empty());
        let uid_map_str = std::str::from_utf8(&spec.uid_map_bytes).unwrap();
        assert!(
            uid_map_str.starts_with("0 ") && uid_map_str.ends_with(" 1\n"),
            "uid_map shape: {uid_map_str:?}"
        );
        let gid_map_str = std::str::from_utf8(&spec.gid_map_bytes).unwrap();
        assert!(gid_map_str.starts_with("0 ") && gid_map_str.ends_with(" 1\n"));
    }
}
