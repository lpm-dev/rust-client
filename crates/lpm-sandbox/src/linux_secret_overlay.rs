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
//! When at least one protected path needs masking, this layer is a
//! security boundary. Namespace creation, ID mapping, private mount
//! propagation, and every bind mount must succeed. Any failure aborts
//! `pre_exec`, so the lifecycle command never runs with the project's
//! broad Landlock read grant and an incomplete overlay. Projects with
//! no protected files, or only explicitly allowlisted files, skip the
//! namespace setup entirely.
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
//! - Extension discovery is depth-capped and prunes dependency and
//!   generated-output directories. Literal paths are checked separately.
//!
//! # Async-signal safety
//!
//! The child-side entry point [`apply_secret_overlay_in_child`] is
//! AS-safe by construction: no heap allocation, no lock acquisition,
//! direct `libc::*` syscalls only. Failures are represented by a
//! small `Copy` stage enum and mapped to static diagnostics. All
//! allocating work (`enumerate_project_secrets`,
//! `SecretOverlaySpec::build`, `CString` allocation, `uid_map`
//! formatting) happens in the parent before fork.

use crate::secret_paths::{SECRET_FILE_EXTENSIONS, SECRET_LITERAL_PATHS, SECRET_SUBPATH_DIRS};
use std::collections::HashSet;
use std::ffi::OsStr;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub(crate) enum SecretOverlayBuildError {
    #[error("failed to {operation} protected-secret path {path:?}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[cfg(target_os = "linux")]
    #[error("protected-secret path contains an interior NUL byte: {path:?}")]
    InteriorNul { path: PathBuf },
}

fn path_io_error(
    operation: &'static str,
    path: &Path,
    source: io::Error,
) -> SecretOverlayBuildError {
    SecretOverlayBuildError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

// Linked Git worktrees store `.git` as a file, so fixed `.git/*` probes
// report ENOTDIR even though the requested descendant is simply absent.
fn fixed_descendant_is_absent(source: &io::Error) -> bool {
    matches!(
        source.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
    )
}

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

/// Exclusive directory-depth bound (root counts as depth 0). A value
/// of 4 walks directories at depths 1–3 and does not enter depth 4.
/// This covers common paths such as `infra/prod/secrets.tfvars` while
/// bounding install-start traversal cost.
const WALK_MAX_DEPTH: usize = 4;

/// Parent-side helper: enumerate the set of files under
/// `project_dir` whose `file-read*` should be denied. Returns
/// project-rooted paths suitable for `mount(2)` calls. Callers provide
/// an absolute `project_dir`, so returned paths are absolute as well.
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
) -> Result<Vec<PathBuf>, SecretOverlayBuildError> {
    let mut allow_set: HashSet<&Path> = HashSet::with_capacity(allow_list.len());
    allow_set.extend(allow_list.iter().map(PathBuf::as_path));
    let mut out: Vec<PathBuf> = Vec::new();

    for rel in SECRET_LITERAL_PATHS {
        let abs = project_dir.join(rel);
        if allow_set.contains(abs.as_path()) {
            continue;
        }
        match std::fs::symlink_metadata(&abs) {
            Ok(meta) if meta.file_type().is_file() => out.push(abs),
            Ok(_) => {}
            Err(source) if fixed_descendant_is_absent(&source) => {}
            Err(source) => return Err(path_io_error("inspect", &abs, source)),
        }
    }

    for rel in SECRET_SUBPATH_DIRS {
        let abs = project_dir.join(rel);
        match std::fs::symlink_metadata(&abs) {
            Ok(meta) if meta.file_type().is_dir() => {
                collect_files_recursive(&abs, &mut out, &allow_set, WALK_MAX_DEPTH)?;
            }
            Ok(_) => {}
            Err(source) if fixed_descendant_is_absent(&source) => {}
            Err(source) => return Err(path_io_error("inspect", &abs, source)),
        }
    }

    walk_for_extensions(project_dir, &mut out, &allow_set)?;

    out.sort();
    out.dedup();
    Ok(out)
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
) -> Result<(), SecretOverlayBuildError> {
    if remaining_depth == 0 {
        return Ok(());
    }
    let entries = std::fs::read_dir(dir).map_err(|source| path_io_error("read", dir, source))?;
    for entry_result in entries {
        let entry = entry_result.map_err(|source| path_io_error("read entry in", dir, source))?;
        let path = entry.path();
        let ft = entry
            .file_type()
            .map_err(|source| path_io_error("inspect", &path, source))?;
        if ft.is_dir() {
            collect_files_recursive(&path, out, allow_set, remaining_depth - 1)?;
        } else if ft.is_file() && !allow_set.contains(path.as_path()) {
            out.push(path);
        }
    }
    Ok(())
}

/// Bounded walk from `root` that pushes any regular file whose
/// basename ends with one of `SECRET_FILE_EXTENSIONS`. Prunes
/// `WALK_PRUNED_DIRS` and caps depth at `WALK_MAX_DEPTH`.
fn walk_for_extensions(
    root: &Path,
    out: &mut Vec<PathBuf>,
    allow_set: &HashSet<&Path>,
) -> Result<(), SecretOverlayBuildError> {
    let mut stack: Vec<(PathBuf, usize)> = Vec::with_capacity(32);
    stack.push((root.to_path_buf(), 0));
    while let Some((dir, depth)) = stack.pop() {
        let entries =
            std::fs::read_dir(&dir).map_err(|source| path_io_error("read", &dir, source))?;
        for entry_result in entries {
            let entry =
                entry_result.map_err(|source| path_io_error("read entry in", &dir, source))?;
            let path = entry.path();
            let ft = entry
                .file_type()
                .map_err(|source| path_io_error("inspect", &path, source))?;
            if ft.is_dir() {
                let name = entry.file_name();
                if WALK_PRUNED_DIRS
                    .iter()
                    .any(|pruned| name.as_os_str() == OsStr::new(pruned))
                {
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
                if SECRET_FILE_EXTENSIONS
                    .iter()
                    .any(|ext| path_ends_with(&name, ext))
                {
                    out.push(path);
                }
            }
        }
    }
    Ok(())
}

fn path_ends_with(name: &OsStr, suffix: &str) -> bool {
    name.as_encoded_bytes().ends_with(suffix.as_bytes())
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
/// keeps non-Linux production builds from compiling dead platform
/// surfaces.
#[cfg(target_os = "linux")]
pub(crate) struct SecretOverlaySpec {
    /// CString-wrapped absolute paths the child will `mount(2)`
    /// `/dev/null` over. Allocated parent-side; the child only
    /// reads the `.as_ptr()` and never frees (see ManuallyDrop
    /// wrapping in the install site).
    pub(crate) paths: Vec<std::ffi::CString>,
    /// Pre-formatted `"0 <uid> 1\n"` bytes for `/proc/self/uid_map`.
    pub(crate) uid_map_bytes: Vec<u8>,
    /// Pre-formatted `"0 <gid> 1\n"` bytes for `/proc/self/gid_map`.
    pub(crate) gid_map_bytes: Vec<u8>,
}

#[cfg(target_os = "linux")]
impl SecretOverlaySpec {
    /// Builds the overlay spec for `project_dir`.
    ///
    /// Returns `Ok(None)` when no protected file needs masking. Any
    /// preparation uncertainty is returned as an error before spawn.
    pub(crate) fn build(
        project_dir: &Path,
        allow_list: &[PathBuf],
    ) -> Result<Option<Self>, SecretOverlayBuildError> {
        use std::os::unix::ffi::OsStrExt;

        let paths_pb = enumerate_project_secrets(project_dir, allow_list)?;
        if paths_pb.is_empty() {
            return Ok(None);
        }
        let mut paths = Vec::with_capacity(paths_pb.len());
        for p in paths_pb {
            let cs = std::ffi::CString::new(p.as_os_str().as_bytes())
                .map_err(|_| SecretOverlayBuildError::InteriorNul { path: p })?;
            paths.push(cs);
        }
        // SAFETY: getuid and getgid have no pointer preconditions and
        // only return the calling process's real IDs.
        let uid = unsafe { libc::getuid() };
        // SAFETY: see the getuid call above.
        let gid = unsafe { libc::getgid() };
        let uid_map_bytes = format!("0 {uid} 1\n").into_bytes();
        let gid_map_bytes = format!("0 {gid} 1\n").into_bytes();
        Ok(Some(Self {
            paths,
            uid_map_bytes,
            gid_map_bytes,
        }))
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SecretOverlayStage {
    Unshare,
    Setgroups,
    UidMap,
    GidMap,
    MountPropagation,
    BindMount,
}

#[cfg(target_os = "linux")]
impl SecretOverlayStage {
    pub(crate) const fn diagnostic(self) -> &'static [u8] {
        match self {
            Self::Unshare => b"lpm-sandbox: secret overlay namespace creation failed\n",
            Self::Setgroups => b"lpm-sandbox: secret overlay setgroups denial failed\n",
            Self::UidMap => b"lpm-sandbox: secret overlay uid mapping failed\n",
            Self::GidMap => b"lpm-sandbox: secret overlay gid mapping failed\n",
            Self::MountPropagation => {
                b"lpm-sandbox: secret overlay mount propagation setup failed\n"
            }
            Self::BindMount => b"lpm-sandbox: secret overlay bind mount failed\n",
        }
    }

    pub(crate) const fn errno(self) -> libc::c_int {
        libc::EPERM
    }
}

#[cfg(target_os = "linux")]
trait SecretOverlayOperations {
    fn unshare_user_and_mount_namespaces(&mut self) -> bool;
    fn deny_setgroups(&mut self) -> bool;
    fn write_uid_map(&mut self, bytes: &[u8]) -> bool;
    fn write_gid_map(&mut self, bytes: &[u8]) -> bool;
    fn make_mounts_private(&mut self) -> bool;
    fn bind_dev_null(&mut self, target: &std::ffi::CStr) -> bool;
    fn remount_proc_restricted(&mut self);
}

#[cfg(target_os = "linux")]
struct LibcSecretOverlayOperations;

#[cfg(target_os = "linux")]
impl SecretOverlayOperations for LibcSecretOverlayOperations {
    fn unshare_user_and_mount_namespaces(&mut self) -> bool {
        // SAFETY: unshare takes only an integer flag mask. This call creates
        // process-local namespaces and does not dereference userspace memory.
        unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS) == 0 }
    }

    fn deny_setgroups(&mut self) -> bool {
        // SAFETY: the path is static and NUL-terminated; the byte slice is
        // valid for the duration of the direct open/write/close sequence.
        unsafe { write_proc_file_assafe(c"/proc/self/setgroups".as_ptr(), b"deny") }
    }

    fn write_uid_map(&mut self, bytes: &[u8]) -> bool {
        // SAFETY: the path is static and NUL-terminated; `bytes` is borrowed
        // from the parent-built spec and remains valid throughout pre_exec.
        unsafe { write_proc_file_assafe(c"/proc/self/uid_map".as_ptr(), bytes) }
    }

    fn write_gid_map(&mut self, bytes: &[u8]) -> bool {
        // SAFETY: the path is static and NUL-terminated; `bytes` is borrowed
        // from the parent-built spec and remains valid throughout pre_exec.
        unsafe { write_proc_file_assafe(c"/proc/self/gid_map".as_ptr(), bytes) }
    }

    fn make_mounts_private(&mut self) -> bool {
        // SAFETY: target is a static NUL-terminated path. MS_PRIVATE ignores
        // source, filesystem type, and data, so null pointers are required.
        unsafe {
            libc::mount(
                std::ptr::null(),
                c"/".as_ptr(),
                std::ptr::null(),
                libc::MS_REC | libc::MS_PRIVATE,
                std::ptr::null(),
            ) == 0
        }
    }

    fn bind_dev_null(&mut self, target: &std::ffi::CStr) -> bool {
        // SAFETY: all three paths are valid NUL-terminated C strings. MS_BIND
        // ignores the data pointer, and the target remains alive for the call.
        unsafe {
            libc::mount(
                c"/dev/null".as_ptr(),
                target.as_ptr(),
                c"none".as_ptr(),
                libc::MS_BIND,
                std::ptr::null(),
            ) == 0
        }
    }

    fn remount_proc_restricted(&mut self) {
        // SAFETY: every pointer refers to a static NUL-terminated byte string.
        // The optional procfs hardening remains best-effort and is outside the
        // secret-overlay success contract.
        unsafe {
            libc::mount(
                c"proc".as_ptr(),
                c"/proc".as_ptr(),
                c"proc".as_ptr(),
                libc::MS_REMOUNT | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
                c"hidepid=2,subset=pid".as_ptr() as *const libc::c_void,
            );
        }
    }
}

#[cfg(target_os = "linux")]
fn apply_secret_overlay<O: SecretOverlayOperations>(
    spec: &SecretOverlaySpec,
    operations: &mut O,
) -> Result<(), SecretOverlayStage> {
    if !operations.unshare_user_and_mount_namespaces() {
        return Err(SecretOverlayStage::Unshare);
    }
    if !operations.deny_setgroups() {
        return Err(SecretOverlayStage::Setgroups);
    }
    if !operations.write_uid_map(&spec.uid_map_bytes) {
        return Err(SecretOverlayStage::UidMap);
    }
    if !operations.write_gid_map(&spec.gid_map_bytes) {
        return Err(SecretOverlayStage::GidMap);
    }
    if !operations.make_mounts_private() {
        return Err(SecretOverlayStage::MountPropagation);
    }
    for path in &spec.paths {
        if !operations.bind_dev_null(path) {
            return Err(SecretOverlayStage::BindMount);
        }
    }
    operations.remount_proc_restricted();
    Ok(())
}

/// Installs the secret-file overlay in the forked child.
///
/// Namespace creation, ID mapping, propagation isolation, and every
/// required bind mount fail closed. The optional procfs remount remains
/// best-effort defense in depth.
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
pub(crate) unsafe fn apply_secret_overlay_in_child(
    spec: &SecretOverlaySpec,
) -> Result<(), SecretOverlayStage> {
    let mut operations = LibcSecretOverlayOperations;
    apply_secret_overlay(spec, &mut operations)
}

/// AS-safe `write_all`-style helper for `/proc/self/*` files.
/// Returns `true` only when the full write and close succeed.
///
/// # Safety
///
/// `path` must point to a NUL-terminated absolute path. `bytes`
/// must outlive the call. No allocations performed.
#[cfg(target_os = "linux")]
unsafe fn write_proc_file_assafe(path: *const libc::c_char, bytes: &[u8]) -> bool {
    // SAFETY: the caller guarantees `path` is NUL-terminated and valid.
    let fd = unsafe { libc::open(path, libc::O_WRONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        return false;
    }
    let mut written: usize = 0;
    while written < bytes.len() {
        let remaining = bytes.len() - written;
        // SAFETY: `fd` is open and the slice points to `remaining` valid bytes.
        let n = unsafe {
            libc::write(
                fd,
                bytes[written..].as_ptr() as *const libc::c_void,
                remaining,
            )
        };
        if n <= 0 {
            // SAFETY: `fd` is an open descriptor owned by this function.
            unsafe { libc::close(fd) };
            return false;
        }
        written += n as usize;
    }
    // SAFETY: `fd` is an open descriptor owned by this function.
    unsafe { libc::close(fd) == 0 }
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

    fn enumerate(project_dir: &Path, allow_list: &[PathBuf]) -> Vec<PathBuf> {
        enumerate_project_secrets(project_dir, allow_list).expect("enumerate project secrets")
    }

    #[test]
    fn permission_denied_is_not_treated_as_an_absent_descendant() {
        let error = io::Error::from(io::ErrorKind::PermissionDenied);

        assert!(!fixed_descendant_is_absent(&error));
    }

    #[cfg(target_os = "linux")]
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum RecordedOperation {
        Unshare,
        Setgroups,
        UidMap,
        GidMap,
        MountPropagation,
        BindMount(usize),
        RemountProc,
    }

    #[cfg(target_os = "linux")]
    struct MockOperations {
        fail_stage: Option<SecretOverlayStage>,
        fail_bind_index: Option<usize>,
        bind_index: usize,
        calls: Vec<RecordedOperation>,
    }

    #[cfg(target_os = "linux")]
    impl MockOperations {
        fn failing(stage: SecretOverlayStage) -> Self {
            Self {
                fail_stage: Some(stage),
                fail_bind_index: None,
                bind_index: 0,
                calls: Vec::new(),
            }
        }

        fn failing_bind(index: usize) -> Self {
            Self {
                fail_stage: None,
                fail_bind_index: Some(index),
                bind_index: 0,
                calls: Vec::new(),
            }
        }

        fn successful() -> Self {
            Self {
                fail_stage: None,
                fail_bind_index: None,
                bind_index: 0,
                calls: Vec::new(),
            }
        }

        fn succeeds_at(&self, stage: SecretOverlayStage) -> bool {
            self.fail_stage != Some(stage)
        }
    }

    #[cfg(target_os = "linux")]
    impl SecretOverlayOperations for MockOperations {
        fn unshare_user_and_mount_namespaces(&mut self) -> bool {
            self.calls.push(RecordedOperation::Unshare);
            self.succeeds_at(SecretOverlayStage::Unshare)
        }

        fn deny_setgroups(&mut self) -> bool {
            self.calls.push(RecordedOperation::Setgroups);
            self.succeeds_at(SecretOverlayStage::Setgroups)
        }

        fn write_uid_map(&mut self, _bytes: &[u8]) -> bool {
            self.calls.push(RecordedOperation::UidMap);
            self.succeeds_at(SecretOverlayStage::UidMap)
        }

        fn write_gid_map(&mut self, _bytes: &[u8]) -> bool {
            self.calls.push(RecordedOperation::GidMap);
            self.succeeds_at(SecretOverlayStage::GidMap)
        }

        fn make_mounts_private(&mut self) -> bool {
            self.calls.push(RecordedOperation::MountPropagation);
            self.succeeds_at(SecretOverlayStage::MountPropagation)
        }

        fn bind_dev_null(&mut self, _target: &std::ffi::CStr) -> bool {
            let index = self.bind_index;
            self.bind_index += 1;
            self.calls.push(RecordedOperation::BindMount(index));
            self.fail_bind_index != Some(index)
        }

        fn remount_proc_restricted(&mut self) {
            self.calls.push(RecordedOperation::RemountProc);
        }
    }

    #[cfg(target_os = "linux")]
    fn mock_spec(path_count: usize) -> SecretOverlaySpec {
        let paths = (0..path_count)
            .map(|index| {
                std::ffi::CString::new(format!("/project/secret-{index}.pem")).expect("mock path")
            })
            .collect();
        SecretOverlaySpec {
            paths,
            uid_map_bytes: b"0 1000 1\n".to_vec(),
            gid_map_bytes: b"0 1000 1\n".to_vec(),
        }
    }

    #[cfg(target_os = "linux")]
    fn assert_stage_failure(stage: SecretOverlayStage, expected_calls: &[RecordedOperation]) {
        let spec = mock_spec(2);
        let mut operations = MockOperations::failing(stage);

        let result = apply_secret_overlay(&spec, &mut operations);

        assert_eq!(result, Err(stage));
        assert_eq!(operations.calls, expected_calls);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn unshare_failure_stops_overlay_before_mapping() {
        assert_stage_failure(SecretOverlayStage::Unshare, &[RecordedOperation::Unshare]);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn setgroups_failure_aborts_overlay_setup() {
        assert_stage_failure(
            SecretOverlayStage::Setgroups,
            &[RecordedOperation::Unshare, RecordedOperation::Setgroups],
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn uid_map_failure_aborts_overlay_setup() {
        assert_stage_failure(
            SecretOverlayStage::UidMap,
            &[
                RecordedOperation::Unshare,
                RecordedOperation::Setgroups,
                RecordedOperation::UidMap,
            ],
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn gid_map_failure_aborts_overlay_setup() {
        assert_stage_failure(
            SecretOverlayStage::GidMap,
            &[
                RecordedOperation::Unshare,
                RecordedOperation::Setgroups,
                RecordedOperation::UidMap,
                RecordedOperation::GidMap,
            ],
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn mount_propagation_failure_aborts_overlay_setup() {
        assert_stage_failure(
            SecretOverlayStage::MountPropagation,
            &[
                RecordedOperation::Unshare,
                RecordedOperation::Setgroups,
                RecordedOperation::UidMap,
                RecordedOperation::GidMap,
                RecordedOperation::MountPropagation,
            ],
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn first_bind_mount_failure_aborts_overlay_setup() {
        let spec = mock_spec(2);
        let mut operations = MockOperations::failing_bind(0);

        let result = apply_secret_overlay(&spec, &mut operations);

        assert_eq!(result, Err(SecretOverlayStage::BindMount));
        assert_eq!(
            operations.calls.last(),
            Some(&RecordedOperation::BindMount(0))
        );
        assert!(!operations.calls.contains(&RecordedOperation::RemountProc));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn later_bind_mount_failure_rejects_partial_masking() {
        let spec = mock_spec(3);
        let mut operations = MockOperations::failing_bind(1);

        let result = apply_secret_overlay(&spec, &mut operations);

        assert_eq!(result, Err(SecretOverlayStage::BindMount));
        assert!(operations.calls.ends_with(&[
            RecordedOperation::BindMount(0),
            RecordedOperation::BindMount(1),
        ]));
        assert!(!operations.calls.contains(&RecordedOperation::BindMount(2)));
        assert!(!operations.calls.contains(&RecordedOperation::RemountProc));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn successful_overlay_masks_every_path_before_optional_proc_remount() {
        let spec = mock_spec(2);
        let mut operations = MockOperations::successful();

        let result = apply_secret_overlay(&spec, &mut operations);

        assert_eq!(result, Ok(()));
        assert!(operations.calls.ends_with(&[
            RecordedOperation::BindMount(0),
            RecordedOperation::BindMount(1),
            RecordedOperation::RemountProc,
        ]));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn failure_stages_map_to_static_diagnostics_and_stable_errno() {
        const STAGES: [SecretOverlayStage; 6] = [
            SecretOverlayStage::Unshare,
            SecretOverlayStage::Setgroups,
            SecretOverlayStage::UidMap,
            SecretOverlayStage::GidMap,
            SecretOverlayStage::MountPropagation,
            SecretOverlayStage::BindMount,
        ];

        for stage in STAGES {
            let diagnostic: &'static [u8] = stage.diagnostic();
            assert!(diagnostic.starts_with(b"lpm-sandbox: secret overlay "));
            assert_eq!(stage.errno(), libc::EPERM);
        }
    }

    /// `.env` at project root is enumerated.
    #[test]
    fn enumerates_dotenv_at_project_root() {
        let tmp = with_project(|root| {
            fs::write(root.join(".env"), "API_KEY=secret").unwrap();
        });
        let v = enumerate(tmp.path(), &[]);
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
        let v = enumerate(tmp.path(), &[]);
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
        let v = enumerate(tmp.path(), &[]);
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
        let v = enumerate(tmp.path(), &[]);
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
        let v = enumerate(tmp.path(), &[]);
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
        let v = enumerate(tmp.path(), &[]);
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
        let v = enumerate(tmp.path(), &[]);
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
        let v = enumerate(tmp.path(), &[]);
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
        let v = enumerate(tmp.path(), &allow);
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
        let v = enumerate(tmp.path(), &allow);
        assert!(v.contains(&tmp.path().join(".env")));
        assert_eq!(v.len(), 1);
    }

    /// Empty project — empty result.
    #[test]
    fn empty_project_yields_empty_enumeration() {
        let tmp = with_project(|_| {});
        let v = enumerate(tmp.path(), &[]);
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
        let v = enumerate(tmp.path(), &[]);
        assert!(v.is_empty(), "no secret-like files: {v:?}");
    }

    /// Walk depth cap — files deeper than WALK_MAX_DEPTH are not
    /// reached by the extension walker. Pin the contract.
    #[test]
    fn walk_max_depth_is_respected() {
        let tmp = with_project(|root| {
            // root, /a, /a/b, /a/b/c, /a/b/c/d — depth 4 exists.
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
        let v = enumerate(tmp.path(), &[]);
        // The walker enters directories at depths 1-3 (capped by
        // `WALK_MAX_DEPTH = 4` via the `depth + 1 < WALK_MAX_DEPTH`
        // push gate) and enumerates files inside them — so files
        // through directory depth 3 are reachable.
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
        let a = enumerate(tmp.path(), &[]);
        let b = enumerate(tmp.path(), &[]);
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
        assert!(
            SecretOverlaySpec::build(tmp.path(), &[])
                .expect("prepare overlay")
                .is_none()
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn linked_git_worktree_without_secrets_skips_overlay_setup() {
        let tmp = with_project(|root| {
            fs::write(root.join("package.json"), "{}").unwrap();
            fs::write(
                root.join(".git"),
                "gitdir: /tmp/main/.git/worktrees/linked\n",
            )
            .unwrap();
        });

        let spec = SecretOverlaySpec::build(tmp.path(), &[]).expect("prepare overlay");

        assert!(spec.is_none());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn overlay_spec_build_returns_none_when_every_secret_is_allowlisted() {
        let tmp = with_project(|root| {
            fs::write(root.join(".env"), "API_KEY=allowed").unwrap();
        });
        let allow = vec![tmp.path().join(".env")];

        let spec = SecretOverlaySpec::build(tmp.path(), &allow).expect("prepare overlay");

        assert!(spec.is_none());
    }

    #[test]
    fn missing_project_root_returns_preparation_error() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let missing = tmp.path().join("missing-project");

        let result = enumerate_project_secrets(&missing, &[]);

        assert!(matches!(result, Err(SecretOverlayBuildError::Io { .. })));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn non_utf8_protected_path_is_preserved_in_overlay_spec() {
        use std::os::unix::ffi::{OsStrExt, OsStringExt};

        let tmp = tempfile::tempdir().expect("tempdir");
        let file_name = std::ffi::OsString::from_vec(b"private-\xff.pem".to_vec());
        let protected_path = tmp.path().join(file_name);
        fs::write(&protected_path, "private key").expect("write protected file");

        let spec = SecretOverlaySpec::build(tmp.path(), &[])
            .expect("prepare overlay")
            .expect("protected path requires overlay");

        assert!(
            spec.paths
                .iter()
                .any(|path| { path.to_bytes() == protected_path.as_os_str().as_bytes() })
        );
    }

    /// SecretOverlaySpec::build returns Some with CStrings + maps
    /// when secrets exist. Pins the uid_map shape.
    #[test]
    #[cfg(target_os = "linux")]
    fn overlay_spec_build_populates_paths_and_uid_map() {
        let tmp = with_project(|root| {
            fs::write(root.join(".env"), "").unwrap();
        });
        let spec = SecretOverlaySpec::build(tmp.path(), &[])
            .expect("prepare overlay")
            .expect("must have spec");
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
