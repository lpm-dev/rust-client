use crate::commands::install_targets::{install_root_for, resolve_install_targets};
use lpm_common::LpmError;
use std::path::{Path, PathBuf};

/// Resolved deploy plan: which member to deploy and where it lives on disk.
/// Returned by [`resolve_deploy_target`] and consumed by the deploy pipeline.
#[derive(Debug, Clone)]
pub(in crate::commands::deploy) struct DeployPlan {
    /// Path to the source member's `package.json`. Read during manifest
    /// rewrite.
    pub member_manifest: PathBuf,
    /// Path to the source member's directory (`member_manifest.parent()`).
    pub member_dir: PathBuf,
    /// Validated, normalized output directory the deploy will write into.
    pub output_dir: PathBuf,
}

/// Resolve the deploy target from CLI flags and validate the output directory.
///
/// Returns a [`DeployPlan`] on success, or an actionable [`LpmError::Script`]
/// describing what's wrong. Validation rules:
///
/// - a filter must be non-empty
/// - filters must match exactly one workspace member
/// - The output directory must NOT be inside the workspace tree (self-deploy
///   loop prevention)
/// - The output directory must be empty (or not exist), unless `force` is set
pub(in crate::commands::deploy) fn resolve_deploy_target(
    cwd: &Path,
    output_dir: &Path,
    filters: &[String],
    filter_prod: &[String],
    changed_files_ignore_pattern: &[String],
    test_pattern: &[String],
    force: bool,
) -> Result<DeployPlan, LpmError> {
    if filters.is_empty() && filter_prod.is_empty() {
        return Err(LpmError::Script(
            "lpm deploy requires --filter <expr> or --filter-prod <expr> to identify the workspace member to deploy".into(),
        ));
    }

    // 1. Resolve target via the shared install_targets helper.
    //    has_packages=true so we never hit the "ambiguous root refresh" branch.
    //    workspace_root_flag=false because deploy never targets the root manifest.
    let targets = resolve_install_targets(
        cwd,
        filters,
        filter_prod,
        changed_files_ignore_pattern,
        test_pattern,
        false,
        true,
    )?;

    // 2. Single-member assertion.
    if targets.member_manifests.is_empty() {
        return Err(LpmError::Script(format!(
            "lpm deploy: --filter {filters:?} matched no workspace members. \
             Refine the filter to point at exactly one member."
        )));
    }
    if targets.member_manifests.len() > 1 {
        return Err(LpmError::Script(format!(
            "lpm deploy: --filter {:?} matched {} workspace members; deploy requires exactly one. \
             Refine the filter to target a single member.",
            filters,
            targets.member_manifests.len()
        )));
    }

    let member_manifest = targets.member_manifests[0].clone();
    let member_dir = install_root_for(&member_manifest).to_path_buf();

    // 3. Output directory validation.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let read_mounts = Mounts::read;
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let read_mounts = || Ok(Mounts::read());
    let output_dir = validate_output_dir(cwd, output_dir, force, read_mounts)?;

    Ok(DeployPlan {
        member_manifest,
        member_dir,
        output_dir,
    })
}

/// Validate the deploy output directory.
///
/// - Must not be inside the workspace tree (prevents self-deploy loops).
/// - Must be empty, not exist yet, or `force == true`.
///
/// Returns the validated, normalized path. Does NOT create the directory
/// or clean it for `--force` — those are the caller's responsibility.
///
/// the self-loop guard now canonicalizes
/// BOTH the workspace root AND the output path through `canonicalize_or_partial`
/// before comparing. The old implementation mixed canonical and lexical paths
/// in the same comparison, which silently passed on macOS when the workspace
/// was under `/tmp/...` (because `/tmp` symlinks to `/private/tmp` and the
/// asymmetric prefix comparison missed the relationship).
pub(in crate::commands::deploy) fn validate_output_dir(
    cwd: &Path,
    output_dir: &Path,
    force: bool,
    read_mounts: impl FnOnce() -> std::io::Result<Mounts>,
) -> Result<PathBuf, LpmError> {
    let normalized = lexical_normalize(&cwd.join(output_dir));

    if let Some(git_directory) = git_directory_holding(&normalized) {
        return Err(LpmError::Script(format!(
            "lpm deploy: output directory {output_dir:?} is in the git directory {}, whose hooks and config git runs. \
             Choose a directory outside it.",
            git_directory.display()
        )));
    }
    let mounts = read_mounts().map_err(|error| {
        LpmError::Script(format!(
            "lpm deploy: can't read the system's mounts to check that output directory {output_dir:?} \
             overlaps none of the workspace, the LPM home and the home directory: {error}"
        ))
    })?;

    // Self-deploy loop guard: walk up from cwd looking for a workspace root,
    // then check that the output dir is not inside it, nor holds it, by
    // directory identity, as a link or a firmlink (macOS's
    // `/System/Volumes/Data/…`), a bind mount or a UNC loopback names it
    // another way than its canonical path.
    if let Ok(Some(workspace)) = lpm_workspace::discover_workspace(cwd) {
        let workspace_canonical = canonicalize_or_partial(&workspace.root);
        let output_canonical = canonicalize_or_partial(&normalized);

        if is_within(&normalized, &workspace.root, &mounts) {
            return Err(LpmError::Script(format!(
                "lpm deploy: output directory {output_dir:?} resolves to {output_canonical:?} \
                 which is inside the workspace at {workspace_canonical:?}. \
                 Choose an output directory outside the workspace to prevent self-deploy loops."
            )));
        }
        if is_within(&workspace.root, &normalized, &mounts) {
            return Err(LpmError::Script(format!(
                "lpm deploy: output directory {output_dir:?} overlaps the workspace at {workspace_canonical:?}. \
                 Choose a directory that does not contain the workspace."
            )));
        }
    }

    // `--force` clears the output, which must take nothing of LPM's own or
    // of the account's with it.
    if let Ok(root) = lpm_common::LpmRoot::from_env()
        && (is_within(&normalized, root.root(), &mounts)
            || is_within(root.root(), &normalized, &mounts))
    {
        return Err(LpmError::Script(format!(
            "lpm deploy: output directory {output_dir:?} overlaps the LPM home at {}, \
             which holds login state, env secrets and packages. Choose a directory outside it.",
            root.root().display()
        )));
    }
    if let Some(home) = dirs::home_dir()
        && is_within(&home, &normalized, &mounts)
    {
        return Err(LpmError::Script(format!(
            "lpm deploy: output directory {output_dir:?} holds the home directory {}. \
             Choose a directory of its own.",
            home.display()
        )));
    }

    // Empty / force check. Non-existent paths are fine — the copy step
    // will create them. For `--force` on a non-empty existing dir, this
    // function only suppresses the non-empty error; the actual cleanup
    // (`remove_output` + `create_dir_all`) lives in `run` AFTER this
    // validation succeeds. That ordering matters: validate_output_dir is
    // the safety gate that confirms the output is OUTSIDE the workspace,
    // and we deliberately never remove anything until the gate has passed.
    if normalized.exists() {
        if !normalized.is_dir() {
            return Err(LpmError::Script(format!(
                "lpm deploy: output directory {output_dir:?} is not a directory. \
                 Choose a directory, or a path that doesn't exist yet."
            )));
        }
        // The removal never enters a mount, so it would stop at one with
        // part of the output deleted.
        if force && is_mount_point(&normalized, &mounts) {
            return Err(LpmError::Script(format!(
                "lpm deploy: output directory {output_dir:?} is a mount point, which --force can't delete and recreate. \
                 Empty it and deploy without --force, or deploy into a directory inside it."
            )));
        }
        if force && let Some(mount) = mount_point_within(&normalized, &mounts) {
            return Err(LpmError::Script(format!(
                "lpm deploy: output directory {output_dir:?} holds the mount point {}, which --force can't delete: \
                 it would stop there with part of the output deleted. Unmount it, or choose a directory that holds none.",
                mount.display()
            )));
        }
        let is_empty =
            std::fs::read_dir(&normalized).map_or(true, |mut iter| iter.next().is_none());
        if !is_empty && !force {
            return Err(LpmError::Script(format!(
                "lpm deploy: output directory {output_dir:?} is not empty. \
                 Use --force to overwrite, or choose an empty/nonexistent output directory."
            )));
        }
    }

    Ok(normalized)
}

/// The git directory `output` is in or is: an ancestor, as `output` names
/// it or where its links lead, that git reads as `.git` by its name, or
/// that is a git directory by what it holds, as a bare repository is.
fn git_directory_holding(output: &Path) -> Option<PathBuf> {
    let resolved = canonicalize_or_partial(output);
    [output, resolved.as_path()].into_iter().find_map(|path| {
        path.ancestors()
            .find(|ancestor| {
                ancestor
                    .file_name()
                    .is_some_and(|name| lpm_common::names::is_git_dir_name(&name.to_string_lossy()))
                    || lpm_common::git_directory::is_git_directory(ancestor)
            })
            .map(Path::to_path_buf)
    })
}

/// The mounts the output's checks read, once per deploy: where each is,
/// and on Linux which files each shows, which a bind mount needs.
pub(in crate::commands::deploy) struct Mounts {
    points: Vec<PathBuf>,
    /// The mounts placed by the files they show: on Linux all of them, on
    /// macOS its NFS volumes, where no bind mounts are.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    table: Vec<lpm_common::mounts::Mount>,
}

impl Mounts {
    /// The mounts as the system lists them.
    #[cfg(target_os = "linux")]
    pub(in crate::commands::deploy) fn read() -> std::io::Result<Self> {
        let table = lpm_common::mounts::mount_table()?;
        Ok(Self {
            points: table
                .iter()
                .map(|mount| mount.mount_point.clone())
                .collect(),
            table,
        })
    }

    /// The mounts as the system lists them.
    #[cfg(target_os = "macos")]
    pub(in crate::commands::deploy) fn read() -> std::io::Result<Self> {
        let volumes = volumes()?;
        Ok(Self {
            table: volumes
                .iter()
                .filter_map(|(mount_point, source, filesystem)| {
                    nfs_volume(mount_point.clone(), source, filesystem)
                })
                .collect(),
            points: volumes
                .into_iter()
                .map(|(mount_point, _, _)| mount_point)
                .collect(),
        })
    }

    /// None elsewhere: Windows removes a folder a volume is mounted on as
    /// the link it is, and other systems tell a mount point by its device.
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    pub(in crate::commands::deploy) fn read() -> Self {
        Self { points: Vec::new() }
    }
}

/// Whether `inner` is `outer` or inside it, as the paths name them, by
/// directory identity, as the volume holding it is, as the system's mounts
/// place their files (on Linux, where a bind mount shows a directory under a
/// path no ancestor walk reaches, and for NFS, by the server directory a
/// mount's source names), or as `outer` shows `inner`'s directory under the
/// names that end its path.
#[cfg_attr(
    not(any(target_os = "linux", target_os = "macos")),
    allow(unused_variables)
)]
fn is_within(inner: &Path, outer: &Path, mounts: &Mounts) -> bool {
    let resolved = canonicalize_or_partial(inner);
    walks_into(inner, outer)
        || volume_root_holds(&resolved, outer)
        || shows_by_identity(
            &resolved,
            &canonicalize_or_partial(outer),
            is_same_directory_reached_directly,
        )
        || {
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            {
                located_within(&mounts.table, &resolved, &canonicalize_or_partial(outer))
            }
            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            {
                false
            }
        }
}

/// Whether `outer` shows `inner`'s directory, by `same`, under the names
/// that end `inner`'s path: its names only, as a drive or a root joined
/// onto `outer` would name `inner` itself.
pub(in crate::commands::deploy) fn shows_by_identity(
    inner: &Path,
    outer: &Path,
    same: impl Fn(&Path, &Path) -> bool,
) -> bool {
    let names: Vec<_> = inner
        .components()
        .filter(|component| matches!(component, std::path::Component::Normal(_)))
        .collect();
    (1..=names.len()).any(|count| {
        let shown = names[names.len() - count..]
            .iter()
            .fold(outer.to_path_buf(), |path, name| path.join(name));
        same(&shown, inner)
    })
}

/// Whether `shown` is the directory `inner` is, reached as it names it,
/// not through a link, which the removal removes rather than enters.
pub(in crate::commands::deploy) fn is_same_directory_reached_directly(
    shown: &Path,
    inner: &Path,
) -> bool {
    lpm_workspace::is_same_directory(shown, inner)
        && std::fs::canonicalize(shown).is_ok_and(|resolved| resolved == shown)
}

/// Whether the files at `inner` are the files at `outer`, canonical paths
/// both, or in them, or in a mount below `outer`, as the table places them
/// ([`lpm_common::mounts::Mount::shows`]).
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(in crate::commands::deploy) fn located_within(
    table: &[lpm_common::mounts::Mount],
    inner: &Path,
    outer: &Path,
) -> bool {
    use lpm_common::mounts::filesystem_location;
    let Some((key, files)) = filesystem_location(table, inner) else {
        return false;
    };
    let below = table
        .iter()
        .filter(|mount| mount.mount_point != outer && mount.mount_point.starts_with(outer))
        .filter_map(|mount| {
            mount
                .shows
                .as_ref()
                .map(|(key, files)| (key.as_str(), files.clone()))
        });
    filesystem_location(table, outer)
        .into_iter()
        .chain(below)
        .any(|(holder_key, holder_files)| holder_key == key && files.starts_with(holder_files))
}

/// An NFS volume `getfsstat` lists, placed by its source (`server:/path`);
/// `None` for any other volume.
#[cfg(target_os = "macos")]
pub(in crate::commands::deploy) fn nfs_volume(
    mount_point: PathBuf,
    source: &[u8],
    filesystem: &str,
) -> Option<lpm_common::mounts::Mount> {
    (filesystem == "nfs").then(|| lpm_common::mounts::Mount {
        device: String::new(),
        root: PathBuf::from("/"),
        mount_point,
        filesystem: filesystem.to_string(),
        shows: lpm_common::mounts::nfs_location(source, b""),
    })
}

/// Whether `inner` is `outer` or inside it, as the paths name them or by
/// directory identity: `inner`'s ancestors are walked both as it names them
/// and where its links lead, which a link outside `outer` can put inside it.
fn walks_into(inner: &Path, outer: &Path) -> bool {
    let resolved = canonicalize_or_partial(inner);
    [inner, resolved.as_path()].into_iter().any(|path| {
        path.ancestors()
            .any(|ancestor| lpm_workspace::is_same_directory(ancestor, outer))
    })
}

/// Whether the mount point of the volume that holds `inner` is `outer` or
/// inside it. On macOS, where nothing mounts part of a volume elsewhere, a
/// volume's root holds every file on it, and firmlinks put the data volume's
/// directories under `/`, so no canonical ancestor of one names that root
/// (`/System/Volumes/Data`) or what holds it; the volumes of one group also
/// share a device number, so only their mount points tell them apart.
#[cfg(target_os = "macos")]
fn volume_root_holds(inner: &Path, outer: &Path) -> bool {
    inner
        .ancestors()
        .find_map(mount_point)
        .is_some_and(|mount| walks_into(Path::new(&mount), outer))
}

/// Where the volume holding `path` is mounted.
#[cfg(target_os = "macos")]
fn mount_point(path: &Path) -> Option<std::ffi::OsString> {
    use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
    let path = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    // SAFETY: an all-zero `statfs` is a valid value for `statfs` to fill.
    let mut volume: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: `path` is NUL-terminated and `volume` is writable storage of
    // the structure `statfs` expects.
    if unsafe { libc::statfs(path.as_ptr(), &mut volume) } != 0 {
        return None;
    }
    // SAFETY: `statfs` NUL-terminates `f_mntonname` within its length.
    let name = unsafe { std::ffi::CStr::from_ptr(volume.f_mntonname.as_ptr()) };
    Some(std::ffi::OsString::from_vec(name.to_bytes().to_vec()))
}

#[cfg(not(target_os = "macos"))]
fn volume_root_holds(_inner: &Path, _outer: &Path) -> bool {
    false
}

/// Whether `path` is a directory a volume is mounted on, or a bind mount,
/// itself and not through a link, as the removal removes a link rather than
/// what it leads to.
pub(in crate::commands::deploy) fn is_mount_point(path: &Path, mounts: &Mounts) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.is_dir())
        && mounted_on(path, mounts)
}

#[cfg(target_os = "macos")]
fn mounted_on(path: &Path, _mounts: &Mounts) -> bool {
    mount_point(path).is_some_and(|mount| lpm_workspace::is_same_directory(Path::new(&mount), path))
}

/// Linux before 5.8 doesn't say in `statx`; there, the mount table lists
/// each mount point by its path.
#[cfg(target_os = "linux")]
fn mounted_on(path: &Path, mounts: &Mounts) -> bool {
    use rustix::fs::{AtFlags, StatxAttributes, StatxFlags};
    match rustix::fs::statx(
        rustix::fs::CWD,
        path,
        AtFlags::NO_AUTOMOUNT | AtFlags::SYMLINK_NOFOLLOW,
        StatxFlags::empty(),
    ) {
        Ok(status)
            if status
                .stx_attributes_mask
                .contains(StatxAttributes::MOUNT_ROOT) =>
        {
            status.stx_attributes.contains(StatxAttributes::MOUNT_ROOT)
        }
        _ => listed_in_mount_table(path, mounts),
    }
}

/// A mount point at `path` or below it, where the removal would stop with
/// part of the output deleted. Windows removes a folder a volume is mounted
/// on as the link it is.
pub(in crate::commands::deploy) fn mount_point_within(
    path: &Path,
    mounts: &Mounts,
) -> Option<PathBuf> {
    let mut spellings = vec![path.to_path_buf()];
    if let Ok(canonical) = std::fs::canonicalize(path) {
        // A firmlink names the data volume's directories from `/` too, and
        // a path given from the data volume's mount point keeps that
        // spelling when canonical, so each is spelled the other way too.
        #[cfg(target_os = "macos")]
        {
            const DATA_VOLUME: &str = "/System/Volumes/Data";
            if let Ok(below_data_volume) = canonical.strip_prefix(DATA_VOLUME) {
                spellings.push(Path::new("/").join(below_data_volume));
            } else if let Ok(below_root) = canonical.strip_prefix("/") {
                spellings.push(Path::new(DATA_VOLUME).join(below_root));
            }
        }
        spellings.push(canonical);
    }
    mounts_within(&mounts.points, &spellings)
}

/// The first of `mounts` at or below one of `spellings`, told by path alone:
/// a mount that can't answer, such as a network share whose server is gone,
/// or one the kernel would mount on first use, is never touched.
pub(in crate::commands::deploy) fn mounts_within(
    mounts: &[PathBuf],
    spellings: &[PathBuf],
) -> Option<PathBuf> {
    mounts
        .iter()
        .find(|mount| spellings.iter().any(|spelling| mount.starts_with(spelling)))
        .cloned()
}

/// Each volume `getfsstat` lists: where it is mounted, its source and its
/// filesystem's type.
#[cfg(target_os = "macos")]
fn volumes() -> std::io::Result<Vec<(PathBuf, Vec<u8>, String)>> {
    use std::os::unix::ffi::OsStringExt as _;
    // SAFETY: a null buffer asks only for the count.
    let count = unsafe { libc::getfsstat(std::ptr::null_mut(), 0, libc::MNT_NOWAIT) };
    let count = usize::try_from(count).map_err(|_| std::io::Error::last_os_error())?;
    // Room for volumes mounted between the two calls.
    let mut volumes: Vec<libc::statfs> = Vec::with_capacity(count + 8);
    let bytes = libc::c_int::try_from(volumes.capacity() * std::mem::size_of::<libc::statfs>())
        .map_err(|_| std::io::Error::other("too many volumes to list"))?;
    // SAFETY: `volumes` has room for `bytes` bytes of `statfs` entries,
    // which `getfsstat` fills from the start.
    let filled = unsafe { libc::getfsstat(volumes.as_mut_ptr(), bytes, libc::MNT_NOWAIT) };
    let filled = usize::try_from(filled).map_err(|_| std::io::Error::last_os_error())?;
    // SAFETY: `getfsstat` initialized the first `filled` entries.
    unsafe { volumes.set_len(filled.min(volumes.capacity())) };
    Ok(volumes
        .iter()
        .map(|volume| {
            // SAFETY: `getfsstat` NUL-terminates `f_mntonname`,
            // `f_mntfromname` and `f_fstypename` within their lengths.
            let (name, source, filesystem) = unsafe {
                (
                    std::ffi::CStr::from_ptr(volume.f_mntonname.as_ptr()),
                    std::ffi::CStr::from_ptr(volume.f_mntfromname.as_ptr()),
                    std::ffi::CStr::from_ptr(volume.f_fstypename.as_ptr()),
                )
            };
            (
                PathBuf::from(std::ffi::OsString::from_vec(name.to_bytes().to_vec())),
                source.to_bytes().to_vec(),
                filesystem.to_string_lossy().into_owned(),
            )
        })
        .collect())
}

#[cfg(target_os = "linux")]
pub(in crate::commands::deploy) fn listed_in_mount_table(path: &Path, mounts: &Mounts) -> bool {
    let canonical = match (path.parent(), path.file_name()) {
        (Some(parent), Some(name)) => std::fs::canonicalize(parent).map(|parent| parent.join(name)),
        _ => std::fs::canonicalize(path),
    };
    let Ok(canonical) = canonical else {
        return false;
    };
    mounts.points.contains(&canonical)
}

/// A drive's root, or a folder a volume is mounted on.
#[cfg(windows)]
fn mounted_on(path: &Path, _mounts: &Mounts) -> bool {
    use std::os::windows::ffi::{OsStrExt as _, OsStringExt as _};
    use windows_sys::Win32::Storage::FileSystem::GetVolumePathNameW;
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
    // The volume's path is a prefix of `path`'s, with a separator after it.
    let mut volume = vec![0u16; wide.len() + 1];
    let Ok(capacity) = u32::try_from(volume.len()) else {
        return false;
    };
    // SAFETY: `wide` is NUL-terminated, and `volume` is writable storage
    // of `capacity` UTF-16 units.
    if unsafe { GetVolumePathNameW(wide.as_ptr(), volume.as_mut_ptr(), capacity) } == 0 {
        return false;
    }
    let end = volume
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(volume.len());
    let volume = std::ffi::OsString::from_wide(&volume[..end]);
    lpm_workspace::is_same_directory(Path::new(&volume), path)
}

#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
fn mounted_on(path: &Path, _mounts: &Mounts) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    let parent = path.parent().unwrap_or(path);
    match (std::fs::metadata(path), std::fs::metadata(parent)) {
        (Ok(directory), Ok(parent_directory)) => {
            parent == path || directory.dev() != parent_directory.dev()
        }
        _ => false,
    }
}

/// Canonicalize a path to its symlink-resolved absolute form, even when
/// the path itself does not exist yet.
///
/// Walks up from `path` looking for the deepest existing ancestor, calls
/// `canonicalize` on it (which follows symlinks), then re-appends the
/// non-existent tail components in their original order. This produces a
/// path that is comparable with other canonicalized paths under the same
/// symlink-resolved root.
///
/// This avoids comparing canonical workspace roots against raw lexical
/// output paths when the requested output path does not exist yet.
pub(in crate::commands::deploy) fn canonicalize_or_partial(path: &Path) -> PathBuf {
    // Fast path: the whole path already exists, canonicalize directly.
    if let Ok(canonical) = path.canonicalize() {
        return canonical;
    }

    // Walk up to the deepest existing ancestor, collecting the tail
    // components we'll re-append in order.
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    let mut current = path.to_path_buf();
    loop {
        if current.exists() {
            // Found an existing ancestor. Canonicalize it and re-append
            // the tail in original order.
            let mut result = current.canonicalize().unwrap_or(current);
            for component in tail.iter().rev() {
                result.push(component);
            }
            return result;
        }
        let Some(parent) = current.parent().map(|p| p.to_path_buf()) else {
            // Reached the filesystem root without finding an existing
            // ancestor. Fall back to the lexical form — we did our best.
            return path.to_path_buf();
        };
        if let Some(name) = current.file_name() {
            tail.push(name.to_os_string());
        }
        current = parent;
    }
}

/// Lexical path normalization: resolve `..` and `.` components without
/// touching the disk. Used as a pre-step before [`canonicalize_or_partial`]
/// to collapse any `..` and `.` components in user-supplied paths.
pub(in crate::commands::deploy) fn lexical_normalize(path: &Path) -> PathBuf {
    let mut result = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                result.pop();
            }
            std::path::Component::CurDir => {}
            other => result.push(other),
        }
    }
    result
}

/// Read the deploy target's package.json `name` field for the success
/// summary. Falls back to the directory name if `name` is missing or
/// non-string.
pub(in crate::commands::deploy) fn read_member_name(manifest_path: &Path) -> String {
    let fallback = || {
        manifest_path
            .parent()
            .and_then(|p| p.file_name())
            .map_or_else(
                || "(unnamed)".to_string(),
                |n| n.to_string_lossy().to_string(),
            )
    };
    let Ok(content) =
        lpm_common::read_text_file_capped(manifest_path, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES)
    else {
        return fallback();
    };
    let Ok(doc) =
        serde_json::from_str::<serde_json::Value>(lpm_common::strip_utf8_bom_str(&content))
    else {
        return fallback();
    };
    doc.get("name")
        .and_then(|v| v.as_str())
        .map_or_else(fallback, |s| s.to_string())
}

pub(in crate::commands::deploy) fn normalize_relative_path(path: &Path) -> String {
    path.components()
        .filter_map(|component| match component {
            std::path::Component::Normal(part) => Some(part.to_string_lossy().to_string()),
            std::path::Component::ParentDir => Some("..".to_string()),
            std::path::Component::CurDir => None,
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// Removes `output` and everything in it without entering another volume or
/// a mount point, which `remove_dir_all` goes into on Unix and empties
/// before it fails to remove: one mounted after the guard looked stops the
/// removal there. Links are removed, not followed.
#[cfg(unix)]
#[cfg_attr(not(target_os = "linux"), allow(unused_variables))]
pub(in crate::commands::deploy) fn remove_output(output: &Path) -> std::io::Result<()> {
    let (Some(parent), Some(name)) = (output.parent(), output.file_name()) else {
        return Err(std::io::Error::other(format!(
            "{} has no parent directory",
            output.display()
        )));
    };
    let parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    // The parent is searched, never listed, as `remove_dir_all` needs: a
    // directory this user may write and search but not read can hold an
    // output it clears.
    #[cfg(target_os = "linux")]
    {
        use rustix::fs::{Mode, OFlags};
        use std::os::fd::AsFd as _;
        let parent = rustix::fs::open(
            parent,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let device = rustix::fs::fstat(&parent)?.st_dev;
        remove_tree_on(parent.as_fd(), name, device, output)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let device = rustix::fs::stat(parent)?.st_dev;
        remove_tree_on(rustix::fs::CWD, output.as_os_str(), device, output)
    }
}

/// Removes `name` in `parent`, entering a directory only on `device` and
/// only where no mount starts.
#[cfg(unix)]
fn remove_tree_on(
    parent: std::os::fd::BorrowedFd<'_>,
    name: &std::ffi::OsStr,
    device: libc::dev_t,
    path: &Path,
) -> std::io::Result<()> {
    use rustix::fs::{AtFlags, FileType, Mode, OFlags};
    use std::os::fd::AsFd as _;
    use std::os::unix::ffi::OsStrExt as _;
    let entry = rustix::fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW)?;
    if FileType::from_raw_mode(entry.st_mode) != FileType::Directory {
        rustix::fs::unlinkat(parent, name, AtFlags::empty())?;
        return Ok(());
    }
    let directory = rustix::fs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    #[cfg(target_os = "linux")]
    let starts_a_mount = starts_a_mount(parent, &directory).map_err(|error| {
        std::io::Error::other(format!(
            "can't tell whether {} starts a mount: {error}",
            path.display()
        ))
    })?;
    // Outside Linux nothing mounts part of a volume elsewhere, so every mount
    // has a device number of its own.
    #[cfg(not(target_os = "linux"))]
    let starts_a_mount = false;
    if rustix::fs::fstat(&directory)?.st_dev != device || starts_a_mount {
        return Err(std::io::Error::other(format!(
            "{} is on another volume, a mount point --force doesn't enter",
            path.display()
        )));
    }
    let mut children = Vec::new();
    for child in rustix::fs::Dir::read_from(&directory)? {
        let child = child?;
        let child = child.file_name().to_bytes();
        if child != b"." && child != b".." {
            children.push(std::ffi::OsString::from(std::ffi::OsStr::from_bytes(child)));
        }
    }
    for child in &children {
        remove_tree_on(directory.as_fd(), child, device, &path.join(child))?;
    }
    rustix::fs::unlinkat(parent, name, AtFlags::REMOVEDIR)?;
    Ok(())
}

/// Whether `directory`, opened in `parent`, starts a mount, which a bind
/// mount of a directory on the same volume does without another device
/// number.
#[cfg(target_os = "linux")]
fn starts_a_mount(
    parent: std::os::fd::BorrowedFd<'_>,
    directory: &std::os::fd::OwnedFd,
) -> std::io::Result<bool> {
    use rustix::fs::{AtFlags, StatxAttributes, StatxFlags};
    let reported = rustix::fs::statx(directory, "", AtFlags::EMPTY_PATH, StatxFlags::empty())
        .ok()
        .and_then(|status| {
            status
                .stx_attributes_mask
                .contains(StatxAttributes::MOUNT_ROOT)
                .then(|| status.stx_attributes.contains(StatxAttributes::MOUNT_ROOT))
        });
    mount_answer(reported, || Ok((mount_id(parent)?, mount_id(directory)?)))
}

/// What `statx` reports of a mount's root, or, where it reports nothing
/// (Linux before 5.8, or a failed call), whether the parent's and the
/// directory's mounts differ; an answer neither gives is an error, as the
/// removal must not guess.
#[cfg(any(target_os = "linux", test))]
pub(in crate::commands::deploy) fn mount_answer(
    reported: Option<bool>,
    mount_ids: impl FnOnce() -> std::io::Result<(u64, u64)>,
) -> std::io::Result<bool> {
    match reported {
        Some(answer) => Ok(answer),
        None => {
            let (parent, directory) = mount_ids()?;
            Ok(parent != directory)
        }
    }
}

/// The mount a descriptor is on, as `/proc/self/fdinfo` names it.
#[cfg(target_os = "linux")]
pub(in crate::commands::deploy) fn mount_id(
    descriptor: impl std::os::fd::AsFd,
) -> std::io::Result<u64> {
    use std::os::fd::AsRawFd as _;
    let info = lpm_common::read_file_capped(
        &Path::new("/proc/self/fdinfo").join(descriptor.as_fd().as_raw_fd().to_string()),
        FDINFO_CAP_BYTES,
    )
    .map_err(|error| std::io::Error::other(error.to_string()))?;
    parse_mount_id(&info).ok_or_else(|| std::io::Error::other("fdinfo names no mount"))
}

#[cfg(target_os = "linux")]
const FDINFO_CAP_BYTES: u64 = 64 * 1024;

/// The `mnt_id:` line of an fdinfo file, there since Linux 3.15.
#[cfg(any(target_os = "linux", test))]
pub(in crate::commands::deploy) fn parse_mount_id(info: &[u8]) -> Option<u64> {
    info.split(|byte| *byte == b'\n').find_map(|line| {
        std::str::from_utf8(line.strip_prefix(b"mnt_id:")?)
            .ok()?
            .trim()
            .parse()
            .ok()
    })
}

/// Windows removes a folder a volume is mounted on as the link it is.
#[cfg(not(unix))]
pub(in crate::commands::deploy) fn remove_output(output: &Path) -> std::io::Result<()> {
    std::fs::remove_dir_all(output)
}
