use super::secret_scan::DeploySecretScan;
use crate::commands::publish_common;
use lpm_common::LpmError;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[cfg(unix)]
use super::paths::canonicalize_or_partial;

/// Names never copied to the deploy output, at any depth, on top of what
/// `lpm publish` leaves out.
///
/// - **LPM state**: `node_modules`, `.lpm`, `lpm.lock`, `lpm.lockb` are
///   recreated by the install the deploy runs, so copying them is wasted work
///   AND would mask any inconsistency.
/// - **Secrets** (CRITICAL security boundary): every `.env*` file, matched
///   separately by prefix, and every credential file publish blocks
///   (`lpm_security::behavioral::secrets::is_blocked_file`). A publish stops
///   at a credential file `files` selects; a deploy leaves them out, even a
///   developer-only `.env.local` that would otherwise ride into a Docker
///   image, and scans the rest as a publish does ([`DeploySecretScan`]).
/// - **Version control and OS cruft**.
const DEPLOY_DENY_BASENAMES: &[&str] = &[
    "node_modules",
    ".lpm",
    "lpm.lock",
    "lpm.lockb",
    ".npmrc",
    ".netrc",
    "_netrc",
    ".git",
    ".gitignore",
    ".npmignore",
    ".gitattributes",
    ".svn",
    ".hg",
    ".DS_Store",
    "Thumbs.db",
];

/// Stats from a [`write_member_source`] call, reported in the deploy's JSON
/// summary.
#[derive(Debug, Clone, Default)]
pub(in crate::commands::deploy) struct CopyStats {
    pub files_copied: usize,
    /// Files `lpm publish`'s selection includes that the deploy withholds:
    /// `.env*` files, credential files and LPM state. What the selection
    /// leaves out on its own isn't counted.
    pub files_skipped: usize,
    pub bytes_copied: u64,
}

/// Copies the files `lpm publish` would pack from `src_dir` into `dst_dir`,
/// less [`DEPLOY_DENY_BASENAMES`], `.env*` files and credential files, so a
/// deploy and a publish read `files`, `.npmignore` and `.gitignore` the same
/// way, and writes the `lpm.json` a publish ships. Each file is a clone where
/// the volume makes one (no disk cost until either is written) and a copy
/// otherwise, never a file the workspace shares.
///
/// **Security invariants:**
/// - Denied names are NEVER copied, at any depth (regression-tested).
/// - The function only writes inside `dst_dir`. It does not modify `src_dir`.
/// - Symbolic links are not copied, as a publish doesn't pack them, and no
///   path is resolved outside `src_dir` or `dst_dir`.
#[cfg(test)]
pub(in crate::commands::deploy) fn copy_member_source(
    src_dir: &Path,
    dst_dir: &Path,
) -> Result<CopyStats, LpmError> {
    write_member_source(&select_member_source(src_dir, None, None)?, dst_dir)
}

/// The files a deploy copies from one package, chosen before anything is
/// written, so that a refusal leaves the output as it was. It holds no open
/// directory and no file content, so a closure of many packages needs no
/// more of either than one. What the secret scan read is bound to what is
/// written: the bytes it read of each file, and the `lpm.json` it scanned.
pub(in crate::commands::deploy) struct MemberSelection {
    src_dir: PathBuf,
    resolved: PathBuf,
    identity: publish_common::DirectoryIdentity,
    files: Vec<publish_common::TarballFile>,
    ships_lpm_json: bool,
    /// For each of `files`, what the scan read of it; empty when no scan ran.
    scanned: Vec<Option<ScannedBytes>>,
    scanned_lpm_json: Option<[u8; 32]>,
}

/// [`MemberSelection`] for the package in `src_dir`, writing nothing, with
/// what it would copy run through `secrets`. A refusal names `provider`, a
/// workspace package the deploy copies besides the member.
pub(in crate::commands::deploy) fn select_member_source(
    src_dir: &Path,
    provider: Option<&str>,
    secrets: Option<&mut DeploySecretScan>,
) -> Result<MemberSelection, LpmError> {
    if !src_dir.exists() {
        return Err(LpmError::Script(format!(
            "deploy: source member directory {src_dir:?} does not exist"
        )));
    }

    let manifest_path = src_dir.join("package.json");
    let manifest =
        lpm_common::read_text_file_capped(&manifest_path, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES)
            .map_err(|e| {
            LpmError::Script(format!(
                "deploy: failed to read package manifest {manifest_path:?}: {e}"
            ))
        })?;
    let manifest: serde_json::Value =
        serde_json::from_str(lpm_common::strip_utf8_bom_str(&manifest))
            .map_err(|e| LpmError::Script(format!("deploy: invalid package.json: {e}")))?;
    let canonical = src_dir
        .canonicalize()
        .map_err(|e| LpmError::Script(format!("deploy: failed to resolve {src_dir:?}: {e}")))?;
    let package = manifest
        .get("name")
        .and_then(serde_json::Value::as_str)
        .map_or_else(
            || src_dir.file_name().unwrap_or_default().to_string_lossy(),
            std::borrow::Cow::Borrowed,
        );
    let select = || -> Result<_, LpmError> {
        let source = Arc::new(publish_common::open_tarball_source_root(&canonical)?);
        let identity =
            publish_common::DirectoryIdentity::from_directory(&source).map_err(LpmError::Io)?;
        let files = publish_common::collect_package_files(&manifest, &source)?;
        let lpm_json = crate::commands::publish::shipped_lpm_json(&source, src_dir)?;
        let mut scanned = Vec::new();
        let mut scanned_lpm_json = None;
        if let Some(secrets) = secrets {
            scanned.reserve_exact(files.len());
            let mut opener = publish_common::SourceFileCursor::new(&source)?;
            for file in &files {
                if file.path == "lpm.json" || deploy_denies(&file.path) {
                    scanned.push(None);
                    continue;
                }
                let relative: PathBuf = file.path.split('/').collect();
                let (opened, size) = opener.open(&relative, &file.path)?;
                scanned.push(Some(scan_bound(
                    secrets, &package, src_dir, &file.path, opened, size,
                )?));
            }
            if let Some(content) = &lpm_json {
                secrets.scan_content(&package, src_dir, "lpm.json", content)?;
                use sha2::Digest as _;
                scanned_lpm_json = Some(sha2::Sha256::digest(content).into());
            }
        }
        Ok((
            identity,
            files,
            lpm_json.is_some(),
            scanned,
            scanned_lpm_json,
        ))
    };
    let (identity, files, ships_lpm_json, scanned, scanned_lpm_json) =
        select().map_err(|error| match error {
            LpmError::Registry(message) => LpmError::Script(match provider {
                Some(name) => format!(
                    "deploy: workspace provider {name:?} ({}): {message}",
                    src_dir.display()
                ),
                None => format!("deploy: {message}"),
            }),
            other => other,
        })?;
    Ok(MemberSelection {
        src_dir: src_dir.to_path_buf(),
        resolved: canonical,
        identity,
        files,
        ships_lpm_json,
        scanned,
        scanned_lpm_json,
    })
}

/// Scans `opened`, a file `size` bytes long when it was opened, and returns
/// what the scan read of it.
pub(in crate::commands::deploy) fn scan_bound(
    secrets: &mut DeploySecretScan,
    package: &str,
    directory: &Path,
    path: &str,
    opened: impl std::io::Read,
    size: u64,
) -> Result<ScannedBytes, LpmError> {
    let mut reader = HashingReader::new(opened);
    secrets.scan_file(package, directory, path, &mut reader, size)?;
    Ok(reader.scanned(size))
}

fn source_changed(path: &Path) -> LpmError {
    LpmError::Script(format!(
        "deploy: {} changed while the deploy ran",
        path.display()
    ))
}

/// What the secret scan read of a file: the digest of its first `covered`
/// bytes, and whether they were all of it, as for an extension the scan
/// reads whole or a file that ended before the scan stopped reading;
/// otherwise they are the start a key would be found in.
#[derive(Clone, Copy, Debug)]
pub(in crate::commands::deploy) struct ScannedBytes {
    digest: [u8; 32],
    covered: u64,
    whole: bool,
}

impl ScannedBytes {
    /// Whether `file` starts with the bytes the scan read, or is them,
    /// when they were all of it.
    pub(in crate::commands::deploy) fn match_file(
        &self,
        file: &std::fs::File,
    ) -> std::io::Result<bool> {
        let limit = if self.whole {
            self.covered + 1
        } else {
            self.covered
        };
        let mut reader = HashingReader::new(std::io::Read::take(file, limit));
        std::io::copy(&mut reader, &mut std::io::sink())?;
        let read = reader.read;
        let digest: [u8; 32] = sha2::Digest::finalize(reader.hasher).into();
        Ok(read == self.covered && digest == self.digest)
    }

    #[cfg(test)]
    pub(in crate::commands::deploy) fn of_whole(content: &[u8]) -> Self {
        Self {
            digest: <sha2::Sha256 as sha2::Digest>::digest(content).into(),
            covered: content.len() as u64,
            whole: true,
        }
    }
}

/// Reads through `inner`, hashing what it reads.
struct HashingReader<R> {
    inner: R,
    hasher: sha2::Sha256,
    read: u64,
    ended: bool,
}

impl<R> HashingReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            hasher: sha2::Digest::new(),
            read: 0,
            ended: false,
        }
    }

    /// What was read of a file `size` bytes long when opened. A file that
    /// ended sooner, as one cut short while the scan read it does, was read
    /// whole, so only those bytes can stand for it.
    fn scanned(self, size: u64) -> ScannedBytes {
        ScannedBytes {
            digest: sha2::Digest::finalize(self.hasher).into(),
            covered: self.read,
            whole: self.ended || self.read == size,
        }
    }
}

impl<R: std::io::Read> std::io::Read for HashingReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(buffer)?;
        if read == 0 && !buffer.is_empty() {
            self.ended = true;
        }
        sha2::Digest::update(&mut self.hasher, &buffer[..read]);
        self.read += read as u64;
        Ok(read)
    }
}

/// The error placing a file reports when the file isn't what the secret
/// scan read.
#[derive(Debug)]
struct SourceChanged;

impl std::fmt::Display for SourceChanged {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("the file changed after the secret scan read it")
    }
}

impl std::error::Error for SourceChanged {}

/// Copies what `selection` chose into `dst_dir`, creating it.
pub(in crate::commands::deploy) fn write_member_source(
    selection: &MemberSelection,
    dst_dir: &Path,
) -> Result<CopyStats, LpmError> {
    let mut stats = CopyStats::default();
    let MemberSelection {
        src_dir,
        resolved,
        identity,
        files,
        ships_lpm_json,
        scanned,
        scanned_lpm_json,
    } = selection;
    let source = Arc::new(
        publish_common::open_tarball_source_root(resolved)
            .map_err(|error| LpmError::Script(format!("deploy: {error}")))?,
    );
    if publish_common::DirectoryIdentity::from_directory(&source).map_err(LpmError::Io)?
        != *identity
    {
        return Err(LpmError::Script(format!(
            "deploy: {} changed while the deploy ran",
            src_dir.display()
        )));
    }
    let lpm_json = if *ships_lpm_json {
        crate::commands::publish::shipped_lpm_json(&source, src_dir)
            .map_err(|error| LpmError::Script(format!("deploy: {error}")))?
    } else {
        None
    };
    if let Some(expected) = scanned_lpm_json {
        use sha2::Digest as _;
        if lpm_json
            .as_deref()
            .is_none_or(|content| <[u8; 32]>::from(sha2::Sha256::digest(content)) != *expected)
        {
            return Err(source_changed(&src_dir.join("lpm.json")));
        }
    }
    std::fs::create_dir_all(dst_dir)
        .map_err(|e| LpmError::Script(format!("failed to create deploy output dir: {e}")))?;
    let output = cap_std::fs::Dir::open_ambient_dir(dst_dir, cap_std::ambient_authority())
        .map_err(|e| LpmError::Script(format!("failed to open deploy output dir: {e}")))?;

    let mut created_dirs: HashSet<PathBuf> = HashSet::new();
    for (index, file) in files.iter().enumerate() {
        if file.path == "lpm.json" {
            continue;
        }
        if deploy_denies(&file.path) {
            stats.files_skipped += 1;
            continue;
        }
        let relative: PathBuf = file.path.split('/').collect();
        if let Some(parent) = relative.parent()
            && !parent.as_os_str().is_empty()
            && !created_dirs.contains(parent)
        {
            output.create_dir_all(parent).map_err(|e| {
                LpmError::Script(format!(
                    "failed to create dir {:?}: {e}",
                    dst_dir.join(parent)
                ))
            })?;
            created_dirs.insert(parent.to_path_buf());
        }
        let expected = scanned.get(index).copied().flatten();
        place_file(&source, &output, &relative, expected.as_ref()).map_err(|e| {
            if e.get_ref().is_some_and(|inner| inner.is::<SourceChanged>()) {
                source_changed(&src_dir.join(&relative))
            } else if e.kind() == std::io::ErrorKind::AlreadyExists {
                LpmError::Script(format!(
                    "deploy: {:?} is in the output already, under a name its filesystem takes for the same file",
                    dst_dir.join(&relative)
                ))
            } else {
                LpmError::Script(format!(
                    "failed to copy {:?} to {:?}: {e}",
                    src_dir.join(&relative),
                    dst_dir.join(&relative)
                ))
            }
        })?;
        stats.files_copied += 1;
        stats.bytes_copied += file.size;
    }
    if let Some(content) = lpm_json {
        lpm_common::write_file_atomic_in_dir_with_options(
            &output,
            std::ffi::OsStr::new("lpm.json"),
            lpm_common::AtomicWriteOptions::new(),
            |file| std::io::Write::write_all(file, &content),
        )
        .map_err(|e| {
            LpmError::Script(format!(
                "failed to write {:?}: {e}",
                dst_dir.join("lpm.json")
            ))
        })?;
        stats.files_copied += 1;
        stats.bytes_copied += content.len() as u64;
    }

    Ok(stats)
}

/// Puts `relative` from `source` in `output` as a file of its own, a clone
/// where the volume makes one and a copy otherwise, so the output shares no
/// file with the workspace: a later write to either never reaches the
/// other, and the output keeps what the secret scan read. An entry the
/// output already holds is never written into, as two selected names that
/// its filesystem takes for one file, as one that ignores case does, would
/// copy one over the other. With `expected`, what the secret scan read, an
/// entry that doesn't hold those bytes, as a file replaced or written since
/// doesn't, is taken back out and fails with [`SourceChanged`].
pub(in crate::commands::deploy) fn place_file(
    source: &cap_std::fs::Dir,
    output: &cap_std::fs::Dir,
    relative: &Path,
    expected: Option<&ScannedBytes>,
) -> std::io::Result<()> {
    copy_new(source, output, relative, expected)
}

/// Takes the entry `relative` back out of `output` unless it is a regular
/// file and, with `expected`, holds the bytes the scan read, read from the
/// entry itself. A selected file that is anything else now, a link, a FIFO
/// or one that can't be read, has changed since it was selected.
fn check_placed(
    output: &cap_std::fs::Dir,
    relative: &Path,
    expected: Option<&ScannedBytes>,
) -> std::io::Result<()> {
    let verified = match expected {
        None => output
            .symlink_metadata(relative)
            .map(|metadata| metadata.is_file()),
        Some(expected) => open_regular(output, relative).and_then(|placed| match placed {
            Some(placed) => expected.match_file(&placed),
            None => Ok(false),
        }),
    };
    if verified.unwrap_or(false) {
        return Ok(());
    }
    let _ = output.remove_file(relative);
    Err(std::io::Error::other(SourceChanged))
}

/// `relative` in `directory`, opened to read if it is a regular file there,
/// and `None` for a link, a FIFO or anything else, which opens without
/// blocking.
fn open_regular(
    directory: &cap_std::fs::Dir,
    relative: &Path,
) -> std::io::Result<Option<std::fs::File>> {
    use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt as _, OpenOptionsSyncExt as _};

    if !directory.symlink_metadata(relative)?.is_file() {
        return Ok(None);
    }
    let mut options = cap_std::fs::OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No).nonblock(true);
    let file = directory.open_with(relative, &options)?;
    Ok(file.metadata()?.is_file().then(|| file.into_std()))
}

/// Copies `relative` from `source` to a file created in `output`, with its
/// permissions; fails if `output` holds that entry already. The data moves
/// as the kernel moves it: a clone where an APFS volume makes one, else
/// `fcopyfile` on macOS and `copy_file_range` on Linux. With `expected`, the
/// copy must hold the bytes the secret scan read, or it is removed and fails
/// with [`SourceChanged`].
pub(in crate::commands::deploy) fn copy_new(
    source: &cap_std::fs::Dir,
    output: &cap_std::fs::Dir,
    relative: &Path,
    expected: Option<&ScannedBytes>,
) -> std::io::Result<()> {
    use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt as _};

    let from = match open_regular(source, relative) {
        Ok(Some(from)) => from,
        Ok(None) => return Err(std::io::Error::other(SourceChanged)),
        // The scan read it, so a file it can't open now has changed since.
        Err(_) if expected.is_some() => return Err(std::io::Error::other(SourceChanged)),
        Err(error) => return Err(error),
    };
    let take_back = |result: std::io::Result<()>| {
        if result.is_err() {
            let _ = output.remove_file(relative);
        }
        result
    };
    #[cfg(target_os = "macos")]
    if clone_new(&from, output, relative)? {
        return check_placed(output, relative, expected);
    }
    let permissions = from.metadata()?.permissions();
    let mut options = cap_std::fs::OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .follow(FollowSymlinks::No);
    let to = output.open_with(relative, &options)?.into_std();
    let copied = copy_contents(&from, &to).and_then(|()| to.set_permissions(permissions));
    drop(to);
    take_back(copied)?;
    check_placed(output, relative, expected)
}

/// Clones `from` to the new entry `relative` in `output`, as it refuses one
/// that exists: whether the volume made the clone.
#[cfg(target_os = "macos")]
fn clone_new(
    from: &std::fs::File,
    output: &cap_std::fs::Dir,
    relative: &Path,
) -> std::io::Result<bool> {
    use rustix::io::Errno;

    let name = relative
        .file_name()
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    // The output opens the parent, so no link on the way is followed.
    let parent = match relative.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => Some(output.open_dir(parent)?),
        _ => None,
    };
    match rustix::fs::fclonefileat(
        from,
        parent.as_ref().unwrap_or(output),
        name,
        rustix::fs::CloneFlags::empty(),
    ) {
        Ok(()) => Ok(true),
        Err(Errno::EXIST) => Err(std::io::ErrorKind::AlreadyExists.into()),
        // Another volume, or one that makes no clones.
        Err(Errno::XDEV | Errno::NOTSUP | Errno::OPNOTSUPP | Errno::NOSYS) => Ok(false),
        Err(error) => Err(error.into()),
    }
}

#[cfg(target_os = "macos")]
fn copy_contents(from: &std::fs::File, to: &std::fs::File) -> std::io::Result<()> {
    struct State(rustix::fs::copyfile_state_t);
    impl Drop for State {
        fn drop(&mut self) {
            // SAFETY: the state was allocated by `copyfile_state_alloc` and
            // is freed here only.
            let _ = unsafe { rustix::fs::copyfile_state_free(self.0) };
        }
    }
    let state = State(rustix::fs::copyfile_state_alloc()?);
    // SAFETY: `state` stays allocated until it drops, after the call.
    unsafe { rustix::fs::fcopyfile(from, to, state.0, rustix::fs::CopyfileFlags::DATA) }?;
    Ok(())
}

/// Linux's standard copy between files is `copy_file_range`.
#[cfg(not(target_os = "macos"))]
fn copy_contents(mut from: &std::fs::File, mut to: &std::fs::File) -> std::io::Result<()> {
    std::io::copy(&mut from, &mut to).map(drop)
}

/// Whether a package-relative `/` path names a file a deploy never copies.
fn deploy_denies(path: &str) -> bool {
    path.split('/').any(|segment| {
        lpm_common::names::fold_name(segment)
            .get(..4)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(".env"))
            || lpm_common::names::is_git_dir_name(segment)
            || publish_common::listed_in(segment, DEPLOY_DENY_BASENAMES)
    }) || lpm_security::behavioral::secrets::is_blocked_file(path)
}

#[cfg(unix)]
pub(in crate::commands::deploy) fn retarget_internal_node_modules_symlinks(
    output_dir: &Path,
) -> Result<usize, LpmError> {
    let node_modules = output_dir.join("node_modules");
    if !node_modules.exists() {
        return Ok(0);
    }
    let output_root = canonicalize_or_partial(output_dir);
    retarget_internal_symlinks_recursive(&node_modules, output_dir, &output_root)
}

#[cfg(unix)]
fn retarget_internal_symlinks_recursive(
    dir: &Path,
    output_dir: &Path,
    output_root: &Path,
) -> Result<usize, LpmError> {
    let mut retargeted = 0;
    for entry in std::fs::read_dir(dir)
        .map_err(|e| LpmError::Script(format!("deploy: failed to read {dir:?}: {e}")))?
    {
        let entry = entry
            .map_err(|e| LpmError::Script(format!("deploy: failed to read dir entry: {e}")))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|e| LpmError::Script(format!("deploy: failed to stat {path:?}: {e}")))?;
        if file_type.is_symlink() {
            let target = std::fs::read_link(&path).map_err(|e| {
                LpmError::Script(format!("deploy: failed to read symlink {path:?}: {e}"))
            })?;
            if !target.is_absolute() {
                continue;
            }
            let target_canonical = canonicalize_or_partial(&target);
            if !target_canonical.starts_with(output_root) {
                continue;
            }
            let target_for_relative = if target.starts_with(output_dir) {
                target
            } else {
                let suffix = target_canonical.strip_prefix(output_root).map_err(|e| {
                    LpmError::Script(format!(
                        "deploy: failed to strip deploy root from {target_canonical:?}: {e}"
                    ))
                })?;
                output_dir.join(suffix)
            };
            let parent = path.parent().ok_or_else(|| {
                LpmError::Script(format!("deploy: symlink path {path:?} has no parent"))
            })?;
            let relative = pathdiff::diff_paths(&target_for_relative, parent).ok_or_else(|| {
                LpmError::Script(format!(
                    "deploy: failed to compute relative symlink target from {parent:?} to {target_for_relative:?}"
                ))
            })?;
            std::fs::remove_file(&path).map_err(|e| {
                LpmError::Script(format!("deploy: failed to replace {path:?}: {e}"))
            })?;
            std::os::unix::fs::symlink(&relative, &path).map_err(|e| {
                LpmError::Script(format!("deploy: failed to write symlink {path:?}: {e}"))
            })?;
            retargeted += 1;
        } else if file_type.is_dir() {
            retargeted += retarget_internal_symlinks_recursive(&path, output_dir, output_root)?;
        }
    }
    Ok(retargeted)
}

#[cfg(not(unix))]
pub(in crate::commands::deploy) fn retarget_internal_node_modules_symlinks(
    _output_dir: &Path,
) -> Result<usize, LpmError> {
    Ok(0)
}
