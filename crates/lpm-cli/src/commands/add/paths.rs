use cap_fs_ext::DirExt as _;
use cap_std::fs::Dir;
use lpm_common::LpmError;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use crate::directory_transaction::{DirectoryIdentity, directory_identity};

pub(super) fn validate_source_delivery_namespace(
    project_root_canonical: &Path,
    destination: &Path,
) -> Result<(), LpmError> {
    let relative = destination
        .strip_prefix(project_root_canonical)
        .map_err(|_| {
            LpmError::Registry(format!(
                "source delivery destination is outside the project: {}",
                destination.display()
            ))
        })?;
    // A disk that folds names, case or a mark HFS+ ignores, takes any such
    // spelling for the name itself.
    let names = |component: std::path::Component<'_>, name: &str| {
        matches!(component, std::path::Component::Normal(given)
        if given.to_str().is_some_and(|given| {
            crate::commands::publish_common::listed_in(given, &[name])
        }))
    };
    if relative
        .components()
        .next()
        .is_some_and(|component| names(component, lpm_common::PROJECT_STATE_DIR))
    {
        return Err(LpmError::Registry(format!(
            "source delivery cannot write into the reserved .lpm state directory: {}",
            destination.display()
        )));
    }
    // LPM writes these itself, `lpm add` and `remove` among them, and a
    // directory under a record file's name leaves no place for the record.
    if let Some(std::path::Component::Normal(first)) = relative.components().next()
        && let Some(first) = first.to_str()
    {
        let is_record =
            |records: &[&str]| crate::commands::publish_common::listed_in(first, records);
        if is_record(crate::commands::publish_common::PROJECT_RECORD_FILES)
            || is_record(crate::commands::publish_common::PROJECT_RECORD_DIRS)
        {
            return Err(LpmError::Registry(format!(
                "source delivery cannot write the project record {first}: {}",
                destination.display()
            )));
        }
    }
    // A file there, such as a hook, would run with the next git command.
    if relative.components().any(|component| {
        matches!(component, std::path::Component::Normal(given)
            if given.to_str().is_some_and(lpm_common::names::is_git_dir_name))
    }) {
        return Err(LpmError::Registry(format!(
            "source delivery cannot write into a git directory: {}",
            destination.display()
        )));
    }
    // So would one in a git directory under another name, as a bare
    // repository such as `vendor/tool.git` is.
    if let Some(git_directory) = destination
        .ancestors()
        .take_while(|ancestor| ancestor.starts_with(project_root_canonical))
        .find(|ancestor| lpm_common::git_directory::is_git_directory(ancestor))
    {
        return Err(LpmError::Registry(format!(
            "source delivery cannot write into a git directory: {} is in {}",
            destination.display(),
            git_directory.display()
        )));
    }
    // NTFS takes a short name, such as `LPM~1.LOC` for `lpm.lock`, for the
    // name itself in every open: `.git` at any depth, and at the root what
    // only the root reserves.
    let mut parent = project_root_canonical.to_path_buf();
    for (depth, component) in relative.components().enumerate() {
        let std::path::Component::Normal(name) = component else {
            continue;
        };
        let reserved_at_root = std::iter::once(lpm_common::PROJECT_STATE_DIR)
            .chain(
                crate::commands::publish_common::PROJECT_RECORD_FILES
                    .iter()
                    .copied(),
            )
            .chain(
                crate::commands::publish_common::PROJECT_RECORD_DIRS
                    .iter()
                    .copied(),
            )
            .filter(|_| depth == 0);
        if lpm_common::project_state::is_short_name_of(
            &parent,
            name,
            std::iter::once(".git").chain(reserved_at_root),
        ) {
            return Err(LpmError::Registry(format!(
                "source delivery cannot write {}: {} is the short name of .lpm, a git directory or a project record",
                destination.display(),
                name.to_string_lossy()
            )));
        }
        parent.push(name);
    }
    Ok(())
}

pub(super) fn portable_destination_identity(path: &Path) -> String {
    let mut identity = String::new();
    for component in path.components() {
        if !identity.is_empty() {
            identity.push('/');
        }
        identity.extend(
            component
                .as_os_str()
                .to_string_lossy()
                .chars()
                .flat_map(char::to_lowercase),
        );
    }
    identity
}

/// Validate that all extracted file paths stay within the target directory.
///
/// Prevents malicious tarballs from writing outside the extraction directory
/// using `../` or symlink tricks.
pub(super) fn validate_extracted_paths(
    files: &[PathBuf],
    _target_dir: &Path,
) -> Result<(), LpmError> {
    for file in files {
        if file.is_absolute()
            || file.components().any(|component| {
                matches!(
                    component,
                    std::path::Component::ParentDir
                        | std::path::Component::RootDir
                        | std::path::Component::Prefix(_)
                )
            })
        {
            return Err(LpmError::Registry(format!(
                "path traversal detected: '{}' escapes target directory",
                file.display()
            )));
        }
    }
    Ok(())
}

/// Compose [`resolve_safe_dest_validate`] + [`prepare_safe_dest_parent`]
/// for the test suite that exercises both phases as a single call.
///
/// Production callers hold the two phases apart so a
/// `ManifestTransaction` snapshot opens between validation and the
/// mkdir-during-copy step. See `resolve_safe_dest_validate` for the
/// threat model.
#[cfg(test)]
fn resolve_safe_dest(
    target_root_canonical: &Path,
    target_dir: &Path,
    dest_rel: &str,
) -> Result<PathBuf, LpmError> {
    let dest = resolve_safe_dest_validate(target_root_canonical, target_dir, dest_rel)?;
    let parent = dest.parent().ok_or_else(|| {
        LpmError::Registry(format!("destination '{}' has no parent", dest.display()))
    })?;
    let parent_canonical = prepare_safe_dest_parent(parent, target_root_canonical)?;
    let file_name = dest.file_name().ok_or_else(|| {
        LpmError::Registry(format!("destination '{}' has no file name", dest.display()))
    })?;
    Ok(parent_canonical.join(file_name))
}

/// Validate a write destination under a canonical target root, without
/// any filesystem side effects.
///
/// Destination-side containment for `lpm add`. `validate_extracted_paths`
/// proves the tarball did not escape extraction; this function proves
/// the user-side write does not escape `target_dir` either, including
/// via existing symlinks.
///
/// **Ordering matters.** Every check that can establish "this destination
/// is unsafe" runs BEFORE any filesystem mutation. `create_dir_all`
/// must not run before the canonical-parent containment check, because a malicious
/// `dest = "../../escape/evil.txt"` or an absolute `dest = "/tmp/elsewhere/evil.txt"`
/// would create the directory outside the target before erroring on the
/// file write. The directory side-effect was the bug; the file write was
/// already blocked.
///
/// Defense in depth, in order:
/// 1. **Lexical absolute-path reject.** `Path::join` replaces the base
///    when the join argument is absolute, so an absolute `dest_rel`
///    would route the write to whatever path the tarball asked for.
///    Reject up-front, no filesystem touch.
/// 2. **Lexical `..` / root-component reject.** Any `dest_rel` containing
///    `ParentDir` (`..`), `RootDir` (`/`), or a `Prefix` (Windows drive)
///    component cannot legitimately resolve to a path under `target_dir`.
///    Reject up-front, no filesystem touch. This kills the entire
///    `../../escape` attack class before any mkdir runs.
/// 3. **Existing-symlink reject.** If `dest_rel` resolves to an existing
///    symlink, refuse to follow/overwrite it — even if it points inside
///    target today, it can be repointed before the write.
/// 4. **Pre-mkdir ancestor canonicalization.** Walk up from the
///    destination's parent until we hit an existing ancestor; canonicalize
///    that and require it to live under `target_root_canonical`. Catches
///    the case where some intermediate dir is itself a symlink pointing
///    outside (e.g., `target_dir/foo` → `/tmp/elsewhere`,
///    `dest_rel = "foo/bar.txt"`).
///
/// The mkdir + post-mkdir re-canonicalize pair lives in
/// [`prepare_safe_dest_parent`]. The copy flow splits the two so a
/// `ManifestTransaction` snapshot can record every validated dest path
/// before any directory side effects happen.
pub(super) fn resolve_safe_dest_validate(
    target_root_canonical: &Path,
    target_dir: &Path,
    dest_rel: &str,
) -> Result<PathBuf, LpmError> {
    resolve_safe_dest_validate_planned(target_root_canonical, target_dir, dest_rel, false)
}

pub(super) fn resolve_safe_dest_validate_planned(
    target_root_canonical: &Path,
    target_dir: &Path,
    dest_rel: &str,
    removed_by_preview: bool,
) -> Result<PathBuf, LpmError> {
    let rel_path = Path::new(dest_rel);

    // Reject absolute `dest_rel`. `Path::join(absolute)` would
    // discard `target_dir` and route the write to the absolute path.
    if rel_path.is_absolute() {
        return Err(LpmError::Registry(format!(
            "destination '{dest_rel}' is absolute; only paths relative to the target are allowed"
        )));
    }

    // Reject `..`, root, and Windows-prefix components. With this
    // gate, the joined path cannot lexically escape `target_dir`, and the
    // mkdir later cannot create directories outside the target — even
    // if the canonical-parent check that follows would later catch the
    // escape attempt.
    for component in rel_path.components() {
        match component {
            std::path::Component::ParentDir => {
                return Err(LpmError::Registry(format!(
                    "destination '{dest_rel}' contains '..'; \
                     parent-directory references are not allowed in destination paths"
                )));
            }
            std::path::Component::RootDir | std::path::Component::Prefix(_) => {
                return Err(LpmError::Registry(format!(
                    "destination '{dest_rel}' contains a root or drive component; \
                     only relative paths under the target are allowed"
                )));
            }
            _ => {}
        }
    }

    let dest = target_dir.join(rel_path);

    // Refuse to overwrite/follow an existing symlink at the
    // destination itself. `symlink_metadata` does NOT follow links.
    if !removed_by_preview && let Ok(metadata) = std::fs::symlink_metadata(&dest) {
        if lpm_common::is_symlink_or_junction(&metadata) {
            return Err(LpmError::Registry(format!(
                "destination '{}' is a symlink; refusing to write through it",
                dest.display()
            )));
        }
        if !metadata.is_file() {
            return Err(LpmError::Registry(format!(
                "destination '{}' is not a regular file",
                dest.display()
            )));
        }
    }

    let parent = dest.parent().ok_or_else(|| {
        LpmError::Registry(format!("destination '{}' has no parent", dest.display()))
    })?;

    // Pre-mkdir ancestor canonicalization: walk up until we hit
    // a path that exists, canonicalize THAT (following any symlinks),
    // and require it to live under `target_root_canonical`. This catches
    // the case where an intermediate directory inside the target is
    // itself a symlink pointing outside.
    let mut probe: PathBuf = parent.to_path_buf();
    let canonical_existing_ancestor = loop {
        match probe.canonicalize() {
            Ok(c) => break c,
            Err(_) => {
                if !probe.pop() {
                    return Err(LpmError::Registry(format!(
                        "could not find any existing ancestor of '{}'",
                        parent.display()
                    )));
                }
            }
        }
    };
    if !canonical_existing_ancestor.starts_with(target_root_canonical)
        && !target_root_canonical.starts_with(&canonical_existing_ancestor)
    {
        return Err(LpmError::Registry(format!(
            "path containment violation: '{}' resolves outside target '{}'",
            dest.display(),
            target_root_canonical.display()
        )));
    }

    Ok(dest)
}

/// mkdir + post-mkdir re-canonicalize phase of [`resolve_safe_dest`].
///
/// Must be called only after [`resolve_safe_dest_validate`] has passed
/// for the dest path that owns this `parent`. Splitting these phases
/// lets the `lpm add` snapshot see every validated dest path
/// before any directory side effects happen — so a rollback restores
/// only files that legitimately needed to land under the target, not
/// anything created by an unvalidated path probe.
#[cfg(test)]
fn prepare_safe_dest_parent(
    parent: &Path,
    target_root_canonical: &Path,
) -> Result<PathBuf, LpmError> {
    let mut rollback = CreatedDirectoryRollback::new(target_root_canonical)?;
    let result =
        prepare_safe_dest_parent_tracked(parent, target_root_canonical, &mut rollback, |_| {});
    if result.is_err() {
        rollback.rollback_best_effort();
    }
    result
}

/// Create a validated destination-parent chain and report only directories
/// created by this call. An `AlreadyExists` result is never treated as
/// ownership: another actor may have won the race after validation.
pub(super) fn prepare_safe_dest_parent_tracked(
    parent: &Path,
    target_root_canonical: &Path,
    rollback: &mut CreatedDirectoryRollback,
    on_created: impl FnMut(&Path),
) -> Result<PathBuf, LpmError> {
    prepare_safe_dest_parent_with(
        parent,
        target_root_canonical,
        rollback,
        on_created,
        |current, name, _| create_destination_directory(current, name),
        |directory| directory.canonicalize(),
    )
}

pub(super) struct CreatedDirectoryRollback {
    root: Dir,
    root_canonical: PathBuf,
    directories: Vec<CreatedDirectory>,
    directory_indices: HashMap<PathBuf, usize>,
}

impl CreatedDirectoryRollback {
    pub(super) fn new(root_canonical: &Path) -> Result<Self, LpmError> {
        let root = open_destination_root(root_canonical).map_err(|error| {
            LpmError::Registry(format!(
                "could not retain destination rollback root '{}': {error}",
                root_canonical.display()
            ))
        })?;
        Ok(Self {
            root,
            root_canonical: root_canonical.to_path_buf(),
            directories: Vec::new(),
            directory_indices: HashMap::new(),
        })
    }

    pub(super) fn is_empty(&self) -> bool {
        self.directories.is_empty()
    }

    pub(super) fn rollback_best_effort(&mut self) {
        let cleanup = self.cleanup();
        if !cleanup.is_empty() {
            tracing::error!("created-directory rollback was incomplete{cleanup}");
        }
    }

    fn track(&mut self, canonical: PathBuf, identity: DirectoryIdentity) -> Result<(), LpmError> {
        let relative = canonical
            .strip_prefix(&self.root_canonical)
            .map_err(|_| {
                LpmError::Registry(format!(
                    "created destination directory '{}' is outside rollback root '{}'",
                    canonical.display(),
                    self.root_canonical.display()
                ))
            })?
            .to_path_buf();
        let parent = relative
            .parent()
            .and_then(|parent| self.directory_indices.get(parent))
            .copied();
        let index = self.directories.len();
        self.directories.push(CreatedDirectory {
            relative,
            identity,
            canonical,
            parent,
            children: Vec::new(),
        });
        if let Some(parent) = parent {
            self.directories[parent].children.push(index);
        }
        self.directory_indices
            .insert(self.directories[index].relative.clone(), index);
        Ok(())
    }

    fn cleanup(&mut self) -> String {
        self.cleanup_with(|_| {})
    }

    fn cleanup_with(&mut self, mut before_quarantine: impl FnMut(&Path)) -> String {
        fn ignore_path(_: &Path) {}

        self.cleanup_with_callbacks(&mut before_quarantine, ignore_path)
    }

    fn cleanup_with_callbacks(
        &mut self,
        mut before_quarantine: impl FnMut(&Path),
        mut before_discard: impl FnMut(&Path),
    ) -> String {
        let mut errors = Vec::new();
        for root_index in self
            .directories
            .iter()
            .enumerate()
            .filter_map(|(index, directory)| directory.parent.is_none().then_some(index))
        {
            remove_tracked_directory_branch(
                &self.root,
                &self.directories,
                root_index,
                &mut before_quarantine,
                &mut before_discard,
                &mut errors,
            );
        }
        self.directories.clear();
        self.directory_indices.clear();
        if errors.is_empty() {
            String::new()
        } else {
            format!(
                "; created-directory cleanup was incomplete: {}",
                errors.join(", ")
            )
        }
    }
}

struct CreatedDirectory {
    relative: PathBuf,
    identity: DirectoryIdentity,
    canonical: PathBuf,
    parent: Option<usize>,
    children: Vec<usize>,
}

/// Creates `name` in `parent` as `mkdir` does, so a delivered directory gets
/// the mode the umask gives and the ACL entries its parent passes on, as the
/// project's other directories do.
fn create_destination_directory(parent: &Dir, name: &OsStr) -> std::io::Result<Dir> {
    parent.create_dir(name)?;
    crate::directory_transaction::open_directory_shared(parent, name)
}

fn prepare_safe_dest_parent_with(
    parent: &Path,
    target_root_canonical: &Path,
    rollback: &mut CreatedDirectoryRollback,
    mut on_created: impl FnMut(&Path),
    mut create_directory: impl FnMut(&Dir, &OsStr, &Path) -> std::io::Result<Dir>,
    mut canonicalize: impl FnMut(&Path) -> std::io::Result<PathBuf>,
) -> Result<PathBuf, LpmError> {
    // Containment is proven before creating the parent.
    let mut missing = Vec::new();
    let mut probe = parent;
    loop {
        match std::fs::symlink_metadata(probe) {
            Ok(_) => break,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                missing.push(probe.to_path_buf());
                probe = probe.parent().ok_or_else(|| {
                    LpmError::Registry(format!(
                        "could not find an existing ancestor of '{}'",
                        parent.display()
                    ))
                })?;
            }
            Err(error) => {
                return Err(LpmError::Registry(format!(
                    "could not inspect destination parent '{}': {error}",
                    probe.display()
                )));
            }
        }
    }
    let mut canonical_current = canonicalize(probe).map_err(|error| {
        LpmError::Registry(format!(
            "could not canonicalize existing destination ancestor '{}': {error}",
            probe.display()
        ))
    })?;
    if !canonical_current.starts_with(target_root_canonical) {
        return Err(LpmError::Registry(format!(
            "path containment violation: '{}' resolves outside target '{}'",
            parent.display(),
            target_root_canonical.display()
        )));
    }

    let mut current = open_destination_root(target_root_canonical).map_err(|error| {
        LpmError::Registry(format!(
            "could not open destination root '{}' without following links: {error}",
            target_root_canonical.display()
        ))
    })?;
    let existing_relative = canonical_current
        .strip_prefix(target_root_canonical)
        .map_err(|_| {
            LpmError::Registry(format!(
                "path containment violation: '{}' resolves outside target '{}'",
                parent.display(),
                target_root_canonical.display()
            ))
        })?;
    for component in existing_relative.components() {
        let std::path::Component::Normal(name) = component else {
            return Err(LpmError::Registry(format!(
                "destination ancestor '{}' has an unsafe component",
                canonical_current.display()
            )));
        };
        current = current.open_dir_nofollow(name).map_err(|error| {
            LpmError::Registry(format!(
                "could not open destination ancestor '{}' without following links: {error}",
                canonical_current.display()
            ))
        })?;
    }

    let mut created = Vec::with_capacity(missing.len());
    for directory in missing.iter().rev() {
        let name = directory.file_name().ok_or_else(|| {
            LpmError::Registry(format!(
                "destination parent '{}' has no directory component",
                directory.display()
            ))
        })?;
        match create_directory(&current, name, directory) {
            Ok(created_child) => {
                let created_identity = directory_identity(&created_child).map_err(|error| {
                    LpmError::Registry(format!(
                        "could not identify created destination parent '{}': {error}",
                        directory.display()
                    ))
                })?;
                canonical_current.push(name);
                let child = current.open_dir_nofollow(name).map_err(|error| {
                    LpmError::Registry(format!(
                        "could not open created destination parent '{}' without following links: {error}",
                        directory.display()
                    ))
                })?;
                let published_identity = directory_identity(&child).map_err(|error| {
                    LpmError::Registry(format!(
                        "could not identify created destination parent '{}': {error}",
                        directory.display()
                    ))
                })?;
                if published_identity == created_identity {
                    rollback.track(canonical_current.clone(), created_identity)?;
                    created.push(canonical_current.clone());
                }
                current = child;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let child = current.open_dir_nofollow(name).map_err(|open_error| {
                    LpmError::Registry(format!(
                        "could not open concurrently created destination parent '{}' without following links: {open_error}",
                        directory.display()
                    ))
                })?;
                canonical_current.push(name);
                current = child;
            }
            Err(error) => {
                return Err(LpmError::Registry(format!(
                    "could not create destination parent '{}': {error}",
                    directory.display()
                )));
            }
        }
    }

    // Post-mkdir re-canonicalize. If a TOCTOU race swapped in a
    // symlink after validation, this surfaces it.
    let parent_canonical = match canonicalize(parent) {
        Ok(parent_canonical) => parent_canonical,
        Err(error) => {
            return Err(LpmError::Registry(format!(
                "could not canonicalize destination parent '{}': {error}",
                parent.display()
            )));
        }
    };
    if parent_canonical != canonical_current || !parent_canonical.starts_with(target_root_canonical)
    {
        return Err(LpmError::Registry(format!(
            "path containment violation post-create: '{}' resolves outside target or changed during creation '{}'",
            parent.display(),
            target_root_canonical.display()
        )));
    }

    for directory in &created {
        on_created(directory);
    }

    Ok(parent_canonical)
}

fn open_relative_directory(root: &Dir, relative: &Path) -> std::io::Result<Dir> {
    let mut current = root.try_clone()?;
    for component in relative.components() {
        let std::path::Component::Normal(name) = component else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "rollback directory has an unsafe relative component",
            ));
        };
        current = current.open_dir_nofollow(name)?;
    }
    Ok(current)
}

#[derive(Clone, Copy)]
enum CreatedDirectoryTraversal {
    Down(usize),
    Up(usize),
}

fn created_directory_traversal(
    directories: &[CreatedDirectory],
    root_index: usize,
) -> Vec<CreatedDirectoryTraversal> {
    let mut traversal =
        Vec::with_capacity(directories[root_index].children.len().saturating_mul(2));
    let mut pending = vec![(root_index, 0usize)];
    while let Some((index, next_child)) = pending.last_mut() {
        if let Some(&child) = directories[*index].children.get(*next_child) {
            *next_child += 1;
            traversal.push(CreatedDirectoryTraversal::Down(child));
            pending.push((child, 0));
        } else {
            let (completed, _) = pending.pop().expect("pending traversal frame");
            if !pending.is_empty() {
                traversal.push(CreatedDirectoryTraversal::Up(completed));
            }
        }
    }
    traversal
}

fn validate_created_directory(
    directory: &Dir,
    directories: &[CreatedDirectory],
    index: usize,
) -> std::io::Result<()> {
    if directory_identity(directory)? != directories[index].identity {
        return Err(std::io::Error::other("directory identity changed"));
    }
    let mut actual = directory
        .entries()?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<std::io::Result<Vec<_>>>()?;
    actual.sort_unstable();
    let mut expected = directories[index]
        .children
        .iter()
        .map(|child| {
            directories[*child]
                .relative
                .file_name()
                .expect("tracked directory has a name")
                .to_os_string()
        })
        .collect::<Vec<_>>();
    expected.sort_unstable();
    if actual != expected {
        return Err(std::io::Error::new(
            std::io::ErrorKind::DirectoryNotEmpty,
            "directory contents changed",
        ));
    }
    Ok(())
}

fn validate_quarantined_directory_branch(
    root: &Dir,
    directories: &[CreatedDirectory],
    root_index: usize,
    traversal: &[CreatedDirectoryTraversal],
) -> std::io::Result<()> {
    validate_created_directory(root, directories, root_index)?;
    let mut current = root.try_clone()?;
    for operation in traversal {
        match *operation {
            CreatedDirectoryTraversal::Down(child) => {
                let name = directories[child]
                    .relative
                    .file_name()
                    .expect("tracked directory has a name");
                current = current.open_dir_nofollow(name)?;
                validate_created_directory(&current, directories, child)?;
            }
            CreatedDirectoryTraversal::Up(child) => {
                let parent_index = directories[child]
                    .parent
                    .expect("non-root traversal node has a parent");
                let parent = crate::directory_transaction::open_directory_parent(&current)?;
                if directory_identity(&parent)? != directories[parent_index].identity {
                    return Err(std::io::Error::other("directory parent identity changed"));
                }
                current = parent;
            }
        }
    }
    Ok(())
}

fn remove_quarantined_directory_descendants(
    root: &Dir,
    directories: &[CreatedDirectory],
    root_index: usize,
    traversal: &[CreatedDirectoryTraversal],
) -> std::io::Result<()> {
    let mut current = root.try_clone()?;
    let mut current_index = root_index;
    for operation in traversal {
        match *operation {
            CreatedDirectoryTraversal::Down(child) => {
                let name = directories[child]
                    .relative
                    .file_name()
                    .expect("tracked directory has a name");
                let child_directory = current.open_dir_nofollow(name)?;
                if directory_identity(&child_directory)? != directories[child].identity {
                    return Err(std::io::Error::other("directory identity changed"));
                }
                current = child_directory;
                current_index = child;
            }
            CreatedDirectoryTraversal::Up(child) => {
                debug_assert_eq!(current_index, child);
                let parent_index = directories[child]
                    .parent
                    .expect("non-root traversal node has a parent");
                let parent = crate::directory_transaction::open_directory_parent(&current)?;
                if directory_identity(&parent)? != directories[parent_index].identity {
                    return Err(std::io::Error::other("directory parent identity changed"));
                }
                drop(current);
                parent.remove_dir(
                    directories[child]
                        .relative
                        .file_name()
                        .expect("tracked directory has a name"),
                )?;
                current = parent;
                current_index = parent_index;
            }
        }
    }
    debug_assert_eq!(current_index, root_index);
    Ok(())
}

fn remove_tracked_directory_branch(
    root: &Dir,
    directories: &[CreatedDirectory],
    root_index: usize,
    before_quarantine: &mut impl FnMut(&Path),
    before_discard: &mut impl FnMut(&Path),
    errors: &mut Vec<String>,
) {
    let directory = &directories[root_index];
    let relative = &directory.relative;
    let canonical = &directory.canonical;
    let Some(name) = relative.file_name() else {
        errors.push(format!(
            "{}: directory has no relative name",
            canonical.display()
        ));
        return;
    };
    let relative_parent = relative.parent().unwrap_or_else(|| Path::new(""));
    let parent = match open_relative_directory(root, relative_parent) {
        Ok(parent) => parent,
        Err(error) => {
            errors.push(format!("{}: {error}", canonical.display()));
            return;
        }
    };
    let (private_name, private_directory) =
        match crate::directory_transaction::create_private_directory_in_project(&parent, "rollback")
        {
            Ok(created) => created,
            Err(error) => {
                errors.push(format!("{}: {error}", canonical.display()));
                return;
            }
        };
    before_quarantine(canonical);
    if let Err(error) = parent.rename(name, &private_directory, OsStr::new("directory")) {
        discard_private_rollback_directory(private_directory, canonical, errors);
        if error.kind() == std::io::ErrorKind::NotFound {
            return;
        }
        errors.push(format!("{}: {error}", canonical.display()));
        return;
    }
    let quarantined = match crate::directory_transaction::open_directory_for_publication(
        &private_directory,
        OsStr::new("directory"),
    ) {
        Ok(directory) => directory,
        Err(error) => {
            let restore = crate::directory_transaction::publish_entry_noreplace(
                &private_directory,
                OsStr::new("directory"),
                &parent,
                name,
            );
            match restore {
                Ok(()) => {
                    discard_private_rollback_directory(private_directory, canonical, errors);
                    errors.push(format!("{}: {error}", canonical.display()));
                }
                Err(restore_error) => errors.push(format!(
                    "{}: {error}; quarantined replacement could not be restored from '{}': {restore_error}",
                    canonical.display(),
                    private_name.to_string_lossy()
                )),
            }
            return;
        }
    };
    let restoration = QuarantinedCreatedDirectoryRestoration {
        parent: &parent,
        name,
        private_name: &private_name,
        canonical,
    };
    let traversal = created_directory_traversal(directories, root_index);
    let cleanup_result =
        validate_quarantined_directory_branch(&quarantined, directories, root_index, &traversal)
            .and_then(|()| {
                remove_quarantined_directory_descendants(
                    &quarantined,
                    directories,
                    root_index,
                    &traversal,
                )
            });
    if let Err(error) = cleanup_result {
        restore_quarantined_created_directory(
            &restoration,
            private_directory,
            quarantined,
            error,
            errors,
        );
        return;
    }
    before_discard(canonical);
    let restore_handle = match quarantined.try_clone() {
        Ok(handle) => handle,
        Err(error) => {
            restore_quarantined_created_directory(
                &restoration,
                private_directory,
                quarantined,
                error,
                errors,
            );
            return;
        }
    };
    if let Err(error) = crate::directory_transaction::discard_private_directory(quarantined) {
        restore_quarantined_created_directory(
            &restoration,
            private_directory,
            restore_handle,
            error,
            errors,
        );
        return;
    }
    drop(restore_handle);
    discard_private_rollback_directory(private_directory, canonical, errors);
}

struct QuarantinedCreatedDirectoryRestoration<'a> {
    parent: &'a Dir,
    name: &'a OsStr,
    private_name: &'a OsStr,
    canonical: &'a Path,
}

fn restore_quarantined_created_directory(
    restoration: &QuarantinedCreatedDirectoryRestoration<'_>,
    private_directory: Dir,
    quarantined: Dir,
    failure: impl std::fmt::Display,
    errors: &mut Vec<String>,
) {
    let restore = crate::directory_transaction::publish_directory_noreplace(
        &private_directory,
        &quarantined,
        OsStr::new("directory"),
        restoration.parent,
        restoration.name,
    );
    drop(quarantined);
    match restore {
        Ok(()) => {
            discard_private_rollback_directory(private_directory, restoration.canonical, errors);
            errors.push(format!("{}: {failure}", restoration.canonical.display()));
        }
        Err(restore_error) => errors.push(format!(
            "{}: {failure}; quarantined directory could not be restored from '{}': {restore_error}",
            restoration.canonical.display(),
            restoration.private_name.to_string_lossy()
        )),
    }
}

fn discard_private_rollback_directory(directory: Dir, canonical: &Path, errors: &mut Vec<String>) {
    if let Err(error) = crate::directory_transaction::discard_private_directory(directory) {
        errors.push(format!(
            "{}: could not discard private rollback directory: {error}",
            canonical.display()
        ));
    }
}

#[cfg(unix)]
fn open_destination_root(path: &Path) -> std::io::Result<Dir> {
    use std::os::unix::fs::OpenOptionsExt as _;

    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    options.open(path).map(Dir::from_std_file)
}

#[cfg(windows)]
fn open_destination_root(path: &Path) -> std::io::Result<Dir> {
    use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    };

    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "destination root is linked or not a directory",
        ));
    }
    Ok(Dir::from_std_file(file))
}

#[cfg(not(any(unix, windows)))]
fn open_destination_root(path: &Path) -> std::io::Result<Dir> {
    Dir::open_ambient_dir(path, cap_std::ambient_authority())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_delivery_never_writes_into_a_git_directory() {
        let project = Path::new("/project");
        for destination in [
            ".git/hooks/pre-commit",
            ".GIT/config",
            "vendor/sub/.git/hooks/post-checkout",
            ".g\u{200C}it/hooks/pre-commit",
            "\u{200E}.git/HEAD",
            // A Linux casefold directory ignores every default-ignorable
            // code point, and git reads these as `.git` everywhere.
            ".g\u{200B}it/HEAD",
            ".git./hooks/pre-commit",
            "vendor/.Git /HEAD",
            "GIT~1/config",
        ] {
            let error = validate_source_delivery_namespace(project, &project.join(destination))
                .unwrap_err()
                .to_string();
            assert!(error.contains("git directory"), "{destination}: {error}");
        }
        for destination in [
            ".github/workflows/ci.yml",
            "src/git/index.ts",
            ".gitignore",
            ".git.d/a",
        ] {
            validate_source_delivery_namespace(project, &project.join(destination))
                .unwrap_or_else(|error| panic!("{destination}: {error}"));
        }
    }

    #[test]
    fn source_delivery_never_writes_into_a_git_directory_under_another_name() {
        let project = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(project.path()).unwrap();
        let bare = root.join("vendor").join("tool.git");
        for directory in ["objects", "refs"] {
            std::fs::create_dir_all(bare.join(directory)).unwrap();
        }
        std::fs::write(bare.join("HEAD"), "ref: refs/heads/main\n").unwrap();
        std::fs::create_dir_all(root.join("vendor").join("notes.git")).unwrap();

        for destination in [bare.join("hooks").join("pre-commit"), bare.join("config")] {
            let error = validate_source_delivery_namespace(&root, &destination)
                .unwrap_err()
                .to_string();
            assert!(error.contains("git directory"), "{destination:?}: {error}");
        }
        validate_source_delivery_namespace(
            &root,
            &root.join("vendor").join("notes.git").join("hooks.md"),
        )
        .unwrap();
    }

    /// A volume that makes short names resolves them from any system; a
    /// second name for the same file or directory stands in for one here.
    #[cfg(unix)]
    #[test]
    fn source_delivery_refuses_a_short_name_on_any_system() {
        let project = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(project.path()).unwrap();
        std::fs::write(root.join("lpm.lock"), "").unwrap();
        std::fs::hard_link(root.join("lpm.lock"), root.join("LPM~1.LOC")).unwrap();
        std::fs::create_dir_all(root.join("vendor/.git")).unwrap();
        std::os::unix::fs::symlink(".git", root.join("vendor/GIT~2")).unwrap();
        for destination in [
            root.join("LPM~1.LOC"),
            root.join("vendor/GIT~2/hooks/pre-commit"),
        ] {
            let error = validate_source_delivery_namespace(&root, &destination)
                .unwrap_err()
                .to_string();
            assert!(error.contains("short name"), "{destination:?}: {error}");
        }
    }

    #[cfg(windows)]
    #[test]
    fn source_delivery_never_writes_a_record_git_or_lpm_through_its_ntfs_short_name() {
        let project = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(project.path()).unwrap();
        std::fs::write(root.join("lpm.lock"), "").unwrap();
        std::fs::create_dir_all(root.join("lpm-changes")).unwrap();
        std::fs::create_dir_all(root.join("vendor/.git")).unwrap();
        let short = |path: &str| crate::commands::publish_common::ntfs_short_name(&root.join(path));
        let Some(lock) = short("lpm.lock") else {
            // The volume makes no short names.
            return;
        };
        let changes = short("lpm-changes").unwrap();
        let git = short("vendor/.git").unwrap();
        for destination in [root.join(&lock), root.join(&changes).join("next.md")] {
            let error = validate_source_delivery_namespace(&root, &destination)
                .unwrap_err()
                .to_string();
            assert!(error.contains("short name"), "{destination:?}: {error}");
        }
        // `.git`'s short name is usually `GIT~1`, which git reads as `.git`
        // by its name already; any other is refused as a short name.
        let destination = root.join("vendor").join(&git).join("hooks/pre-commit");
        let error = validate_source_delivery_namespace(&root, &destination)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("git directory") || error.contains("short name"),
            "{destination:?}: {error}"
        );
        // A record's name, and `.lpm`, are reserved only at the project's
        // root, as their own spellings are.
        std::fs::create_dir_all(root.join("lib/.lpm")).unwrap();
        std::fs::write(root.join("lib/lpm.lock"), "").unwrap();
        for nested in ["lib/lpm.lock", "lib/.lpm"] {
            let short_name = short(nested).unwrap();
            validate_source_delivery_namespace(&root, &root.join("lib").join(short_name))
                .unwrap_or_else(|error| panic!("{nested}: {error}"));
        }
    }

    #[test]
    fn resolve_safe_dest_normal_path_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path();
        let canonical = target.canonicalize().unwrap();
        let resolved = resolve_safe_dest(&canonical, target, "components/foo.tsx").unwrap();
        assert!(resolved.starts_with(&canonical));
        assert!(resolved.ends_with("foo.tsx"));
    }

    #[test]
    fn resolve_safe_dest_dotdot_in_path_rejected_with_no_external_dir_created() {
        // The path must be rejected before mkdir can leave a stray
        // `target_dir/../escaped/` directory outside the target.
        let outer = tempfile::tempdir().unwrap();
        let target = outer.path().join("project").join("src").join("copied");
        std::fs::create_dir_all(&target).unwrap();
        let canonical = target.canonicalize().unwrap();

        let err = resolve_safe_dest(&canonical, &target, "../../escaped/evil.txt")
            .expect_err("should reject");
        match err {
            LpmError::Registry(msg) => {
                assert!(
                    msg.contains("'..'") || msg.contains("parent-directory"),
                    "expected lexical `..` reject, got: {msg}"
                );
            }
            other => panic!("expected Registry error, got {other:?}"),
        }

        // No directory is created outside target_dir.
        let escaped_within_project = outer.path().join("project").join("escaped");
        assert!(
            !escaped_within_project.exists(),
            "containment failure: '{}' was created as a side-effect before the error fired",
            escaped_within_project.display(),
        );
        let canonical_outer = outer.path().canonicalize().unwrap();
        for entry in std::fs::read_dir(&canonical_outer).unwrap().flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            assert_eq!(
                name, "project",
                "containment failure: unexpected entry '{name}' in outer tempdir",
            );
        }
    }

    #[test]
    fn resolve_safe_dest_absolute_dest_rejected_with_no_external_dir_created() {
        // `target_dir.join(absolute)` returns the absolute path verbatim,
        // so the lexical absolute-path reject must fire before any mkdir.
        let outer = tempfile::tempdir().unwrap();
        let target = outer.path().join("project").join("src").join("copied");
        std::fs::create_dir_all(&target).unwrap();
        let canonical = target.canonicalize().unwrap();

        // Use a deterministic external path inside an UNRELATED tempdir
        // so the test cannot accidentally observe the test harness's
        // own scratch directory.
        let elsewhere =
            std::env::temp_dir().join(format!("lpm-abs-dest-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&elsewhere);
        let abs_dest = elsewhere.join("evil.txt");
        let abs_dest_str = abs_dest.to_string_lossy().to_string();

        let err = resolve_safe_dest(&canonical, &target, &abs_dest_str)
            .expect_err("should reject absolute dest");
        match err {
            LpmError::Registry(msg) => {
                assert!(
                    msg.contains("absolute"),
                    "expected lexical absolute-path reject, got: {msg}"
                );
            }
            other => panic!("expected Registry error, got {other:?}"),
        }

        // The external directory must not be created.
        assert!(
            !elsewhere.exists(),
            "containment failure: absolute-dest mkdir leaked outside target — '{}' was created",
            elsewhere.display(),
        );
    }

    #[test]
    fn resolve_safe_dest_dotdot_in_middle_of_path_also_rejected() {
        // `foo/../bar.txt` lexically resolves back inside target, but we
        // still reject it: legitimate package authors don't need
        // parent-references in their dest paths, and accepting them
        // would force a more complex lexical-resolution path that's
        // easier to get wrong than a blanket reject.
        let outer = tempfile::tempdir().unwrap();
        let target = outer.path().join("project").join("copied");
        std::fs::create_dir_all(&target).unwrap();
        let canonical = target.canonicalize().unwrap();

        let err = resolve_safe_dest(&canonical, &target, "foo/../bar.txt")
            .expect_err("should reject `..` in middle");
        match err {
            LpmError::Registry(msg) => assert!(
                msg.contains("'..'") || msg.contains("parent-directory"),
                "expected lexical `..` reject, got: {msg}"
            ),
            other => panic!("expected Registry error, got {other:?}"),
        }
        // No `foo/` created inside target.
        assert!(
            !target.join("foo").exists(),
            "containment failure: even a benign-looking `foo/../bar.txt` should not mkdir `foo/`"
        );
    }

    #[test]
    fn resolve_safe_dest_existing_symlink_destination_rejected() {
        // Pre-create target_dir/foo as a symlink to /tmp/elsewhere
        // and confirm resolve_safe_dest refuses to write through it.
        #[cfg(unix)]
        {
            let dir = tempfile::tempdir().unwrap();
            let elsewhere = tempfile::tempdir().unwrap();
            let target = dir.path();
            let canonical = target.canonicalize().unwrap();
            let symlink_path = target.join("foo");
            std::os::unix::fs::symlink(elsewhere.path(), &symlink_path).unwrap();

            let err = resolve_safe_dest(&canonical, target, "foo").expect_err("should reject");
            match err {
                LpmError::Registry(msg) => assert!(
                    msg.contains("symlink"),
                    "expected symlink-refusal error, got: {msg}"
                ),
                other => panic!("expected Registry error, got {other:?}"),
            }
        }
    }

    #[test]
    fn resolve_safe_dest_intermediate_symlink_dir_rejected() {
        // target/foo/ is a symlink to /tmp/elsewhere. Writing `foo/bar.txt`
        // would resolve to `/tmp/elsewhere/bar.txt` — outside the target
        // root. The canonical-parent check must catch this.
        #[cfg(unix)]
        {
            let dir = tempfile::tempdir().unwrap();
            let elsewhere = tempfile::tempdir().unwrap();
            let target = dir.path();
            let canonical = target.canonicalize().unwrap();
            let symlink_dir = target.join("foo");
            std::os::unix::fs::symlink(elsewhere.path(), &symlink_dir).unwrap();

            let err =
                resolve_safe_dest(&canonical, target, "foo/bar.txt").expect_err("should reject");
            match err {
                LpmError::Registry(msg) => assert!(
                    msg.contains("path containment violation"),
                    "expected containment error, got: {msg}"
                ),
                other => panic!("expected Registry error, got {other:?}"),
            }
        }
    }

    // The validate phase is the half of `resolve_safe_dest` that has
    // NO directory side effects. `lpm add`'s rollback flow opens a
    // `ManifestTransaction` snapshot between validation and the
    // mkdir-during-copy step, so validate must reject every malicious
    // dest_rel without creating ancestor directories. Otherwise a
    // failed `lpm add` would leave empty directories under the
    // target that the rollback can't reach.

    #[test]
    fn resolve_safe_dest_validate_does_not_mkdir_on_success() {
        // Happy path. `dest_rel` points inside an existing target dir;
        // validate must NOT create the `components/` parent that the
        // copy step would later need. That mkdir belongs in the
        // separate prepare phase.
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path();
        let canonical = target.canonicalize().unwrap();
        let dest_path =
            resolve_safe_dest_validate(&canonical, target, "components/foo.tsx").unwrap();
        assert_eq!(dest_path, target.join("components/foo.tsx"));
        assert!(
            !target.join("components").exists(),
            "validate must not create ancestor directories"
        );
    }

    #[test]
    fn resolve_safe_dest_validate_rejects_dotdot_without_mkdir() {
        let outer = tempfile::tempdir().unwrap();
        let target = outer.path().join("project").join("src").join("copied");
        std::fs::create_dir_all(&target).unwrap();
        let canonical = target.canonicalize().unwrap();

        let err = resolve_safe_dest_validate(&canonical, &target, "../../escaped/evil.txt")
            .expect_err("should reject");
        match err {
            LpmError::Registry(msg) => assert!(
                msg.contains("'..'") || msg.contains("parent-directory"),
                "expected `..` reject, got: {msg}"
            ),
            other => panic!("expected Registry error, got {other:?}"),
        }
        assert!(
            !outer.path().join("escaped").exists(),
            "validate must not create directories outside target"
        );
    }

    #[test]
    fn resolve_safe_dest_validate_rejects_absolute_without_mkdir() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path();
        let canonical = target.canonicalize().unwrap();
        // Build an absolute path that lives outside the target.
        let scratch = tempfile::tempdir().unwrap();
        let abs_dest = scratch.path().join("evil.txt");
        let abs_dest_str = abs_dest.to_string_lossy();

        let err = resolve_safe_dest_validate(&canonical, target, &abs_dest_str)
            .expect_err("should reject absolute path");
        match err {
            LpmError::Registry(msg) => assert!(
                msg.contains("absolute"),
                "expected absolute reject, got: {msg}"
            ),
            other => panic!("expected Registry error, got {other:?}"),
        }
    }

    #[test]
    fn write_path_pins_canonical_parent_through_intermediate_symlink() {
        // The copy flow must compose the final dest path from the
        // canonicalized parent: `parent_canonical.join(file_name)`.
        // This test reproduces the symlinked-intermediate-parent
        // case (inside target, so validation passes) and asserts
        // that the composed path follows the canonical resolution
        // — i.e., points at the real underlying directory, not the
        // symlinked alias.
        #[cfg(unix)]
        {
            let outer = tempfile::tempdir().unwrap();
            let target = outer.path().join("project").join("components");
            let real_dir = target.join("real");
            std::fs::create_dir_all(&real_dir).unwrap();
            // Create a symlinked alias INSIDE target pointing at real_dir.
            std::os::unix::fs::symlink(&real_dir, target.join("aliased")).unwrap();
            let target_root_canonical = target.canonicalize().unwrap();

            // Validate the path through the symlinked alias. Validation
            // passes because the canonical ancestor (real_dir) lives
            // inside target_root_canonical.
            let validated =
                resolve_safe_dest_validate(&target_root_canonical, &target, "aliased/foo.tsx")
                    .expect("validation should pass for symlink-inside-target");
            // Pre-canonicalize path runs through `aliased/`.
            assert!(
                validated.to_string_lossy().contains("aliased"),
                "validate returns the pre-canonicalize path, got {validated:?}"
            );

            // Prepare phase canonicalizes the parent. Returns the
            // CANONICAL parent — production composes the final dest
            // from this, not from the pre-canonicalize value.
            let parent_canonical =
                prepare_safe_dest_parent(validated.parent().unwrap(), &target_root_canonical)
                    .unwrap();
            let file_name = validated.file_name().unwrap();
            let final_dest = parent_canonical.join(file_name);

            // Production must write through the canonical resolution
            // (`real/foo.tsx`), NOT through the alias (`aliased/foo.tsx`).
            // Using the alias path here would reintroduce a
            // write-through-symlink risk.
            let canonical_target = real_dir.canonicalize().unwrap();
            assert_eq!(
                final_dest,
                canonical_target.join("foo.tsx"),
                "final dest must use the canonical parent, got {final_dest:?}"
            );
            assert!(
                !final_dest.to_string_lossy().contains("aliased"),
                "final dest must not retain the symlinked-alias name, got {final_dest:?}"
            );
        }
    }

    #[test]
    fn resolve_safe_dest_validate_rejects_dest_that_is_existing_symlink_without_mkdir() {
        // The dest path itself already resolves through a symlink.
        // Validate must reject before mkdir touches the parent chain.
        #[cfg(unix)]
        {
            let outer = tempfile::tempdir().unwrap();
            let target = outer.path().join("target");
            std::fs::create_dir_all(&target).unwrap();
            let canonical = target.canonicalize().unwrap();
            let outside = outer.path().join("outside");
            std::fs::create_dir_all(&outside).unwrap();

            // Create a symlink at `<target>/dest.tsx` → `<outside>`.
            std::os::unix::fs::symlink(&outside, target.join("dest.tsx")).unwrap();

            let err = resolve_safe_dest_validate(&canonical, &target, "dest.tsx")
                .expect_err("should reject existing symlink at dest");
            match err {
                LpmError::Registry(msg) => assert!(
                    msg.contains("symlink"),
                    "expected symlink reject, got: {msg}"
                ),
                other => panic!("expected Registry error, got {other:?}"),
            }
        }
    }

    #[test]
    fn prepare_safe_dest_parent_does_not_claim_a_directory_created_by_a_racing_actor() {
        let project = tempfile::tempdir().unwrap();
        let canonical_project = project.path().canonicalize().unwrap();
        let parent = project.path().join("components").join("nested");
        let mut recorded = Vec::new();
        let mut rollback = CreatedDirectoryRollback::new(&canonical_project).unwrap();

        let canonical_parent = prepare_safe_dest_parent_with(
            &parent,
            &canonical_project,
            &mut rollback,
            |directory| recorded.push(directory.to_path_buf()),
            |current, name, _| {
                current.create_dir(name)?;
                Err::<Dir, _>(std::io::Error::from(std::io::ErrorKind::AlreadyExists))
            },
            |directory| directory.canonicalize(),
        )
        .unwrap();

        assert_eq!(canonical_parent, parent.canonicalize().unwrap());
        assert!(recorded.is_empty());
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn prepare_safe_dest_parent_does_not_claim_a_replacement_after_successful_creation() {
        let project = tempfile::tempdir().unwrap();
        let canonical_project = project.path().canonicalize().unwrap();
        let parent = project.path().join("components");
        let displaced = project.path().join("displaced-components");
        let mut recorded = Vec::new();
        let mut rollback = CreatedDirectoryRollback::new(&canonical_project).unwrap();

        prepare_safe_dest_parent_with(
            &parent,
            &canonical_project,
            &mut rollback,
            |directory| recorded.push(directory.to_path_buf()),
            |current, name, directory| {
                let created = create_destination_directory(current, name)?;
                std::fs::rename(directory, &displaced)?;
                std::fs::create_dir(directory)?;
                Ok(created)
            },
            |directory| directory.canonicalize(),
        )
        .unwrap();
        rollback.rollback_best_effort();

        assert!(recorded.is_empty());
        assert!(parent.is_dir());
        assert!(displaced.is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn prepare_safe_dest_parent_reports_canonical_directories_created_through_an_internal_link() {
        let project = tempfile::tempdir().unwrap();
        let real = project.path().join("real");
        std::fs::create_dir(&real).unwrap();
        std::os::unix::fs::symlink("real", project.path().join("alias")).unwrap();
        let canonical_project = project.path().canonicalize().unwrap();
        let parent = project.path().join("alias/nested");
        let mut recorded = Vec::new();
        let mut rollback = CreatedDirectoryRollback::new(&canonical_project).unwrap();

        let canonical_parent = prepare_safe_dest_parent_tracked(
            &parent,
            &canonical_project,
            &mut rollback,
            |directory| recorded.push(directory.to_path_buf()),
        )
        .unwrap();

        assert_eq!(
            canonical_parent,
            real.join("nested").canonicalize().unwrap()
        );
        assert_eq!(recorded, [real.join("nested").canonicalize().unwrap()]);
    }

    #[test]
    fn prepare_safe_dest_parent_canonicalizes_a_deep_created_chain_twice() {
        let project = tempfile::tempdir().unwrap();
        let canonical_project = project.path().canonicalize().unwrap();
        let parent = (0..64).fold(project.path().to_path_buf(), |mut path, index| {
            path.push(format!("level-{index}"));
            path
        });
        let mut canonicalizations = 0;
        let mut rollback = CreatedDirectoryRollback::new(&canonical_project).unwrap();

        let canonical_parent = prepare_safe_dest_parent_with(
            &parent,
            &canonical_project,
            &mut rollback,
            |_| {},
            |current, name, _| create_destination_directory(current, name),
            |directory| {
                canonicalizations += 1;
                directory.canonicalize()
            },
        )
        .unwrap();

        assert_eq!(canonical_parent, parent.canonicalize().unwrap());
        assert_eq!(canonicalizations, 2);
    }

    #[cfg(unix)]
    #[test]
    fn prepare_safe_dest_parent_cleanup_preserves_external_directory_after_substitution() {
        let project = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        let canonical_project = project.path().canonicalize().unwrap();
        let parent = project.path().join("components/nested");
        let external_nested = elsewhere.path().join("nested");
        std::fs::create_dir(&external_nested).unwrap();
        let mut canonicalizations = 0;
        let mut rollback = CreatedDirectoryRollback::new(&canonical_project).unwrap();

        let error = match prepare_safe_dest_parent_with(
            &parent,
            &canonical_project,
            &mut rollback,
            |_| {},
            |current, name, _| create_destination_directory(current, name),
            |directory| {
                canonicalizations += 1;
                if canonicalizations == 2 {
                    std::fs::rename(
                        project.path().join("components"),
                        project.path().join("displaced-components"),
                    )?;
                    std::os::unix::fs::symlink(
                        elsewhere.path(),
                        project.path().join("components"),
                    )?;
                }
                directory.canonicalize()
            },
        ) {
            Ok(_) => panic!("substituted destination parent unexpectedly passed validation"),
            Err(error) => error,
        };
        rollback.rollback_best_effort();

        assert!(
            error.to_string().contains("changed during creation"),
            "unexpected error: {error}"
        );
        assert!(
            external_nested.is_dir(),
            "cleanup removed a directory outside the project"
        );
    }

    #[cfg(unix)]
    #[test]
    fn created_directory_rollback_preserves_external_directory_after_substitution() {
        let project = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        let canonical_project = project.path().canonicalize().unwrap();
        let parent = project.path().join("components/nested");
        let external_nested = elsewhere.path().join("nested");
        std::fs::create_dir(&external_nested).unwrap();
        let mut rollback = CreatedDirectoryRollback::new(&canonical_project).unwrap();
        prepare_safe_dest_parent_tracked(&parent, &canonical_project, &mut rollback, |_| {})
            .unwrap();
        let displaced = project.path().join("displaced-components");
        std::fs::rename(project.path().join("components"), &displaced).unwrap();
        std::os::unix::fs::symlink(elsewhere.path(), project.path().join("components")).unwrap();

        rollback.rollback_best_effort();

        assert!(
            external_nested.is_dir(),
            "transaction rollback removed a directory outside the project"
        );
        assert!(
            displaced.join("nested").is_dir(),
            "rollback must preserve a created branch moved by another actor"
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn created_directory_rollback_preserves_a_replacement_swapped_before_quarantine() {
        let project = tempfile::tempdir().unwrap();
        let canonical_project = project.path().canonicalize().unwrap();
        let parent = project.path().join("components/nested");
        let displaced = project.path().join("displaced-components");
        let mut rollback = CreatedDirectoryRollback::new(&canonical_project).unwrap();
        prepare_safe_dest_parent_tracked(&parent, &canonical_project, &mut rollback, |_| {})
            .unwrap();
        let mut replacement_identity = None;

        let cleanup = rollback.cleanup_with(|directory| {
            std::fs::rename(directory, &displaced).unwrap();
            std::fs::create_dir(directory).unwrap();
            let replacement = open_destination_root(directory).unwrap();
            replacement_identity = Some(directory_identity(&replacement).unwrap());
        });

        let replacement = open_destination_root(&project.path().join("components")).unwrap();
        assert!(
            replacement_identity.as_ref() == Some(&directory_identity(&replacement).unwrap()),
            "rollback removed or replaced the concurrently created directory: {cleanup}"
        );
        assert!(displaced.join("nested").is_dir());
    }

    #[test]
    fn created_directory_rollback_restores_a_file_swapped_before_quarantine() {
        let project = tempfile::tempdir().unwrap();
        let canonical_project = project.path().canonicalize().unwrap();
        let parent = project.path().join("components/nested");
        let displaced = project.path().join("displaced-components");
        let replacement = project.path().join("components");
        let mut rollback = CreatedDirectoryRollback::new(&canonical_project).unwrap();
        prepare_safe_dest_parent_tracked(&parent, &canonical_project, &mut rollback, |_| {})
            .unwrap();

        let cleanup = rollback.cleanup_with(|directory| {
            std::fs::rename(directory, &displaced).unwrap();
            std::fs::write(directory, b"replacement\n").unwrap();
        });

        assert_eq!(
            std::fs::read(&replacement).unwrap(),
            b"replacement\n",
            "rollback stranded the concurrently created file: {cleanup}"
        );
        assert!(displaced.join("nested").is_dir());
    }

    #[test]
    fn created_directory_rollback_restores_content_added_after_validation() {
        let project = tempfile::tempdir().unwrap();
        let canonical_project = project.path().canonicalize().unwrap();
        let parent = project.path().join("components/nested");
        let mut rollback = CreatedDirectoryRollback::new(&canonical_project).unwrap();
        prepare_safe_dest_parent_tracked(&parent, &canonical_project, &mut rollback, |_| {})
            .unwrap();
        let original = open_destination_root(&project.path().join("components")).unwrap();
        let original_identity = directory_identity(&original).unwrap();
        drop(original);

        let cleanup = rollback.cleanup_with_callbacks(
            |_| {},
            |_| {
                let private = std::fs::read_dir(project.path())
                    .unwrap()
                    .flatten()
                    .find(|entry| {
                        entry
                            .file_name()
                            .to_string_lossy()
                            .starts_with(".lpm-rollback-")
                    })
                    .expect("private rollback directory");
                std::fs::write(private.path().join("directory/late.txt"), b"late content\n")
                    .unwrap();
            },
        );

        assert_eq!(
            std::fs::read(project.path().join("components/late.txt")).unwrap(),
            b"late content\n",
            "rollback stranded late content: {cleanup}"
        );
        let restored = open_destination_root(&project.path().join("components")).unwrap();
        assert!(
            directory_identity(&restored).unwrap() == original_identity,
            "rollback replaced the directory instead of restoring its identity: {cleanup}"
        );
        assert!(
            std::fs::read_dir(project.path())
                .unwrap()
                .flatten()
                .all(|entry| {
                    !entry
                        .file_name()
                        .to_string_lossy()
                        .starts_with(".lpm-rollback-")
                }),
            "rollback left a private wrapper behind: {cleanup}"
        );
    }

    #[test]
    fn created_directory_rollback_removes_a_multi_level_chain_from_one_root() {
        let project = tempfile::tempdir().unwrap();
        let canonical_project = project.path().canonicalize().unwrap();
        let parent = project.path().join("components/nested/deep");
        let mut rollback = CreatedDirectoryRollback::new(&canonical_project).unwrap();

        prepare_safe_dest_parent_tracked(&parent, &canonical_project, &mut rollback, |_| {})
            .unwrap();

        assert_eq!(rollback.directories.len(), 3);
        let root_index = rollback
            .directories
            .iter()
            .position(|directory| directory.parent.is_none())
            .unwrap();
        assert_eq!(
            created_directory_traversal(&rollback.directories, root_index).len(),
            2 * (rollback.directories.len() - 1)
        );
        rollback.rollback_best_effort();
        assert!(!project.path().join("components").exists());
    }

    #[test]
    fn created_directory_rollback_removes_wide_siblings_from_one_root() {
        let project = tempfile::tempdir().unwrap();
        let canonical_project = project.path().canonicalize().unwrap();
        let existing = project.path().join("src");
        std::fs::create_dir(&existing).unwrap();
        let mut rollback = CreatedDirectoryRollback::new(&canonical_project).unwrap();

        for index in 0..256 {
            prepare_safe_dest_parent_tracked(
                &existing.join(format!("branch-{index}")),
                &canonical_project,
                &mut rollback,
                |_| {},
            )
            .unwrap();
        }

        assert_eq!(rollback.directories.len(), 256);
        rollback.rollback_best_effort();
        assert_eq!(std::fs::read_dir(&existing).unwrap().count(), 0);
    }

    /// What decides who may use a directory: its mode, or its DACL.
    #[cfg(unix)]
    fn directory_access(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::metadata(path).unwrap().permissions().mode() & 0o7777
    }

    #[cfg(windows)]
    fn directory_access(path: &Path) -> String {
        let directory = Dir::open_ambient_dir(path, cap_std::ambient_authority()).unwrap();
        crate::commands::remove::windows_directory_security::test_sddl(&directory).unwrap()
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn source_delivery_creates_destination_directories_as_mkdir_does() {
        let project = tempfile::tempdir().unwrap();
        let canonical_project = project.path().canonicalize().unwrap();
        let reference = canonical_project.join("made-by-mkdir");
        std::fs::create_dir(&reference).unwrap();
        let parent = canonical_project.join("src").join("ui");

        prepare_safe_dest_parent(&parent, &canonical_project).unwrap();

        let expected = directory_access(&reference);
        assert_eq!(directory_access(&canonical_project.join("src")), expected);
        assert_eq!(directory_access(&parent), expected);
    }

    #[cfg(unix)]
    #[test]
    fn source_delivery_creates_and_rolls_back_directories_in_a_group_writable_project() {
        use std::os::unix::fs::PermissionsExt as _;

        let project = tempfile::tempdir().unwrap();
        let canonical_project = project.path().canonicalize().unwrap();
        std::fs::set_permissions(&canonical_project, std::fs::Permissions::from_mode(0o775))
            .unwrap();
        let mut rollback = CreatedDirectoryRollback::new(&canonical_project).unwrap();

        prepare_safe_dest_parent_tracked(
            &canonical_project.join("src/ui"),
            &canonical_project,
            &mut rollback,
            |_| {},
        )
        .unwrap();
        assert!(canonical_project.join("src/ui").is_dir());

        assert_eq!(rollback.cleanup(), "");
        assert!(!canonical_project.join("src").exists());
    }

    #[test]
    fn source_delivery_never_writes_the_project_s_lpm_records() {
        let project = Path::new("/project");
        for destination in [
            "lpm-sources.json",
            "LPM-Sources.json",
            "lpm-agent-skills.json",
            "lpm.lock",
            "lpm-changes/next.md",
            // As a disk that folds case beyond ASCII resolves them.
            "lpm-\u{17F}ources.json",
            "lpm-agent-s\u{212A}ills.json",
            "lpm-change\u{17F}/next.md",
            "lpm-change\u{200C}s/next.md",
            "lpm-sources.json\u{200C}",
            // A directory where the record has to go.
            "lpm.lock/copied.txt",
            "lpm-sources.json/data/x.txt",
        ] {
            let error = validate_source_delivery_namespace(project, &project.join(destination))
                .unwrap_err()
                .to_string();
            assert!(error.contains("project record"), "{destination}: {error}");
        }
        // A package's own copy, delivered below the project's root.
        validate_source_delivery_namespace(project, &project.join("vendor/lpm-sources.json"))
            .unwrap();
    }
}
