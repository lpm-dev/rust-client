use cap_fs_ext::DirExt as _;
use cap_std::fs::Dir;
use std::io;
use std::path::{Component, Path, PathBuf};

pub(crate) fn open_directory(anchor: &Path, relative: &Path) -> io::Result<Option<Dir>> {
    let mut directory = Dir::open_ambient_dir(anchor, cap_std::ambient_authority())?;
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unsafe project directory",
            ));
        };
        directory = match directory.open_dir_nofollow(Path::new(name)) {
            Ok(directory) => directory,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(io::Error::new(
                    error.kind(),
                    format!(
                        "refusing cleanup through a linked or inaccessible directory {}: {error}",
                        anchor.join(relative).display()
                    ),
                ));
            }
        };
    }
    Ok(Some(directory))
}

pub(crate) fn remove_entry(directory: &Dir, name: &Path) -> io::Result<()> {
    let mut components = name.components();
    if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unsafe cleanup entry",
        ));
    }
    let metadata = match directory.symlink_metadata(name) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if metadata.is_dir() && !is_link(&metadata) {
        directory.open_dir_nofollow(name)?.remove_open_dir_all()
    } else {
        directory.remove_file_or_symlink(name)
    }
}

/// Whether `metadata`, read without following links, describes a symbolic
/// link or a Windows junction.
pub(crate) fn is_link(metadata: &cap_std::fs::Metadata) -> bool {
    let linked = metadata.file_type().is_symlink();
    #[cfg(windows)]
    let linked = {
        use cap_std::fs::MetadataExt as _;
        linked || metadata.file_attributes() & 0x0400 != 0
    };
    linked
}

pub(crate) fn canonicalize_with_missing_tail(path: &Path) -> Option<PathBuf> {
    if let Ok(canonical) = path.canonicalize() {
        return Some(canonical);
    }
    let mut prefix = path;
    let mut suffix = Vec::new();
    loop {
        suffix.push(prefix.file_name()?);
        prefix = prefix.parent()?;
        if let Ok(mut canonical) = prefix.canonicalize() {
            for component in suffix.iter().rev() {
                canonical.push(component);
            }
            return Some(canonical);
        }
    }
}

/// Where `path` leads once every link on the way is followed, a link whose
/// destination doesn't exist yet included, with the part that doesn't exist
/// kept as written: the folder LPM would create there. A chain of more
/// links than any file system follows is left where it stands.
pub(crate) fn resolve_links_with_missing_tail(path: &Path) -> PathBuf {
    use std::path::Component;

    const MAX_LINKS: usize = 40;
    let mut pending: Vec<std::ffi::OsString> = Vec::new();
    let mut resolved = PathBuf::with_capacity(path.as_os_str().len());
    fn push_components(path: &Path, pending: &mut Vec<std::ffi::OsString>) {
        let start = pending.len();
        pending.extend(
            path.components()
                .map(|component| component.as_os_str().to_os_string()),
        );
        pending[start..].reverse();
    }
    push_components(path, &mut pending);
    let mut links = 0usize;
    while let Some(part) = pending.pop() {
        match Path::new(&part).components().next() {
            Some(Component::Prefix(_) | Component::RootDir) => {
                resolved.push(&part);
                continue;
            }
            Some(Component::CurDir) | None => continue,
            Some(Component::ParentDir) => {
                resolved.pop();
                continue;
            }
            Some(Component::Normal(_)) => resolved.push(&part),
        }
        let is_link = std::fs::symlink_metadata(&resolved)
            .is_ok_and(|metadata| lpm_common::is_symlink_or_junction(&metadata));
        if !is_link || links == MAX_LINKS {
            continue;
        }
        let Ok(destination) = std::fs::read_link(&resolved) else {
            continue;
        };
        links += 1;
        resolved.pop();
        if destination.is_absolute() {
            resolved = PathBuf::with_capacity(destination.as_os_str().len());
        }
        push_components(&destination, &mut pending);
    }
    resolved
}

/// Where the entry at `path` really sits: its folder once the links on the
/// way are followed, and its own name, which isn't followed, so one entry
/// reached through two linked folders has one identity.
pub(crate) fn resolve_entry(path: &Path) -> PathBuf {
    match (path.parent(), path.file_name()) {
        (Some(parent), Some(name)) => {
            let mut entry = resolve_links_with_missing_tail(parent);
            entry.push(name);
            entry
        }
        _ => path.to_path_buf(),
    }
}

/// `typed`, a relative path a user gave in `invocation_dir`, as a path
/// relative to `project_dir`, which holds `invocation_dir`. Leading `..`
/// leave `invocation_dir` for its parent, as the operating system resolves
/// them from a working directory; `..` past `project_dir` are kept, for the
/// command to refuse. A rooted path is returned as it is.
pub(crate) fn project_relative_path(
    invocation_dir: &std::path::Path,
    project_dir: &std::path::Path,
    typed: &std::path::Path,
) -> std::path::PathBuf {
    use std::path::Component;

    if matches!(
        typed.components().next(),
        Some(Component::Prefix(_) | Component::RootDir)
    ) {
        return typed.to_path_buf();
    }
    let Ok(invocation) = invocation_dir.strip_prefix(project_dir) else {
        return invocation_dir.join(typed);
    };
    let mut base: Vec<_> = invocation.components().collect();
    let mut escaped = 0usize;
    let mut rest = typed.components().peekable();
    while let Some(component @ (Component::ParentDir | Component::CurDir)) = rest.peek().copied() {
        rest.next();
        if component == Component::ParentDir && base.pop().is_none() {
            escaped += 1;
        }
    }
    let mut relative = std::path::PathBuf::new();
    for _ in 0..escaped {
        relative.push("..");
    }
    relative.extend(base);
    relative.extend(rest);
    relative
}

/// A Windows verbatim path (`\\?\C:\work\app`) as people and shells write
/// it (`C:\work\app`), when dropping the prefix keeps its meaning: a drive
/// path with no `/`, no `.` or `..` component, and no component ending in a
/// dot or space, which the plain form would rewrite.
pub(crate) fn plain_drive_path(verbatim: &str) -> Option<&str> {
    let rest = verbatim.strip_prefix(r"\\?\")?;
    let path = match rest.as_bytes() {
        [drive, b':', b'\\', ..] if drive.is_ascii_alphabetic() => &rest[3..],
        _ => return None,
    };
    let unchanged_by_win32 = !path.contains('/')
        && path
            .split('\\')
            .filter(|part| !part.is_empty())
            .all(|part| {
                part != "."
                    && part != ".."
                    && !part.ends_with('.')
                    && !part.ends_with(' ')
                    && !reserved_device_name(part)
            });
    unchanged_by_win32.then_some(rest)
}

/// A name Win32 reads as a device rather than a file, with or without an
/// extension or spaces before it.
fn reserved_device_name(part: &str) -> bool {
    crate::patch_fs::is_windows_reserved_component(
        part.split('.').next().unwrap_or(part).trim_end(),
    )
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    #[test]
    fn links_resolve_on_the_way_even_to_a_destination_not_created_yet() {
        let home = tempfile::tempdir().unwrap();
        let home = home.path().canonicalize().unwrap();
        std::fs::create_dir(home.join(".claude")).unwrap();
        std::os::unix::fs::symlink(home.join(".agents/skills"), home.join(".claude/skills"))
            .unwrap();
        std::fs::create_dir(home.join("dotfiles")).unwrap();
        std::os::unix::fs::symlink("dotfiles", home.join(".cursor")).unwrap();

        assert_eq!(
            super::resolve_links_with_missing_tail(&home.join(".claude/skills")),
            home.join(".agents/skills")
        );
        assert_eq!(
            super::resolve_links_with_missing_tail(&home.join(".cursor/skills/x")),
            home.join("dotfiles/skills/x")
        );
        std::os::unix::fs::symlink("loop", home.join("loop")).unwrap();
        assert_eq!(
            super::resolve_links_with_missing_tail(&home.join("loop")),
            home.join("loop")
        );
    }

    use super::*;

    #[test]
    fn typed_paths_are_rebased_from_the_invocation_directory_onto_the_project() {
        let project = std::path::Path::new("/work/app");
        let invocation = project.join("src").join("deep");
        let rebased =
            |typed: &str| project_relative_path(&invocation, project, std::path::Path::new(typed));

        assert_eq!(rebased("widgets"), std::path::Path::new("src/deep/widgets"));
        assert_eq!(
            rebased("./widgets/ui"),
            std::path::Path::new("src/deep/widgets/ui")
        );
        assert_eq!(rebased("../shared"), std::path::Path::new("src/shared"));
        assert_eq!(rebased("../../lib"), std::path::Path::new("lib"));
        assert_eq!(
            rebased("../../../outside"),
            std::path::Path::new("../outside")
        );
        assert_eq!(
            rebased("a/../b"),
            std::path::Path::new("src/deep/a/../b"),
            "a `..` after a name is left for the command to refuse"
        );
        assert_eq!(
            project_relative_path(project, project, std::path::Path::new("widgets")),
            std::path::Path::new("widgets")
        );
    }

    #[cfg(unix)]
    #[test]
    fn rooted_typed_paths_are_kept() {
        let project = std::path::Path::new("/work/app");
        assert_eq!(
            project_relative_path(
                &project.join("src"),
                project,
                std::path::Path::new("/elsewhere")
            ),
            std::path::Path::new("/elsewhere")
        );
    }

    #[test]
    fn a_verbatim_drive_path_loses_its_prefix_only_where_that_keeps_its_meaning() {
        assert_eq!(plain_drive_path(r"\\?\C:\work\app"), Some(r"C:\work\app"));
        assert_eq!(plain_drive_path(r"\\?\C:\"), Some(r"C:\"));
        for verbatim in [
            r"\\?\UNC\server\share\app",
            r"\\?\C:\work\app.",
            r"\\?\C:\work\..\app",
            r"\\?\C:\work/app",
            r"\\?\C",
            r"\\?\C:\work\aux\app",
            r"\\?\C:\work\com1.txt",
            r"\\?\C:\work\CONIN$",
            r"\\?\C:\work\conout$.log\app",
            r"\\?\C:\work\con .txt",
            r"C:\work\app",
        ] {
            assert_eq!(plain_drive_path(verbatim), None, "{verbatim}");
        }
    }
}
