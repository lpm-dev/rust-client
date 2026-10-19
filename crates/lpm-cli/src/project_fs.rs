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
    let linked = metadata.file_type().is_symlink();
    #[cfg(windows)]
    let linked = {
        use cap_std::fs::MetadataExt as _;
        linked || metadata.file_attributes() & 0x0400 != 0
    };
    if metadata.is_dir() && !linked {
        directory.open_dir_nofollow(name)?.remove_open_dir_all()
    } else {
        directory.remove_file_or_symlink(name)
    }
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

#[cfg(test)]
mod tests {
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
}
