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
