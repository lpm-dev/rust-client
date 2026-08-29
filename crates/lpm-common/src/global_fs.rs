use crate::{LpmError, LpmRoot};
use cap_fs_ext::DirExt as _;
use std::ffi::OsStr;
use std::path::{Component, Path, PathBuf};

#[derive(Debug)]
pub struct GlobalStateDirectories {
    _home: cap_std::fs::Dir,
    _global: cap_std::fs::Dir,
    _installs: cap_std::fs::Dir,
    _links: cap_std::fs::Dir,
    _bin: cap_std::fs::Dir,
}

impl GlobalStateDirectories {
    pub fn open_or_create(root: &LpmRoot) -> Result<Self, LpmError> {
        ensure_real_lpm_home(root)?;
        let home = cap_std::fs::Dir::open_ambient_dir(root.root(), cap_std::ambient_authority())
            .map_err(|error| {
                contextual_io_error(error, "LPM home directory", root.root(), "open")
            })?;
        let global = open_or_create_directory(
            &home,
            OsStr::new("global"),
            &root.global_root(),
            "global install directory",
        )?;
        let installs = open_or_create_directory(
            &global,
            OsStr::new("installs"),
            &root.global_installs(),
            "global installs directory",
        )?;
        let links = open_or_create_directory(
            &global,
            OsStr::new("links"),
            &root.global_root().join("links"),
            "global links directory",
        )?;
        let bin = open_or_create_directory(
            &home,
            OsStr::new("bin"),
            &root.bin_dir(),
            "global bin directory",
        )?;
        Ok(Self {
            _home: home,
            _global: global,
            _installs: installs,
            _links: links,
            _bin: bin,
        })
    }
}

#[derive(Debug)]
pub struct GlobalInstallsDirectory {
    directory: cap_std::fs::Dir,
    display: PathBuf,
}

impl GlobalInstallsDirectory {
    pub fn open_or_create(root: &LpmRoot) -> Result<Self, LpmError> {
        ensure_real_lpm_home(root)?;
        let home = cap_std::fs::Dir::open_ambient_dir(root.root(), cap_std::ambient_authority())
            .map_err(|error| {
                contextual_io_error(error, "LPM home directory", root.root(), "open")
            })?;
        let global_display = root.global_root();
        let global = open_or_create_directory(
            &home,
            OsStr::new("global"),
            &global_display,
            "global install directory",
        )?;
        let display = root.global_installs();
        let directory = open_or_create_directory(
            &global,
            OsStr::new("installs"),
            &display,
            "global installs directory",
        )?;
        Ok(Self { directory, display })
    }

    pub fn open_or_create_install(&self, leaf: &OsStr) -> Result<GlobalInstallDirectory, LpmError> {
        validate_leaf(leaf)?;
        let display = self.display.join(leaf);
        let directory =
            open_or_create_directory(&self.directory, leaf, &display, "global install root")?;
        Ok(GlobalInstallDirectory { directory, display })
    }

    pub fn open_install_if_exists(
        &self,
        leaf: &OsStr,
    ) -> Result<Option<GlobalInstallDirectory>, LpmError> {
        validate_leaf(leaf)?;
        let display = self.display.join(leaf);
        match self.directory.open_dir_nofollow(Path::new(leaf)) {
            Ok(directory) => Ok(Some(GlobalInstallDirectory { directory, display })),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(contextual_io_error(
                error,
                "global install root",
                &display,
                "open without following filesystem links",
            )),
        }
    }

    pub fn as_dir(&self) -> &cap_std::fs::Dir {
        &self.directory
    }

    pub fn display_path(&self) -> &Path {
        &self.display
    }
}

fn ensure_real_lpm_home(root: &LpmRoot) -> Result<(), LpmError> {
    match std::fs::symlink_metadata(root.root()) {
        Ok(metadata) if crate::is_symlink_or_junction(&metadata) || !metadata.is_dir() => {
            return Err(LpmError::Io(std::io::Error::other(format!(
                "refusing LPM home directory that is not a real directory: {}",
                root.root().display()
            ))));
        }
        Ok(_) => return Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(contextual_io_error(
                error,
                "LPM home directory",
                root.root(),
                "inspect",
            ));
        }
    }
    std::fs::create_dir_all(root.root())
        .map_err(|error| contextual_io_error(error, "LPM home directory", root.root(), "create"))?;
    let metadata = std::fs::symlink_metadata(root.root()).map_err(|error| {
        contextual_io_error(error, "LPM home directory", root.root(), "inspect")
    })?;
    if crate::is_symlink_or_junction(&metadata) || !metadata.is_dir() {
        return Err(LpmError::Io(std::io::Error::other(format!(
            "refusing LPM home directory that is not a real directory: {}",
            root.root().display()
        ))));
    }
    Ok(())
}

#[derive(Debug)]
pub struct GlobalInstallDirectory {
    directory: cap_std::fs::Dir,
    display: PathBuf,
}

impl GlobalInstallDirectory {
    pub fn as_dir(&self) -> &cap_std::fs::Dir {
        &self.directory
    }

    pub fn display_path(&self) -> &Path {
        &self.display
    }

    pub fn remove_all(self) -> Result<(), LpmError> {
        let display = self.display;
        self.directory
            .remove_open_dir_all()
            .map_err(|error| contextual_io_error(error, "global install root", &display, "remove"))
    }
}

fn open_or_create_directory(
    parent: &cap_std::fs::Dir,
    component: &OsStr,
    display: &Path,
    role: &str,
) -> Result<cap_std::fs::Dir, LpmError> {
    match parent.open_dir_nofollow(Path::new(component)) {
        Ok(directory) => return Ok(directory),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(contextual_io_error(
                error,
                role,
                display,
                "open without following filesystem links",
            ));
        }
    }

    match parent.create_dir(Path::new(component)) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(contextual_io_error(error, role, display, "create")),
    }
    parent
        .open_dir_nofollow(Path::new(component))
        .map_err(|error| {
            contextual_io_error(
                error,
                role,
                display,
                "open without following filesystem links",
            )
        })
}

fn validate_leaf(leaf: &OsStr) -> Result<(), LpmError> {
    let path = Path::new(leaf);
    let mut components = path.components();
    let valid = matches!(
        components.next(),
        Some(Component::Normal(component)) if component == leaf
    ) && components.next().is_none();
    if valid {
        return Ok(());
    }
    Err(LpmError::Io(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        format!(
            "refusing global install root leaf that is not one normal path component: {:?}",
            leaf
        ),
    )))
}

fn contextual_io_error(
    error: std::io::Error,
    role: &str,
    display: &Path,
    operation: &str,
) -> LpmError {
    LpmError::Io(std::io::Error::new(
        error.kind(),
        format!(
            "failed to {operation} {role} {}: {error}",
            display.display()
        ),
    ))
}

#[cfg(test)]
mod tests {
    use super::{GlobalInstallsDirectory, GlobalStateDirectories};
    use crate::LpmRoot;
    use std::ffi::OsStr;
    use tempfile::TempDir;

    #[cfg(unix)]
    use std::os::unix::fs::symlink;

    #[cfg(unix)]
    #[test]
    fn open_or_create_refuses_symlinked_lpm_home_without_touching_target() {
        let parent = TempDir::new().unwrap();
        let victim = TempDir::new().unwrap();
        std::fs::write(victim.path().join("sentinel"), "keep").unwrap();
        let home = parent.path().join("lpm-home");
        symlink(victim.path(), &home).unwrap();

        let error = GlobalInstallsDirectory::open_or_create(&LpmRoot::from_dir(&home)).unwrap_err();

        assert!(error.to_string().contains("LPM home directory"));
        assert_eq!(
            std::fs::read_to_string(victim.path().join("sentinel")).unwrap(),
            "keep"
        );
        assert!(!victim.path().join("global").exists());
    }

    #[cfg(unix)]
    #[test]
    fn open_or_create_refuses_symlinked_global_directory_without_touching_target() {
        let home = TempDir::new().unwrap();
        let victim = TempDir::new().unwrap();
        std::fs::write(victim.path().join("sentinel"), "keep").unwrap();
        symlink(victim.path(), home.path().join("global")).unwrap();

        let error =
            GlobalInstallsDirectory::open_or_create(&LpmRoot::from_dir(home.path())).unwrap_err();

        assert!(error.to_string().contains("global install directory"));
        assert_eq!(
            std::fs::read_to_string(victim.path().join("sentinel")).unwrap(),
            "keep"
        );
        assert!(!victim.path().join("installs").exists());
    }

    #[cfg(unix)]
    #[test]
    fn state_guard_refuses_symlinked_bin_directory_without_touching_target() {
        let home = TempDir::new().unwrap();
        let victim = TempDir::new().unwrap();
        std::fs::write(victim.path().join("sentinel"), "keep").unwrap();
        symlink(victim.path(), home.path().join("bin")).unwrap();

        let error =
            GlobalStateDirectories::open_or_create(&LpmRoot::from_dir(home.path())).unwrap_err();

        assert!(error.to_string().contains("global bin directory"));
        assert_eq!(
            std::fs::read_to_string(victim.path().join("sentinel")).unwrap(),
            "keep"
        );
    }

    #[cfg(unix)]
    #[test]
    fn state_guard_refuses_symlinked_links_directory_without_touching_target() {
        let home = TempDir::new().unwrap();
        let victim = TempDir::new().unwrap();
        std::fs::create_dir(home.path().join("global")).unwrap();
        std::fs::write(victim.path().join("sentinel"), "keep").unwrap();
        symlink(victim.path(), home.path().join("global/links")).unwrap();

        let error =
            GlobalStateDirectories::open_or_create(&LpmRoot::from_dir(home.path())).unwrap_err();

        assert!(error.to_string().contains("global links directory"));
        assert_eq!(
            std::fs::read_to_string(victim.path().join("sentinel")).unwrap(),
            "keep"
        );
    }

    #[cfg(unix)]
    #[test]
    fn open_or_create_refuses_symlinked_installs_directory_without_touching_target() {
        let home = TempDir::new().unwrap();
        let victim = TempDir::new().unwrap();
        std::fs::create_dir(home.path().join("global")).unwrap();
        std::fs::write(victim.path().join("sentinel"), "keep").unwrap();
        symlink(victim.path(), home.path().join("global/installs")).unwrap();

        let error =
            GlobalInstallsDirectory::open_or_create(&LpmRoot::from_dir(home.path())).unwrap_err();

        assert!(error.to_string().contains("global installs directory"));
        assert_eq!(
            std::fs::read_to_string(victim.path().join("sentinel")).unwrap(),
            "keep"
        );
    }

    #[cfg(unix)]
    #[test]
    fn open_or_create_install_refuses_symlinked_install_root_without_touching_target() {
        let home = TempDir::new().unwrap();
        let victim = TempDir::new().unwrap();
        let installs =
            GlobalInstallsDirectory::open_or_create(&LpmRoot::from_dir(home.path())).unwrap();
        std::fs::write(victim.path().join("sentinel"), "keep").unwrap();
        symlink(victim.path(), home.path().join("global/installs/pkg@1.0.0")).unwrap();

        let error = installs
            .open_or_create_install(OsStr::new("pkg@1.0.0"))
            .unwrap_err();

        assert!(error.to_string().contains("global install root"));
        assert_eq!(
            std::fs::read_to_string(victim.path().join("sentinel")).unwrap(),
            "keep"
        );
    }

    #[cfg(unix)]
    #[test]
    fn open_install_refuses_replaced_symlink_without_removing_target() {
        let home = TempDir::new().unwrap();
        let victim = TempDir::new().unwrap();
        let installs =
            GlobalInstallsDirectory::open_or_create(&LpmRoot::from_dir(home.path())).unwrap();
        let leaf = OsStr::new("pkg@1.0.0");
        installs.open_or_create_install(leaf).unwrap();
        std::fs::remove_dir(home.path().join("global/installs/pkg@1.0.0")).unwrap();
        std::fs::write(victim.path().join("sentinel"), "keep").unwrap();
        symlink(victim.path(), home.path().join("global/installs/pkg@1.0.0")).unwrap();

        let error = installs.open_install_if_exists(leaf).unwrap_err();

        assert!(error.to_string().contains("global install root"));
        assert_eq!(
            std::fs::read_to_string(victim.path().join("sentinel")).unwrap(),
            "keep"
        );
    }

    #[test]
    fn remove_all_deletes_only_the_retained_install_directory() {
        let home = TempDir::new().unwrap();
        let installs =
            GlobalInstallsDirectory::open_or_create(&LpmRoot::from_dir(home.path())).unwrap();
        let install = installs
            .open_or_create_install(OsStr::new("pkg@1.0.0"))
            .unwrap();
        install.as_dir().create_dir("nested").unwrap();
        install.as_dir().write("nested/file", "contents").unwrap();

        install.remove_all().unwrap();

        assert!(!home.path().join("global/installs/pkg@1.0.0").exists());
        assert!(home.path().join("global/installs").is_dir());
    }
}
