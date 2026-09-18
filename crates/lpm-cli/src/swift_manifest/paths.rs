use lpm_common::LpmError;
use std::path::{Path, PathBuf};

fn shared_root(home: &Path, xdg: Option<&Path>, macos: bool) -> Result<PathBuf, LpmError> {
    if xdg.is_some_and(|path| !path.is_absolute()) {
        return Err(LpmError::Registry(
            "XDG_CONFIG_HOME must be an absolute path for SwiftPM".into(),
        ));
    }
    Ok(if macos {
        home.join("Library/org.swift.swiftpm")
    } else if let Some(xdg) = xdg {
        xdg.join("swiftpm")
    } else {
        home.join(".swiftpm")
    })
}

fn directory(name: &str) -> Result<PathBuf, LpmError> {
    let home = dirs::home_dir().ok_or_else(|| {
        LpmError::Registry("Could not determine the SwiftPM home directory".into())
    })?;
    let xdg = std::env::var_os("XDG_CONFIG_HOME");
    let path = shared_root(
        &home,
        xdg.as_deref().map(Path::new),
        cfg!(target_os = "macos"),
    )?
    .join(name);
    let mut existing = path.as_path();
    let mut missing = Vec::new();
    loop {
        match std::fs::symlink_metadata(existing) {
            Ok(_) => {
                let mut resolved = std::fs::canonicalize(existing)?;
                for component in missing.into_iter().rev() {
                    resolved.push(component);
                }
                return Ok(resolved);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                missing.push(
                    existing.file_name().ok_or_else(|| {
                        LpmError::Registry("SwiftPM directory has no parent".into())
                    })?,
                );
                existing = existing
                    .parent()
                    .ok_or_else(|| LpmError::Registry("SwiftPM directory has no parent".into()))?;
            }
            Err(error) => return Err(error.into()),
        }
    }
}

pub(crate) fn configuration_dir() -> Result<PathBuf, LpmError> {
    directory("configuration")
}
pub(crate) fn security_dir() -> Result<PathBuf, LpmError> {
    directory("security")
}

pub(super) fn append_to(command: &mut std::process::Command) -> Result<(), LpmError> {
    command
        .arg("--config-path")
        .arg(configuration_dir()?)
        .arg("--security-path")
        .arg(security_dir()?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_paths_match_swiftpm_defaults_and_xdg_precedence() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        let xdg = temp.path().join("xdg");
        assert_eq!(
            shared_root(&home, Some(&xdg), true).unwrap(),
            home.join("Library/org.swift.swiftpm")
        );
        assert_eq!(
            shared_root(&home, Some(&xdg), false).unwrap(),
            xdg.join("swiftpm")
        );
        assert_eq!(
            shared_root(&home, None, false).unwrap(),
            home.join(".swiftpm")
        );
        for value in [Path::new(""), Path::new("relative")] {
            assert!(shared_root(&home, Some(value), false).is_err());
        }
    }
}
