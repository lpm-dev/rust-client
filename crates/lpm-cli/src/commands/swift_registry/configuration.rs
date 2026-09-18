use lpm_common::LpmError;
use serde_json::Value;
use std::path::{Path, PathBuf};

pub(super) fn global_path() -> Result<PathBuf, LpmError> {
    Ok(crate::swift_manifest::paths::configuration_dir()?.join("registries.json"))
}

fn invalid(path: &Path, detail: impl std::fmt::Display) -> LpmError {
    LpmError::Registry(format!(
        "Invalid SwiftPM configuration at {}: {detail}. Correct the existing file before retrying.",
        path.display()
    ))
}

fn validate_object<'a>(
    path: &Path,
    value: &'a Value,
    keys: &[&str],
) -> Result<Option<&'a Value>, LpmError> {
    let mut current = value;
    for key in keys {
        let Some(next) = current.get(key) else {
            return Ok(None);
        };
        current = next;
    }
    if !current.is_object() {
        return Err(invalid(
            path,
            format!("{} must be an object", keys.join(".")),
        ));
    }
    Ok(Some(current))
}

fn validate_string(path: &Path, value: &Value, key: &str, location: &str) -> Result<(), LpmError> {
    if value.get(key).is_some_and(|field| !field.is_string()) {
        return Err(invalid(path, format!("{location}.{key} must be a string")));
    }
    Ok(())
}

fn validate(path: &Path, value: &Value, host: &str) -> Result<(), LpmError> {
    validate_object(path, value, &[])?;
    if value
        .get("version")
        .is_some_and(|version| version.as_u64() != Some(1))
    {
        return Err(invalid(path, "version must be 1"));
    }
    if let Some(authentication) = validate_object(path, value, &["authentication"])? {
        for (authority, entry) in authentication.as_object().into_iter().flatten() {
            if !entry.is_object() {
                return Err(invalid(
                    path,
                    format!("authentication.{authority} must be an object"),
                ));
            }
            for key in ["type", "loginAPIPath"] {
                validate_string(path, entry, key, &format!("authentication.{authority}"))?;
            }
        }
    }
    for keys in [
        &["registries"][..],
        &["registries", "lpmdev"],
        &["security"],
        &["security", "default"],
        &["security", "default", "signing"],
        &["security", "scopeOverrides"],
        &["security", "scopeOverrides", "lpmdev"],
        &["security", "scopeOverrides", "lpmdev", "signing"],
        &["security", "registryOverrides"],
        &["security", "registryOverrides", host],
        &["security", "registryOverrides", host, "signing"],
    ] {
        if let Some(section) = validate_object(path, value, keys)? {
            if keys.last() == Some(&"signing") {
                for action in ["onUnsigned", "onUntrustedCertificate"] {
                    validate_string(path, section, action, &keys.join("."))?;
                }
            }
            if keys == ["registries", "lpmdev"] {
                validate_string(path, section, "url", "registries.lpmdev")?;
                if section
                    .get("supportsAvailability")
                    .is_some_and(|value| !value.is_boolean())
                {
                    return Err(invalid(
                        path,
                        "registries.lpmdev.supportsAvailability must be a boolean",
                    ));
                }
            }
        }
    }
    Ok(())
}

fn directory(path: &Path, create: bool) -> Result<(), LpmError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if !metadata.is_dir() || lpm_common::is_symlink_or_junction(&metadata) => Err(
            invalid(path, "configuration directory must be a real directory"),
        ),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if !create {
                return Ok(());
            }
            let parent = path
                .parent()
                .ok_or_else(|| invalid(path, "missing parent directory"))?;
            directory(parent, true)?;
            match std::fs::create_dir(path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(invalid(path, error)),
            }
            directory(path, false)
        }
        Err(error) => Err(invalid(path, error)),
    }
}

fn directories(path: &Path, create: bool) -> Result<(), LpmError> {
    let parent = path
        .parent()
        .ok_or_else(|| invalid(path, "missing parent directory"))?;
    let swiftpm = parent
        .parent()
        .ok_or_else(|| invalid(path, "missing SwiftPM directory"))?;
    directory(swiftpm, create)?;
    directory(parent, create)
}

fn regular_file(path: &Path, metadata: &std::fs::Metadata) -> Result<(), LpmError> {
    if !metadata.is_file() || lpm_common::is_symlink_or_junction(metadata) {
        return Err(invalid(
            path,
            "expected a regular file, not a link or special file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if metadata.nlink() != 1 {
            return Err(invalid(
                path,
                "hard-linked configuration files are unsupported",
            ));
        }
    }
    Ok(())
}

fn read(path: &Path) -> Result<Option<String>, LpmError> {
    directories(path, false)?;
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => regular_file(path, &metadata)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(invalid(path, error)),
    }
    lpm_common::read_text_file_capped_nofollow(path, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES)
        .map(Some)
        .map_err(|error| invalid(path, error))
}

pub(super) fn load(path: &Path, host: &str) -> Result<Value, LpmError> {
    parse(path, read(path)?.as_deref(), host)
}

fn parse(path: &Path, original: Option<&str>, host: &str) -> Result<Value, LpmError> {
    let config = match original {
        Some(content) => serde_json::from_str(content).map_err(|error| invalid(path, error))?,
        None => serde_json::json!({"version": 1}),
    };
    validate(path, &config, host)?;
    Ok(config)
}

pub(super) fn update(
    path: &Path,
    host: &str,
    mutate: impl FnOnce(&mut Value) -> Result<(), LpmError>,
) -> Result<bool, LpmError> {
    load(path, host)?;
    directories(path, true)?;
    let lock_path = path.with_file_name(".lpm-registries.lock");
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        options.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let lock_file = options
        .open(&lock_path)
        .map_err(|error| invalid(&lock_path, error))?;
    regular_file(&lock_path, &lock_file.metadata()?)?;
    let _guard = lpm_common::paths::acquire_single_file_exclusive_lock_from_file(lock_file)?;
    let original = read(path)?;
    let mut config = parse(path, original.as_deref(), host)?;
    let before = config.clone();
    mutate(&mut config)?;
    if config == before {
        return Ok(false);
    }
    validate(path, &config, host)?;
    let rendered = serde_json::to_string_pretty(&config)?;
    if rendered.len() as u64 > lpm_common::CONFIG_FILE_SIZE_CAP_BYTES {
        return Err(invalid(
            path,
            "updated configuration exceeds the size limit",
        ));
    }
    if read(path)? != original {
        return Err(invalid(path, "file changed during setup"));
    }
    lpm_common::write_file_atomic(path, rendered).map_err(|error| invalid(path, error))?;
    Ok(true)
}
