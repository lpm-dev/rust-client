#![no_main]

use libfuzzer_sys::fuzz_target;
use lpm_extractor::sanitize_entry_path;
use std::path::{Component, PathBuf};

#[cfg(unix)]
fn path_from_bytes(data: &[u8]) -> PathBuf {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    PathBuf::from(OsStr::from_bytes(data))
}

#[cfg(not(unix))]
fn path_from_bytes(data: &[u8]) -> PathBuf {
    PathBuf::from(String::from_utf8_lossy(data).into_owned())
}

fuzz_target!(|data: &[u8]| {
    if data.len() > 4096 {
        return;
    }

    let path = path_from_bytes(data);
    let Ok(sanitized) = sanitize_entry_path(&path) else {
        return;
    };
    let Some(relative) = sanitized else {
        return;
    };

    assert!(relative.components().all(|component| {
        !matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    }));
});
