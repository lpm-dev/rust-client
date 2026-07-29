//! Host platform detection helpers shared across the workspace.
//!
//! `detect_libc()` lives here so the v2 store's `PlatformTuple` keying
//! and the resolver's optional-dep platform filter agree on a single
//! definition of "this host's libc." Duplicating the probe would let
//! the two layers disagree on Alpine and silently materialize a
//! glibc-built native binary even though the store keyed correctly.
//!
//! On Linux the detection probes the host filesystem for the canonical
//! musl / glibc loader paths rather than using `cfg!(target_env)`,
//! because the lpm binary's own libc doesn't have to match the host's
//! libc (a glibc-built lpm running on Alpine would otherwise mis-detect).
//! The probe result is cached in a process-local `OnceLock`.

#[cfg(target_os = "linux")]
use std::path::Path;
#[cfg(target_os = "linux")]
use std::sync::OnceLock;

/// Serialize Keychain calls while legacy Security.framework probes may
/// temporarily change the process-wide interaction setting.
#[cfg(target_os = "macos")]
pub fn macos_keychain_operation_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| std::sync::Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Detect the running host's libc flavor.
///
/// Returns `Some("musl")` / `Some("glibc")` on Linux when the loader
/// is identifiable, `None` on every other platform and on Linux hosts
/// where neither loader can be probed.
///
/// The returned `&'static str` is one of two compile-time literals
/// (`"musl"` or `"glibc"`), so callers can keep `Option<&'static str>`
/// in cache-line-friendly structs without allocating.
#[cfg(target_os = "linux")]
pub fn detect_libc() -> Option<&'static str> {
    static CACHED: OnceLock<Option<&'static str>> = OnceLock::new();
    *CACHED.get_or_init(|| {
        if has_musl_loader() {
            return Some("musl");
        }
        if has_glibc_loader() {
            return Some("glibc");
        }
        if cfg!(target_env = "musl") {
            Some("musl")
        } else if cfg!(target_env = "gnu") {
            Some("glibc")
        } else {
            None
        }
    })
}

#[cfg(not(target_os = "linux"))]
pub fn detect_libc() -> Option<&'static str> {
    None
}

#[cfg(target_os = "linux")]
fn has_musl_loader() -> bool {
    const CANDIDATES: &[&str] = &[
        "/lib/ld-musl-x86_64.so.1",
        "/lib/ld-musl-aarch64.so.1",
        "/lib/ld-musl-armhf.so.1",
        "/lib/ld-musl-i386.so.1",
    ];
    CANDIDATES.iter().any(|p| Path::new(p).exists())
}

#[cfg(target_os = "linux")]
fn has_glibc_loader() -> bool {
    const CANDIDATES: &[&str] = &[
        "/lib/x86_64-linux-gnu/libc.so.6",
        "/lib64/libc.so.6",
        "/lib/aarch64-linux-gnu/libc.so.6",
        "/lib/libc.so.6",
    ];
    CANDIDATES.iter().any(|p| Path::new(p).exists())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_libc_is_consistent_with_target_os() {
        let probed = detect_libc();
        if cfg!(target_os = "linux") {
            if let Some(libc) = probed {
                assert!(
                    libc == "musl" || libc == "glibc",
                    "linux libc must be musl or glibc, got {libc:?}"
                );
            }
        } else {
            assert!(probed.is_none(), "non-linux host must return None");
        }
    }

    #[test]
    fn detect_libc_is_cached() {
        // OnceLock memoization: two calls return the same value, and on
        // Linux the probe never flips between callers within a process.
        let first = detect_libc();
        let second = detect_libc();
        assert_eq!(first, second);
    }
}
