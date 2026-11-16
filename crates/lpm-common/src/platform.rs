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

/// The Mach services that serve Data Protection keychain items: secd's,
/// including the shared access group LPM's signed builds use for env values
/// and registry tokens, and securityd_system's. securityd
/// (`com.apple.SecurityServer`) is deliberately absent: it serves the trust
/// settings HTTPS clients list the system roots from, and the file-based
/// keychains it also serves stay closed by the sandbox's file rules. So is
/// trustd, which verifies certificates.
#[cfg(target_os = "macos")]
pub const MACOS_KEYCHAIN_MACH_SERVICES: &[&str] = &[
    "com.apple.securityd.xpc",
    "com.apple.securityd.general",
    "com.apple.security.kcsharing",
    "com.apple.security.octagon",
    "com.apple.securityd.ckks",
    "com.apple.securityd.sos",
    "com.apple.security.escrow-update",
    "com.apple.securityd.aps",
    "com.apple.securityd.systemkeychain",
];

/// A Mach service name LPM's lifecycle-script profile denies while allowing
/// [`MACOS_LIFECYCLE_SANDBOX_MEMBER`], which its broad Mach allowance covers.
/// A deny-by-default profile denies both, and no profile but LPM's answers
/// the pair this way, so a process can tell which sandbox closed its
/// Keychain.
#[cfg(target_os = "macos")]
pub const MACOS_LIFECYCLE_SANDBOX_MARK: &std::ffi::CStr = c"dev.lpm.sandbox.lifecycle";

#[cfg(target_os = "macos")]
pub const MACOS_LIFECYCLE_SANDBOX_MEMBER: &std::ffi::CStr = c"dev.lpm.sandbox.lifecycle.member";

#[cfg(target_os = "macos")]
mod macos_sandbox {
    use std::ffi::{CStr, c_char, c_int};

    /// `SANDBOX_FILTER_GLOBAL_NAME` from `enum sandbox_filter_type`.
    const SANDBOX_FILTER_GLOBAL_NAME: c_int = 2;

    unsafe extern "C" {
        safe static SANDBOX_CHECK_NO_REPORT: c_int;
        fn sandbox_check(pid: libc::pid_t, operation: *const c_char, filter: c_int, ...) -> c_int;
    }

    pub fn mach_lookup_denied(pid: libc::pid_t, name: &CStr) -> Option<bool> {
        // SAFETY: both strings are NUL-terminated and outlive the call; the
        // global-name filter takes exactly one `const char *` variadic argument.
        let result = unsafe {
            sandbox_check(
                pid,
                c"mach-lookup".as_ptr(),
                SANDBOX_FILTER_GLOBAL_NAME | SANDBOX_CHECK_NO_REPORT,
                name.as_ptr(),
            )
        };
        match result {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        }
    }

    #[cfg(test)]
    pub fn is_sandboxed(pid: libc::pid_t) -> bool {
        // SAFETY: a null operation with no filter asks only whether `pid` has
        // a profile, and takes no variadic arguments.
        unsafe { sandbox_check(pid, std::ptr::null(), 0) != 0 }
    }
}

/// `Some(true)` when `pid`'s Seatbelt profile denies looking up the Mach
/// service `name`, `Some(false)` when it allows it, `None` when the check
/// failed.
#[cfg(target_os = "macos")]
pub fn macos_mach_lookup_denied(pid: libc::pid_t, name: &std::ffi::CStr) -> Option<bool> {
    macos_sandbox::mach_lookup_denied(pid, name)
}

/// Which sandbox closes the macOS Keychain to this process.
#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacosKeychainDenial {
    /// LPM's own lifecycle-script sandbox, as when a package's install
    /// script runs `lpm`.
    LifecycleSandbox,
    /// Another sandbox around this process.
    OtherSandbox,
}

/// Which sandbox, if any, refuses this process the Keychain. Keychain
/// backends use it to turn the resulting `errSecNotAvailable` into an error
/// that says why, rather than one indistinguishable from a session with no
/// keychain.
#[cfg(target_os = "macos")]
pub fn macos_keychain_denial() -> Option<MacosKeychainDenial> {
    // SAFETY: getpid has no preconditions and cannot fail.
    let pid = unsafe { libc::getpid() };
    classify_keychain_denial(|name| macos_sandbox::mach_lookup_denied(pid, name))
}

#[cfg(target_os = "macos")]
fn classify_keychain_denial(
    lookup_denied: impl Fn(&std::ffi::CStr) -> Option<bool>,
) -> Option<MacosKeychainDenial> {
    if lookup_denied(c"com.apple.securityd.xpc") != Some(true) {
        return None;
    }
    let lifecycle = lookup_denied(MACOS_LIFECYCLE_SANDBOX_MARK) == Some(true)
        && lookup_denied(MACOS_LIFECYCLE_SANDBOX_MEMBER) == Some(false);
    Some(if lifecycle {
        MacosKeychainDenial::LifecycleSandbox
    } else {
        MacosKeychainDenial::OtherSandbox
    })
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

/// Whether Rosetta translates this process: an x86_64 build of LPM on an
/// arm64 Mac. Its children run the x86_64 slice of universal tools but arm64
/// tools natively, so their output matches neither an Intel Mac's nor a
/// native arm64 run's.
#[cfg(target_os = "macos")]
pub fn translated_by_rosetta() -> bool {
    static TRANSLATED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *TRANSLATED.get_or_init(|| {
        let mut translated: libc::c_int = 0;
        let mut size = std::mem::size_of::<libc::c_int>();
        // SAFETY: the name is NUL-terminated, and `translated` and `size`
        // describe a writable buffer of the size passed.
        let status = unsafe {
            libc::sysctlbyname(
                c"sysctl.proc_translated".as_ptr(),
                (&raw mut translated).cast(),
                &mut size,
                std::ptr::null_mut(),
                0,
            )
        };
        status == 0 && translated == 1
    })
}

/// Whether Rosetta translates this process. Only macOS has Rosetta.
#[cfg(not(target_os = "macos"))]
pub fn translated_by_rosetta() -> bool {
    false
}

/// The Windows system directory, normally `C:\Windows\System32`.
///
/// Asked of Windows itself rather than read from `SystemRoot` or found
/// on `PATH`, so a program LPM starts from here (such as `cmd.exe`) can't
/// be swapped through the environment or the working directory.
#[cfg(windows)]
pub fn windows_system_directory() -> std::io::Result<std::path::PathBuf> {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;

    let mut buffer = vec![0_u16; 260];
    loop {
        let capacity = u32::try_from(buffer.len()).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Windows system directory path is too long",
            )
        })?;
        // SAFETY: `buffer` is writable for `capacity` UTF-16 units for the
        // duration of this synchronous call.
        let written = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), capacity) } as usize;
        if written == 0 {
            return Err(std::io::Error::last_os_error());
        }
        if written < buffer.len() {
            buffer.truncate(written);
            return Ok(std::path::PathBuf::from(OsString::from_wide(&buffer)));
        }
        buffer.resize(written + 1, 0);
    }
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

    #[cfg(target_os = "macos")]
    #[test]
    fn a_process_outside_any_sandbox_is_not_reported_as_keychain_denied() {
        // SAFETY: getpid has no preconditions and cannot fail.
        if macos_sandbox::is_sandboxed(unsafe { libc::getpid() }) {
            return;
        }
        assert_eq!(macos_keychain_denial(), None);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_keychain_refusal_is_put_down_to_lpms_sandbox_only_when_its_mark_answers() {
        fn classify(denied: &[&std::ffi::CStr]) -> Option<MacosKeychainDenial> {
            classify_keychain_denial(|name| Some(denied.contains(&name)))
        }
        let securityd: &std::ffi::CStr = c"com.apple.securityd.xpc";
        assert_eq!(
            classify(&[securityd, MACOS_LIFECYCLE_SANDBOX_MARK]),
            Some(MacosKeychainDenial::LifecycleSandbox)
        );
        assert_eq!(
            classify(&[
                securityd,
                MACOS_LIFECYCLE_SANDBOX_MARK,
                MACOS_LIFECYCLE_SANDBOX_MEMBER
            ]),
            Some(MacosKeychainDenial::OtherSandbox),
            "a deny-by-default profile denies the mark's sibling too"
        );
        assert_eq!(
            classify(&[securityd]),
            Some(MacosKeychainDenial::OtherSandbox)
        );
        assert_eq!(classify(&[]), None);
    }

    /// Every service the system's secd and securityd_system launch
    /// definitions advertise must be on the list, so a macOS release that
    /// adds one can't reopen the Keychain to lifecycle scripts unnoticed.
    #[cfg(target_os = "macos")]
    #[test]
    fn every_data_protection_keychain_service_this_macos_advertises_is_listed() {
        for plist in [
            "/System/Library/LaunchAgents/com.apple.secd.plist",
            "/System/Library/LaunchDaemons/com.apple.securityd.system.plist",
        ] {
            let output = std::process::Command::new("/usr/bin/plutil")
                .args(["-extract", "MachServices", "json", "-o", "-", plist])
                .output()
                .unwrap();
            assert!(output.status.success(), "{plist}: {output:?}");
            let services: serde_json::Map<String, serde_json::Value> =
                serde_json::from_slice(&output.stdout).unwrap();
            assert!(!services.is_empty(), "{plist} advertises no services");
            for service in services.keys() {
                assert!(
                    MACOS_KEYCHAIN_MACH_SERVICES.contains(&service.as_str()),
                    "{plist} advertises {service}, which lifecycle scripts can still reach"
                );
            }
        }
    }

    #[test]
    fn only_an_x86_64_build_on_macos_can_be_translated_by_rosetta() {
        if !(cfg!(target_os = "macos") && std::env::consts::ARCH == "x86_64") {
            assert!(!translated_by_rosetta());
        }
    }

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

    #[cfg(windows)]
    #[test]
    fn windows_system_directory_is_the_absolute_directory_holding_cmd_exe() {
        let system = windows_system_directory().unwrap();
        assert!(system.is_absolute(), "{}", system.display());
        assert!(system.join("cmd.exe").is_file(), "{}", system.display());
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
