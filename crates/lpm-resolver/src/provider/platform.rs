use super::prelude::*;

/// Compile-time platform detection for the current build target, plus
/// runtime libc probing.
///
/// `os` and `cpu` are resolved from `cfg!()` macros against the build
/// target. `libc` is probed at runtime from the host filesystem (see
/// [`lpm_common::platform::detect_libc`]) because the lpm binary's own
/// libc doesn't have to match the host's libc — a glibc-built lpm on
/// Alpine would mis-detect via `cfg!(target_env)` alone.
///
/// This represents the current host only. Cross-platform resolution would
/// need a caller-supplied target tuple instead of this helper.
pub(crate) struct Platform {
    pub os: &'static str,
    pub cpu: &'static str,
    /// `Some("glibc")` / `Some("musl")` on Linux when the loader is
    /// identifiable; `None` on every other platform and on Linux hosts
    /// where neither loader can be probed.
    pub libc: Option<&'static str>,
}

impl Platform {
    pub fn current() -> Self {
        Self {
            os: if cfg!(target_os = "macos") {
                "darwin"
            } else if cfg!(target_os = "linux") {
                "linux"
            } else if cfg!(target_os = "windows") {
                "win32"
            } else if cfg!(target_os = "freebsd") {
                "freebsd"
            } else {
                "unknown"
            },
            cpu: if cfg!(target_arch = "x86_64") {
                "x64"
            } else if cfg!(target_arch = "aarch64") {
                "arm64"
            } else if cfg!(target_arch = "x86") {
                "ia32"
            } else if cfg!(target_arch = "arm") {
                "arm"
            } else {
                "unknown"
            },
            libc: lpm_common::platform::detect_libc(),
        }
    }
}

/// Check if a platform filter matches, following npm's semantics.
///
/// Platform filtering follows npm's semantics:
/// - If ANY entry starts with '!', the filter is treated as exclusion-only
///   e.g., `["darwin", "!win32"]` → exclusion mode → only "!win32" matters, "darwin" is ignored
/// - If no entries start with '!', the filter is treated as inclusion
///   e.g., `["darwin", "linux"]` → only these platforms are allowed
///
/// This matches npm's behavior: <https://docs.npmjs.com/cli/v9/configuring-npm/package-json#os>
pub(super) fn check_platform_filter(entries: &[String], current: &str, field_name: &str) -> bool {
    if entries.is_empty() {
        return true;
    }

    let has_exclusions = entries.iter().any(|e| e.starts_with('!'));
    let has_inclusions = entries.iter().any(|e| !e.starts_with('!'));

    if has_exclusions && has_inclusions {
        tracing::debug!(
            "mixed include/exclude in {field_name} filter: {entries:?} — using exclusion mode (positive entries ignored)"
        );
    }

    if has_exclusions {
        // Exclusion mode: ALL exclusions must not match
        entries.iter().all(|e| {
            if let Some(stripped) = e.strip_prefix('!') {
                stripped != current
            } else {
                true
            }
        })
    } else {
        // Inclusion mode: at least one must match
        entries.iter().any(|e| e == current)
    }
}

/// Check if a package version is compatible with the current platform.
/// Empty os/cpu/libc means no restriction (compatible with all platforms).
/// Entries starting with `!` are exclusions (e.g., `!win32` = all except win32).
pub fn is_platform_compatible(meta: &PlatformMeta) -> bool {
    is_platform_compatible_for(meta, &Platform::current())
}

/// Testable inner gate: the same predicate against an explicit [`Platform`]
/// rather than the host. Production code calls [`is_platform_compatible`]
/// which fixes the platform to `Platform::current()`.
///
/// libc semantics, when `meta.libc` is non-empty:
/// - `host_libc == Some(x)` → run `check_platform_filter` normally.
/// - `host_libc == None` → fail closed. The package declared a libc
///   requirement and the host couldn't be probed (non-Linux, or a
///   minimal Linux image with neither `ld-musl-*` nor `libc.so.6`
///   exposed). Materializing a libc-tagged binary in that state risks
///   a load-time interpreter mismatch, so the safer choice is to drop
///   the version and surface a `platform_skipped` count.
pub(super) fn is_platform_compatible_for(meta: &PlatformMeta, platform: &Platform) -> bool {
    let os_ok = check_platform_filter(&meta.os, platform.os, "os");
    let cpu_ok = check_platform_filter(&meta.cpu, platform.cpu, "cpu");
    let libc_ok = if meta.libc.is_empty() {
        true
    } else {
        match platform.libc {
            Some(host_libc) => check_platform_filter(&meta.libc, host_libc, "libc"),
            None => false,
        }
    };
    os_ok && cpu_ok && libc_ok
}
