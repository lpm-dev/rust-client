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
/// A value must match none of the negative entries and, when positive entries
/// are present, at least one positive entry. A sole `"any"` entry allows all.
/// Matches npm-install-checks' `checkList` predicate.
#[cfg(test)]
pub(super) fn check_platform_filter(entries: &[String], current: &str, field_name: &str) -> bool {
    check_platform_filter_values(entries.iter().map(String::as_str), current, field_name)
}

fn check_platform_filter_values<'a>(
    entries: impl IntoIterator<Item = &'a str>,
    current: &str,
    field_name: &str,
) -> bool {
    let mut entry_count = 0usize;
    let mut negative_count = 0usize;
    let mut positive_match = false;
    let mut saw_any = false;
    for entry in entries {
        entry_count += 1;
        saw_any |= entry == "any";
        if let Some(negative) = entry.strip_prefix('!') {
            negative_count += 1;
            if negative == current {
                return false;
            }
        } else if entry == current {
            positive_match = true;
        }
    }
    if entry_count == 0 || (entry_count == 1 && saw_any) {
        return true;
    }
    let compatible = positive_match || negative_count == entry_count;
    tracing::debug!(field_name, current, compatible, "checked platform filter");
    compatible
}

/// Check if a package version is compatible with the current platform.
/// Empty os/cpu/libc means no restriction (compatible with all platforms).
/// Entries starting with `!` are exclusions (e.g., `!win32` = all except win32).
pub fn is_platform_compatible(meta: &PlatformMeta) -> bool {
    is_platform_compatible_for(meta, &Platform::current())
}

pub(super) fn is_platform_compatible_values<'a>(
    os: impl IntoIterator<Item = &'a str>,
    cpu: impl IntoIterator<Item = &'a str>,
    libc: impl IntoIterator<Item = &'a str>,
) -> bool {
    is_platform_compatible_values_for(os, cpu, libc, &Platform::current())
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
    is_platform_compatible_values_for(
        meta.os.iter().map(String::as_str),
        meta.cpu.iter().map(String::as_str),
        meta.libc.iter().map(String::as_str),
        platform,
    )
}

fn is_platform_compatible_values_for<'a>(
    os: impl IntoIterator<Item = &'a str>,
    cpu: impl IntoIterator<Item = &'a str>,
    libc: impl IntoIterator<Item = &'a str>,
    platform: &Platform,
) -> bool {
    let os_ok = check_platform_filter_values(os, platform.os, "os");
    let cpu_ok = check_platform_filter_values(cpu, platform.cpu, "cpu");
    let mut libc = libc.into_iter().peekable();
    let libc_ok = if libc.peek().is_none() {
        true
    } else {
        match platform.libc {
            Some(host_libc) => check_platform_filter_values(libc, host_libc, "libc"),
            None => false,
        }
    };
    os_ok && cpu_ok && libc_ok
}
