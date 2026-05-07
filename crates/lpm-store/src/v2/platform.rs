//! Platform tuple for v2 graph keys.
//!
//! Per the Phase 66 preplan §2.2 audit lock-in, the platform component
//! is `(os, cpu, libc)`. `libc` is `Some` only on Linux — sharp /
//! esbuild and other native modules ship per-libc binaries on Linux
//! (glibc vs musl), so collapsing the libc dimension would let an
//! Alpine wrapper materialize a glibc-built native binary.
//!
//! `cfg!(target_env = "musl")` reflects how the lpm binary itself was
//! built, not the host's libc — a glibc-built lpm running on Alpine
//! would silently mis-detect. Linux detection therefore probes the host
//! filesystem at runtime (`/lib/ld-musl-*` and friends) with cfg as the
//! fallback. Result is cached in a `OnceLock` so the probe runs once
//! per process.

#[cfg(target_os = "linux")]
use std::path::Path;
#[cfg(target_os = "linux")]
use std::sync::OnceLock;

/// Concrete platform identity used as one component of a [`GraphKey`].
///
/// `os` and `cpu` use the npm-engine vocabulary
/// (`darwin` / `linux` / `win32`, `arm64` / `x64`, …) so a future
/// cross-platform consistency check can compare directly against
/// values from `node-canvas`-style `engines.os` fields.
///
/// [`GraphKey`]: crate::v2::GraphKey
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PlatformTuple {
    /// `darwin`, `linux`, `win32`, `freebsd`, …
    pub os: String,
    /// `arm64`, `x64`, `arm`, `ia32`, …
    pub cpu: String,
    /// `Some("glibc")` / `Some("musl")` on Linux; `None` everywhere else.
    pub libc: Option<String>,
}

impl PlatformTuple {
    /// Detect the running host's platform tuple.
    ///
    /// On non-Linux hosts this is a pure-cfg lookup. On Linux the libc
    /// flavor is detected at runtime (cached) because the lpm binary's
    /// own `target_env` doesn't necessarily match the host's libc.
    pub fn current() -> Self {
        Self {
            os: detect_os().to_string(),
            cpu: detect_cpu().to_string(),
            libc: detect_libc(),
        }
    }

    /// Construct an arbitrary tuple, intended for tests and for callers
    /// that already have platform info from a different source (e.g.
    /// recorded against a fixture or read off `process.platform`).
    pub fn new(os: impl Into<String>, cpu: impl Into<String>, libc: Option<String>) -> Self {
        Self {
            os: os.into(),
            cpu: cpu.into(),
            libc,
        }
    }
}

fn detect_os() -> &'static str {
    if cfg!(target_os = "macos") {
        "darwin"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "windows") {
        "win32"
    } else if cfg!(target_os = "freebsd") {
        "freebsd"
    } else {
        // Unknown host. The graph key still hashes a stable string so two
        // installs on the same unsupported OS produce the same key.
        std::env::consts::OS
    }
}

fn detect_cpu() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        "arm64"
    } else if cfg!(target_arch = "x86_64") {
        "x64"
    } else if cfg!(target_arch = "arm") {
        "arm"
    } else if cfg!(target_arch = "x86") {
        "ia32"
    } else {
        std::env::consts::ARCH
    }
}

#[cfg(target_os = "linux")]
fn detect_libc() -> Option<String> {
    static CACHED: OnceLock<Option<String>> = OnceLock::new();
    CACHED
        .get_or_init(|| {
            // Probe the host filesystem first — `cfg!(target_env)` only
            // tells us how the lpm binary was built, not what's on the
            // host. The `/lib/ld-musl-*` loader is the canonical musl
            // marker (Alpine, Void, etc.).
            if has_musl_loader() {
                return Some("musl".to_string());
            }
            // glibc systems ship `/lib*/libc.so.6` (or its symlinks).
            // We don't strictly need the negative test, but it makes
            // the result self-describing on weird minimal images
            // (distroless, etc.) — better to return the cfg fallback
            // than to assert glibc when we can't see either loader.
            if has_glibc_loader() {
                return Some("glibc".to_string());
            }
            // Fall back to cfg-time detection. This is what the lpm
            // binary was BUILT against; it's the best signal we have
            // when the filesystem doesn't expose either loader.
            if cfg!(target_env = "musl") {
                Some("musl".to_string())
            } else if cfg!(target_env = "gnu") {
                Some("glibc".to_string())
            } else {
                None
            }
        })
        .clone()
}

#[cfg(not(target_os = "linux"))]
fn detect_libc() -> Option<String> {
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
    fn current_is_consistent_with_cfg() {
        let p = PlatformTuple::current();
        // OS/CPU strings should be non-empty on every supported host.
        assert!(!p.os.is_empty());
        assert!(!p.cpu.is_empty());

        if cfg!(target_os = "linux") {
            assert_eq!(p.os, "linux");
            // libc is detected on Linux; we only assert it's present
            // (could be glibc or musl depending on host).
            assert!(p.libc.is_some(), "Linux must report a libc flavor");
            let libc = p.libc.as_deref().unwrap();
            assert!(
                libc == "glibc" || libc == "musl",
                "unexpected libc flavor: {libc}"
            );
        } else if cfg!(target_os = "macos") {
            assert_eq!(p.os, "darwin");
            assert_eq!(p.libc, None);
        } else if cfg!(target_os = "windows") {
            assert_eq!(p.os, "win32");
            assert_eq!(p.libc, None);
        }
    }

    #[test]
    fn new_constructor_round_trips() {
        let p = PlatformTuple::new("linux", "x64", Some("musl".into()));
        assert_eq!(p.os, "linux");
        assert_eq!(p.cpu, "x64");
        assert_eq!(p.libc.as_deref(), Some("musl"));
    }

    #[test]
    fn equality_distinguishes_libc() {
        let glibc = PlatformTuple::new("linux", "x64", Some("glibc".into()));
        let musl = PlatformTuple::new("linux", "x64", Some("musl".into()));
        assert_ne!(glibc, musl);
    }
}
