//! Platform tuple for v2 graph keys: `(os, cpu, libc)`.
//!
//! `libc` is `Some` only on Linux — native modules (sharp, esbuild)
//! ship distinct glibc vs musl binaries, so collapsing this dimension
//! would let an Alpine wrapper materialize a glibc-built binary.
//!
//! libc detection is delegated to [`lpm_common::platform::detect_libc`]
//! so the resolver's optional-dep filter and the store's graph keys
//! agree on what "this host's libc" means — divergence here would let
//! the resolver select a glibc-built version and the store key it
//! under musl (or vice versa).

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
    /// On non-Linux hosts the libc slot is `None`. On Linux it's the
    /// runtime-probed flavor from [`lpm_common::platform::detect_libc`].
    pub fn current() -> Self {
        Self {
            os: detect_os().to_string(),
            cpu: detect_cpu().to_string(),
            libc: lpm_common::platform::detect_libc().map(str::to_string),
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
