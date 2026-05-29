//! OS and architecture detection for downloading pre-built binaries.

use lpm_common::LpmError;

/// Supported platforms for managed runtime downloads.
const SUPPORTED_PLATFORMS: &str = "Node: darwin-arm64, darwin-x64, linux-x64, linux-arm64, win-x64; Bun: darwin-aarch64, darwin-x64, linux-aarch64, linux-x64, linux-*-musl, windows-*";

/// Current platform information.
#[derive(Debug, Clone)]
pub struct Platform {
    /// Operating system: "darwin", "linux", "win"
    pub os: &'static str,
    /// CPU architecture: "arm64", "x64"
    pub arch: &'static str,
}

impl Platform {
    /// Detect the current platform.
    ///
    /// Returns an error with a clear message listing supported platforms
    /// if the current OS or architecture is not recognized.
    pub fn current() -> Result<Self, LpmError> {
        let os = detect_os();
        let arch = detect_arch();

        if os == "unknown" {
            return Err(LpmError::Script(format!(
                "unsupported operating system (target_os = \"{}\"). \
				 Supported platforms: {SUPPORTED_PLATFORMS}",
                std::env::consts::OS
            )));
        }

        if arch == "unknown" {
            return Err(LpmError::Script(format!(
                "unsupported CPU architecture (target_arch = \"{}\"). \
				 Supported platforms: {SUPPORTED_PLATFORMS}",
                std::env::consts::ARCH
            )));
        }

        Ok(Platform { os, arch })
    }

    /// Node.js distribution filename suffix.
    /// e.g., "darwin-arm64", "linux-x64", "win-x64"
    pub fn node_suffix(&self) -> String {
        format!("{}-{}", self.os, self.arch)
    }

    /// Bun distribution filename suffix.
    ///
    /// Bun follows installer target names such as `darwin-aarch64`,
    /// `linux-x64-musl`, `linux-x64-baseline`, and `windows-x64`.
    pub fn bun_suffix(&self) -> String {
        self.bun_suffix_with(detect_avx2(), lpm_common::platform::detect_libc())
    }

    pub(crate) fn bun_suffix_with(&self, has_avx2: bool, libc: Option<&str>) -> String {
        let os = match self.os {
            "win" => "windows",
            other => other,
        };
        let arch = match self.arch {
            "arm64" => "aarch64",
            other => other,
        };

        let mut suffix = format!("{os}-{arch}");
        if self.os == "linux" && libc == Some("musl") {
            suffix.push_str("-musl");
        }
        if self.arch == "x64" && !has_avx2 {
            suffix.push_str("-baseline");
        }
        suffix
    }
}

impl std::fmt::Display for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}-{}", self.os, self.arch)
    }
}

fn detect_os() -> &'static str {
    if cfg!(target_os = "macos") {
        "darwin"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "windows") {
        "win"
    } else {
        "unknown"
    }
}

fn detect_arch() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        "arm64"
    } else if cfg!(target_arch = "x86_64") {
        "x64"
    } else {
        "unknown"
    }
}

fn detect_avx2() -> bool {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        std::arch::is_x86_feature_detected!("avx2")
    }
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_platform_succeeds_on_known_os() {
        // Platform::current() returns Result and succeeds on supported platforms
        let p = Platform::current();
        assert!(
            p.is_ok(),
            "Platform::current() should succeed on this platform"
        );
        let p = p.unwrap();
        assert!(
            ["darwin", "linux", "win"].contains(&p.os),
            "OS should be a known value, got: {}",
            p.os
        );
        assert!(
            ["arm64", "x64"].contains(&p.arch),
            "Arch should be a known value, got: {}",
            p.arch
        );
    }

    #[test]
    fn node_suffix_format() {
        let p = Platform::current().unwrap();
        let suffix = p.node_suffix();
        assert!(suffix.contains('-'));
        // Should be something like "darwin-arm64" or "linux-x64"
        assert!(suffix.len() > 5);
    }

    #[test]
    fn bun_suffix_maps_macos_arm64_to_aarch64() {
        let p = Platform {
            os: "darwin",
            arch: "arm64",
        };
        assert_eq!(p.bun_suffix_with(true, None), "darwin-aarch64");
    }

    #[test]
    fn bun_suffix_maps_windows_os_name() {
        let p = Platform {
            os: "win",
            arch: "x64",
        };
        assert_eq!(p.bun_suffix_with(true, None), "windows-x64");
    }

    #[test]
    fn bun_suffix_adds_musl_before_baseline_for_linux_x64() {
        let p = Platform {
            os: "linux",
            arch: "x64",
        };
        assert_eq!(
            p.bun_suffix_with(false, Some("musl")),
            "linux-x64-musl-baseline"
        );
    }

    #[test]
    fn bun_suffix_does_not_add_baseline_for_arm64() {
        let p = Platform {
            os: "linux",
            arch: "arm64",
        };
        assert_eq!(p.bun_suffix_with(false, Some("glibc")), "linux-aarch64");
    }
}
