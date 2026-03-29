//! OS and architecture detection for downloading pre-built binaries.

use lpm_common::LpmError;

/// Supported platforms for Node.js runtime downloads.
const SUPPORTED_PLATFORMS: &str = "darwin-arm64, darwin-x64, linux-x64, linux-arm64, win-x64";

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

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn current_platform_succeeds_on_known_os() {
		// Finding #12: Platform::current() returns Result and succeeds on supported platforms
		let p = Platform::current();
		assert!(p.is_ok(), "Platform::current() should succeed on this platform");
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
}
