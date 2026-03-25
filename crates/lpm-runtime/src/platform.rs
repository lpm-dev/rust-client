//! OS and architecture detection for downloading pre-built binaries.

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
	pub fn current() -> Self {
		Platform {
			os: detect_os(),
			arch: detect_arch(),
		}
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
	fn current_platform_not_unknown() {
		let p = Platform::current();
		assert_ne!(p.os, "unknown");
		assert_ne!(p.arch, "unknown");
	}

	#[test]
	fn node_suffix_format() {
		let p = Platform::current();
		let suffix = p.node_suffix();
		assert!(suffix.contains('-'));
		// Should be something like "darwin-arm64" or "linux-x64"
		assert!(suffix.len() > 5);
	}
}
