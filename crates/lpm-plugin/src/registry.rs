//! Hardcoded plugin registry — defines available tools, download URLs, and platforms.

/// A plugin definition.
#[derive(Debug, Clone)]
pub struct PluginDef {
	/// Plugin name (e.g., "oxlint", "biome").
	pub name: &'static str,
	/// Name of the binary file inside the download.
	pub binary_name: &'static str,
	/// Latest known version.
	pub latest_version: &'static str,
	/// Download URL template. Placeholders: `{version}`, `{platform}`.
	pub url_template: &'static str,
	/// Map from LPM platform string to asset suffix in the release.
	pub platform_map: &'static [(&'static str, &'static str)],
	/// Whether the download is a tar.gz archive (true) or a direct binary (false).
	pub is_archive: bool,
	/// Expected SHA-256 checksums for the hardcoded `latest_version`, keyed by platform string.
	///
	/// For user-pinned custom versions, checksums are not available and verification is skipped
	/// with a warning.
	pub checksums: &'static [(&'static str, &'static str)],
}

/// Get a plugin definition by name.
pub fn get_plugin(name: &str) -> Option<&'static PluginDef> {
	PLUGINS.iter().find(|p| p.name == name)
}

/// List all available plugins.
pub fn list_plugins() -> &'static [PluginDef] {
	PLUGINS
}

/// Resolve the platform-specific asset name for a plugin.
pub fn resolve_platform_asset(def: &PluginDef, platform: &str) -> Option<&'static str> {
	def.platform_map
		.iter()
		.find(|(p, _)| *p == platform)
		.map(|(_, asset)| *asset)
}

/// Look up the expected checksum for a plugin on a given platform.
pub fn resolve_checksum(def: &PluginDef, platform: &str) -> Option<&'static str> {
	def.checksums
		.iter()
		.find(|(p, _)| *p == platform)
		.map(|(_, hash)| *hash)
}

// --- Plugin definitions ---

static PLUGINS: &[PluginDef] = &[
	// Oxlint: distributed as .tar.gz archives from oxc-project/oxc
	// Tag format: apps_v{version}
	// Asset: oxlint-{rust-target-triple}.tar.gz (contains oxlint binary inside)
	PluginDef {
		name: "oxlint",
		binary_name: "oxlint",
		latest_version: "1.57.0",
		url_template: "https://github.com/oxc-project/oxc/releases/download/apps_v{version}/{platform}",
		platform_map: &[
			("darwin-arm64", "oxlint-aarch64-apple-darwin.tar.gz"),
			("darwin-x64", "oxlint-x86_64-apple-darwin.tar.gz"),
			("linux-x64", "oxlint-x86_64-unknown-linux-gnu.tar.gz"),
			("linux-arm64", "oxlint-aarch64-unknown-linux-gnu.tar.gz"),
			("win-x64", "oxlint-x86_64-pc-windows-msvc.zip"),
		],
		is_archive: true,
		// Checksums for the hardcoded latest_version only.
		// These must be updated when latest_version changes.
		// Empty for now — will be populated when verified checksums are obtained.
		checksums: &[],
	},
	// Biome: distributed as direct binary downloads from biomejs/biome
	// Tag format: @biomejs/biome@{version} (URL-encoded: %40biomejs/biome%40{version})
	// Asset: biome-{platform} (direct binary, no archive)
	PluginDef {
		name: "biome",
		binary_name: "biome",
		latest_version: "2.4.8",
		url_template: "https://github.com/biomejs/biome/releases/download/%40biomejs/biome%40{version}/{platform}",
		platform_map: &[
			("darwin-arm64", "biome-darwin-arm64"),
			("darwin-x64", "biome-darwin-x64"),
			("linux-x64", "biome-linux-x64"),
			("linux-arm64", "biome-linux-arm64"),
			("win-x64", "biome-win32-x64.exe"),
		],
		is_archive: false,
		checksums: &[],
	},
];

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn get_oxlint_plugin() {
		let p = get_plugin("oxlint").unwrap();
		assert_eq!(p.name, "oxlint");
		assert!(p.is_archive);
	}

	#[test]
	fn get_biome_plugin() {
		let p = get_plugin("biome").unwrap();
		assert_eq!(p.name, "biome");
		assert!(!p.is_archive);
	}

	#[test]
	fn unknown_plugin_returns_none() {
		assert!(get_plugin("nonexistent").is_none());
	}

	#[test]
	fn resolve_darwin_arm64_oxlint() {
		let p = get_plugin("oxlint").unwrap();
		let asset = resolve_platform_asset(p, "darwin-arm64").unwrap();
		assert_eq!(asset, "oxlint-aarch64-apple-darwin.tar.gz");
	}

	#[test]
	fn resolve_darwin_arm64_biome() {
		let p = get_plugin("biome").unwrap();
		let asset = resolve_platform_asset(p, "darwin-arm64").unwrap();
		assert_eq!(asset, "biome-darwin-arm64");
	}

	#[test]
	fn oxlint_url_format() {
		let p = get_plugin("oxlint").unwrap();
		let url = p.url_template
			.replace("{version}", "1.57.0")
			.replace("{platform}", "oxlint-aarch64-apple-darwin.tar.gz");
		assert_eq!(url, "https://github.com/oxc-project/oxc/releases/download/apps_v1.57.0/oxlint-aarch64-apple-darwin.tar.gz");
	}

	#[test]
	fn resolve_checksum_missing_returns_none() {
		let p = get_plugin("oxlint").unwrap();
		// Currently no checksums populated
		assert!(resolve_checksum(p, "darwin-arm64").is_none());
	}
}
