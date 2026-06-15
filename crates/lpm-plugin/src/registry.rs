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
        latest_version: "1.70.0",
        url_template: "https://github.com/oxc-project/oxc/releases/download/apps_v{version}/{platform}",
        platform_map: &[
            ("darwin-arm64", "oxlint-aarch64-apple-darwin.tar.gz"),
            ("darwin-x64", "oxlint-x86_64-apple-darwin.tar.gz"),
            ("linux-x64", "oxlint-x86_64-unknown-linux-gnu.tar.gz"),
            ("linux-arm64", "oxlint-aarch64-unknown-linux-gnu.tar.gz"),
            ("win-x64", "oxlint-x86_64-pc-windows-msvc.zip"),
        ],
        is_archive: true,
        // SHA-256 checksums for the hardcoded latest_version archives.
        // These MUST be updated whenever latest_version is bumped.
        // Computed from GitHub Release assets.
        checksums: &[
            (
                "darwin-arm64",
                "9d3d8b2637a2d60edc152e890a83bc9f01a45592899f74c64eca3bb2baba88d8",
            ),
            (
                "darwin-x64",
                "bd88a870298e75549e0dfe931dc3a8aaca1eb3763d66c7ea5fb73ccf8ce544bc",
            ),
            (
                "linux-x64",
                "cba0142899d1ed1c79d4ff3a8a6c715cd06b5df74085abb7f5df47fb3fc3a42c",
            ),
            (
                "linux-arm64",
                "0a52768ac98831024e0ede1d1a057d7ca2718d7abe6747a97bff87f70dc2de90",
            ),
            (
                "win-x64",
                "0b20a8ee0cf4a651277ef9803954351722c50db486475d28945ca041938d75a1",
            ),
        ],
    },
    // Biome: distributed as direct binary downloads from biomejs/biome
    // Tag format: @biomejs/biome@{version} (URL-encoded: %40biomejs/biome%40{version})
    // Asset: biome-{platform} (direct binary, no archive)
    PluginDef {
        name: "biome",
        binary_name: "biome",
        latest_version: "2.5.0",
        url_template: "https://github.com/biomejs/biome/releases/download/%40biomejs/biome%40{version}/{platform}",
        platform_map: &[
            ("darwin-arm64", "biome-darwin-arm64"),
            ("darwin-x64", "biome-darwin-x64"),
            ("linux-x64", "biome-linux-x64"),
            ("linux-arm64", "biome-linux-arm64"),
            ("win-x64", "biome-win32-x64.exe"),
        ],
        is_archive: false,
        // SHA-256 checksums for the hardcoded latest_version binaries.
        // These MUST be updated whenever latest_version is bumped.
        // Computed from GitHub Release assets.
        checksums: &[
            (
                "darwin-arm64",
                "9b9e04f749db6b037b0ad38ba0c5cce63b185a7cc3b049e577dad3c18f4adb2c",
            ),
            (
                "darwin-x64",
                "0c7002cc808eebabe7852c8417b9deb1a5615342e6881c588b49367c6c56db8c",
            ),
            (
                "linux-x64",
                "e7df298f0551dd90bea4425779369aa3130d9817f4acc4f663ef63c327206a19",
            ),
            (
                "linux-arm64",
                "27c9bc5994dfb5711f5f09a4c3c35749ca9c4a898a063bb062e6b932dbc2571d",
            ),
            (
                "win-x64",
                "84d4e71fdbb4b15b1aa83c1b1cc033aae9856d48a7a857c1381b1bd499430f7c",
            ),
        ],
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
        let url = p
            .url_template
            .replace("{version}", "1.70.0")
            .replace("{platform}", "oxlint-aarch64-apple-darwin.tar.gz");
        assert_eq!(
            url,
            "https://github.com/oxc-project/oxc/releases/download/apps_v1.70.0/oxlint-aarch64-apple-darwin.tar.gz"
        );
    }

    #[test]
    fn resolve_checksum_returns_hash_for_known_platform() {
        let p = get_plugin("oxlint").unwrap();
        let hash = resolve_checksum(p, "darwin-arm64");
        assert!(
            hash.is_some(),
            "oxlint should have checksum for darwin-arm64"
        );
        assert_eq!(hash.unwrap().len(), 64, "SHA-256 hex should be 64 chars");
    }

    #[test]
    fn resolve_checksum_biome_returns_hash() {
        let p = get_plugin("biome").unwrap();
        let hash = resolve_checksum(p, "linux-x64");
        assert!(hash.is_some(), "biome should have checksum for linux-x64");
        assert_eq!(hash.unwrap().len(), 64);
    }

    #[test]
    fn resolve_checksum_unknown_platform_returns_none() {
        let p = get_plugin("oxlint").unwrap();
        assert!(resolve_checksum(p, "freebsd-arm64").is_none());
    }

    #[test]
    fn all_platforms_have_checksums() {
        for plugin in list_plugins() {
            for (platform, _) in plugin.platform_map {
                assert!(
                    resolve_checksum(plugin, platform).is_some(),
                    "plugin '{}' missing checksum for platform '{}'",
                    plugin.name,
                    platform,
                );
            }
        }
    }
}
