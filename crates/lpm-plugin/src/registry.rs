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
        latest_version: "1.78.0",
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
                "6045c729ac1d31f2a7f02ec784c5c56199d0ae1065ddf6515b0f0271e320ad73",
            ),
            (
                "darwin-x64",
                "6c7d8a72840d1a2ea5648b6d59ca79d9502a279abddfc2dddca92c5ed2595022",
            ),
            (
                "linux-x64",
                "41aeb2a54673882c3ab383c44405482e54530dadd216d32cddd8645496fb5409",
            ),
            (
                "linux-arm64",
                "1932e7dfd971e23fabc46c568a13c55b11bce9204a0a9fafcac7e3b0be7c8246",
            ),
            (
                "win-x64",
                "71630f9bd91923a12ddbd3dbb1877fc8268153acd2aeb9065604f70284fd9971",
            ),
        ],
    },
    // Biome: distributed as direct binary downloads from biomejs/biome
    // Tag format: @biomejs/biome@{version} (URL-encoded: %40biomejs/biome%40{version})
    // Asset: biome-{platform} (direct binary, no archive)
    PluginDef {
        name: "biome",
        binary_name: "biome",
        latest_version: "2.5.7",
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
                "f71fe80909d2f70f1e051320f5ba9dfd553bc5ef3bacef5cdee1b00ee96a285c",
            ),
            (
                "darwin-x64",
                "887431b79e45758e05d94a89111af72b28e5d6545c92480ecac9247d8bacb321",
            ),
            (
                "linux-x64",
                "7b5045d6d34f055df8ffe1bf3077164e6f6a24c45a41497d628a5e86d0e12fe7",
            ),
            (
                "linux-arm64",
                "27490d47af66420788b634afb48db23b588f272c8a284ba3daf706a5faa640ab",
            ),
            (
                "win-x64",
                "62adea0ea523f04cc5c074b2bb00e748b97252023aede03196e1bf4aacf80a9c",
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
            .replace("{version}", "1.78.0")
            .replace("{platform}", "oxlint-aarch64-apple-darwin.tar.gz");
        assert_eq!(
            url,
            "https://github.com/oxc-project/oxc/releases/download/apps_v1.78.0/oxlint-aarch64-apple-darwin.tar.gz"
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
