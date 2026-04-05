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
        latest_version: "1.58.0",
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
        // Computed from GitHub Release assets on 2026-04-05.
        checksums: &[
            ("darwin-arm64", "422756416c840b77212c673ae4aa88c8ef27e0e09b8ae51aeed21a2cef6b7191"),
            ("darwin-x64", "f4d49bb4a636c8a0810e4c5a56adb02be9cf448570292a102d8a8835f7ba1980"),
            ("linux-x64", "15c00abe9dd9e1c2a278494ed0c1e70cc86de74fa16fb3a5f573f8ee702db934"),
            ("linux-arm64", "d7e57bb36895b0763f75bd0d45183efab2042f1a03907dfebc37d30b80ea8434"),
            ("win-x64", "348a9194cdabbca30141d46228351b80f5e31c2bb5134f2148a45da4e18b5b63"),
        ],
    },
    // Biome: distributed as direct binary downloads from biomejs/biome
    // Tag format: @biomejs/biome@{version} (URL-encoded: %40biomejs/biome%40{version})
    // Asset: biome-{platform} (direct binary, no archive)
    PluginDef {
        name: "biome",
        binary_name: "biome",
        latest_version: "2.4.10",
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
        // Computed from GitHub Release assets on 2026-04-05.
        checksums: &[
            ("darwin-arm64", "c6782336dff872beec7d34e1b801c533bd296b5dcf2a30d3cf6335bca975e984"),
            ("darwin-x64", "8269b5ef30bbc1fcf0cff5695bdc3733d417744ae638df70e7dabc3b82590fca"),
            ("linux-x64", "fb9423a99ea4be5036f4ee95667fcc5a67e8ff72bd6d23e392033a70fb755d90"),
            ("linux-arm64", "4ce5f5750abdce244087e42d73a177c0c1b930f23320c52bf3e973bbc18489de"),
            ("win-x64", "a2bdc915914114c09a6f38ea092af2e450953bf3ace76bc143f2ab4d5a17b238"),
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
            .replace("{version}", "1.58.0")
            .replace("{platform}", "oxlint-aarch64-apple-darwin.tar.gz");
        assert_eq!(
            url,
            "https://github.com/oxc-project/oxc/releases/download/apps_v1.58.0/oxlint-aarch64-apple-darwin.tar.gz"
        );
    }

    #[test]
    fn resolve_checksum_returns_hash_for_known_platform() {
        let p = get_plugin("oxlint").unwrap();
        let hash = resolve_checksum(p, "darwin-arm64");
        assert!(hash.is_some(), "oxlint should have checksum for darwin-arm64");
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
