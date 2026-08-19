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
        latest_version: "1.79.0",
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
                "930e3656277ca6ad135fe7bda18e1f64886e0f8d0755df8b19cd6b499f12931b",
            ),
            (
                "darwin-x64",
                "debd377ff3e7929743c440c6f23546a99658f7b0271725718c45197ace49bc5a",
            ),
            (
                "linux-x64",
                "c7ddeff22c8d5ebd23648ff0917dd67a85178d86937acc3300ff4e974faaa042",
            ),
            (
                "linux-arm64",
                "47ae11cb1745202e26652a633449065f85bb974b5404d932d673995f39e9a724",
            ),
            (
                "win-x64",
                "bd706727f9fb5e5e343fe3ad8166dfd4755b6843673c7451eb40a58a7df384c8",
            ),
        ],
    },
    // Biome: distributed as direct binary downloads from biomejs/biome
    // Tag format: @biomejs/biome@{version} (URL-encoded: %40biomejs/biome%40{version})
    // Asset: biome-{platform} (direct binary, no archive)
    PluginDef {
        name: "biome",
        binary_name: "biome",
        latest_version: "2.5.9",
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
                "7d8b51dec857ffa8aa35ce5eaa3a4476cd62bed013adc2896bf43cac0a67a79b",
            ),
            (
                "darwin-x64",
                "df2b50ee283634cdd6f7570b7da06bc3c9cd7ec0590ecbbaf986c7590bef3289",
            ),
            (
                "linux-x64",
                "013eb5158b9e53235dbbf31255cb3b776fb9338b32fa6ff4a44ee1ceed65ee63",
            ),
            (
                "linux-arm64",
                "bf593f7955e3a437fb8056b255142b50872baa3e81371cda2c3fce9239af1890",
            ),
            (
                "win-x64",
                "f8474a0f9f457df176c10be3f0e82be890e8986ff2805d4a7f3c5a4cba5962ca",
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
            .replace("{version}", "1.79.0")
            .replace("{platform}", "oxlint-aarch64-apple-darwin.tar.gz");
        assert_eq!(
            url,
            "https://github.com/oxc-project/oxc/releases/download/apps_v1.79.0/oxlint-aarch64-apple-darwin.tar.gz"
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
