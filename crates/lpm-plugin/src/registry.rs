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
        latest_version: "1.73.0",
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
                "f27b2959685ae13694a83a7d420154b440d6b4f62fd2942c136666e2ab3cc2cc",
            ),
            (
                "darwin-x64",
                "bddfbbdd38cfc7b22def9b6698b9d87e4477730763ce1fa2605afcdcea08ba73",
            ),
            (
                "linux-x64",
                "63c47cfe83fe1cd4e474dc1789d1914f448bd970853950e0256e8c1a1eae0d48",
            ),
            (
                "linux-arm64",
                "093878dd1e01127b8fa5eff39b23407d1b07fda0829f04a77b8754d2f1858ae6",
            ),
            (
                "win-x64",
                "4705fa429bc730cd4663ab5ca227d2bc73bace2a87e6c7d0882012fb4b947619",
            ),
        ],
    },
    // Biome: distributed as direct binary downloads from biomejs/biome
    // Tag format: @biomejs/biome@{version} (URL-encoded: %40biomejs/biome%40{version})
    // Asset: biome-{platform} (direct binary, no archive)
    PluginDef {
        name: "biome",
        binary_name: "biome",
        latest_version: "2.5.3",
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
                "610d3e1e770d373368d4ccee5a19c5e1735b0235024fcbed6ae07eb080d3bb09",
            ),
            (
                "darwin-x64",
                "4df90556830ed35e6238e4b976b942d369a5378447c8d68b260b7a38e08b26f9",
            ),
            (
                "linux-x64",
                "ab8e74af2366127306e250652d2f32bd193601f208fcd0604112080c0ca3245b",
            ),
            (
                "linux-arm64",
                "b642ded43aebcad738926b40eefd4dc2187a206d1fbfb37a45f1db4986804dbd",
            ),
            (
                "win-x64",
                "04c9ca46af43a0d060b22b21f94c7e1a9e8c57963a09778b8ff1d808ed536b31",
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
            .replace("{version}", "1.73.0")
            .replace("{platform}", "oxlint-aarch64-apple-darwin.tar.gz");
        assert_eq!(
            url,
            "https://github.com/oxc-project/oxc/releases/download/apps_v1.73.0/oxlint-aarch64-apple-darwin.tar.gz"
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
