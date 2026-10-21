//! Hardcoded plugin registry — defines available tools, download URLs, and platforms.

use std::borrow::Cow;

/// A GitHub release tag naming scheme that applies to versions at or above `since`.
#[derive(Debug, Clone, Copy)]
pub struct ReleaseTagScheme {
    /// Lowest version released under this scheme.
    pub since: &'static str,
    /// Tag text before the version, e.g. `oxlint_v` in `oxlint_v1.89.0`.
    pub prefix: &'static str,
}

/// A plugin definition.
#[derive(Debug, Clone)]
pub struct PluginDef {
    /// Plugin name (e.g., "oxlint", "biome").
    pub name: &'static str,
    /// Name of the binary file inside the download.
    pub binary_name: &'static str,
    /// Latest known version.
    pub latest_version: &'static str,
    /// Download URL template. Placeholders: `{tag}` (the release tag, with `@`
    /// percent-encoded) and `{platform}` (the asset name).
    pub url_template: &'static str,
    /// Release tag schemes ordered by descending `since`. A version's release
    /// tag uses the first scheme whose `since` is at or below it.
    pub release_tags: &'static [ReleaseTagScheme],
    /// Map from LPM platform string to asset suffix in the release.
    pub platform_map: &'static [(&'static str, &'static str)],
    /// Whether the download is a tar.gz archive (true) or a direct binary (false).
    pub is_archive: bool,
    /// Expected SHA-256 checksums for the hardcoded `latest_version`, keyed by platform string.
    ///
    /// Other versions require upstream verification data or an explicit unverified override.
    pub checksums: &'static [(&'static str, &'static str)],
}

impl PluginDef {
    fn release_tag_prefix(&self, version: &str) -> &'static str {
        self.release_tags
            .iter()
            .find(|scheme| crate::versions::compare_versions(version, scheme.since).is_ge())
            .map_or("", |scheme| scheme.prefix)
    }

    /// The GitHub release tag that publishes `version`.
    pub fn release_tag(&self, version: &str) -> String {
        let prefix = self.release_tag_prefix(version);
        let mut tag = String::with_capacity(prefix.len() + version.len());
        tag.push_str(prefix);
        tag.push_str(version);
        tag
    }

    /// The version a release tag publishes, if the tag follows the scheme that
    /// version belongs to. Tags from other release families in the same
    /// repository, or under a scheme that does not cover their version, are
    /// rejected so the download URL built from the version names that tag.
    pub fn version_from_release_tag<'a>(&self, tag: &'a str) -> Option<&'a str> {
        self.release_tags.iter().find_map(|scheme| {
            tag.strip_prefix(scheme.prefix)
                .filter(|version| self.release_tag_prefix(version) == scheme.prefix)
        })
    }

    /// The download URL of `asset` in the release that publishes `version`.
    pub fn asset_url(&self, version: &str, asset: &str) -> String {
        let tag = self.release_tag(version);
        let tag = if tag.contains('@') {
            Cow::Owned(tag.replace('@', "%40"))
        } else {
            Cow::Borrowed(tag.as_str())
        };
        self.url_template
            .replace("{tag}", &tag)
            .replace("{platform}", asset)
    }
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
    // Tag format: oxlint_v{version} from 1.85.0, apps_v{version} before it
    // Asset: oxlint-{rust-target-triple}.tar.gz (contains oxlint binary inside)
    PluginDef {
        name: "oxlint",
        binary_name: "oxlint",
        latest_version: "1.89.0",
        url_template: "https://github.com/oxc-project/oxc/releases/download/{tag}/{platform}",
        release_tags: &[
            ReleaseTagScheme {
                since: "1.85.0",
                prefix: "oxlint_v",
            },
            ReleaseTagScheme {
                since: "0.0.0",
                prefix: "apps_v",
            },
        ],
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
                "fa4349f33b24221e2d303ace66de3dac2ff756eab48126b2cb58429ed36bccbc",
            ),
            (
                "darwin-x64",
                "198261cfb91c0f0387c55642ba5c2c4aa2c3cf9593188f86187c759f280bae88",
            ),
            (
                "linux-x64",
                "88492c336807a34062fa540416fe75037c04bcce1ed77824e3db3aaec215949a",
            ),
            (
                "linux-arm64",
                "69b3680c38b21395d4ea509fbd1019fa011db0cd717dd7be2ede2575cb6f7915",
            ),
            (
                "win-x64",
                "50be9b3d180a48f2a33fb9ab6d92383c6464d38e4df347b08b1bce6b999c8c15",
            ),
        ],
    },
    // Biome: distributed as direct binary downloads from biomejs/biome
    // Tag format: @biomejs/biome@{version} (URL-encoded: %40biomejs/biome%40{version})
    // Asset: biome-{platform} (direct binary, no archive)
    PluginDef {
        name: "biome",
        binary_name: "biome",
        latest_version: "2.6.2",
        url_template: "https://github.com/biomejs/biome/releases/download/{tag}/{platform}",
        release_tags: &[ReleaseTagScheme {
            since: "0.0.0",
            prefix: "@biomejs/biome@",
        }],
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
                "be66b76dcb930b1e365bd36c4f5d8557c2dda70b31567f8bd15509e487753a69",
            ),
            (
                "darwin-x64",
                "9bba9be8c50bf2a58bc6de8023b599e57613588800bd843273e9ccaa4deba52c",
            ),
            (
                "linux-x64",
                "43c08f3454d375d38c6441939acc8a557702bc8459272dd513f4f7474a4ed352",
            ),
            (
                "linux-arm64",
                "08536c586089e603dae610f73adc3ab95c0a0fdb00c029662c09456c42ea3ac8",
            ),
            (
                "win-x64",
                "283639d771d82502b7498e87cee2e703f84aa040144b04ea1bcfc0ab942a9184",
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
    fn oxlint_release_urls_follow_the_tag_scheme_of_each_version() {
        let p = get_plugin("oxlint").unwrap();
        let asset = "oxlint-aarch64-apple-darwin.tar.gz";
        for (version, tag) in [
            ("1.89.0", "oxlint_v1.89.0"),
            ("1.85.0", "oxlint_v1.85.0"),
            ("1.84.0", "apps_v1.84.0"),
            ("1.57.0", "apps_v1.57.0"),
        ] {
            assert_eq!(p.release_tag(version), tag);
            assert_eq!(
                p.asset_url(version, asset),
                format!("https://github.com/oxc-project/oxc/releases/download/{tag}/{asset}")
            );
        }
    }

    #[test]
    fn biome_release_urls_percent_encode_the_scoped_tag() {
        let p = get_plugin("biome").unwrap();

        assert_eq!(p.release_tag("2.6.2"), "@biomejs/biome@2.6.2");
        assert_eq!(
            p.asset_url("2.6.2", "biome-darwin-arm64"),
            "https://github.com/biomejs/biome/releases/download/%40biomejs/biome%402.6.2/biome-darwin-arm64"
        );
    }

    #[test]
    fn release_tags_map_to_versions_only_under_the_scheme_that_covers_them() {
        let oxlint = get_plugin("oxlint").unwrap();
        assert_eq!(
            oxlint.version_from_release_tag("oxlint_v1.89.0"),
            Some("1.89.0")
        );
        assert_eq!(
            oxlint.version_from_release_tag("apps_v1.84.0"),
            Some("1.84.0")
        );
        assert_eq!(oxlint.version_from_release_tag("apps_v1.89.0"), None);
        assert_eq!(oxlint.version_from_release_tag("oxlint_v1.27.0"), None);
        assert_eq!(oxlint.version_from_release_tag("oxfmt_v0.74.0"), None);
        assert_eq!(oxlint.version_from_release_tag("crates_v0.155.0"), None);

        let biome = get_plugin("biome").unwrap();
        assert_eq!(
            biome.version_from_release_tag("@biomejs/biome@2.6.2"),
            Some("2.6.2")
        );
        assert_eq!(
            biome.version_from_release_tag("@biomejs/js-api@2.6.2"),
            None
        );
    }

    #[test]
    fn every_plugin_round_trips_its_latest_version_through_its_release_tag() {
        for plugin in list_plugins() {
            let tag = plugin.release_tag(plugin.latest_version);
            assert_eq!(
                plugin.version_from_release_tag(&tag),
                Some(plugin.latest_version),
                "{}",
                plugin.name
            );
        }
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
