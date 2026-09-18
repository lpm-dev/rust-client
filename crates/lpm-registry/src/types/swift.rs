use lpm_common::LpmError;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwiftMeta {
    #[serde(default)]
    pub products: Vec<SwiftProduct>,
    #[serde(default)]
    pub platforms: Vec<SwiftPlatform>,
    #[serde(default, rename = "requiredCapabilities")]
    pub required_capabilities: Vec<String>,
    #[serde(default, rename = "manifestSet")]
    pub manifest_set: Option<SwiftManifestSet>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwiftManifestSet {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,
    pub manifests: Vec<SwiftManifest>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwiftManifest {
    pub filename: String,
    #[serde(rename = "toolsVersion")]
    pub tools_version: String,
    #[serde(default)]
    pub products: Vec<SwiftProduct>,
    #[serde(default)]
    pub platforms: Vec<SwiftPlatform>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwiftProduct {
    pub name: String,
    #[serde(default, rename = "type")]
    pub product_type: Option<serde_json::Value>,
    #[serde(default)]
    pub targets: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwiftPlatform {
    #[serde(default, rename = "platformName", alias = "name")]
    pub platform_name: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SwiftToolsVersion([u32; 3]);

impl SwiftToolsVersion {
    pub fn parse(text: &str) -> Option<Self> {
        let mut parts = [0; 3];
        let mut count = 0;
        for (index, value) in text.split('.').enumerate() {
            if index >= 3
                || value.is_empty()
                || value.len() > 5
                || !value.bytes().all(|c| c.is_ascii_digit())
            {
                return None;
            }
            parts[index] = value.parse().ok()?;
            count += 1;
        }
        (count > 0).then_some(Self(parts))
    }

    fn supported_by(self, current: Self) -> bool {
        self >= Self([4, 0, 0]) && self <= current
    }
}

pub struct SwiftSelectedManifest<'a> {
    pub products: &'a [SwiftProduct],
    pub platforms: &'a [SwiftPlatform],
}

impl<'a> SwiftSelectedManifest<'a> {
    pub fn library_product(&self) -> Option<&'a SwiftProduct> {
        self.products.iter().find(|product| {
            !product.targets.is_empty()
                && product.product_type.as_ref().is_some_and(|kind| {
                    kind.as_str() == Some("library")
                        || kind
                            .as_object()
                            .is_some_and(|object| object.contains_key("library"))
                })
        })
    }
}

impl SwiftMeta {
    pub fn select_manifest(
        &self,
        current: Option<SwiftToolsVersion>,
    ) -> Result<SwiftSelectedManifest<'_>, LpmError> {
        let invalid = || {
            LpmError::Registry("Invalid or unsupported Swift manifest metadata. Update LPM CLI or republish the package.".into())
        };
        if self
            .required_capabilities
            .iter()
            .any(|value| value != "swift-manifest-variants-v1")
        {
            return Err(invalid());
        }
        let Some(set) = &self.manifest_set else {
            if !self.required_capabilities.is_empty() {
                return Err(invalid());
            }
            return Ok(SwiftSelectedManifest {
                products: &self.products,
                platforms: &self.platforms,
            });
        };
        let current = current.ok_or_else(invalid)?;
        if set.schema_version != 1 || set.manifests.is_empty() || set.manifests.len() > 32 {
            return Err(invalid());
        }
        let mut names = HashSet::with_capacity(set.manifests.len());
        let mut versions = HashSet::with_capacity(set.manifests.len());
        let mut root = None;
        let mut candidates = Vec::with_capacity(set.manifests.len());
        for manifest in &set.manifests {
            let version = SwiftToolsVersion::parse(&manifest.tools_version).ok_or_else(invalid)?;
            if !names.insert(manifest.filename.as_str()) || !versions.insert(version.0) {
                return Err(invalid());
            }
            if manifest.filename == "Package.swift" {
                root = Some((manifest, version));
            } else {
                let suffix = manifest
                    .filename
                    .strip_prefix("Package@swift-")
                    .and_then(|value| value.strip_suffix(".swift"))
                    .ok_or_else(invalid)?;
                if suffix
                    .split('.')
                    .any(|value| value.len() > 1 && value.starts_with('0'))
                    || SwiftToolsVersion::parse(suffix) != Some(version)
                {
                    return Err(invalid());
                }
                candidates.push((manifest, version));
            }
        }
        let (root, root_version) = root.ok_or_else(invalid)?;
        let [major, minor, patch] = current.0;
        let exact = [
            format!("Package@swift-{major}.{minor}.{patch}.swift"),
            format!("Package@swift-{major}.{minor}.swift"),
            format!("Package@swift-{major}.swift"),
        ]
        .into_iter()
        .find_map(|name| {
            candidates
                .iter()
                .find(|(manifest, _)| manifest.filename == name)
                .copied()
        });
        let selected = exact
            .or_else(|| {
                candidates
                    .into_iter()
                    .filter(|(_, version)| *version <= current)
                    .max_by_key(|(_, version)| *version)
                    .filter(|(_, version)| {
                        *version > root_version || !root_version.supported_by(current)
                    })
            })
            .unwrap_or((root, root_version));
        if !selected.1.supported_by(current) {
            return Err(LpmError::Registry(format!(
                "Swift manifest {} requires tools {}, which this SwiftPM does not support.",
                selected.0.filename, selected.0.tools_version
            )));
        }
        Ok(SwiftSelectedManifest {
            products: &selected.0.products,
            platforms: &selected.0.platforms,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn metadata(root: &str, variants: &[(&str, &str)]) -> SwiftMeta {
        let manifests = std::iter::once(("Package.swift", root)).chain(variants.iter().copied()).map(|(filename, tools)| serde_json::json!({"filename":filename,"toolsVersion":tools,"products":[{"name":filename,"type":"library","targets":["Kit"]}]})).collect::<Vec<_>>();
        serde_json::from_value(
            serde_json::json!({"manifestSet":{"schemaVersion":1,"manifests":manifests}}),
        )
        .unwrap()
    }
    fn selected(root: &str, variants: &[(&str, &str)], current: &str) -> String {
        metadata(root, variants)
            .select_manifest(SwiftToolsVersion::parse(current))
            .unwrap()
            .products[0]
            .name
            .clone()
    }
    #[test]
    fn named_cache_payload_retains_variant_selection() {
        let original = metadata("5.9", &[("Package@swift-6.swift", "6.0")]);
        let bytes = rmp_serde::to_vec_named(&original).unwrap();
        let restored: SwiftMeta = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(
            restored
                .select_manifest(SwiftToolsVersion::parse("6.4"))
                .unwrap()
                .products[0]
                .name,
            "Package@swift-6.swift"
        );
    }
    #[test]
    fn exact_major_filename_precedes_a_newer_compatible_suffix() {
        assert_eq!(
            selected(
                "5.9",
                &[
                    ("Package@swift-6.swift", "6.0"),
                    ("Package@swift-6.3.swift", "6.3")
                ],
                "6.4"
            ),
            "Package@swift-6.swift"
        );
    }
    #[test]
    fn fallback_keeps_a_newer_compatible_root() {
        assert_eq!(
            selected("6.3", &[("Package@swift-6.2.swift", "6.2")], "6.4"),
            "Package.swift"
        );
    }
    #[test]
    fn older_alternate_can_replace_an_incompatible_root() {
        assert_eq!(
            selected("6.5", &[("Package@swift-6.2.swift", "6.2")], "6.4"),
            "Package@swift-6.2.swift"
        );
    }
    #[test]
    fn exact_patch_precedes_minor_and_major_filenames() {
        assert_eq!(
            selected(
                "5.9",
                &[
                    ("Package@swift-6.swift", "6.0"),
                    ("Package@swift-6.4.swift", "6.4"),
                    ("Package@swift-6.4.1.swift", "6.4.1")
                ],
                "6.4.1"
            ),
            "Package@swift-6.4.1.swift"
        );
    }
    #[test]
    fn incompatible_root_without_a_compatible_alternate_fails() {
        assert!(
            metadata("6.5", &[])
                .select_manifest(SwiftToolsVersion::parse("6.4"))
                .is_err()
        );
    }
    #[test]
    fn ambiguous_or_noncanonical_variants_fail() {
        for variants in [
            vec![("Package@swift-06.swift", "6")],
            vec![("Package@swift-6.swift", "5.8")],
            vec![
                ("Package@swift-6.swift", "6"),
                ("Package@swift-6.0.swift", "6"),
            ],
            vec![("Package@swift-5.9.swift", "5.9")],
        ] {
            assert!(
                metadata("5.9", &variants)
                    .select_manifest(SwiftToolsVersion::parse("6.4"))
                    .is_err()
            );
        }
    }
}
