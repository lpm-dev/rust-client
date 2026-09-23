use crate::types::{PackageMetadata, VersionMetadata};
use serde::Deserialize;
use serde::de::{MapAccess, Visitor};
use std::collections::HashMap;

#[derive(Deserialize)]
#[serde(transparent)]
pub(super) struct ResolverMetadata(
    #[serde(with = "ResolverMetadataWire")] pub(super) PackageMetadata,
);

#[derive(Deserialize)]
#[serde(transparent)]
struct ResolverVersion(
    #[serde(deserialize_with = "crate::types::deserialize_version_without_dev_dependencies")]
    VersionMetadata,
);

#[derive(Deserialize)]
#[serde(remote = "PackageMetadata")]
struct ResolverMetadataWire {
    pub name: String,

    #[serde(default)]
    pub description: Option<String>,

    #[serde(default)]
    pub modified: Option<String>,

    #[serde(default, rename = "dist-tags")]
    pub dist_tags: HashMap<String, String>,

    #[serde(default, deserialize_with = "deserialize_versions")]
    pub versions: HashMap<String, VersionMetadata>,

    #[serde(default)]
    pub time: HashMap<String, String>,

    #[serde(default)]
    pub downloads: Option<u64>,

    #[serde(default, rename = "distributionMode")]
    pub distribution_mode: Option<String>,

    #[serde(default, rename = "packageType")]
    pub package_type: Option<String>,

    #[serde(default, rename = "latestVersion")]
    pub latest_version: Option<String>,

    #[serde(default)]
    pub ecosystem: Option<String>,
}

fn deserialize_versions<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<HashMap<String, VersionMetadata>, D::Error> {
    struct Versions;
    impl<'de> Visitor<'de> for Versions {
        type Value = HashMap<String, VersionMetadata>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("cached package versions")
        }

        fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
            let mut versions = HashMap::with_capacity(map.size_hint().unwrap_or(0).min(4096));
            while let Some((version, metadata)) = map.next_entry::<String, ResolverVersion>()? {
                versions.insert(version, metadata.0);
            }
            Ok(versions)
        }
    }
    deserializer.deserialize_map(Versions)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolver_cache_projection_omits_only_development_dependencies() {
        let original: PackageMetadata = serde_json::from_str(r#"{
            "name": "pkg", "description": "description", "modified": "2025-01-01",
            "dist-tags": {"latest": "1.0.0"}, "time": {"1.0.0": "2024-01-01"},
            "downloads": 23, "distributionMode": "public", "packageType": "npm",
            "latestVersion": "1.0.0", "ecosystem": "npm",
            "versions": {"1.0.0": {
                "name": "pkg", "version": "1.0.0", "publicationStatus": "published",
                "description": "version description", "deprecated": "legacy",
                "dependencies": {"runtime": "^1.0.0"}, "devDependencies": {"compiler": "^2.0.0"},
                "optionalDependencies": {"native": "~3.0.0"}, "peerDependencies": {"peer": "*"},
                "peerDependenciesMeta": {"peer": {"optional": true}}, "bundleDependencies": ["runtime"],
                "engines": {"node": ">=20", "npm": ">=10"}, "os": ["linux", "!darwin"],
                "cpu": ["arm64"], "libc": ["musl"], "readme": "readme",
                "scripts": {"install": "node build.js"}, "hasInstallScript": true,
                "lpmConfig": {"key": "value"}, "_ecosystem": "npm", "_qualityScore": 87,
                "_lifecycleScripts": {"postinstall": "node post.js"},
                "dist": {"tarball": "https://example.test/pkg.tgz", "integrity": "sha512-AA==", "unpackedSize": 42,
                    "signatures": [{"keyid": "key", "sig": "signed"}],
                    "attestations": {"url": "https://example.test/provenance", "provenance": {"predicateType": "slsa"}}},
                "_behavioralTags": {"network": true, "childProcess": true},
                "_securityFindings": [{"severity": "high", "description": "finding", "file": "index.js"}],
                "_vulnerabilities": [{"id": "example", "summary": "summary", "severity": "low", "aliases": ["alias"]}],
                "_npmUser": {"trustedPublisher": {"id": "github"}, "approver": "reviewer"}
            }}
        }"#).unwrap();
        let mut expected = original.clone();
        for version in expected.versions.values_mut() {
            version.dev_dependencies.clear();
        }
        let bytes = rmp_serde::to_vec_named(&original).unwrap();
        let projected: ResolverMetadata =
            rmp_serde::from_read(std::io::Cursor::new(&bytes)).unwrap();
        assert_eq!(
            serde_json::to_value(projected.0).unwrap(),
            serde_json::to_value(expected).unwrap()
        );
        let full: PackageMetadata = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(
            full.versions["1.0.0"].dev_dependencies["compiler"],
            "^2.0.0"
        );
    }

    #[test]
    fn resolver_cache_keeps_bundle_precedence_and_tolerant_platform_normalization() {
        for fields in [
            r#""bundleDependencies":false,"bundledDependencies":["runtime"]"#,
            r#""bundleDependencies":null,"bundledDependencies":["runtime"]"#,
            r#""bundledDependencies":["runtime"]"#,
        ] {
            let body = format!(
                r#"{{"name":"pkg","versions":{{"1.0.0":{{"name":"pkg","version":"1.0.0",{fields},"engines":["node"],"os":"linux","cpu":"arm64","libc":"musl","peerDependenciesMeta":{{"peer":{{"optional":true}}}}}}}}}}"#
            );
            let full: PackageMetadata = serde_json::from_str(&body).unwrap();
            let projected: ResolverMetadata = serde_json::from_str(&body).unwrap();
            assert_eq!(
                serde_json::to_value(full).unwrap(),
                serde_json::to_value(projected.0).unwrap()
            );
        }
    }

    #[test]
    fn resolver_cache_rejects_missing_manifest_identity() {
        for fields in [r#""name":"pkg""#, r#""version":"1.0.0""#] {
            let body = format!(r#"{{"name":"pkg","versions":{{"1.0.0":{{{fields}}}}}}}"#);
            assert!(serde_json::from_str::<ResolverMetadata>(&body).is_err());
        }
    }
}
