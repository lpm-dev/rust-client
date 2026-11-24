use super::*;

#[derive(Debug)]
enum WireBundleDependencies {
    All,
    List(Vec<String>),
    Empty,
}

struct WireBundleDependenciesVisitor;

impl<'de> serde::de::Visitor<'de> for WireBundleDependenciesVisitor {
    type Value = WireBundleDependencies;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a boolean, list, or object of bundled dependency names")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(if value {
            WireBundleDependencies::All
        } else {
            WireBundleDependencies::Empty
        })
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(WireBundleDependencies::Empty)
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(WireBundleDependencies::Empty)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(self)
    }

    fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
        Ok(WireBundleDependencies::Empty)
    }

    fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
        Ok(WireBundleDependencies::Empty)
    }

    fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E> {
        Ok(WireBundleDependencies::Empty)
    }

    fn visit_str<E>(self, _: &str) -> Result<Self::Value, E> {
        Ok(WireBundleDependencies::Empty)
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        struct OptionalString(Option<String>);

        impl<'de> serde::Deserialize<'de> for OptionalString {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct ItemVisitor;
                impl<'de> serde::de::Visitor<'de> for ItemVisitor {
                    type Value = OptionalString;

                    fn expecting(
                        &self,
                        formatter: &mut std::fmt::Formatter<'_>,
                    ) -> std::fmt::Result {
                        formatter.write_str("a bundled dependency entry")
                    }

                    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E> {
                        Ok(OptionalString(Some(v.to_owned())))
                    }

                    fn visit_string<E>(self, v: String) -> Result<Self::Value, E> {
                        Ok(OptionalString(Some(v)))
                    }

                    fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
                        Ok(OptionalString(None))
                    }

                    fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
                        Ok(OptionalString(None))
                    }

                    fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
                        Ok(OptionalString(None))
                    }

                    fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E> {
                        Ok(OptionalString(None))
                    }

                    fn visit_unit<E>(self) -> Result<Self::Value, E> {
                        Ok(OptionalString(None))
                    }

                    fn visit_none<E>(self) -> Result<Self::Value, E> {
                        Ok(OptionalString(None))
                    }

                    fn visit_seq<S>(self, mut seq: S) -> Result<Self::Value, S::Error>
                    where
                        S: serde::de::SeqAccess<'de>,
                    {
                        while seq.next_element::<serde::de::IgnoredAny>()?.is_some() {}
                        Ok(OptionalString(None))
                    }

                    fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
                    where
                        M: serde::de::MapAccess<'de>,
                    {
                        while map
                            .next_entry::<serde::de::IgnoredAny, serde::de::IgnoredAny>()?
                            .is_some()
                        {}
                        Ok(OptionalString(None))
                    }
                }
                deserializer.deserialize_any(ItemVisitor)
            }
        }

        let mut names = Vec::with_capacity(seq.size_hint().unwrap_or(0));
        while let Some(OptionalString(entry)) = seq.next_element::<OptionalString>()? {
            if let Some(name) = entry {
                names.push(name);
            }
        }
        names.sort_unstable();
        names.dedup();
        Ok(if names.is_empty() {
            WireBundleDependencies::Empty
        } else {
            WireBundleDependencies::List(names)
        })
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        let mut names = Vec::with_capacity(map.size_hint().unwrap_or(0));
        while let Some((key, _)) = map.next_entry::<String, serde::de::IgnoredAny>()? {
            names.push(key);
        }
        names.sort_unstable();
        Ok(if names.is_empty() {
            WireBundleDependencies::Empty
        } else {
            WireBundleDependencies::List(names)
        })
    }
}

#[derive(Deserialize)]
pub(super) struct VersionMetadataWire<const OMIT_DEV: bool = false> {
    name: String,
    version: String,

    #[serde(
        default,
        rename = "publicationStatus",
        skip_serializing_if = "Option::is_none"
    )]
    publication_status: Option<String>,

    #[serde(default)]
    description: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    deprecated: Option<serde_json::Value>,

    #[serde(default)]
    dependencies: HashMap<String, String>,

    #[serde(
        default,
        rename = "devDependencies",
        deserialize_with = "deserialize_dev_dependencies::<_, OMIT_DEV>"
    )]
    dev_dependencies: HashMap<String, String>,

    #[serde(default, rename = "peerDependencies")]
    peer_dependencies: HashMap<String, String>,

    #[serde(
        default,
        rename = "peerDependenciesMeta",
        deserialize_with = "deserialize_peer_dependencies_meta"
    )]
    peer_dependencies_meta: HashMap<String, PeerDependencyMeta>,

    #[serde(
        default,
        rename = "bundleDependencies",
        deserialize_with = "deserialize_present_bundle_dependencies"
    )]
    bundle_dependencies: Option<WireBundleDependencies>,

    #[serde(default, rename = "optionalDependencies")]
    optional_dependencies: HashMap<String, String>,

    #[serde(default, deserialize_with = "deserialize_engine_constraints")]
    engines: HashMap<String, String>,

    #[serde(default, deserialize_with = "deserialize_string_or_string_list")]
    os: Vec<String>,

    #[serde(default, deserialize_with = "deserialize_string_or_string_list")]
    cpu: Vec<String>,

    #[serde(default, deserialize_with = "deserialize_string_or_string_list")]
    libc: Vec<String>,

    #[serde(default)]
    dist: Option<DistInfo>,

    #[serde(default)]
    readme: Option<String>,

    #[serde(default, rename = "lpmConfig")]
    lpm_config: Option<serde_json::Value>,

    #[serde(default, rename = "_ecosystem")]
    ecosystem: Option<String>,

    #[serde(default, rename = "_swiftMeta")]
    swift_meta: Option<Box<SwiftMeta>>,

    #[serde(default, rename = "_npmUser")]
    npm_user: Option<Box<NpmUserMetadata>>,

    #[serde(default, rename = "_behavioralTags")]
    behavioral_tags: Option<BehavioralTags>,

    #[serde(default, rename = "_testOnlyTags")]
    test_only_tags: Option<Vec<String>>,

    #[serde(default, rename = "_lifecycleScripts")]
    lifecycle_scripts: Option<HashMap<String, String>>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    scripts: Option<HashMap<String, String>>,

    #[serde(
        default,
        rename = "hasInstallScript",
        skip_serializing_if = "Option::is_none"
    )]
    has_install_script: Option<bool>,

    #[serde(default, rename = "_securityFindings")]
    security_findings: Option<Vec<SecurityFinding>>,

    #[serde(default, rename = "_qualityScore")]
    quality_score: Option<u32>,

    #[serde(
        default,
        rename = "bundledDependencies",
        deserialize_with = "deserialize_present_bundle_dependencies"
    )]
    bundled_dependencies: Option<WireBundleDependencies>,
}

fn deserialize_present_bundle_dependencies<'de, D>(
    deserializer: D,
) -> Result<Option<WireBundleDependencies>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserializer
        .deserialize_any(WireBundleDependenciesVisitor)
        .map(Some)
}

impl<const OMIT_DEV: bool> TryFrom<VersionMetadataWire<OMIT_DEV>> for VersionMetadata {
    type Error = serde_json::Error;

    fn try_from(wire: VersionMetadataWire<OMIT_DEV>) -> Result<Self, Self::Error> {
        let bundle_dependencies = match wire.bundle_dependencies.or(wire.bundled_dependencies) {
            Some(WireBundleDependencies::All) => {
                let mut names: Vec<String> = wire.dependencies.keys().cloned().collect();
                names.sort_unstable();
                names
            }
            Some(WireBundleDependencies::List(names)) => names,
            Some(WireBundleDependencies::Empty) | None => Vec::new(),
        };
        Ok(Self {
            name: wire.name,
            version: wire.version,
            publication_status: wire.publication_status,
            description: wire.description,
            deprecated: wire.deprecated,
            dependencies: wire.dependencies,
            dev_dependencies: wire.dev_dependencies,
            peer_dependencies: wire.peer_dependencies,
            peer_dependencies_meta: wire.peer_dependencies_meta,
            bundle_dependencies,
            optional_dependencies: wire.optional_dependencies,
            engines: wire.engines,
            os: wire.os,
            cpu: wire.cpu,
            libc: wire.libc,
            dist: wire.dist,
            readme: wire.readme,
            lpm_config: wire.lpm_config,
            ecosystem: wire.ecosystem,
            swift_meta: wire.swift_meta,
            npm_user: wire.npm_user,
            behavioral_tags: wire.behavioral_tags,
            test_only_tags: wire.test_only_tags,
            lifecycle_scripts: wire.lifecycle_scripts,
            scripts: wire.scripts,
            has_install_script: wire.has_install_script,
            security_findings: wire.security_findings,
            quality_score: wire.quality_score,
        })
    }
}

fn deserialize_dev_dependencies<'de, D: serde::Deserializer<'de>, const OMIT_DEV: bool>(
    deserializer: D,
) -> Result<HashMap<String, String>, D::Error> {
    if OMIT_DEV {
        serde::de::IgnoredAny::deserialize(deserializer)?;
        Ok(HashMap::new())
    } else {
        HashMap::deserialize(deserializer)
    }
}

pub(crate) fn deserialize_version_without_dev_dependencies<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<VersionMetadata, D::Error> {
    VersionMetadataWire::<true>::deserialize(deserializer)?
        .try_into()
        .map_err(serde::de::Error::custom)
}
