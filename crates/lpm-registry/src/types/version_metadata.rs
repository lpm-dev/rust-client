use super::*;

#[derive(Deserialize)]
pub(super) struct VersionMetadataWire {
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

    #[serde(default, rename = "devDependencies")]
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
    bundle_dependencies: Option<serde_json::Value>,

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

    #[serde(default, rename = "_vulnerabilities")]
    vulnerabilities: Option<Vec<Vulnerability>>,
    #[serde(
        default,
        rename = "bundledDependencies",
        deserialize_with = "deserialize_present_bundle_dependencies"
    )]
    bundled_dependencies: Option<serde_json::Value>,
}

fn deserialize_present_bundle_dependencies<'de, D>(
    deserializer: D,
) -> Result<Option<serde_json::Value>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    serde_json::Value::deserialize(deserializer).map(Some)
}

impl TryFrom<VersionMetadataWire> for VersionMetadata {
    type Error = serde_json::Error;

    fn try_from(wire: VersionMetadataWire) -> Result<Self, Self::Error> {
        let bundle_dependencies = wire
            .bundle_dependencies
            .or(wire.bundled_dependencies)
            .map(deserialize_bundle_dependencies)
            .transpose()?
            .unwrap_or_default();
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
            lifecycle_scripts: wire.lifecycle_scripts,
            scripts: wire.scripts,
            has_install_script: wire.has_install_script,
            security_findings: wire.security_findings,
            quality_score: wire.quality_score,
            vulnerabilities: wire.vulnerabilities,
        })
    }
}
