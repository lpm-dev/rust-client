use lpm_registry::{DistInfo, PackageMetadata, VersionMetadata};
use lpm_resolver::parse_metadata_to_cache_info;
use std::collections::HashMap;

fn version_metadata(version: &str) -> VersionMetadata {
    VersionMetadata {
        name: "chalk".to_string(),
        version: version.to_string(),
        ..VersionMetadata::default()
    }
}

#[test]
fn parse_metadata_to_cache_info_is_available_to_external_callers() {
    let mut versions = HashMap::new();

    let prerelease = version_metadata("1.0.0-beta.1");
    versions.insert("1.0.0-beta.1".to_string(), prerelease);

    let mut stable = version_metadata("1.0.0");
    stable
        .dependencies
        .insert("kleur".to_string(), "^4.0.0".to_string());
    stable
        .peer_dependencies
        .insert("react".to_string(), "^19.0.0".to_string());
    stable
        .optional_dependencies
        .insert("fsevents".to_string(), "^2.0.0".to_string());
    stable.os.push("darwin".to_string());
    stable.cpu.push("arm64".to_string());
    stable.dist = Some(DistInfo {
        tarball: Some("https://example.test/chalk/-/chalk-1.0.0.tgz".to_string()),
        integrity: Some("sha512-deadbeef".to_string()),
        shasum: None,
    });
    versions.insert("1.0.0".to_string(), stable);

    let metadata = PackageMetadata {
        name: "chalk".to_string(),
        description: Some("external public API smoke test".to_string()),
        dist_tags: HashMap::from([("latest".to_string(), "1.0.0".to_string())]),
        versions,
        time: HashMap::new(),
        downloads: None,
        distribution_mode: None,
        package_type: None,
        latest_version: Some("1.0.0".to_string()),
        ecosystem: None,
    };

    let info = parse_metadata_to_cache_info(&metadata, true);

    assert_eq!(
        info.versions
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>(),
        vec!["1.0.0".to_string()]
    );
    assert_eq!(info.deps["1.0.0"]["kleur"], "^4.0.0");
    assert_eq!(info.peer_deps["1.0.0"]["react"], "^19.0.0");
    assert!(info.optional_dep_names["1.0.0"].contains("fsevents"));
    assert_eq!(
        info.dist["1.0.0"].tarball_url.as_deref(),
        Some("https://example.test/chalk/-/chalk-1.0.0.tgz")
    );
}
